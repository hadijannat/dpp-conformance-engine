"""The one policy-enforcing transport. Every adapter reaches the network through it.

Implements docs/explanation/architecture.md, section 9. A transport failure is returned as
data in ``Record.error``. It is never raised, and it is never a verdict by itself.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import re
import socket
import ssl
import stat
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import quote, urljoin, urlsplit

from dppce.evidence.recording import new_salt
from dppce.infrastructure.clock import parse_stamp, utc_stamp
from dppce.infrastructure.interfaces import Clock, Record, Request, TransportError
from dppce.infrastructure.redaction import (
    REMOVED,
    is_public_address,
    redact_request_headers,
    redact_response_headers,
    redact_url,
)
from dppce.models import Authorization, NetworkPolicy, Scope

SAFE_METHODS: Final = ("GET", "HEAD")
ANONYMOUS: Final = "anonymous"
_REDIRECTS: Final = (301, 302, 303, 307, 308)
_ACTIVE_SCOPES: Final = (Scope.WRITE, Scope.TAMPER, Scope.FUZZ)
_RETRYABLE: Final = ("connect", "timeout")
# A shorter credential could match ordinary text, and its removal would change the evidence.
MIN_SECRET_LENGTH: Final = 12
# The shortest head of a credential that is removed where the body limit cut the credential.
_MIN_CUT_HEAD: Final = 8


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> list[str]:
        """Return the IP addresses of ``host``. Raise OSError if it does not resolve."""
        ...


class SystemResolver:
    def resolve(self, host: str, port: int) -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})


_URL_SAFE: Final = "/%:@!$&'()*+,;=-._~"


def origin_of(url: str) -> str:
    """Return the origin of a URL in one normal form: lower case, no default port, IPv6 in brackets.

    Every comparison of origins uses this function. Two spellings of one origin must never
    decide whether a credential is sent.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    default = 443 if parts.scheme == "https" else 80
    # Not "parts.port or default": an explicit port 0 is not the default port.
    port = default if parts.port is None else parts.port
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + ("" if port == default else f":{port}")


def _forms(token: str) -> tuple[str, ...]:
    """The spellings of a credential that a system commonly echoes, longest first.

    Plain; percent-encoded with or without '/' kept, in upper-case or lower-case hex; and with
    the JSON escape of '/' that PHP writes by default.
    """
    encoded = (quote(token, safe=""), quote(token))
    lower = tuple(re.sub("%[0-9A-F]{2}", lambda m: m[0].lower(), form) for form in encoded)
    forms = {token, token.replace("/", "\\/"), *encoded, *lower}
    return tuple(sorted(forms, key=len, reverse=True))


def _origins(urls: tuple[str, ...] | frozenset[str]) -> frozenset[str]:
    """The origins of ``urls``. A URL that cannot be parsed names no origin."""
    found = set()
    for url in urls:
        with contextlib.suppress(ValueError):
            found.add(origin_of(url))
    return frozenset(found)


def _pin(path: Path) -> tuple[tuple[int, int] | None, int | None]:
    """Open a regular file and return its device and inode, and the open descriptor.

    The descriptor stays open while the transport lives. An open file keeps its inode, so a file
    that replaces it at the same path gets a different inode number: some file systems reuse a
    freed number at once. Returns (None, None) if there is no regular file at ``path`` now.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        handle = os.open(path, flags)
    except OSError:
        return None, None
    found = os.fstat(handle)
    if not stat.S_ISREG(found.st_mode):
        os.close(handle)
        return None, None
    return (found.st_dev, found.st_ino), handle


def _close_all(handles: tuple[int, ...]) -> None:
    for handle in handles:
        with contextlib.suppress(OSError):
            os.close(handle)


@dataclass(frozen=True)
class TransportConfig:
    policy: NetworkPolicy
    engine_version: str
    # role -> (origin, bearer token). A token is sent only to its own origin.
    credentials: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    authorization: Authorization | None = None
    # Public origins for which the operator states that the owner permits bounded read-only access.
    remote_read_origins: frozenset[str] = frozenset()
    # Non-public origins that the operator confirmed. None: any port of a host in
    # ``policy.allow_private_hosts`` (library use). The command line always sets it, so that the
    # IXIT cannot choose a different service on a confirmed host.
    private_origins: frozenset[str] | None = None
    samples: Mapping[str, Path] = field(default_factory=dict)
    max_artifact_bytes: int = 8 * 1024 * 1024


@dataclass(frozen=True)
class _Target:
    scheme: str
    host: str
    port: int
    origin: str
    path: str
    address: str


class _DeniedError(Exception):
    def __init__(self, error: TransportError) -> None:
        super().__init__(error)
        self.error = error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to an address that the policy already checked, not to a fresh DNS answer."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


def _tls_context() -> ssl.SSLContext:
    """A client context that checks certificates and host names and refuses TLS below 1.2.

    The default context already refuses TLS 1.0 and 1.1. The minimum is stated here, so that no
    change of a default can lower it.
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=_tls_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        # The certificate is checked against the host name, not against the pinned address.
        context = _tls_context()
        self.sock = context.wrap_socket(raw, server_hostname=self.host)


class PolicyTransport:
    """Live ``Acquirer``: applies the policy, performs the request, and records the exchange."""

    def __init__(
        self,
        config: TransportConfig,
        clock: Clock,
        resolver: Resolver | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._clock = clock
        self._resolver = resolver or SystemResolver()
        self._sleep = sleep
        self._monotonic = monotonic
        self._records: list[Record] = []
        # The identity of each sample file is taken now. A file read later must be the same one.
        self._samples: dict[str, tuple[Path, tuple[int, int] | None]] = {}
        pins: list[int] = []
        for name, path in config.samples.items():
            identity, handle = _pin(path.resolve())
            self._samples[name] = (path.resolve(), identity)
            if handle is not None:
                pins.append(handle)
        weakref.finalize(self, _close_all, tuple(pins))
        tokens = [token for _, token in config.credentials.values()]
        if any(len(token) < MIN_SECRET_LENGTH for token in tokens):
            raise ValueError(f"a credential needs {MIN_SECRET_LENGTH} characters or more")
        # Longest first: a credential that begins with a shorter one is removed as a whole.
        self._secrets = tuple(sorted(set(tokens), key=len, reverse=True))
        self._sent = 0
        self._last_sent: float | None = None

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)

    # -- policy -----------------------------------------------------------------------------

    def _target(self, url: str, method: str, role: str) -> _Target:
        """Check one hop against the policy and pin its address. Raises ``_DeniedError``."""
        policy, auth = self._config.policy, self._config.authorization
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            port = (443 if parts.scheme == "https" else 80) if parts.port is None else parts.port
            origin = origin_of(url)
        except ValueError as exc:
            # A URL that cannot be parsed is outside every policy. It is never raised.
            raise _DeniedError("policy_denied") from exc
        # urlsplit drops tab, CR, and LF and strips edge controls and spaces. The record would
        # then name a request that was never sent, so such a URL is refused, never rewritten.
        controls = any(c <= " " or c == "\x7f" for c in url)
        if controls or parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
            raise _DeniedError("policy_denied")
        if host not in {h.lower() for h in policy.allowed_hosts}:
            raise _DeniedError("policy_denied")
        try:
            addresses = self._resolver.resolve(host, port)
        except OSError as exc:
            raise _DeniedError("dns") from exc
        if not addresses:
            raise _DeniedError("dns")
        private_ok = host in {h.lower() for h in policy.allow_private_hosts}
        try:
            public = [is_public_address(a) for a in addresses]
        except ValueError as exc:
            raise _DeniedError("dns") from exc
        # Every answer must pass. One private answer among public ones is a rebinding attempt.
        if not all(public) and not private_ok:
            raise _DeniedError("policy_denied")
        confirmed = self._config.private_origins
        if not all(public) and confirmed is not None and origin not in confirmed:
            raise _DeniedError("policy_denied")
        if any(public) and auth is None and origin not in self._config.remote_read_origins:
            raise _DeniedError("authorization_denied")
        if auth is not None:
            now = self._clock.now()
            permitted = (
                origin in _origins(auth.endpoints)
                and method in auth.methods
                and role in auth.roles
                and parse_stamp(auth.not_before) <= now <= parse_stamp(auth.not_after)
            )
            if not permitted:
                raise _DeniedError("authorization_denied")
        path = quote(parts.path or "/", safe=_URL_SAFE)
        if parts.query:
            path += "?" + quote(parts.query, safe=_URL_SAFE + "?")
        return _Target(parts.scheme, host, port, origin, path, addresses[0])

    def _budget_left(self) -> bool:
        limit = self._config.policy.max_requests
        if self._config.authorization is not None:
            limit = min(limit, self._config.authorization.max_requests)
        return self._sent < limit

    # -- one HTTP request -------------------------------------------------------------------

    def _send(
        self, target: _Target, method: str, headers: Mapping[str, str], body: bytes | None, left: float
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes, bool] | TransportError:
        policy = self._config.policy
        if self._last_sent is not None and policy.min_interval_ms:
            wait = policy.min_interval_ms / 1000 - (self._monotonic() - self._last_sent)
            if wait > 0:
                self._sleep(wait)
        self._sent += 1
        self._last_sent = self._monotonic()
        # ``left`` is what remains of the total time of the whole fetch: every hop and attempt.
        timeout = max(0.001, min(policy.timeout_ms / 1000, left))
        connection: http.client.HTTPConnection = (
            _PinnedHTTPSConnection(target.host, target.port, target.address, timeout)
            if target.scheme == "https"
            else _PinnedHTTPConnection(target.host, target.port, target.address, timeout)
        )
        # The socket timeout bounds one read. A system that sends one byte at a time would keep a
        # request alive without end. This timer bounds the whole request.
        expired = threading.Event()

        def expire(sock: socket.socket) -> None:
            expired.set()
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)

        timer: threading.Timer | None = None
        try:
            connection.connect()
            # Keep the socket itself. http.client forgets it when a response says that the
            # connection closes, and the body is still being read at that time.
            timer = threading.Timer(left, expire, (connection.sock,))
            timer.daemon = True
            timer.start()
            connection.request(method, target.path, body=body, headers=dict(headers))
            response = connection.getresponse()
            data = response.read(policy.max_body_bytes + 1)
            response_headers = tuple((k, v) for k, v in response.getheaders())
            if expired.is_set():
                # The timer ended the read. What arrived is a partial answer and proves nothing.
                return "timeout"
            limit = policy.max_body_bytes
            return response.status, response_headers, data[:limit], len(data) > limit
        except TimeoutError:
            return "timeout"
        except ssl.SSLError:
            return "timeout" if expired.is_set() else "tls"
        except http.client.HTTPException:
            return "timeout" if expired.is_set() else "protocol"
        except OSError:
            return "timeout" if expired.is_set() else "connect"
        except (UnicodeError, ValueError):
            # A transport failure is data. It is never raised to the check.
            return "protocol"
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def _credential_fits(self, role: str, target: _Target) -> bool:
        """True for the anonymous role, or if the credential of ``role`` belongs to this origin."""
        if role == ANONYMOUS:
            return True
        credential = self._config.credentials.get(role)
        return credential is not None and origin_of(credential[0]) == target.origin

    def _headers(self, request: Request, target: _Target, first_origin: str) -> dict[str, str]:
        contact = f" (+{self._config.policy.contact})" if self._config.policy.contact else ""
        # No check decompresses a body, so the transport asks for none. A system can still send
        # an encoded body: the checks then report it as not assessable, never as clean.
        headers = {
            "User-Agent": f"dppce/{self._config.engine_version}{contact}",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        # Caller headers are bound to the first origin. A redirect to a different origin gets none.
        if target.origin == first_origin:
            headers.update(request.headers)
        credential = self._config.credentials.get(request.role)
        # The anonymous role never carries a credential, also if one is configured under its name.
        if request.role != ANONYMOUS and credential is not None and origin_of(credential[0]) == target.origin:
            headers["Authorization"] = f"Bearer {credential[1]}"
        return headers

    def _scrub(
        self, headers: tuple[tuple[str, str], ...], body: bytes, redirects: list[str], *, truncated: bool
    ) -> tuple[tuple[tuple[str, str], ...], bytes, tuple[str, ...]]:
        """Remove the engine's own credentials if the tested system echoes them back.

        Each form of ``_forms`` is removed from header names and values, from redirect targets,
        and from the body. Where the body limit cut the body, a cut head of a form is removed
        too. A complete body keeps its tail: it is evidence. Other encodings, such as base64 or a
        mix of forms, are not recognized.
        """
        removed = REMOVED.encode("ascii")
        for token in self._secrets:
            forms = _forms(token)
            for form in forms:
                headers = tuple((k.replace(form, REMOVED), v.replace(form, REMOVED)) for k, v in headers)
                redirects = [target.replace(form, REMOVED) for target in redirects]
                body = body.replace(form.encode("utf-8"), removed)
            heads = [form.encode("utf-8") for form in forms] if truncated else []
            # The longest cut head of any form first, so that no shorter head leaves a remainder.
            size = next(
                (
                    size
                    for size in range(max(map(len, heads), default=0) - 1, _MIN_CUT_HEAD - 1, -1)
                    if any(len(head) > size and body.endswith(head[:size]) for head in heads)
                ),
                0,
            )
            if size:
                body = body[:-size] + removed
        return headers, body, tuple(redirects)

    # -- Acquirer ---------------------------------------------------------------------------

    def fetch(self, request: Request) -> Record:  # noqa: PLR0912 - one loop over hops; each branch is one outcome
        method = request.method.upper()
        sent_headers: dict[str, str] = {}
        redirects: list[str] = []
        attempts = 0
        # One deadline for the whole fetch: every redirect hop and every retry share it.
        deadline = self._monotonic() + self._config.policy.total_timeout_ms / 1000

        def done(
            error: TransportError | None,
            status: int | None = None,
            headers: tuple[tuple[str, str], ...] = (),
            body: bytes = b"",
            truncated: bool = False,
        ) -> Record:
            headers, body, kept_redirects = self._scrub(headers, body, redirects, truncated=truncated)
            record = Record(
                record_id=f"r{len(self._records) + 1:04d}",
                kind="http",
                acquired_at=utc_stamp(self._clock.now()),
                method=method,
                url=redact_url(request.url),
                role=request.role,
                request_headers=redact_request_headers(sent_headers),
                status=status,
                headers=redact_response_headers(headers),
                body=body,
                truncated=truncated,
                error=error,
                redirects=kept_redirects,
                attempts=attempts,
                salt=new_salt(),
            )
            self._records.append(record)
            return record

        auth = self._config.authorization
        if method not in SAFE_METHODS and (auth is None or not set(auth.scopes) & set(_ACTIVE_SCOPES)):
            return done("authorization_denied")
        try:
            target = self._target(request.url, method, request.role)
        except _DeniedError as denied:
            return done(denied.error)
        first_origin = target.origin
        if not self._credential_fits(request.role, target):
            # The answer would be the anonymous view, recorded under the name of the role.
            return done("authorization_denied")

        while True:
            sent_headers = self._headers(request, target, first_origin)
            result: tuple[int, tuple[tuple[str, str], ...], bytes, bool] | TransportError = "connect"
            for _ in range(1 + (self._config.policy.retries if method in SAFE_METHODS else 0)):
                if not self._budget_left():
                    return done("budget_exhausted")
                left = deadline - self._monotonic()
                if left <= 0:
                    return done("timeout")
                attempts += 1
                result = self._send(target, method, sent_headers, request.body, left)
                if not isinstance(result, str) or result not in _RETRYABLE:
                    break
            if isinstance(result, str):
                return done(result)
            status, headers, body, truncated = result
            location = next((v for k, v in headers if k.lower() == "location"), None)
            if status not in _REDIRECTS or location is None or method not in SAFE_METHODS:
                return done(None, status, headers, body, truncated)
            if len(redirects) >= self._config.policy.max_redirects:
                return done("too_many_redirects", status, headers)
            try:
                next_url = urljoin(f"{target.origin}{target.path}", location)
            except ValueError:
                # The system sent a Location that is not a URL. The engine does not follow it.
                return done("redirect_out_of_scope", status, headers)
            redirects.append(redact_url(next_url))
            try:
                target = self._target(next_url, method, request.role)
            except _DeniedError as denied:
                # The engine refuses the hop. It has no answer from the system to judge.
                out_of_scope = denied.error in ("policy_denied", "authorization_denied")
                return done("redirect_out_of_scope" if out_of_scope else denied.error, status, headers)
            if not self._credential_fits(request.role, target):
                # The credential of the role does not follow to a different origin.
                return done("redirect_out_of_scope", status, headers)

    def artifact(self, name: str) -> Record:
        sample = self._samples.get(name)
        body = b""
        error: TransportError | None = None
        if sample is None:
            error = "artifact_unavailable"
        else:
            path, identity = sample
            try:
                # The path was resolved when the transport was built. If a component is a link
                # now, the file is not the one that was confirmed. The final component is opened
                # without following a link and without blocking (a FIFO would block). The open
                # file must be a regular file, and the same file that was confirmed.
                if path.resolve(strict=True) != path:
                    raise OSError("the sample path changed after it was confirmed")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                handle = os.open(path, flags)
                with os.fdopen(handle, "rb") as source:
                    found = os.fstat(source.fileno())
                    if not stat.S_ISREG(found.st_mode) or (found.st_dev, found.st_ino) != identity:
                        raise OSError("the sample is not the confirmed regular file")
                    if found.st_size > self._config.max_artifact_bytes:
                        error = "body_too_large"
                    else:
                        body = source.read(self._config.max_artifact_bytes)
            except OSError:
                error = "artifact_unavailable"
        record = Record(
            record_id=f"r{len(self._records) + 1:04d}",
            kind="artifact",
            acquired_at=utc_stamp(self._clock.now()),
            method="READ",
            url=f"artifact:{name}",
            role="local",
            request_headers=(),
            status=None,
            headers=(),
            body=body,
            truncated=False,
            error=error,
            redirects=(),
            attempts=1,
            salt=new_salt(),
        )
        self._records.append(record)
        return record
