"""The one policy-enforcing transport. Every adapter reaches the network through it.

Implements docs/explanation/architecture.md, section 9. A transport failure is returned as
data in ``Record.error``. It is never raised, and it is never a verdict by itself.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urljoin, urlsplit

from dppce.evidence.recording import new_salt
from dppce.infrastructure.clock import parse_stamp, utc_stamp
from dppce.infrastructure.interfaces import Clock, Record, Request, TransportError
from dppce.models import Authorization, NetworkPolicy, Scope

SAFE_METHODS: Final = ("GET", "HEAD")
REMOVED: Final = "<removed>"
_SECRET_REQUEST_HEADERS: Final = frozenset({"authorization", "cookie", "proxy-authorization", "x-api-key"})
_SECRET_RESPONSE_HEADERS: Final = frozenset({"set-cookie"})
_REDIRECTS: Final = (301, 302, 303, 307, 308)
_ACTIVE_SCOPES: Final = (Scope.WRITE, Scope.TAMPER, Scope.FUZZ)
_RETRYABLE: Final = ("connect", "timeout")


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> list[str]:
        """Return the IP addresses of ``host``. Raise OSError if it does not resolve."""
        ...


class SystemResolver:
    def resolve(self, host: str, port: int) -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True)
class TransportConfig:
    policy: NetworkPolicy
    engine_version: str
    # role -> (origin, bearer token). A token is sent only to its own origin.
    credentials: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    authorization: Authorization | None = None
    # The operator states that the system owner permits bounded read-only access.
    remote_read_authorized: bool = False
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


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        self._tls = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._tls)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        # The certificate is checked against the host name, not against the pinned address.
        self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


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
        self._sent = 0
        self._last_sent: float | None = None

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)

    # -- policy -----------------------------------------------------------------------------

    def _target(self, url: str, method: str, role: str) -> _Target:
        """Check one hop against the policy and pin its address. Raises ``_DeniedError``."""
        policy, auth = self._config.policy, self._config.authorization
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise _DeniedError("policy_denied") from exc
        if parts.scheme not in ("http", "https") or not host or parts.username or parts.password:
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
            public = [_is_public(a) for a in addresses]
        except ValueError as exc:
            raise _DeniedError("dns") from exc
        # Every answer must pass. One private answer among public ones is a rebinding attempt.
        if not all(public) and not private_ok:
            raise _DeniedError("policy_denied")
        if any(public) and auth is None and not self._config.remote_read_authorized:
            raise _DeniedError("authorization_denied")
        default_port = port == (443 if parts.scheme == "https" else 80)
        origin = f"{parts.scheme}://{host}" + ("" if default_port else f":{port}")
        if auth is not None:
            now = self._clock.now()
            permitted = (
                origin in auth.endpoints
                and method in auth.methods
                and role in auth.roles
                and parse_stamp(auth.not_before) <= now <= parse_stamp(auth.not_after)
            )
            if not permitted:
                raise _DeniedError("authorization_denied")
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        return _Target(parts.scheme, host, port, origin, path, addresses[0])

    def _budget_left(self) -> bool:
        limit = self._config.policy.max_requests
        if self._config.authorization is not None:
            limit = min(limit, self._config.authorization.max_requests)
        return self._sent < limit

    # -- one HTTP request -------------------------------------------------------------------

    def _send(
        self, target: _Target, method: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes, bool] | TransportError:
        policy = self._config.policy
        if self._last_sent is not None and policy.min_interval_ms:
            wait = policy.min_interval_ms / 1000 - (self._monotonic() - self._last_sent)
            if wait > 0:
                self._sleep(wait)
        self._sent += 1
        self._last_sent = self._monotonic()
        timeout = policy.timeout_ms / 1000
        connection: http.client.HTTPConnection = (
            _PinnedHTTPSConnection(target.host, target.port, target.address, timeout)
            if target.scheme == "https"
            else _PinnedHTTPConnection(target.host, target.port, target.address, timeout)
        )
        try:
            connection.request(method, target.path, body=body, headers=dict(headers))
            response = connection.getresponse()
            data = response.read(policy.max_body_bytes + 1)
            response_headers = tuple((k, v) for k, v in response.getheaders())
            return (
                response.status,
                response_headers,
                data[: policy.max_body_bytes],
                len(data) > policy.max_body_bytes,
            )
        except TimeoutError:
            return "timeout"
        except ssl.SSLError:
            return "tls"
        except http.client.HTTPException:
            return "protocol"
        except OSError:
            return "connect"
        finally:
            connection.close()

    def _headers(self, request: Request, target: _Target, first_origin: str) -> dict[str, str]:
        contact = f" (+{self._config.policy.contact})" if self._config.policy.contact else ""
        headers = {"User-Agent": f"dppce/{self._config.engine_version}{contact}", "Accept": "*/*"}
        for name, value in request.headers.items():
            # A secret header that the caller supplies stays with the first origin.
            if name.lower() not in _SECRET_REQUEST_HEADERS or target.origin == first_origin:
                headers[name] = value
        credential = self._config.credentials.get(request.role)
        if credential is not None and credential[0] == target.origin:
            headers["Authorization"] = f"Bearer {credential[1]}"
        return headers

    # -- Acquirer ---------------------------------------------------------------------------

    def fetch(self, request: Request) -> Record:
        method = request.method.upper()
        sent_headers: dict[str, str] = {}
        redirects: list[str] = []
        attempts = 0

        def done(
            error: TransportError | None,
            status: int | None = None,
            headers: tuple[tuple[str, str], ...] = (),
            body: bytes = b"",
            truncated: bool = False,
        ) -> Record:
            record = Record(
                record_id=f"r{len(self._records) + 1:04d}",
                kind="http",
                acquired_at=utc_stamp(self._clock.now()),
                method=method,
                url=request.url,
                role=request.role,
                request_headers=tuple(
                    (k, REMOVED if k.lower() in _SECRET_REQUEST_HEADERS else v)
                    for k, v in sorted(sent_headers.items())
                ),
                status=status,
                headers=tuple(
                    (k, REMOVED if k.lower() in _SECRET_RESPONSE_HEADERS else v) for k, v in headers
                ),
                body=body,
                truncated=truncated,
                error=error,
                redirects=tuple(redirects),
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

        while True:
            sent_headers = self._headers(request, target, first_origin)
            result: tuple[int, tuple[tuple[str, str], ...], bytes, bool] | TransportError = "connect"
            for _ in range(1 + (self._config.policy.retries if method in SAFE_METHODS else 0)):
                if not self._budget_left():
                    return done("budget_exhausted")
                attempts += 1
                result = self._send(target, method, sent_headers, request.body)
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
            next_url = urljoin(f"{target.origin}{target.path}", location)
            redirects.append(next_url)
            try:
                target = self._target(next_url, method, request.role)
            except _DeniedError as denied:
                # The engine refuses the hop. It has no answer from the system to judge.
                out_of_scope = denied.error in ("policy_denied", "authorization_denied")
                return done("redirect_out_of_scope" if out_of_scope else denied.error, status, headers)

    def artifact(self, name: str) -> Record:
        path = self._config.samples.get(name)
        body = b""
        error: TransportError | None = None
        if path is None:
            error = "artifact_unavailable"
        else:
            try:
                if path.stat().st_size > self._config.max_artifact_bytes:
                    error = "body_too_large"
                else:
                    body = path.read_bytes()
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
