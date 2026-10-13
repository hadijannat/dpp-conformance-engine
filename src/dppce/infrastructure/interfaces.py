"""Injected interfaces for every external interaction.

Catalogue interpretation, applicability, verdicts, and evidence construction do no I/O.
They get what they need through these protocols. See ADR 0005.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time as an aware UTC datetime."""
        ...


@dataclass(frozen=True)
class Request:
    """One bounded read or write that a check asks for."""

    method: str
    url: str
    role: str = "anonymous"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


# Why a record holds no response. A check maps these to "unreachable", never to "fail" by itself.
TransportError = Literal[
    "policy_denied",
    "authorization_denied",
    "budget_exhausted",
    "dns",
    "connect",
    "tls",
    "timeout",
    "too_many_redirects",
    "redirect_out_of_scope",
    "body_too_large",
    "protocol",
    "recording_mismatch",
]


@dataclass(frozen=True)
class Record:
    """One raw record: an HTTP exchange or a local input artifact.

    Request headers are stored after secrets are removed. ``body`` holds the raw bytes.
    ``salt`` is random, is drawn when the record is acquired, and is stored with the record.
    """

    record_id: str
    kind: Literal["http", "artifact"]
    acquired_at: str
    method: str
    url: str
    role: str
    request_headers: tuple[tuple[str, str], ...]
    status: int | None
    headers: tuple[tuple[str, str], ...]
    body: bytes
    truncated: bool
    error: TransportError | None
    redirects: tuple[str, ...]
    attempts: int
    salt: bytes

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((v for k, v in self.headers if k.lower() == wanted), None)


class Acquirer(Protocol):
    """The only way a check reaches the outside world.

    The live implementation applies the transport policy and records every exchange.
    The replay implementation serves the same records from a recording.
    """

    def fetch(self, request: Request) -> Record:
        """Perform one request. Never raises for a transport failure: see ``Record.error``."""
        ...

    def artifact(self, name: str) -> Record:
        """Read the input artifact that ``IXIT.samples[name]`` names, for example a QR image."""
        ...

    def records(self) -> tuple[Record, ...]:
        """Return every record acquired so far, in acquisition order."""
        ...


class Signer(Protocol):
    """Produces raw signatures. A KMS or PKCS#11 provider implements this protocol."""

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, signing_input: bytes) -> bytes:
        """Return the raw JWS signature bytes for ``signing_input``."""
        ...


class DataKeyProvider(Protocol):
    """Supplies the 256-bit key that encrypts retained observations. Keys live apart from recordings."""

    def data_key(self, key_id: str) -> bytes: ...

    def default_key_id(self) -> str: ...
