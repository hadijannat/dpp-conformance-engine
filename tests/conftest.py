"""Shared fixtures. Every key here is generated for the test run and is not a real key."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import EvidenceEnvelope, TrustBundle, TrustedKey
from tests.support import ISSUER, KID, Handler, LoopbackServer, make_envelope


@pytest.fixture(scope="session")
def signer() -> LocalSigner:
    return LocalSigner.generate(KID)


@pytest.fixture(scope="session")
def trust(signer: LocalSigner) -> TrustBundle:
    key = TrustedKey(
        kid=KID,
        issuer=ISSUER,
        purposes=("report", "authorization"),
        public_jwk=signer.public_jwk(),
        not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z",
    )
    return TrustBundle(schema_version="dppce.trust/1", policy_version="test-1", keys=(key,))


@pytest.fixture
def signed(signer: LocalSigner) -> EvidenceEnvelope:
    return sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")


@pytest.fixture
def loopback() -> Iterator[Callable[[Handler], LoopbackServer]]:
    servers: list[LoopbackServer] = []

    def start(handler: Handler) -> LoopbackServer:
        server = LoopbackServer(handler)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()
