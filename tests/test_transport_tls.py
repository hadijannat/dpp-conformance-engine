"""The policy transport against a loopback HTTPS server with a TEST-ONLY certificate.

Verification stays on. The test trusts its own TEST-ONLY certificate authority through the trust
mechanism that the transport already uses: ``ssl.create_default_context()`` loads the default
verify paths, and OpenSSL reads ``SSL_CERT_FILE`` for them. No production code changes for this
test, and no other test trusts the certificate. A certificate that the transport does not trust,
or that names another host, is a transport failure: ``unreachable``, never ``pass``.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dppce.adapters.identifier import resolve
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.models import ExecutionStatus, NetworkPolicy
from tests.support import LoopbackServer, reply
from tests.test_adapters_identifier import _with_identifier, live

NOW = datetime.now(UTC)
LOCAL = {"allowed_hosts": ("127.0.0.1", "localhost"), "allow_private_hosts": ("127.0.0.1", "localhost")}
Pair = tuple[ec.EllipticCurvePrivateKey, x509.Certificate]


class _Loopback:
    """Every name resolves to the loopback address, so no test needs DNS."""

    def resolve(self, host: str, port: int) -> list[str]:
        return ["127.0.0.1"]


def _name(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def _certificate(
    subject: str, key: ec.EllipticCurvePrivateKey, issuer: Pair | None, *, ca: bool
) -> x509.Certificate:
    signer, issuer_name = (key, _name(subject)) if issuer is None else (issuer[0], issuer[1].subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(hours=1))
        .not_valid_after(NOW + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]), critical=False
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, hashes.SHA256())


def _authority(subject: str) -> Pair:
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _certificate(subject, key, None, ca=True)


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Any]:
    authority, stranger = _authority("TEST-ONLY lab CA"), _authority("TEST-ONLY stranger CA")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _certificate("TEST-ONLY 127.0.0.1", leaf_key, authority, ca=False)
    paths = {name: tmp_path / f"TEST-ONLY-{name}.pem" for name in ("ca", "stranger", "chain", "key")}
    paths["ca"].write_bytes(_pem(authority[1]))
    paths["stranger"].write_bytes(_pem(stranger[1]))
    paths["chain"].write_bytes(_pem(leaf) + _pem(authority[1]))
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    paths["key"].write_bytes(key_pem)
    return paths


@pytest.fixture
def https(pki: dict[str, Path]) -> Iterator[LoopbackServer]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki["chain"], pki["key"])
    server = LoopbackServer(lambda r: reply(r, body=b'{"id": "x"}'), tls=context)
    yield server
    server.close()


def _transport() -> PolicyTransport:
    config = TransportConfig(policy=NetworkPolicy(**LOCAL), engine_version="1")
    return PolicyTransport(config, FrozenClock(NOW), resolver=_Loopback(), sleep=lambda _: None)


def test_a_trusted_certificate_gives_an_answer(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["ca"]))
    record = _transport().fetch(Request("GET", f"{https.origin}/dpp/1"))
    assert (record.error, record.status, record.body) == (None, 200, b'{"id": "x"}')
    assert [seen["path"] for seen in https.seen] == ["/dpp/1"]


def test_an_untrusted_certificate_is_a_transport_failure(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["stranger"]))
    record = _transport().fetch(Request("GET", f"{https.origin}/dpp/1"))
    assert (record.error, record.status) == ("tls", None)
    assert https.seen == [], "no request is sent over a connection that failed verification"


def test_a_certificate_for_another_host_is_a_transport_failure(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["ca"]))
    # The certificate names 127.0.0.1. The URL names localhost, which resolves to the same address.
    record = _transport().fetch(Request("GET", f"https://localhost:{https.port}/dpp/1"))
    assert (record.error, record.status) == ("tls", None)
    assert https.seen == []


@pytest.mark.parametrize("trusted", [True, False], ids=["trusted", "untrusted"])
def test_a_check_over_tls_is_unreachable_never_pass_when_verification_fails(
    trusted: bool,
    https: LoopbackServer,
    pki: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["ca" if trusted else "stranger"]))
    base = live(tmp_path, _Server(https), {}, acquirer=_transport())
    ctx = _with_identifier(base, f"{https.origin}/01/09506000134352/21/EV0001")
    outcome = resolve(ctx)
    if trusted:
        assert (outcome.status, outcome.passed, outcome.reason_code) == (
            ExecutionStatus.COMPLETED,
            True,
            "IDENTIFIER.RESOLVED",
        )
    else:
        assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
            ExecutionStatus.COMPLETED,
            False,
            True,
            "TRANSPORT.UNREACHABLE",
        )


class _Server:
    """The shape that ``live`` reads from a resolver double: its loopback server."""

    def __init__(self, server: LoopbackServer) -> None:
        self.server = server
