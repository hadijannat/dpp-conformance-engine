"""The policy transport against a loopback HTTPS server with a TEST-ONLY certificate.

Verification stays on. The test trusts its own TEST-ONLY certificate authority through the trust
mechanism that the transport already uses: ``ssl.create_default_context()`` loads the default
verify paths, and OpenSSL reads ``SSL_CERT_FILE`` for them. No production code changes for this
test, and no other test trusts the certificate. A certificate that the transport does not trust,
or that names another host, is a transport failure: ``unreachable``, never ``pass``.

The operator options of P2-12 are tested here too: a private CA file (``--ca-file``) and a client
certificate (``--client-cert``, ``--client-key``). Each key is generated per test and is TEST-ONLY.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from dppce import cli
from dppce.adapters.identifier import resolve
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import issue_authorization
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.transport import ClientIdentity, PolicyTransport, TransportConfig
from dppce.models import Authorization, ExecutionStatus, NetworkPolicy
from tests.support import LoopbackServer, reply
from tests.test_adapters_identifier import _with_identifier, live
from tests.test_family_profiles import FIXTURES, TRUST, _example

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
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: Pair | None,
    *,
    ca: bool,
    usage: ObjectIdentifier = ExtendedKeyUsageOID.SERVER_AUTH,
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
        # Python 3.13 verifies with X509_STRICT, which requires both key identifiers (RFC 5280).
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]), critical=False
        ).add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
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
    # A client certificate of the same CA. Its key is encrypted with a TEST-ONLY passphrase.
    client_key = ec.generate_private_key(ec.SECP256R1())
    client = _certificate(
        "TEST-ONLY client", client_key, authority, ca=False, usage=ExtendedKeyUsageOID.CLIENT_AUTH
    )
    paths["client"] = tmp_path / "TEST-ONLY-client.cert.pem"
    paths["client"].write_bytes(_pem(client))
    paths["client-key"] = tmp_path / "TEST-ONLY-client.key.pem"
    encryption = serialization.BestAvailableEncryption(PASSPHRASE.encode("ascii"))
    paths["client-key"].write_bytes(
        client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )
    return paths


PASSPHRASE = "TEST-ONLY-client-key-passphrase-0001"
PASSPHRASE_ENV = "DPPCE_SECRET_TEST_ONLY_CLIENT_KEY"
Peers = list[str | None]


def _client_ca_server(pki: dict[str, Path], verify: ssl.VerifyMode) -> tuple[LoopbackServer, Peers]:
    """A server that asks for a client certificate of the lab CA. It records the subject it got."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS 1.2: the server refuses a missing client certificate inside the handshake, so the client
    # sees "tls" every time. With TLS 1.3 the refusal arrives later, at the first read.
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(pki["chain"], pki["key"])
    context.load_verify_locations(pki["ca"])
    context.verify_mode = verify
    peers: Peers = []

    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        peer = request.connection.getpeercert()
        peers.append(dict(pair[0] for pair in peer["subject"])["commonName"] if peer else None)
        reply(request, body=b'{"id": "x"}')

    return LoopbackServer(handle, tls=context), peers


@pytest.fixture
def mutual(pki: dict[str, Path]) -> Iterator[tuple[LoopbackServer, Peers]]:
    server, peers = _client_ca_server(pki, ssl.CERT_REQUIRED)
    yield server, peers
    server.close()


@pytest.fixture
def optional(pki: dict[str, Path]) -> Iterator[tuple[LoopbackServer, Peers]]:
    server, peers = _client_ca_server(pki, ssl.CERT_OPTIONAL)
    yield server, peers
    server.close()


@pytest.fixture
def https(pki: dict[str, Path]) -> Iterator[LoopbackServer]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(pki["chain"], pki["key"])
    server = LoopbackServer(lambda r: reply(r, body=b'{"id": "x"}'), tls=context)
    yield server
    server.close()


def _transport(**changes: Any) -> PolicyTransport:
    config = TransportConfig(policy=NetworkPolicy(**LOCAL), engine_version="1", **changes)
    return PolicyTransport(config, FrozenClock(NOW), resolver=_Loopback(), sleep=lambda _: None)


def _grant(*origins: str) -> Authorization:
    return Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-tls-authorization",
        issuer="urn:example:operator:0001",
        subject="urn:example:test-lab",
        sut_identifier="urn:example:sut:reference-dpp",
        endpoints=origins,
        methods=("GET",),
        roles=("anonymous",),
        scopes=("read",),
        not_before="2026-01-01T00:00:00Z",
        not_after="2036-01-01T00:00:00Z",
        max_requests=100,
    )


def _identity(pki: dict[str, Path], passphrase: str = PASSPHRASE) -> ClientIdentity:
    return ClientIdentity(certificate=pki["client"], key=pki["client-key"], passphrase=passphrase)


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


# -- P2-12: a private CA file and a client certificate --------------------------------------------


def test_a_private_ca_file_lets_the_transport_reach_a_server_that_chains_to_it(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The default store alone does not trust the lab CA.
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["stranger"]))
    assert _transport().fetch(Request("GET", f"{https.origin}/dpp/1")).error == "tls"
    record = _transport(ca_file=pki["ca"]).fetch(Request("GET", f"{https.origin}/dpp/1"))
    assert (record.error, record.status, record.body) == (None, 200, b'{"id": "x"}')


def test_a_ca_file_adds_to_the_default_store_and_never_replaces_it(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["ca"]))
    record = _transport(ca_file=pki["stranger"]).fetch(Request("GET", f"{https.origin}/dpp/1"))
    assert (record.error, record.status) == (None, 200)


def test_a_ca_file_keeps_the_host_name_check_and_the_tls_minimum(
    https: LoopbackServer, pki: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["stranger"]))
    transport = _transport(
        ca_file=pki["ca"], client_identity=_identity(pki), authorization=_grant(https.origin)
    )
    # One context with the client certificate, one without. Both keep every check.
    for context in (transport._tls_for(https.origin), transport._tls_for("https://localhost")):
        assert context.minimum_version is ssl.TLSVersion.TLSv1_2
        assert (context.verify_mode, context.check_hostname) == (ssl.CERT_REQUIRED, True)
    # The certificate chains to the CA file but names 127.0.0.1, not localhost.
    record = _transport(ca_file=pki["ca"]).fetch(Request("GET", f"https://localhost:{https.port}/dpp/1"))
    assert (record.error, record.status, https.seen) == ("tls", None, [])


def test_a_server_that_requires_a_client_certificate_refuses_a_transport_without_one(
    mutual: tuple[LoopbackServer, Peers], pki: dict[str, Path]
) -> None:
    server, peers = mutual
    record = _transport(ca_file=pki["ca"], authorization=_grant(server.origin)).fetch(
        Request("GET", f"{server.origin}/dpp/1")
    )
    assert (record.error, record.status, server.seen, peers) == ("tls", None, [], [])


def test_a_server_that_requires_a_client_certificate_accepts_the_configured_one(
    mutual: tuple[LoopbackServer, Peers], pki: dict[str, Path]
) -> None:
    server, peers = mutual
    transport = _transport(
        ca_file=pki["ca"], client_identity=_identity(pki), authorization=_grant(server.origin)
    )
    record = transport.fetch(Request("GET", f"{server.origin}/dpp/1"))
    assert (record.error, record.status, peers) == (None, 200, ["TEST-ONLY client"])


def test_the_client_certificate_goes_only_to_an_origin_that_the_authorization_names(
    mutual: tuple[LoopbackServer, Peers], optional: tuple[LoopbackServer, Peers], pki: dict[str, Path]
) -> None:
    (named, named_peers), (other, other_peers) = mutual, optional
    transport = _transport(
        ca_file=pki["ca"], client_identity=_identity(pki), authorization=_grant(named.origin)
    )
    # The policy refuses the second origin before a connection exists.
    record = transport.fetch(Request("GET", f"{other.origin}/dpp/1"))
    assert (record.error, other.seen) == ("authorization_denied", [])
    # The context for the second origin carries no client certificate. The server asks for one.
    for origin, server in ((other.origin, other), (named.origin, named)):
        connection = http.client.HTTPSConnection("127.0.0.1", server.port, context=transport._tls_for(origin))
        connection.request("GET", "/dpp/1")
        assert connection.getresponse().status == 200
        connection.close()
    assert (other_peers, named_peers) == ([None], ["TEST-ONLY client"])


def test_without_an_authorization_the_transport_never_sends_the_client_certificate(
    optional: tuple[LoopbackServer, Peers], pki: dict[str, Path]
) -> None:
    server, peers = optional
    record = _transport(ca_file=pki["ca"], client_identity=_identity(pki)).fetch(
        Request("GET", f"{server.origin}/dpp/1")
    )
    assert (record.error, record.status, peers) == (None, 200, [None])


def test_a_client_identity_that_does_not_load_is_a_value_error_before_any_request(
    pki: dict[str, Path],
) -> None:
    with pytest.raises(ValueError, match=r"^TLS\.CONTEXT\.UNUSABLE: ") as caught:
        _transport(client_identity=_identity(pki, "TEST-ONLY-wrong-passphrase"))
    assert "TEST-ONLY-wrong-passphrase" not in str(caught.value)


# -- the command line -----------------------------------------------------------------------------


def _authorization(tmp_path: Path, origin: str) -> Path:
    owner = LocalSigner.from_pem(
        FIXTURES / "authorization" / "TEST-ONLY-owner.key.pem", "TEST-ONLY-owner-key-1"
    )
    token = tmp_path / "TEST-ONLY-tls-authorization.jws"
    token.write_text(issue_authorization(_grant(origin), owner) + "\n", encoding="ascii")
    return token


def _run(
    tmp_path: Path, origin: str, capsys: pytest.CaptureFixture[str], *extra: str, authorize: bool = True
) -> tuple[int, str]:
    ics, ixit = _example(tmp_path, "web", origin)
    grant = ["--authorization", str(_authorization(tmp_path, origin))] if authorize else []
    code = cli.main(
        [
            "run",
            "--profile", "family/web",
            "--ics", str(ics),
            "--ixit", str(ixit),
            "--trust", str(TRUST),
            *grant,
            "--at", "2026-10-13T12:00:00Z",
            "--out", str(tmp_path / "run"),
            "--keys", str(tmp_path / "keys"),
            "--create-data-key",
            "--allow-private-host", origin,
            *extra,
            "--json",
        ]
    )  # fmt: skip
    return code, capsys.readouterr().err


def _client_options(pki: dict[str, Path]) -> list[str]:
    return [
        "--client-cert", str(pki["client"]),
        "--client-key", str(pki["client-key"]),
        "--client-key-passphrase-ref", f"env:{PASSPHRASE_ENV}",
    ]  # fmt: skip


def test_a_run_with_the_tls_options_reaches_a_server_that_requires_a_client_certificate(
    mutual: tuple[LoopbackServer, Peers],
    pki: dict[str, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, peers = mutual
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["stranger"]))
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    code, err = _run(tmp_path, server.origin, capsys, "--ca-file", str(pki["ca"]), *_client_options(pki))
    assert code in (cli.EXIT_OK, cli.EXIT_SUT_FAIL, cli.EXIT_INCONCLUSIVE), err
    assert server.seen, "the run reached the server"
    assert set(peers) == {"TEST-ONLY client"}
    # The run log names the SHA-256 of the CA file and of the client certificate. Never the passphrase.
    client = x509.load_pem_x509_certificate(pki["client"].read_bytes())
    assert hashlib.sha256(pki["ca"].read_bytes()).hexdigest() in err
    assert client.fingerprint(hashes.SHA256()).hex() in err
    assert PASSPHRASE not in err


def test_a_run_without_the_client_certificate_is_refused_by_that_server(
    mutual: tuple[LoopbackServer, Peers],
    pki: dict[str, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, peers = mutual
    monkeypatch.setenv("SSL_CERT_FILE", str(pki["stranger"]))
    code, err = _run(tmp_path, server.origin, capsys, "--ca-file", str(pki["ca"]))
    assert code not in (cli.EXIT_USAGE, cli.EXIT_ERROR), err
    assert (server.seen, peers) == ([], [])


TLS_ERRORS: list[tuple[str, list[str], str]] = [
    ("missing CA file", ["--ca-file", "{tmp}/TEST-ONLY-absent.pem"], "TLS.FILE.UNREADABLE"),
    ("CA file that is not PEM", ["--ca-file", "{key}"], "TLS.CA_FILE.INVALID"),
    ("missing client key", ["--client-cert", "{client}", "--client-key", "{tmp}/TEST-ONLY-absent.pem"],
     "TLS.FILE.UNREADABLE"),
    ("certificate without key", ["--client-cert", "{client}"], "TLS.CLIENT_CERT.INCOMPLETE"),
    ("passphrase without key", ["--client-key-passphrase-ref", "env:{env}"], "TLS.CLIENT_CERT.INCOMPLETE"),
    ("encrypted key without passphrase", ["--client-cert", "{client}", "--client-key", "{client_key}"],
     "TLS.CLIENT_KEY.PASSPHRASE"),
    ("wrong passphrase", ["--client-cert", "{client}", "--client-key", "{client_key}",
                          "--client-key-passphrase-ref", "env:{wrong_env}"], "TLS.CLIENT_KEY.PASSPHRASE"),
    ("key of another certificate", ["--client-cert", "{client}", "--client-key", "{key}"],
     "TLS.CLIENT_KEY.MISMATCH"),
    ("certificate that is not PEM", ["--client-cert", "{key}", "--client-key", "{key}"],
     "TLS.CLIENT_CERT.INVALID"),
]  # fmt: skip


WRONG_ENV = "DPPCE_SECRET_TEST_ONLY_WRONG"


@pytest.fixture
def passphrases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    monkeypatch.setenv(WRONG_ENV, "TEST-ONLY-wrong-passphrase")


@pytest.mark.usefixtures("passphrases")
@pytest.mark.parametrize("case", TLS_ERRORS, ids=[c[0] for c in TLS_ERRORS])
def test_an_unusable_tls_option_is_an_input_error_before_any_request(
    case: tuple[str, list[str], str],
    mutual: tuple[LoopbackServer, Peers],
    pki: dict[str, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, options, code = case
    server, _ = mutual
    names = {
        "tmp": str(tmp_path), "key": str(pki["key"]), "client": str(pki["client"]),
        "client_key": str(pki["client-key"]), "env": PASSPHRASE_ENV, "wrong_env": WRONG_ENV,
    }  # fmt: skip
    exit_code, err = _run(tmp_path, server.origin, capsys, *(o.format(**names) for o in options))
    assert (exit_code, err.startswith(f"error: {code}: ")) == (cli.EXIT_USAGE, True), err
    assert (server.seen, (tmp_path / "run").exists()) == ([], False)
    assert PASSPHRASE not in err
    assert "TEST-ONLY-wrong-passphrase" not in err


def test_a_client_certificate_without_an_authorization_is_an_input_error(
    mutual: tuple[LoopbackServer, Peers],
    pki: dict[str, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, _ = mutual
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    code, err = _run(tmp_path, server.origin, capsys, *_client_options(pki), authorize=False)
    assert (code, err.startswith("error: TLS.CLIENT_CERT.NO_AUTHORIZATION: ")) == (cli.EXIT_USAGE, True), err
    assert server.seen == []
