"""Regression tests for the findings of the independent security review of 2026-10-13.

Report: validation/records/review-evidence-security-2026-10-13.md. Each test names its finding.
The rule behind most of them: a limit or a defect of the engine must never read as a failure
of the tested system, and a look that was not complete must never read as a pass.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import time
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from dppce.adapters.access import restricted_fields
from dppce.adapters.integrity import jws_check
from dppce.cli import main
from dppce.evidence.envelope import build_decision, sign_envelope
from dppce.evidence.jws import LocalSigner, SignatureError, sign_compact, verify_compact
from dppce.evidence.recording import (
    RecordingError,
    purge_expired,
    read_recording,
    record_commitments,
    write_recording,
)
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import redact_response_headers
from dppce.infrastructure.transport import PolicyTransport, TransportConfig, origin_of
from dppce.models import (
    ICS,
    IXIT,
    EvidenceEnvelope,
    ExecutionStatus,
    NetworkPolicy,
    Profile,
    TestPurpose,
    TrustBundle,
)
from dppce.report import render
from dppce.testdefs.registry import CheckContext
from dppce.verdicts import overall_verdict
from dppce.verifier import verify
from tests.conftest import LoopbackServer
from tests.support import (
    AT,
    ISSUER,
    Handler,
    make_manifest,
    make_record,
    make_requirement_result,
    make_test_result,
    reply,
)
from tests.test_adapters_security import _POLICY, _Canned, _context, bundle, issue
from tests.test_evidence import make_envelope

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
LOCAL: dict[str, Any] = {
    "allowed_hosts": ("127.0.0.1", "localhost"),
    "allow_private_hosts": ("127.0.0.1", "localhost"),
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token(header: dict[str, Any], payload: bytes, key: ec.EllipticCurvePrivateKey, size: int = 32) -> str:
    """A compact JWS made with no JOSE library, so that any header can be tried."""
    signing_input = f"{b64u(json.dumps(header, separators=(',', ':')).encode())}.{b64u(payload)}".encode()
    digest = hashes.SHA384() if size == 48 else hashes.SHA256()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(digest)))
    return f"{signing_input.decode()}.{b64u(r.to_bytes(size, 'big') + s.to_bytes(size, 'big'))}"


class Passport:
    """An acquirer that serves one signed passport and one published passport."""

    def __init__(
        self, signed: str | bytes, published: bytes, status: int = 200, published_status: int = 200
    ) -> None:
        self._signed = signed.encode() if isinstance(signed, str) else signed
        self._published, self._status, self._records = published, status, []  # type: ignore[var-annotated]
        self._published_status = published_status

    def fetch(self, request: Request) -> Record:
        is_signed = request.url.endswith("/signed")
        base = make_record(
            len(self._records) + 1, self._signed if is_signed else self._published, request.url
        )
        status = self._status if is_signed else self._published_status
        record = Record(**{**base.__dict__, "status": status})
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        raise AssertionError("not used")

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)


def integrity_context(acquirer: Passport, trust: TrustBundle) -> CheckContext:
    purpose = TestPurpose.model_validate(
        {
            "id": "TP-X",
            "title": "t",
            "requirements": ["R"],
            "profiles": ["*"],
            "applicability": {"const": "true"},
            "stimulus": {"check": "integrity.jws"},
            "permitted_modes": ["illustrative"],
        }
    )
    profile = Profile.model_validate(
        {
            "schema_version": "dppce.profile/1",
            "id": "p/x",
            "title": "t",
            "product_category": "x",
            "packs": [],
            "testpacks": [],
        }
    )
    ics = ICS.model_validate(
        {"schema_version": "dppce.ics/1", "sut": {"name": "s", "identifier": "urn:x"}, "profile": "p/x"}
    )
    ixit = IXIT.model_validate(
        {
            "schema_version": "dppce.ixit/1",
            "endpoints": {"api": "http://sut.example"},
            "samples": {"passport_id": "P1"},
            "resources": {
                "item": {"endpoint": "api", "path": "/dpp/{id}"},
                "signed": {"endpoint": "api", "path": "/dpp/{id}/signed"},
            },
        }
    )
    return CheckContext(
        purpose=purpose,
        ics=ics,
        ixit=ixit,
        profile=profile,
        acquirer=acquirer,
        evaluation_time=NOW,
        data_root=Path(),
        trust=trust,
    )


@pytest.fixture(scope="module")
def pki() -> dict[str, Any]:
    root = issue("root", None, ca=True)
    leaf = issue("leaf", root, ca=False)
    x5c = [base64.b64encode(leaf[1].public_bytes(serialization.Encoding.DER)).decode()]
    return {
        "root": root,
        "leaf": leaf,
        "trust": bundle(root[1]),
        "header": {"alg": "ES256", "typ": "dpp+jws", "x5c": x5c},
    }


# -- F-01: a limit of the engine is not an invalid signature ------------------------------------


def test_f01_control_a_good_token_passes(pki: dict[str, Any]) -> None:
    item = b'{"a":1}'
    outcome = jws_check(
        integrity_context(Passport(token(pki["header"], item, pki["leaf"][0]), item), pki["trust"])
    )
    assert (outcome.passed, outcome.reason_code) == (True, "INTEGRITY.OK")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"alg": "ES384"}, "INTEGRITY.TOKEN.NOT_PROCESSABLE"),
        ({"alg": "RS256"}, "INTEGRITY.TOKEN.NOT_PROCESSABLE"),
        ({"x5t#S256": "abc"}, "INTEGRITY.TOKEN.NOT_PROCESSABLE"),
        ({"cty": "json"}, "INTEGRITY.TOKEN.NOT_PROCESSABLE"),
        ({"typ": "JWT"}, "INTEGRITY.TOKEN.NOT_PROCESSABLE"),
    ],
)
def test_f01_a_token_outside_the_supported_profile_is_not_assessed(
    change: dict[str, Any], code: str, pki: dict[str, Any]
) -> None:
    item = b'{"a":1}'
    signed = token(pki["header"] | change, item, pki["leaf"][0])
    outcome = jws_check(integrity_context(Passport(signed, item), pki["trust"]))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def test_f01_a_token_with_no_certificate_header_is_not_assessed(pki: dict[str, Any]) -> None:
    item = b'{"a":1}'
    signed = token({"alg": "ES256", "typ": "dpp+jws"}, item, pki["leaf"][0])
    outcome = jws_check(integrity_context(Passport(signed, item), pki["trust"]))
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "INTEGRITY.KEY.UNSUPPORTED")


def test_f01_a_server_error_is_no_answer_and_a_missing_token_has_its_own_code(pki: dict[str, Any]) -> None:
    item, signed = b'{"a":1}', token(pki["header"], b'{"a":1}', pki["leaf"][0])
    unavailable = jws_check(integrity_context(Passport(signed, item, status=503), pki["trust"]))
    assert (unavailable.passed, unavailable.unreachable, unavailable.reason_code) == (
        False,
        True,
        "INTEGRITY.TOKEN.NO_ANSWER",
    )
    missing = jws_check(integrity_context(Passport(signed, item, status=404), pki["trust"]))
    assert (missing.passed, missing.unreachable, missing.reason_code) == (
        False,
        False,
        "INTEGRITY.TOKEN.NOT_AVAILABLE",
    )
    not_a_token = jws_check(integrity_context(Passport("<html>maintenance</html>", item), pki["trust"]))
    assert (not_a_token.passed, not_a_token.reason_code) == (False, "INTEGRITY.TOKEN.MALFORMED")


def test_f01_a_server_error_on_the_published_passport_is_no_answer(pki: dict[str, Any]) -> None:
    """Owner decision of 2026-10-18: a 5xx answer counts like a connectivity failure."""
    item, signed = b'{"a":1}', token(pki["header"], b'{"a":1}', pki["leaf"][0])
    outcome = jws_check(integrity_context(Passport(signed, item, published_status=503), pki["trust"]))
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


def test_f01_only_a_failed_cryptographic_check_is_an_invalid_signature(pki: dict[str, Any]) -> None:
    item = b'{"a":1}'
    header, _, signature = token(pki["header"], item, pki["leaf"][0]).split(".")
    forged = f"{header}.{b64u(b'{"a":2}')}.{signature}"
    outcome = jws_check(integrity_context(Passport(forged, item), pki["trust"]))
    assert (outcome.passed, outcome.reason_code) == (False, "INTEGRITY.SIGNATURE.INVALID")


# -- F-02: the canonical form of the engine is not a rule for a third-party document ----------


@pytest.mark.parametrize("raw", [b'{"a":1.5}', b'{"b":1,"a":2}', b'{"a": 1}', b'{\n  "a": 1e2\n}'])
def test_f02_a_payload_that_equals_the_published_document_passes_in_any_json_form(
    raw: bytes, pki: dict[str, Any]
) -> None:
    outcome = jws_check(
        integrity_context(Passport(token(pki["header"], raw, pki["leaf"][0]), raw), pki["trust"])
    )
    assert (outcome.passed, outcome.reason_code) == (True, "INTEGRITY.OK")


def test_f02_a_payload_that_differs_still_fails_and_a_broken_document_is_not_compared(
    pki: dict[str, Any],
) -> None:
    signed = token(pki["header"], b'{"a":1}', pki["leaf"][0])
    different = jws_check(integrity_context(Passport(signed, b'{"a":2}'), pki["trust"]))
    assert (different.passed, different.reason_code) == (False, "INTEGRITY.PAYLOAD.MISMATCH")
    not_json = jws_check(integrity_context(Passport(signed, b"<html>"), pki["trust"]))
    assert (not_json.status, not_json.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.PAYLOAD.NOT_COMPARABLE",
    )


@pytest.mark.parametrize(
    ("signed", "published"),
    [
        (b'{"a":true}', b'{"a":1}'),
        (b'{"a":false}', b'{"a":0}'),
        (b'{"a":1}', b'{"a":"1"}'),
        (b'{"a":null}', b'{"a":0}'),
        (b'{"a":0.1}', b'{"a":0.10000000000000001}'),
        (b'{"a":[1,2]}', b'{"a":[2,1]}'),
        (b'{"a":1}', b'{"a":1,"b":null}'),
    ],
)
def test_f02_values_that_python_calls_equal_are_still_a_mismatch(
    signed: bytes, published: bytes, pki: dict[str, Any]
) -> None:
    """Found by the review of the fix: ``True == 1`` in Python, and two decimals can share a float."""
    token_ = token(pki["header"], signed, pki["leaf"][0])
    for a, b in ((token_, published), (token(pki["header"], published, pki["leaf"][0]), signed)):
        outcome = jws_check(integrity_context(Passport(a, b), pki["trust"]))
        assert (outcome.passed, outcome.reason_code) == (False, "INTEGRITY.PAYLOAD.MISMATCH")


def test_f02_one_number_in_two_notations_is_one_number(pki: dict[str, Any]) -> None:
    signed = token(pki["header"], b'{"a":1.0,"b":1e2,"c":[0.50]}', pki["leaf"][0])
    outcome = jws_check(integrity_context(Passport(signed, b'{"c":[0.5],"b":100,"a":1}'), pki["trust"]))
    assert (outcome.passed, outcome.reason_code) == (True, "INTEGRITY.OK")


# -- F-07 and F-16: certificates that the engine cannot judge ---------------------------------


def _certificate(
    subject: str, key: ec.EllipticCurvePublicKey, parent: Any, *extensions: x509.ExtensionType
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(parent[1].subject)
        .public_key(key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2036, 1, 1, tzinfo=UTC))
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=True)
    return builder.sign(parent[0], hashes.SHA256())


def _x5c(*certificates: x509.Certificate) -> list[str]:
    return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in certificates]


def test_f07_a_leaf_on_a_different_curve_is_not_assessed_and_raises_nothing(pki: dict[str, Any]) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    leaf = _certificate("p384 leaf", key.public_key(), pki["root"])
    header = {"alg": "ES384", "typ": "dpp+jws", "x5c": _x5c(leaf)}
    outcome = jws_check(
        integrity_context(Passport(token(header, b'{"a":1}', key, size=48), b'{"a":1}'), pki["trust"])
    )
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.TOKEN.NOT_PROCESSABLE",
    )


def test_f16_a_certificate_that_may_not_sign_fails_and_a_name_constraint_is_not_assessed(
    pki: dict[str, Any],
) -> None:
    item = b'{"a":1}'
    key = ec.generate_private_key(ec.SECP256R1())
    usage = x509.KeyUsage(
        digital_signature=False, key_cert_sign=False, crl_sign=False, content_commitment=False,
        key_encipherment=True, data_encipherment=False, key_agreement=False,
        encipher_only=False, decipher_only=False,
    )  # fmt: skip
    no_signing = _certificate("encipher only", key.public_key(), pki["root"], usage)
    header = {"alg": "ES256", "typ": "dpp+jws", "x5c": _x5c(no_signing)}
    refused = jws_check(integrity_context(Passport(token(header, item, key), item), pki["trust"]))
    assert (refused.passed, refused.reason_code) == (False, "INTEGRITY.CERT.KEY_USAGE")

    middle_key = ec.generate_private_key(ec.SECP256R1())
    constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.test")], excluded_subtrees=None
    )
    middle = _certificate(
        "constrained authority",
        middle_key.public_key(),
        pki["root"],
        x509.BasicConstraints(ca=True, path_length=0),
        constraints,
    )
    below = _certificate("leaf below", key.public_key(), (middle_key, middle))
    header = {"alg": "ES256", "typ": "dpp+jws", "x5c": _x5c(below, middle)}
    outcome = jws_check(integrity_context(Passport(token(header, item, key), item), pki["trust"]))
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT",
    )


# -- F-03 and F-17: a role always carries its credential --------------------------------------


def transport(policy: dict[str, Any] | None = None, **config: Any) -> PolicyTransport:
    settings = TransportConfig(policy=NetworkPolicy(**(LOCAL | (policy or {}))), engine_version="1", **config)
    return PolicyTransport(settings, FrozenClock(NOW), sleep=lambda _: None)


def test_f03_a_request_for_a_role_with_no_credential_is_not_sent(loopback: Any) -> None:
    server = loopback(reply)
    record = transport().fetch(Request("GET", f"{server.origin}/dpp/1", role="authority"))
    assert record.error == "authorization_denied"
    assert server.seen == [], "an anonymous view must never be recorded under the name of a role"
    elsewhere = transport(credentials={"authority": ("http://elsewhere.example", "TEST-ONLY-token")})
    assert (
        elsewhere.fetch(Request("GET", f"{server.origin}/dpp/1", role="authority")).error
        == "authorization_denied"
    )
    fitted = transport(credentials={"authority": (server.origin, "TEST-ONLY-token")})
    assert fitted.fetch(Request("GET", f"{server.origin}/dpp/1", role="authority")).status == 200
    assert server.seen[-1]["Authorization"] == "Bearer TEST-ONLY-token"


def test_f03_a_role_request_does_not_follow_a_redirect_to_a_different_origin(loopback: Any) -> None:
    other = loopback(reply)
    first = loopback(lambda r: reply(r, 302, b"", {"Location": f"http://localhost:{other.port}/landed"}))
    engine = transport(credentials={"authority": (first.origin, "TEST-ONLY-token")})
    record = engine.fetch(Request("GET", f"{first.origin}/hop", role="authority"))
    assert record.error == "redirect_out_of_scope"
    assert other.seen == []
    assert engine.fetch(Request("GET", f"{first.origin}/hop")).status == 200, "the anonymous role can follow"


def test_f03_the_access_check_does_not_pass_for_a_role_that_was_never_authenticated(
    tmp_path: Path, loopback: Any
) -> None:
    server = loopback(lambda r: reply(r, body=b'{"id": "x"}'))
    context = _context(
        tmp_path,
        _POLICY | {"restricted": [{"path": "restricted.secret", "roles": ["authority"]}]},
        _Canned(b"{}"),
    )
    live = CheckContext(
        purpose=context.purpose.model_copy(
            update={
                "stimulus": context.purpose.stimulus.model_copy(
                    update={"params": {"role": "legitimate_interest"}}
                )
            }
        ),
        ics=context.ics,
        ixit=context.ixit.model_copy(update={"endpoints": {"api": server.origin}}),
        profile=context.profile,
        acquirer=transport(),
        evaluation_time=NOW,
        data_root=tmp_path,
    )
    outcome = restricted_fields(live)
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (False, True, "TRANSPORT.DENIED")
    assert server.seen == []


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://Example.COM:443/x", "https://example.com"),
        ("http://example.com:80", "http://example.com"),
        ("http://example.com:8080/a?b", "http://example.com:8080"),
        ("http://[::1]:8080/x", "http://[::1]:8080"),
        ("https://[2001:DB8::1]/", "https://[2001:db8::1]"),
    ],
)
def test_f17_an_origin_has_one_normal_form(url: str, origin: str) -> None:
    assert origin_of(url) == origin


# -- F-04: an encoded or disguised body ------------------------------------------------------


class _Encoded(_Canned):
    def __init__(self, body: bytes, media_type: str, encoding: str) -> None:
        super().__init__(body, media_type)
        self._encoding = encoding

    def fetch(self, request: Request) -> Record:
        record = super().fetch(request)
        return Record(
            **{**record.__dict__, "headers": (*record.headers, ("Content-Encoding", self._encoding))}
        )


def test_f04_a_compressed_body_is_not_assessed(tmp_path: Path) -> None:
    body = gzip.compress(b"<p>CANARY-test</p>")
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Encoded(body, "text/html", "gzip")))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "TRANSPORT.BODY_ENCODED",
    )


@pytest.mark.parametrize(
    ("body", "media_type"),
    [
        ("<p>CANARY-test</p>".encode("utf-16"), "text/html"),
        ("<p>CANARY-test</p>".encode("utf-16-le"), "text/html; charset=utf-16-le"),
        (b"<p>CANARY&#45;test</p>", "text/html"),
        (b"<p>CANARY&#x2D;test</p>", "text/html"),
        (b"<a href='/x?ref=CANARY%2Dtest'>x</a>", "text/html"),
        (b'{"note": "\\u0043ANARY-test"}', "application/json"),
        (b'{"note": "see CANARY&#45;test"}', "application/json"),
    ],
)
def test_f04_a_canary_is_found_in_each_common_encoding(body: bytes, media_type: str, tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body, media_type)))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


def test_f04_bytes_that_cannot_be_decoded_are_not_a_clean_channel(tmp_path: Path) -> None:
    outcome = restricted_fields(
        _context(tmp_path, _POLICY, _Canned(b"\xff\xfe\x00\xd8", "text/html; charset=utf-16"))
    )
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.RESPONSE.NOT_DECODABLE")
    assert (
        restricted_fields(_context(tmp_path, _POLICY, _Canned(b"\x80\x81", "text/plain"))).status
        is ExecutionStatus.BLOCKED
    )


# -- F-05 and F-06: the transport ends a request and raises nothing -------------------------


def test_f05_the_total_time_of_a_request_is_limited(loopback: Any) -> None:
    def trickle(request: Any) -> None:
        request.send_response(200)
        request.send_header("Content-Type", "text/plain")
        request.send_header("Content-Length", "400")
        request.end_headers()
        try:
            for _ in range(400):  # one byte each 20 ms: every read is inside the socket timeout
                request.wfile.write(b"x")
                request.wfile.flush()
                time.sleep(0.02)
        except OSError:
            return

    server = loopback(trickle)
    started = time.monotonic()
    record = transport({"timeout_ms": 1000, "total_timeout_ms": 300}).fetch(
        Request("GET", f"{server.origin}/slow")
    )
    assert record.error == "timeout"
    assert record.body == b"", "a partial body is not kept"
    assert time.monotonic() - started < 3


def test_f06_a_redirect_to_a_path_outside_ascii_is_followed_and_raises_nothing(loopback: Any) -> None:
    def handler(request: Any) -> None:
        if request.path == "/hop":
            reply(request, 302, b"", {"Location": "/dpp/ü"})
        else:
            reply(request)

    server = loopback(handler)
    record = transport().fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.error, record.status) == (None, 200)
    assert server.seen[-1]["path"] == "/dpp/%C3%BC"
    assert transport().fetch(Request("GET", f"{server.origin}/dpp/é?q=é")).status == 200


# -- F-08: a sample is read from the path that was confirmed ---------------------------------


def test_f08_a_sample_that_became_a_link_after_the_check_is_not_read(tmp_path: Path) -> None:
    samples = tmp_path / "ixit" / "samples"
    samples.mkdir(parents=True)
    image = samples / "qr.png"
    image.write_bytes(b"image")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "qr.png").write_bytes(b"private")
    engine = transport(samples={"qr_image": image})
    assert engine.artifact("qr_image").body == b"image"
    image.unlink()
    os.symlink(outside / "qr.png", image)  # the final component is a link now
    assert engine.artifact("qr_image").error == "artifact_unavailable"
    image.unlink()
    samples.rmdir()
    os.symlink(outside, samples)  # a parent directory is a link now
    record = engine.artifact("qr_image")
    assert (record.error, record.body) == ("artifact_unavailable", b"")


# -- F-09, F-10, F-11: recordings -------------------------------------------------------------


class _Keys:
    def __init__(self, key: bytes = bytes(range(32))) -> None:
        self._key = key

    def data_key(self, key_id: str) -> bytes:
        return self._key

    def default_key_id(self) -> str:
        return "TEST-ONLY-data-key"


def _recording(path: Path, created: date, days: int = 30) -> None:
    write_recording(path, [make_record(1)], _Keys(), created=created, retention_days=days)


def test_f09_purge_lists_first_and_deletes_only_an_authentic_expired_recording(tmp_path: Path) -> None:
    runs, today = tmp_path / "run", date(2026, 10, 13)
    _recording(runs / "old", date(2026, 1, 1))
    _recording(runs / "new", date(2026, 10, 1))
    listed = purge_expired(runs, today, _Keys())
    assert (listed.expired, listed.deleted) == ((runs / "old",), False)
    assert (runs / "old").is_dir(), "without the delete option nothing is removed"
    assert purge_expired(runs, date(2026, 1, 31), _Keys()).expired == (), "the last day of the period is kept"
    removed = purge_expired(runs, today, _Keys(), delete=True)
    assert (removed.expired, removed.deleted) == ((runs / "old",), True)
    assert sorted(p.name for p in runs.iterdir()) == ["new"]
    assert purge_expired(tmp_path / "absent", today, _Keys(), delete=True).expired == ()


def test_f09_a_directory_that_only_looks_like_a_recording_is_left_alone(tmp_path: Path) -> None:
    runs, today = tmp_path / "run", date(2026, 10, 13)
    notes = runs / "my-notes"
    notes.mkdir(parents=True)
    (notes / "important.txt").write_text("keep me")
    (notes / "recording.json").write_text(
        json.dumps(
            {
                "schema_version": "dppce.recording/1",
                "key_id": "k",
                "created": "2020-01-01",
                "delete_after": "2020-01-02",
                "records": [],
            }
        )
    )
    _recording(runs / "extra", date(2026, 1, 1))
    (runs / "extra" / "notes.txt").write_text("not part of the recording")
    _recording(runs / "other-key", date(2026, 1, 1))
    _recording(runs / "date-changed", date(2026, 10, 1))
    index = json.loads((runs / "date-changed" / "recording.json").read_text())
    index["delete_after"] = "2020-01-01"  # make a current recording look expired
    (runs / "date-changed" / "recording.json").write_text(json.dumps(index))

    result = purge_expired(runs, today, _Keys(), delete=True)
    assert result.expired == (runs / "other-key",)
    assert (notes / "important.txt").read_text() == "keep me"
    kept = {path.name: reason for path, reason in result.kept}
    assert set(kept) == {"my-notes", "extra", "date-changed"}
    assert "not part of the recording" in kept["extra"]
    assert "not an authentic recording" in kept["date-changed"]
    wrong_key = purge_expired(runs, today, _Keys(bytes(32)), delete=True)
    assert wrong_key.expired == (), "a different key authenticates nothing, so nothing is removed"


def test_f09_a_changed_index_is_refused_when_a_recording_is_read(tmp_path: Path) -> None:
    _recording(tmp_path / "r", date(2026, 10, 1))
    index = json.loads((tmp_path / "r" / "recording.json").read_text())
    index["delete_after"] = "2099-01-01"
    (tmp_path / "r" / "recording.json").write_text(json.dumps(index))
    with pytest.raises(RecordingError, match="sealed copy"):
        read_recording(tmp_path / "r", _Keys())
    (tmp_path / "r" / "recording.json").write_text(
        '{"schema_version": "dppce.recording/1", "schema_version": "x"}'
    )
    with pytest.raises(RecordingError, match="index"):
        read_recording(tmp_path / "r", _Keys())


def test_f10_a_sealed_file_that_is_too_short_is_a_recording_error(tmp_path: Path) -> None:
    _recording(tmp_path / "r", date(2026, 10, 1))
    for size in (0, 5, 12, 27):
        (tmp_path / "r" / "records" / "r0001.enc").write_bytes(bytes(size))
        with pytest.raises(RecordingError):
            read_recording(tmp_path / "r", _Keys())


@pytest.mark.parametrize("identifier", ["r0001\n", "r0001 ", "r001", "r0000001", "R0001", "../r0001"])
def test_f11_a_record_identifier_must_match_as_a_whole(identifier: str) -> None:
    with pytest.raises(RecordingError, match="not valid"):
        record_commitments([Record(**{**make_record(1).__dict__, "record_id": identifier})])


# -- F-12: response headers ------------------------------------------------------------------


def test_f12_a_response_header_value_is_kept_only_if_its_name_is_known_to_be_safe() -> None:
    headers = (
        ("Content-Type", "application/json"),
        ("ETag", '"v3"'),
        ("Link", '<http://h/next?access_token=S3CRET&page=2>; rel="next", <http://h/first>; rel="first"'),
        ("Location", "http://h/x?sig=S3CRET"),
        ("X-Session-Token", "S3CRET"),
        ("Proxy-Authenticate", "Basic S3CRET"),
        ("Server-Timing", "db;desc=S3CRET"),
    )
    redacted = dict(redact_response_headers(headers))
    assert "S3CRET" not in repr(redacted)
    assert (redacted["Content-Type"], redacted["ETag"]) == ("application/json", '"v3"')
    assert "page=2" in redacted["Link"]
    assert "http://h/first" in redacted["Link"]
    assert redacted["X-Session-Token"] == redacted["Server-Timing"] == "<removed>"


@pytest.mark.parametrize(
    "value",
    [
        '<http://h/a>; rel="next"; title="S3CRET"',
        "<http://h/a>; anchor=S3CRET",
        '<http://h/a>; rel="next", S3CRET',
        "S3CRET",
        '<http://h/a,b>; rel="next"; S3CRET',
        "<http://h/a>; rel=next; type=S3CRET",
        '<http://h/a>; rel="next S3CRET"',
        "<http://h/a>; rel=S3CRET",
        '<http://h/a>; rel="next"; rel="prev"',
    ],
)
def test_f12_a_link_header_with_anything_but_targets_and_relation_names_is_removed(value: str) -> None:
    """Found by the review of the fix: a link parameter is free text."""
    assert dict(redact_response_headers((("Link", value),)))["Link"] == "<removed>"


# -- F-13: the type of the verification key --------------------------------------------------


@pytest.mark.parametrize("kty", ["oct", "RSA", "OKP", ""])
def test_f13_a_verification_key_that_is_not_an_elliptic_curve_key_is_refused(kty: str) -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    signed = sign_compact(b'{"a":1}', signer, typ="dpp+jws")
    with pytest.raises(SignatureError) as caught:
        verify_compact(signed, signer.public_jwk() | {"kty": kty}, typ="dpp+jws")
    assert caught.value.code == "KEY"


# -- F-14 and F-15: confirmations by the operator ---------------------------------------------


def test_f14_remote_read_is_confirmed_for_each_public_host() -> None:
    class Public:
        def resolve(self, host: str, port: int) -> list[str]:
            return ["93.184.216.34"]

    policy = NetworkPolicy(allowed_hosts=("a.example", "b.example"))
    engine = PolicyTransport(
        TransportConfig(
            policy=policy, engine_version="1", remote_read_origins=frozenset({"http://a.example"})
        ),
        FrozenClock(NOW),
        Public(),
    )
    assert engine.fetch(Request("GET", "http://b.example/")).error == "authorization_denied"
    # The confirmed host passes the policy. The test stops there: no test connects to a public host.
    assert engine._target("http://a.example/", "GET", "anonymous").host == "a.example"


def test_f15_a_report_with_a_verification_section_needs_an_explicit_time(
    signed: EvidenceEnvelope, trust: TrustBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope, bundle_file = tmp_path / "envelope.json", tmp_path / "trust.json"
    envelope.write_text(signed.model_dump_json(by_alias=True))
    bundle_file.write_text(trust.model_dump_json())
    assert main(["report", "--envelope", str(envelope), "--trust", str(bundle_file)]) == 2
    assert "--at" in capsys.readouterr().err
    out = tmp_path / "report.html"
    arguments = [
        "report",
        "--envelope",
        str(envelope),
        "--trust",
        str(bundle_file),
        "--at",
        "2026-10-14T00:00:00Z",
    ]
    assert main([*arguments, "--out", str(out)]) == 0
    assert "Verification at 2026-10-14T00:00:00Z" in out.read_text()


# -- Contract gap 8: a signed report must also agree with itself ------------------------------


def test_a_signed_report_whose_verdict_does_not_follow_from_its_results_fails_verification(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """The issuer signs a pass for a requirement whose only step failed."""
    base = make_envelope(("pass",)).decision
    requirement = make_requirement_result(1, "pass")  # its path says pass ...
    step = make_test_result(1, "fail")  # ... and its only step failed
    overall, reason = overall_verdict([requirement])
    decision = build_decision(
        manifest=make_manifest(),
        overall=overall,
        overall_reason=reason,
        requirement_results=[requirement],
        test_results=[step],
        exclusions=(),
        conflicts=(),
        coverage=base.coverage,
        record_commitments=base.record_commitments,
    )
    envelope = sign_envelope(
        EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision),
        signer,
        issuer=ISSUER,
        signed_at="2026-10-13T12:05:00Z",
    )
    report = verify(json.loads(envelope.model_dump_json(by_alias=True)), trust, AT)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    assert outcomes["signature"] == "pass", "the issuer did sign it"
    assert outcomes["counts"] == "fail", "but the report does not agree with itself"
    assert not report.complete


DEFAULT_SEVERITY = "<br><small>Default: the test purpose is not available.</small>"


def test_the_html_step_table_shows_the_severity() -> None:
    """D1-11: the severity of each step is visible. A fallback value is labeled as a default."""
    base = make_envelope()
    fallback = make_test_result(9, "inconclusive").model_copy(
        update={
            "test_purpose_id": "TP-GONE",
            "requirement_ids": (),
            "check": "unavailable",
            "execution_status": ExecutionStatus.NOT_RUN,
        }
    )
    decision = base.decision.model_copy(update={"test_results": (*base.decision.test_results, fallback)})
    page = render(base.model_copy(update={"decision": decision}))
    table = page.split("<caption>Test step results</caption>", 1)[1].split("</table>", 1)[0]
    assert (
        '<th scope="col">Verdict</th><th scope="col">Severity</th><th scope="col">Reason code</th>' in table
    )
    rows = {
        re.findall(r"<td><code>(.*?)</code></td>", row)[0]: re.findall(r"<td>(.*?)</td>", row)
        for row in table.split("<tr>")[2:]
    }
    assert sorted(rows) == ["TP-001", "TP-002", "TP-003", "TP-GONE"]
    for test_id, cells in rows.items():
        assert 'class="verdict"' in cells[3]
        if test_id == "TP-GONE":
            assert cells[4] == "major" + DEFAULT_SEVERITY
        else:
            assert cells[4] == "major"
            assert DEFAULT_SEVERITY not in "".join(cells)


__all__ = ["Handler", "LoopbackServer"]
