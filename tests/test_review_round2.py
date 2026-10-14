"""Regression tests for the findings of review round 2 (2026-10-14).

Each test names its finding: an area (transport, evidence, adapters, verdicts, legal,
provenance) and a number. The round-2 record is
validation/records/review-round-2-2026-10-14.md.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import time
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from dppce import cli
from dppce.evidence import recording as recording_module
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.envelope import build_decision, sign_envelope
from dppce.evidence.jws import LocalSigner, SignatureError, header_of
from dppce.evidence.recording import RecordingError, purge_expired, read_recording, write_recording
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import redact_url
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.models import IXIT, Authorization, ClaimLevel, EvidenceEnvelope, NetworkPolicy, TrustBundle
from dppce.verifier import verify, verify_json
from tests.support import AT, ISSUER, make_envelope, make_record, reply
from tests.test_review_findings import LOCAL, NOW, _Keys, _recording, transport

FIXTURES = Path("fixtures/reference")


# -- transport ------------------------------------------------------------------------------------


@pytest.mark.parametrize("location", ["//[::1", "http://[::1x]/", "http://[127.0.0.1]/", "http://[::1"])
def test_transport1_a_redirect_to_an_unparsable_url_is_refused_and_recorded(
    location: str, loopback: Any
) -> None:
    server = loopback(lambda r: reply(r, 302, b"", {"Location": location}))
    engine = transport()
    record = engine.fetch(Request("GET", f"{server.origin}/hop"))
    assert record.error == "redirect_out_of_scope"
    assert record.status == 302, "the hostile answer stays visible in the record"
    assert engine.fetch(Request("GET", "http://[::1x]/dpp/1")).error == "policy_denied"


def test_transport1_an_unparsable_ixit_endpoint_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixtures = tmp_path / "reference"
    shutil.copytree(FIXTURES, fixtures)
    ixit = fixtures / "ev.ixit.yaml"
    ixit.write_text(ixit.read_text().replace("http://127.0.0.1:8765", "http://[::1x]/"))
    code = cli.main(_run_arguments(fixtures, tmp_path, ixit=ixit))
    assert code == 2
    assert "not a URL" in capsys.readouterr().err


def _run_arguments(
    fixtures: Path, tmp_path: Path, *, ixit: Path | None = None, extra: tuple[str, ...] = ()
) -> list[str]:
    return [
        "run", "--profile", "battery/ev", "--ics", str(fixtures / "ev.ics.yaml"),
        "--ixit", str(ixit or fixtures / "ev.ixit.yaml"),
        "--trust", str(fixtures / "trust/TEST-ONLY-trust-bundle.json"),
        "--secrets", str(fixtures / "secrets"),
        "--allow-private-host", "http://127.0.0.1:8765",
        "--role-secret", "legitimate_interest=file:TEST-ONLY-legitimate_interest.token",
        "--role-secret", "authority=file:TEST-ONLY-authority.token",
        "--at", "2026-10-13T12:00:00Z", "--keys", str(tmp_path / "keys"),
        "--out", str(tmp_path / "run"), *extra,
    ]  # fmt: skip


def test_transport2_an_anonymous_request_never_carries_a_credential(loopback: Any) -> None:
    server = loopback(reply)
    engine = transport(credentials={"anonymous": (server.origin, "TEST-ONLY-token")})
    assert engine.fetch(Request("GET", f"{server.origin}/dpp/1")).status == 200
    assert "Authorization" not in server.seen[-1]


def test_transport3_a_sample_that_became_a_fifo_is_not_read_and_nothing_blocks(tmp_path: Path) -> None:
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"image")
    engine = transport(samples={"qr_image": sample})
    sample.unlink()
    os.mkfifo(sample)
    started = time.monotonic()
    assert engine.artifact("qr_image").error == "artifact_unavailable"
    assert time.monotonic() - started < 2


def test_transport3_a_sample_replaced_by_a_different_regular_file_is_not_read(tmp_path: Path) -> None:
    sample = tmp_path / "qr.png"
    sample.write_bytes(b"image")
    engine = transport(samples={"qr_image": sample})
    sample.unlink()
    sample.write_bytes(b"a different file at the same path")
    assert engine.artifact("qr_image").error == "artifact_unavailable"


def test_transport4_the_total_time_covers_every_hop_of_one_fetch(loopback: Any) -> None:
    def chain(request: Any) -> None:
        time.sleep(0.25)
        hop = int(request.path.rsplit("/", 1)[1])
        if hop < 3:
            reply(request, 302, b"", {"Location": f"/hop/{hop + 1}"})
        else:
            reply(request)

    server = loopback(chain)
    started = time.monotonic()
    record = transport({"timeout_ms": 1000, "total_timeout_ms": 400}).fetch(
        Request("GET", f"{server.origin}/hop/0")
    )
    assert record.error == "timeout"
    assert time.monotonic() - started < 0.9


def test_transport5_an_authorization_endpoint_with_a_trailing_slash_names_the_same_origin(
    loopback: Any,
) -> None:
    server = loopback(reply)
    authorization = Authorization.model_validate(
        {
            "schema_version": "dppce.authorization/1",
            "authorization_id": "TEST-ONLY-a",
            "issuer": "urn:i",
            "subject": "urn:s",
            "sut_identifier": "urn:x",
            "endpoints": (f"{server.origin.upper().replace('HTTP://', 'http://')}/",),
            "methods": ("GET",),
            "roles": ("anonymous",),
            "scopes": ("read",),
            "not_before": "2026-10-01T00:00:00Z",
            "not_after": "2026-10-31T00:00:00Z",
            "max_requests": 5,
        }
    )
    assert (
        transport(authorization=authorization).fetch(Request("GET", f"{server.origin}/dpp/1")).status == 200
    )


def test_transport6_a_url_fragment_never_reaches_a_record(loopback: Any) -> None:
    assert redact_url("http://h/cb#access_token=S3CRET&state=1") == "http://h/cb"
    assert redact_url("http://h/a#") == "http://h/a"
    assert redact_url("http://h/a?page=2") == "http://h/a?page=2"
    first = loopback(
        lambda r: reply(
            r, 302, b"", {"Location": "/cb#access_token=S3CRET", "Link": '</n#token=S3CRET>; rel="next"'}
        )
    )
    for redirects in (3, 0):
        record = transport({"max_redirects": redirects}).fetch(Request("GET", f"{first.origin}/start"))
        assert "S3CRET" not in repr(record)


def test_transport7_only_a_confirmed_origin_on_a_private_host_is_reached(loopback: Any) -> None:
    confirmed, other = loopback(reply), loopback(reply)
    engine = transport(private_origins=frozenset({confirmed.origin}))
    assert engine.fetch(Request("GET", f"{confirmed.origin}/dpp/1")).status == 200
    assert engine.fetch(Request("GET", f"{other.origin}/dpp/1")).error == "policy_denied"
    assert other.seen == []
    with pytest.raises(cli.UsageError, match="origin"):
        cli._confirmed_origins(["127.0.0.1"], "--allow-private-host")
    assert cli._confirmed_origins(["HTTP://127.0.0.1:80/"], "--allow-private-host") == {"http://127.0.0.1"}


def test_transport8_an_echoed_credential_is_removed_from_the_record(loopback: Any) -> None:
    def echo(request: Any) -> None:
        secret = request.headers.get("Authorization", "")
        reply(
            request,
            body=json.dumps({"you_sent": secret}).encode(),
            headers={"ETag": secret, "Cache-Control": secret},
        )

    server = loopback(echo)
    engine = transport(credentials={"authority": (server.origin, "TEST-ONLY-S3CRET-token")})
    record = engine.fetch(Request("GET", f"{server.origin}/dpp/1", role="authority"))
    assert record.status == 200
    assert "TEST-ONLY-S3CRET-token" not in repr(record.headers)
    assert b"TEST-ONLY-S3CRET-token" not in record.body


def test_transport9_the_retention_period_is_bounded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for days in ("-1", "3651"):
        assert cli.main(_run_arguments(FIXTURES, tmp_path, extra=("--retention-days", days))) == 2
        assert "--retention-days" in capsys.readouterr().err
    with pytest.raises(RecordingError, match="negative"):
        write_recording(
            tmp_path / "r", [make_record(1)], _Keys(), created=date(2026, 10, 1), retention_days=-5
        )


# -- evidence -------------------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_evidence1_a_deeply_nested_protected_header_is_malformed_not_a_crash(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    deep = _b64u(b"[" * 100_000 + b"]" * 100_000) + ".e30.AAAA"
    with pytest.raises(SignatureError):
        header_of(deep)
    with pytest.raises(SignatureError):
        header_of(_b64u(b'{"alg":"ES256","alg":"none"}') + ".e30.AAAA")
    data = json.loads(signed.model_dump_json(by_alias=True))
    data["signatures"] = [deep, *data["signatures"]]
    report = verify_json(json.dumps(data).encode(), trust, AT)
    assert {d.name: d.outcome for d in report.dimensions}["signature"] == "pass", (
        "the good signature still counts"
    )


def _signed_variant(signer: LocalSigner, change: Any) -> dict[str, Any]:
    decision = change(make_envelope(("pass",)).decision)
    rebuilt = build_decision(
        manifest=decision.manifest,
        overall=decision.overall,
        overall_reason=decision.overall_reason,
        requirement_results=decision.requirement_results,
        test_results=decision.test_results,
        exclusions=decision.exclusions,
        conflicts=decision.conflicts,
        coverage=decision.coverage,
        record_commitments=decision.record_commitments,
    )
    envelope = sign_envelope(
        EvidenceEnvelope(schema_version="dppce.envelope/1", decision=rebuilt),
        signer,
        issuer=ISSUER,
        signed_at="2026-10-13T12:05:00Z",
    )
    return json.loads(envelope.model_dump_json(by_alias=True))


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.model_copy(
            update={
                "requirement_results": (
                    d.requirement_results[0].model_copy(update={"claim_level": ClaimLevel.REVIEWED}),
                )
            }
        ),
        lambda d: d.model_copy(
            update={
                "requirement_results": (
                    d.requirement_results[0].model_copy(
                        update={"verdict_reason": "A valid failing observation exists."}
                    ),
                )
            }
        ),
        lambda d: d.model_copy(
            update={"overall_reason": "Every applicable mandatory requirement passed. Trust us."}
        ),
        lambda d: d.model_copy(
            update={"coverage": d.coverage.model_copy(update={"unknown_applicability": 1})}
        ),
        lambda d: d.model_copy(
            update={"coverage": d.coverage.model_copy(update={"by_applicability": {"true": 2}})}
        ),
        lambda d: d.model_copy(update={"coverage": d.coverage.model_copy(update={"manual_missing": 1})}),
        lambda d: d.model_copy(
            update={"coverage": d.coverage.model_copy(update={"by_review_status": {"approved": 9}})}
        ),
    ],
    ids=[
        "claim level",
        "verdict reason",
        "overall reason",
        "unknown count",
        "by applicability",
        "manual missing",
        "category total",
    ],
)
def test_evidence2_a_signed_report_that_contradicts_its_own_body_is_not_complete(
    change: Any, signer: LocalSigner, trust: TrustBundle
) -> None:
    control = verify(_signed_variant(signer, lambda d: d), trust, AT)
    assert control.complete, "the control is a consistent report"
    report = verify(_signed_variant(signer, change), trust, AT)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    assert (outcomes["signature"], outcomes["counts"], report.complete) == ("pass", "fail", False)


def test_evidence3_purge_keeps_a_recording_whose_index_was_copied_from_another(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_recording(
        runs / "a", [make_record(1), make_record(2)], _Keys(), created=date(2026, 1, 1), retention_days=30
    )
    _recording(runs / "b", date(2026, 10, 1), days=3650)
    for name in ("recording.json", "recording.sealed"):
        shutil.copy(runs / "a" / name, runs / "b" / name)
    result = purge_expired(runs, date(2026, 10, 13), _Keys(), delete=True)
    assert result.expired == (runs / "a",)
    assert (runs / "b" / "records" / "r0001.enc").is_file()
    assert [path.name for path, _ in result.kept] == ["b"]


def test_evidence4_records_come_back_in_acquisition_order_past_r9999(tmp_path: Path) -> None:
    records = [
        Record(**{**make_record(1).__dict__, "record_id": f"r{n}"}) for n in (9998, 9999, 10000, 10001)
    ]
    write_recording(tmp_path / "r", records, _Keys(), created=date(2026, 10, 1), retention_days=30)
    assert [r.record_id for r in read_recording(tmp_path / "r", _Keys())] == [
        "r9998",
        "r9999",
        "r10000",
        "r10001",
    ]


def _arrive(directory_fd: int) -> None:
    handle = os.open("arrived-after-the-check.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=directory_fd)
    with os.fdopen(handle, "w") as target:
        target.write("keep me")


def test_evidence5_a_file_that_appears_after_the_check_is_never_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = tmp_path / "runs"
    _recording(runs / "r", date(2026, 1, 1))
    original = recording_module._is_only_a_recording

    def then_a_file_arrives(directory_fd: int, index: Any) -> bool:
        answer = original(directory_fd, index)
        _arrive(directory_fd)
        return answer

    monkeypatch.setattr(recording_module, "_is_only_a_recording", then_a_file_arrives)
    result = purge_expired(runs, date(2026, 10, 13), _Keys(), delete=True)
    assert result.expired == ()
    assert (runs / "r" / "arrived-after-the-check.txt").read_text() == "keep me"
    assert "not deleted completely" in result.kept[0][1]


def test_evidence7_a_number_that_overflows_to_infinity_is_refused() -> None:
    for raw in (b'{"a":1e999}', b'{"a":-1e999}', b"[1E400]"):
        with pytest.raises(CanonicalizationError, match="range"):
            parse_strict(raw)
    assert parse_strict(b'{"a":1e308}') == {"a": 1e308}


__all__ = ["LOCAL", "NOW", "NetworkPolicy", "PolicyTransport", "TransportConfig"]


# -- adapters: integrity --------------------------------------------------------------------------

from cryptography import x509  # noqa: E402 - the adapter tests below need the X.509 builders
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from dppce.adapters.access import restricted_fields  # noqa: E402
from dppce.adapters.common import unusable  # noqa: E402
from dppce.adapters.integrity import _same_json, jws_check  # noqa: E402
from dppce.models import ExecutionStatus  # noqa: E402
from tests.test_adapters_security import _POLICY, _Canned, _context, bundle  # noqa: E402
from tests.test_review_findings import Passport, _certificate, _x5c, integrity_context, pki, token  # noqa: E402

ITEM = b'{"a":1}'


def _check(
    header_extra: dict[str, Any], key: ec.EllipticCurvePrivateKey, trust: TrustBundle, x5c: list[str]
) -> Any:
    header = {"alg": "ES256", "typ": "dpp+jws", "x5c": x5c} | header_extra
    return jws_check(integrity_context(Passport(token(header, ITEM, key), ITEM), trust))


def _leaf(
    pki: dict[str, Any], *extensions: x509.ExtensionType
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _certificate("leaf", key.public_key(), pki["root"], *extensions)


@pytest.mark.parametrize(
    ("extension", "status", "code"),
    [
        (
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"),
            ExecutionStatus.BLOCKED,
            "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT",
        ),
        (
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            ExecutionStatus.COMPLETED,
            "INTEGRITY.CERT.KEY_USAGE",
        ),
        (
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.2.3.4.6")]),
            ExecutionStatus.BLOCKED,
            "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT",
        ),
        (
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")]),
            ExecutionStatus.COMPLETED,
            "INTEGRITY.OK",
        ),
        (
            x509.UnrecognizedExtension(x509.KeyUsage.oid, b"\x01\x02\x03"),
            ExecutionStatus.BLOCKED,
            "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT",
        ),
    ],
    ids=["unknown critical", "TLS only", "unknown purpose", "document signing", "unreadable key usage"],
)
def test_adapters1_3_a_leaf_extension_is_judged_or_not_assessed_and_never_raises(
    extension: x509.ExtensionType, status: ExecutionStatus, code: str, pki: dict[str, Any]
) -> None:
    key, leaf = _leaf(pki, extension)
    outcome = _check({}, key, pki["trust"], _x5c(leaf))
    assert (outcome.status, outcome.reason_code) == (status, code)


def test_adapters3_an_unreadable_intermediate_is_never_an_issuer_and_raises_nothing(
    pki: dict[str, Any],
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    stranger = _certificate("self", key.public_key(), (key, _self_signed(key, "self")))
    broken = _certificate(
        "broken",
        key.public_key(),
        pki["root"],
        x509.UnrecognizedExtension(x509.BasicConstraints.oid, b"\xff"),
    )
    outcome = _check({}, key, pki["trust"], _x5c(stranger, broken))
    assert (outcome.passed, outcome.reason_code) == (False, "INTEGRITY.ISSUER.UNTRUSTED")


def _self_signed(
    key: ec.EllipticCurvePrivateKey, name: str, *, until: Any = None, start: Any = None
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x1111)
        .not_valid_before(start or NOW.replace(year=2025))
        .not_valid_after(until or NOW.replace(year=2036))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def test_adapters4_a_leaf_key_of_an_unknown_algorithm_is_not_processable(pki: dict[str, Any]) -> None:
    key, leaf = _leaf(pki)
    der = leaf.public_bytes(serialization.Encoding.DER)
    ec_public_key = bytes.fromhex("06072a8648ce3d0201")
    assert ec_public_key in der
    unknown = der.replace(ec_public_key, bytes.fromhex("06072a8648ce3d0209"), 1)
    x5c = [base64.b64encode(unknown).decode()]
    outcome = _check({}, key, pki["trust"], x5c)
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.TOKEN.NOT_PROCESSABLE",
    )


def test_adapters6_deep_documents_are_compared_without_recursion() -> None:
    def deep(leaf: Any) -> Any:
        node = leaf
        for _ in range(5000):
            node = {"k": [node]}
        return node

    assert _same_json(deep(1), deep(1))
    assert not _same_json(deep(1), deep(2))
    assert not _same_json({"a": 1}, {"a": 1, "b": None})


def test_adapters8_a_chain_longer_than_the_engine_follows_is_too_large_not_malformed(
    pki: dict[str, Any],
) -> None:
    key, leaf = _leaf(pki)
    outcome = _check({}, key, pki["trust"], _x5c(leaf) * 6)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "INTEGRITY.TOKEN.TOO_LARGE")


def test_adapters9_an_expired_or_revoked_anchor_is_a_problem_of_the_bundle_not_of_the_system() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    expired_root = _self_signed(
        root_key, "old root", start=NOW.replace(year=2020), until=NOW.replace(year=2026, month=1, day=1)
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = _certificate("leaf", key.public_key(), (root_key, expired_root))
    outcome = _check({}, key, bundle(expired_root), _x5c(leaf))
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.TRUST.ANCHOR_INVALID",
    )
    valid_root = _self_signed(root_key, "old root")
    leaf = _certificate("leaf", key.public_key(), (root_key, valid_root))
    revoked_anchor = _check({}, key, bundle(valid_root, revoked_serials=("1111",)), _x5c(leaf))
    assert (revoked_anchor.status, revoked_anchor.reason_code) == (
        ExecutionStatus.BLOCKED,
        "INTEGRITY.TRUST.ANCHOR_INVALID",
    )


def test_adapters11_a_cross_signed_authority_listed_twice_still_finds_the_trusted_path() -> None:
    old_key, new_key, middle_key, key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    old_root, new_root = _self_signed(old_key, "old root"), _self_signed(new_key, "new root")
    authority = x509.BasicConstraints(ca=True, path_length=0)
    by_old = _certificate("middle", middle_key.public_key(), (old_key, old_root), authority)
    by_new = _certificate("middle", middle_key.public_key(), (new_key, new_root), authority)
    leaf = _certificate("leaf", key.public_key(), (middle_key, by_new))
    for chain in ((leaf, by_old, by_new), (leaf, by_new, by_old)):
        outcome = _check({}, key, bundle(new_root), _x5c(*chain))
        assert outcome.reason_code == "INTEGRITY.OK", chain


def test_adapters12_a_hostile_header_value_is_not_copied_into_the_report(pki: dict[str, Any]) -> None:
    key, leaf = _leaf(pki)
    for extra in ({"alg": "A" * 200_000}, {"typ": "x\nFORGED LINE: passed=True"}):
        outcome = _check(extra, key, pki["trust"], _x5c(leaf))
        assert outcome.status is ExecutionStatus.BLOCKED
        assert len(outcome.message) < 300
        assert "FORGED" not in outcome.message
        assert "AAAA" not in outcome.message


@pytest.mark.parametrize(
    "headers",
    [
        (("Content-Encoding", "identity"), ("Content-Encoding", "gzip")),
        (("Content-Encoding", "identity, br"),),
        (("Transfer-Encoding", "gzip, chunked"),),
    ],
)
def test_adapters13_every_coding_line_is_read(headers: tuple[tuple[str, str], ...], tmp_path: Path) -> None:
    record = Record(**{**make_record(1).__dict__, "headers": headers})
    outcome = unusable(_context(tmp_path, _POLICY, _Canned(b"{}")), record)
    assert outcome is not None
    assert outcome.reason_code == "TRANSPORT.BODY_ENCODED"
    plain = Record(**{**make_record(1).__dict__, "headers": (("Transfer-Encoding", "chunked"),)})
    assert unusable(_context(tmp_path, _POLICY, _Canned(b"{}")), plain) is None


# -- adapters: access -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "media_type"),
    [
        (b"\xff\xfe\x00\x00" + "<p>CANARY-test</p>".encode("utf-32-le"), "text/html; charset=utf-32"),
        ("<p>CANARY-test</p>".encode("utf-16-be"), "text/html; charset=utf-16"),
        ("<p>CANARY-test</p>".encode("utf-16-le"), "text/html"),
        (b'<script>var d = {"n": "CANARY\\u002Dtest"}</script>', "text/html"),
        (b'{"blob": "{\\"restricted\\": {\\"secret\\": \\"CANARY\\\\u002Dtest\\"}}"}', "application/json"),
    ],
    ids=[
        "utf-32 with mark",
        "utf-16 big-endian without mark",
        "utf-16 under a utf-8 label",
        "json escape in html",
        "escape in nested json",
    ],
)
def test_adapters2_16_a_canary_is_found_in_wide_encodings_and_json_escapes(
    body: bytes, media_type: str, tmp_path: Path
) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body, media_type)))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


def test_adapters5_a_deeply_nested_body_is_searched_without_recursion(tmp_path: Path) -> None:
    depth = 500
    body = b'{"k":' * depth + b'{"restricted":{"secret":"CANARY-test"}}' + b"}" * depth
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body)))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


class _Redirected(_Canned):
    def __init__(
        self, body: bytes, redirects: tuple[str, ...] = (), headers: tuple[tuple[str, str], ...] = ()
    ) -> None:
        super().__init__(body, "text/html")
        self._redirects, self._extra = redirects, headers

    def fetch(self, request: Request) -> Record:
        record = super().fetch(request)
        return Record(
            **{**record.__dict__, "redirects": self._redirects, "headers": (*record.headers, *self._extra)}
        )


def test_adapters14_a_canary_in_a_redirect_or_a_link_is_a_leak(tmp_path: Path) -> None:
    for acquirer in (
        _Redirected(b"<p>clean</p>", redirects=("http://sut.example/dpp/CANARY-test",)),
        _Redirected(b"<p>clean</p>", headers=(("Link", '</dpp/CANARY-test>; rel="next"'),)),
    ):
        outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer))
        assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


def test_adapters14_a_url_part_removed_by_redaction_is_not_a_clean_channel(tmp_path: Path) -> None:
    """Found by the automated review of the fix: a canary in ?session=... is redacted away."""
    acquirer = _Redirected(b"<p>clean</p>", redirects=("http://sut.example/dpp/x?session=<removed>",))
    outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer))
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "ACCESS.POLICY.NOT_FULLY_CHECKABLE",
    )


def test_adapters15_a_withheld_field_with_the_value_null_is_withheld(tmp_path: Path) -> None:
    outcome = restricted_fields(
        _context(tmp_path, _POLICY, _Canned(b'{"id":"x","restricted":{"secret":null}}'))
    )
    assert (outcome.passed, outcome.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    leaked = restricted_fields(_context(tmp_path, _POLICY, _Canned(b'{"id":"x","restricted":{"secret":""}}')))
    assert (leaked.passed, leaked.reason_code) == (False, "ACCESS.LEAK.FETCH"), "an empty string is a value"


__all__ += ["pki"]


def test_evidence5_a_recording_that_cannot_be_deleted_does_not_stop_the_next_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by mutation testing: one failed deletion must not end the purge."""
    runs = tmp_path / "runs"
    _recording(runs / "a", date(2026, 1, 1))
    _recording(runs / "b", date(2026, 1, 1))
    original = recording_module._is_only_a_recording

    def a_file_arrives_in_a(directory_fd: int, index: Any) -> bool:
        answer = original(directory_fd, index)
        if os.fstat(directory_fd).st_ino == os.stat(runs / "a").st_ino:
            _arrive(directory_fd)
        return answer

    monkeypatch.setattr(recording_module, "_is_only_a_recording", a_file_arrives_in_a)
    result = purge_expired(runs, date(2026, 10, 13), _Keys(), delete=True)
    assert result.expired == (runs / "b",)
    assert not (runs / "b").exists()
    assert (runs / "a" / "arrived-after-the-check.txt").is_file()


def test_verdicts4_a_step_missing_from_a_hand_built_plan_has_a_neutral_label(tmp_path: Path) -> None:
    """Found by mutation testing: the fallback label of a left-out step had no test."""
    from dppce.models import ExecutionMode as Mode  # noqa: PLC0415 - local to this one test
    from dppce.orchestrator.run import RunInputs, make_plan  # noqa: PLC0415, TID251 - the run core is the unit
    from dppce.verdicts import aggregate  # noqa: PLC0415
    from tests.core import builders as b  # noqa: PLC0415

    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-AUTO", "T-X")])
    purposes = b.purposes_pack(b.purpose("T-AUTO", stimulus={"check": "tests_core.passes"}), b.purpose("T-X"))
    inputs = RunInputs(
        mode=Mode.EXPLORATORY,
        profile=b.profile(),
        catalogue=b.catalogue(b.pack(requirement)),
        testpacks={"tp/a": purposes},
        ics=b.ics(),
        ixit=IXIT(schema_version="dppce.ixit/1"),
        data_root=tmp_path,
        evaluation_time=AT,
    )
    plan = make_plan(inputs)
    path = plan.requirements[0].paths[0].model_copy(update={"tests": ("T-AUTO",)})
    forged = plan.model_copy(
        update={
            "requirements": (plan.requirements[0].model_copy(update={"paths": (path,)}),),
            "exclusions": (),
        }
    )
    (result,) = aggregate(forged, {"R-1": requirement}, {})
    assert "p1/T-X: left out (PLAN.STEP_MISSING)" in result.retained


def test_evidence5_a_dry_run_does_not_list_a_recording_with_an_extra_record_file(tmp_path: Path) -> None:
    """Found by mutation testing: the content check decides the dry-run list on its own."""
    runs = tmp_path / "runs"
    _recording(runs / "r", date(2026, 1, 1))
    (runs / "r" / "records" / "r0009.enc").write_bytes(b"not part of the index")
    result = purge_expired(runs, date(2026, 10, 13), _Keys())
    assert result.expired == ()
    assert [reason for _, reason in result.kept] == ["holds files that are not part of the recording"]


# -- follow-up reviews of the round-2 fixes (critic gaps 1 to 4) ------------------------------------

from urllib.parse import quote  # noqa: E402 - only the gap tests below need it


def _echo_engine(server: Any, *tokens: str) -> PolicyTransport:
    roles = {f"role{i}": (server.origin, token) for i, token in enumerate(tokens)}
    return transport(credentials=roles)


def test_gap1_an_echoed_credential_is_removed_from_redirects_header_names_and_encoded_forms(
    loopback: Any,
) -> None:
    secret = "TEST-ONLY-tok/en+S3CRET"

    def echo(request: Any) -> None:
        if request.path.startswith("/start"):
            reply(request, 302, b"", {"Location": f"/cb/{secret}", "X-" + quote(secret, safe=""): "1"})
        else:
            reply(request, body=f"{secret} {quote(secret, safe='')}".encode())

    server = loopback(echo)
    engine = _echo_engine(server, secret)
    for redirects in (3, 0):
        engine = transport({"max_redirects": redirects}, credentials={"role0": (server.origin, secret)})
        record = engine.fetch(Request("GET", f"{server.origin}/start", role="role0"))
        assert "S3CRET" not in repr(record), redirects


def test_gap1_a_credential_that_begins_with_another_is_removed_as_a_whole(loopback: Any) -> None:
    short, longer = "TEST-ONLY-abcdef", "TEST-ONLY-abcdef-longer-tail"
    server = loopback(lambda r: reply(r, body=f"echo {longer} end".encode()))
    record = _echo_engine(server, short, longer).fetch(Request("GET", f"{server.origin}/x", role="role1"))
    assert record.body == b"echo <removed> end"


def test_gap1_a_credential_cut_by_the_body_limit_leaves_no_head(loopback: Any) -> None:
    secret = "TEST-ONLY-cut-S3CRET-value"
    body = b"x" * (1024 - 14) + secret.encode()  # the limit cuts the credential after 14 bytes
    server = loopback(lambda r: reply(r, body=body))
    engine = transport({"max_body_bytes": 1024}, credentials={"role0": (server.origin, secret)})
    record = engine.fetch(Request("GET", f"{server.origin}/x", role="role0"))
    assert record.truncated
    assert b"TEST-ONLY-cut" not in record.body


def test_gap1_a_short_credential_is_refused_before_any_request() -> None:
    with pytest.raises(ValueError, match="12 characters"):
        transport(credentials={"role0": ("http://127.0.0.1", "abc")})


@pytest.mark.parametrize(
    "change",
    [
        lambda c: {"by_review_status": {"approved": 1}},
        lambda c: {"by_authority_class": {"illustrative": -1, "legal_obligation": 2}},
        lambda c: {"by_review_status": {"certified": 1}},
        lambda c: {
            "implementation": c.implementation.model_copy(update={"numerator": 999, "denominator": 999})
        },
        lambda c: {
            "implementation": c.implementation.model_copy(update={"of": "legal obligations of a regulation"})
        },
        lambda c: {"placeholders": 1},
    ],
    ids=[
        "upgraded status",
        "negative count",
        "unknown status",
        "implementation denominator",
        "ratio label",
        "placeholders",
    ],
)
def test_gap2_a_coverage_figure_that_the_body_contradicts_fails_verification(
    change: Any, signer: LocalSigner, trust: TrustBundle
) -> None:
    def altered(decision: Any) -> Any:
        return decision.model_copy(
            update={"coverage": decision.coverage.model_copy(update=change(decision.coverage))}
        )

    report = verify(_signed_variant(signer, altered), trust, AT)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    assert (outcomes["signature"], outcomes["counts"], report.complete) == ("pass", "fail", False)


def test_gap3_purge_never_empties_a_directory_that_was_swapped_in_after_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = tmp_path / "runs"
    write_recording(
        runs / "expired",
        [make_record(1), make_record(2)],
        _Keys(),
        created=date(2026, 1, 1),
        retention_days=30,
    )
    write_recording(
        runs / "fresh",
        [make_record(1), make_record(2)],
        _Keys(),
        created=date(2026, 10, 1),
        retention_days=30,
    )
    original = recording_module._is_only_a_recording

    def then_swap(directory_fd: int, index: Any) -> bool:
        answer = original(directory_fd, index)
        if os.fstat(directory_fd).st_ino == os.stat(runs / "expired").st_ino:
            (runs / "expired").rename(runs / "expired.moved")
            (runs / "fresh").rename(runs / "expired")
        return answer

    monkeypatch.setattr(recording_module, "_is_only_a_recording", then_swap)
    result = purge_expired(runs, date(2026, 10, 13), _Keys(), delete=True)
    assert result.expired == ()
    assert "replaced" in dict(result.kept)[runs / "expired"]
    assert len(read_recording(runs / "expired", _Keys())) == 2, "the fresh recording is intact"


def test_gap4_a_passport_signed_with_the_key_of_a_self_signed_anchor_passes() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    anchor = _self_signed(key, "anchor")
    for x5c in (_x5c(anchor), _x5c(anchor, anchor)):
        outcome = _check({}, key, bundle(anchor), x5c)
        assert outcome.reason_code == "INTEGRITY.OK", x5c
