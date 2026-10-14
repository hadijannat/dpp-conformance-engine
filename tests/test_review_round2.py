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
from dppce.models import Authorization, ClaimLevel, EvidenceEnvelope, NetworkPolicy, TrustBundle
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


def test_evidence5_a_file_that_appears_after_the_check_is_never_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = tmp_path / "runs"
    _recording(runs / "r", date(2026, 1, 1))
    original = recording_module._is_only_a_recording

    def then_a_file_arrives(directory: Path, index: Any) -> bool:
        answer = original(directory, index)
        (directory / "arrived-after-the-check.txt").write_text("keep me")
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
