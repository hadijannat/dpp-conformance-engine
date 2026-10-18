"""The issuer statement of a report is bound to the signing key (gaps D8-12, D6-04; ADR 0014).

Expected values come from docs/explanation/architecture.md, section 11.4 (the dimension
``issuer_trust``). Every key and issuer is TEST-ONLY. No value describes a real laboratory or
a real accreditation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dppce import cli
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import EvidenceEnvelope, IssuerStatement, TrustBundle, TrustedKey, VerificationReport
from dppce.report import render
from dppce.verifier import verify
from tests.support import AT, ISSUER, KID, make_envelope

LAB_A, LAB_B = "urn:example:test-lab-a", "urn:example:test-lab-b"
SIGNER_A = LocalSigner.generate("TEST-ONLY-report-key-a")
SIGNER_B = LocalSigner.generate("TEST-ONLY-report-key-b")
STATUS, REFERENCE = "TEST-ONLY synthetic status", "TEST-ONLY-ACCREDITATION-REF"
SIGNED_AT = "2026-10-13T12:05:00Z"


def _key(signer: LocalSigner, issuer: str) -> TrustedKey:
    return TrustedKey(
        kid=signer.key_id,
        issuer=issuer,
        purposes=("report",),
        public_jwk=signer.public_jwk(),
        not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z",
    )


def _bundle(*keys: TrustedKey) -> TrustBundle:
    return TrustBundle(schema_version="dppce.trust/2", policy_version="test-1", keys=keys)


def _signed(
    signer: LocalSigner, key_issuer: str, statement: IssuerStatement | None = None
) -> EvidenceEnvelope:
    return sign_envelope(make_envelope(issuer=statement), signer, issuer=key_issuer, signed_at=SIGNED_AT)


def _check(envelope: EvidenceEnvelope, trust: TrustBundle) -> tuple[VerificationReport, dict[str, str]]:
    report = verify(json.loads(envelope.model_dump_json(by_alias=True)), trust, AT)
    return report, {d.name: d.outcome for d in report.dimensions}


def _detail(report: VerificationReport) -> str:
    return next(d.detail for d in report.dimensions if d.name == "issuer_trust")


def test_a_report_that_states_the_signing_issuer_passes(signer: LocalSigner, trust: TrustBundle) -> None:
    report, outcomes = _check(_signed(signer, ISSUER), trust)
    assert outcomes["issuer_trust"] == "pass"
    assert report.complete
    assert _detail(report) == (
        f"Key '{KID}' of issuer 'urn:example:test-lab' is trusted at the evaluation time, and the report "
        "states that issuer. The verifier does not check the issuer name. Accreditation status as "
        "declared by the operator: 'not accredited', reference none. The engine does not validate "
        "accreditation."
    )


def test_a_report_that_states_another_issuer_fails_and_names_both(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    statement = IssuerStatement(name="TEST-ONLY other laboratory", identifier="urn:example:other-lab")
    report, outcomes = _check(_signed(signer, ISSUER, statement), trust)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "fail")
    detail = _detail(report)
    assert detail.startswith("ISSUER.STATEMENT.MISMATCH")
    assert "urn:example:other-lab" in detail
    assert "urn:example:test-lab" in detail
    assert not report.complete


def test_two_trusted_issuers_a_swap_is_detected() -> None:
    trust = _bundle(_key(SIGNER_A, LAB_A), _key(SIGNER_B, LAB_B))
    states_a = IssuerStatement(name="TEST-ONLY laboratory A", identifier=LAB_A)
    states_b = IssuerStatement(name="TEST-ONLY laboratory B", identifier=LAB_B)

    report, outcomes = _check(_signed(SIGNER_A, LAB_A, states_a), trust)
    assert outcomes["issuer_trust"] == "pass"
    assert report.complete

    # The same body, re-signed by B only: B's attestation names B, but the report states A.
    unsigned = make_envelope(issuer=states_a)
    swapped = sign_envelope(unsigned, SIGNER_B, issuer=LAB_B, signed_at=SIGNED_AT)
    report, outcomes = _check(swapped, trust)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "fail")
    assert _detail(report).startswith("ISSUER.STATEMENT.MISMATCH")
    assert LAB_A in _detail(report)
    assert LAB_B in _detail(report)
    assert not report.complete

    report, outcomes = _check(_signed(SIGNER_A, LAB_A, states_b), trust)
    assert outcomes["issuer_trust"] == "fail"
    assert _detail(report).startswith("ISSUER.STATEMENT.MISMATCH")
    assert not report.complete


def test_a_signed_report_with_the_issuer_unspecified_is_not_complete(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    report, outcomes = _check(_signed(signer, ISSUER, IssuerStatement()), trust)
    assert outcomes["issuer_trust"] == "fail"
    assert _detail(report).startswith("ISSUER.STATEMENT.UNSPECIFIED")
    assert not report.complete

    # A trust bundle that names a key with the issuer 'unspecified' gives no exception.
    unspecified = _bundle(_key(SIGNER_A, "unspecified"))
    report, outcomes = _check(_signed(SIGNER_A, "unspecified", IssuerStatement()), unspecified)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "fail")
    assert _detail(report).startswith("ISSUER.STATEMENT.UNSPECIFIED")
    assert not report.complete


def test_an_accreditation_status_needs_a_reference_that_the_verifier_displays(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    missing = IssuerStatement(name="TEST-ONLY laboratory", identifier=ISSUER, accreditation_status=STATUS)
    report, outcomes = _check(_signed(signer, ISSUER, missing), trust)
    assert outcomes["issuer_trust"] == "fail"
    assert _detail(report).startswith("ISSUER.ACCREDITATION.NO_REFERENCE")
    assert not report.complete

    stated = missing.model_copy(update={"accreditation_reference": REFERENCE})
    report, outcomes = _check(_signed(signer, ISSUER, stated), trust)
    assert outcomes["issuer_trust"] == "pass"
    assert STATUS in _detail(report)
    assert REFERENCE in _detail(report)
    assert "does not validate accreditation" in _detail(report)
    assert report.complete


def test_report_values_are_escaped_in_the_detail(signer: LocalSigner, trust: TrustBundle) -> None:
    statement = IssuerStatement(name="TEST-ONLY laboratory", identifier="urn:x\x1b[31m")
    report, _ = _check(_signed(signer, ISSUER, statement), trust)
    detail = _detail(report)
    assert "\\x1b" in detail
    assert "\x1b" not in detail


def _plan(tmp_path: Path, *extra: str) -> list[str]:
    ixit = tmp_path / "ixit.json"
    document = {"schema_version": "dppce.ixit/1", "endpoints": {"api": "https://id.example.test"}}
    ixit.write_text(json.dumps(document), encoding="utf-8")
    return [
        "plan", "--profile", "battery/ev", "--ics", "fixtures/reference/ev.ics.yaml",
        "--ixit", str(ixit), "--at", "2026-10-13T12:00:00Z", *extra,
    ]  # fmt: skip


def test_plan_refuses_an_accreditation_status_without_a_reference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(_plan(tmp_path, "--accreditation-status", STATUS)) == 2
    assert "ISSUER.ACCREDITATION.NO_REFERENCE" in capsys.readouterr().err
    stated = ("--accreditation-status", STATUS, "--accreditation-reference", REFERENCE)
    assert cli.main(_plan(tmp_path, *stated)) == 0
    assert cli.main(_plan(tmp_path)) == 0


def test_html_marks_the_issuer_and_the_accreditation_as_declared_by_the_operator() -> None:
    page = render(make_envelope())
    assert "Issuer (declared by the operator)" in page
    assert (
        "Accreditation status of the issuer (declared by the operator; the engine does not validate it)"
        in page
    )
    assert "Accreditation reference (declared by the operator)" in page
