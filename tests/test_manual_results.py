"""Signed manual-step results (gaps D1-01, D1-03, and the expected_evidence check of D1-11).

Expected values come from docs/explanation/architecture.md: section 6 (planning), section 8.1
(the order of the tests and the MANUAL.* reason codes), section 9.1 (only the operator supplies
a manual result), and section 11.4 (the dimension ``manual_results``). Every key is TEST-ONLY
and generated here or by scripts/gen_fixtures.py. Every system is the synthetic reference
system on loopback. No manual result here describes a real system.
"""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from validation.evidence_cases import TAMPER
from validation.rig import FIXTURES, ROOT, TRUST, ReferenceRig, RunResult

from dppce import cli
from dppce.adapters.capabilities import manifest
from dppce.catalogue import load_testpacks
from dppce.catalogue.lint import lint
from dppce.evidence.canonical import canonical_bytes, parse_strict
from dppce.evidence.envelope import records_root, sign_envelope
from dppce.evidence.jws import LocalSigner, header_of, sign_compact, verify_compact
from dppce.evidence.manual import MANUAL_RESULT_TYP, issue_manual_result
from dppce.infrastructure.interfaces import TransportError
from dppce.models import (
    IXIT,
    CapabilityState,
    EvidenceEnvelope,
    ExecutionMode,
    ExecutionStatus,
    ManualResult,
    TestPurpose,
    TestResult,
    TrustBundle,
    TrustedKey,
    Verdict,
)
from dppce.orchestrator.run import RunInputs, execute, make_plan  # noqa: TID251 - the run core runs the check
from dppce.report import render
from dppce.verifier import verify, verify_json
from dppce.verifier.__main__ import main as verifier_main
from tests.core import builders as b
from tests.support import AT, ISSUER, ArtifactAcquirer, make_artifact, make_envelope

MANUAL = LocalSigner.generate("TEST-ONLY-manual-key-unit")
REPORT = LocalSigner.generate("TEST-ONLY-report-key-unit")
STRANGER = LocalSigner.generate("TEST-ONLY-stranger-key")
EVIDENCE = ("A photograph of the marking.", "The reader that was used.")
PURPOSE = b.purpose(
    "T-MAN", manual=True, stimulus={"check": "manual.review"}, expected_evidence=list(EVIDENCE)
)
FIELDS = ("jws", "kid", "role", "performed_at", "outcome")
EU_STEP = "TP-EU-13-6-MANUAL"
FIXTURE_MANUAL_KEY = FIXTURES / "trust" / "TEST-ONLY-manual-signing.key.pem"
FIXTURE_MANUAL_KID = "TEST-ONLY-manual-key-1"
REFERENCE_SUT = "urn:example:sut:reference-dpp"
RUN_AT = "2026-10-13T12:00:00Z"
VERIFY_AT = datetime(2026, 10, 14, tzinfo=UTC)


def _key(signer: LocalSigner, purposes: tuple[str, ...], **changes: Any) -> TrustedKey:
    fields: dict[str, Any] = {
        "kid": signer.key_id,
        "issuer": ISSUER,
        "purposes": purposes,
        "public_jwk": signer.public_jwk(),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }
    return TrustedKey.model_validate(fields | changes)


UNIT_TRUST = TrustBundle(
    schema_version="dppce.trust/1",
    policy_version="test-1",
    keys=(_key(MANUAL, ("manual",)), _key(REPORT, ("report",))),
)


def result(**changes: Any) -> ManualResult:
    fields: dict[str, Any] = {
        "schema_version": "dppce.manualresult/1",
        "test_purpose_id": "T-MAN",
        "sut_identifier": "urn:example:sut",
        "role": "inspector",
        "performed_at": "2026-10-13T08:00:00Z",
        "outcome": "pass",
        "evidence": list(EVIDENCE),
    }
    return ManualResult.model_validate(fields | changes)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _header(**changes: Any) -> dict[str, Any]:
    return {"alg": "ES256", "kid": MANUAL.key_id, "typ": MANUAL_RESULT_TYP} | changes


def compact(header: dict[str, Any], payload: bytes, signature: bytes | None = None) -> str:
    """A compact JWS with any header. ``sign_compact`` writes only the three allowed parameters."""
    signing_input = f"{_b64(canonical_bytes(header))}.{_b64(payload)}"
    raw = MANUAL.sign(signing_input.encode("ascii")) if signature is None else signature
    return f"{signing_input}.{_b64(raw)}"


def run_check(
    body: bytes | None,
    *,
    error: TransportError | None = None,
    trust: TrustBundle | None = UNIT_TRUST,
    purpose: TestPurpose = PURPOSE,
) -> TestResult:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", purpose.id)])
    inputs = RunInputs(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(),
        catalogue=b.catalogue(b.pack(requirement)),
        testpacks={"tp/a": b.purposes_pack(purpose)},
        ics=b.ics(),
        ixit=IXIT(schema_version="dppce.ixit/1"),
        data_root=Path(),
        evaluation_time=AT,
        trust=trust,
        manual_results=frozenset({purpose.id}),
    )
    name = f"manual/{purpose.id}"
    artifacts = {} if body is None else {name: make_artifact(name, body, error)}
    return execute(make_plan(inputs), inputs, ArtifactAcquirer(artifacts))[purpose.id]


# -- the model and the trust purpose ------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        {"performer_name": "TEST-ONLY person"},
        {"role": "TEST-ONLY person"},
        {"role": "Inspector"},
        {"role": 1.0},
        {"performed_at": "2026-10-13 08:00:00"},
    ],
    ids=["extra-field", "role-with-space", "role-with-capitals", "float", "bad-stamp"],
)
def test_manualresult_is_closed_and_refuses_a_name_like_role(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        result(**changes)


def test_trust_bundle_accepts_the_manual_purpose_and_old_bundles_still_load() -> None:
    bundle = TrustBundle.model_validate(parse_strict(TRUST.read_bytes()))
    assert {p for k in bundle.keys for p in k.purposes} >= {"report", "authorization", "manual"}
    assert _key(MANUAL, ("manual",)).purposes == ("manual",)
    old = parse_strict(TRUST.read_bytes())
    old["keys"] = [k for k in old["keys"] if "manual" not in k["purposes"]]
    assert TrustBundle.model_validate(old).keys, "a bundle without a manual key still loads"


def test_issue_manual_result_header_is_exactly_alg_kid_typ() -> None:
    token = issue_manual_result(result(), MANUAL)
    assert header_of(token) == {"alg": "ES256", "kid": MANUAL.key_id, "typ": MANUAL_RESULT_TYP}
    assert verify_compact(token, MANUAL.public_jwk(), typ=MANUAL_RESULT_TYP) == canonical_bytes(result())


# -- the check ----------------------------------------------------------------------------------


def test_check_accepts_a_pass_and_a_fail_record() -> None:
    token = issue_manual_result(result(), MANUAL)
    passed = run_check(token.encode("ascii"))
    assert (passed.execution_status, passed.verdict, passed.reason_code) == (
        ExecutionStatus.COMPLETED,
        Verdict.PASS,
        "MANUAL.REVIEW.OK",
    )
    (observation,) = passed.observations
    assert (observation.kind, observation.record_ids) == ("artifact", ("r0001",))
    assert set(observation.summary) == set(FIELDS)
    assert observation.summary == {
        "jws": token,
        "kid": MANUAL.key_id,
        "role": "inspector",
        "performed_at": "2026-10-13T08:00:00Z",
        "outcome": "pass",
    }
    assert "did not perform the review" in passed.message

    failing = issue_manual_result(result(outcome="fail"), MANUAL).encode("ascii")
    failed = run_check(failing)
    assert (failed.execution_status, failed.verdict, failed.reason_code) == (
        ExecutionStatus.COMPLETED,
        Verdict.FAIL,
        "MANUAL.REVIEW.FAILED",
    )
    lenient = b.purpose(
        "T-MAN",
        manual=True,
        stimulus={"check": "manual.review"},
        expected_evidence=list(EVIDENCE),
        verdict_rules={"on_check_failed": "inconclusive"},
    )
    assert run_check(failing, purpose=lenient).verdict is Verdict.INCONCLUSIVE


def _token(**changes: Any) -> bytes:
    return issue_manual_result(result(**changes), MANUAL).encode("ascii")


def _parts() -> list[str]:
    return issue_manual_result(result(), MANUAL).split(".")


_PAYLOAD = canonical_bytes(result())
_EXPIRED = UNIT_TRUST.model_copy(
    update={"keys": (_key(MANUAL, ("manual",), not_after="2026-10-01T00:00:00Z"), UNIT_TRUST.keys[1])}
)
_REVOKED = UNIT_TRUST.model_copy(update={"revoked_kids": (MANUAL.key_id,)})
_NO_OUTCOME = canonical_bytes({k: v for k, v in result().model_dump(mode="json").items() if k != "outcome"})

# (id, body, error, trust, expected reason code)
REFUSALS: list[tuple[str, Callable[[], bytes], TransportError | None, TrustBundle, str]] = [
    (
        "another-purpose",
        lambda: _token(test_purpose_id="T-OTHER"),
        None,
        UNIT_TRUST,
        "MANUAL.PURPOSE.MISMATCH",
    ),
    (
        "another-sut",
        lambda: _token(sut_identifier="urn:example:other"),
        None,
        UNIT_TRUST,
        "MANUAL.SUT.MISMATCH",
    ),
    (
        "untrusted-kid",
        lambda: issue_manual_result(result(), STRANGER).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.KEY.UNTRUSTED",
    ),
    (
        "report-purpose-key",
        lambda: issue_manual_result(result(), REPORT).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.KEY.UNTRUSTED",
    ),
    ("expired-key", _token, None, _EXPIRED, "MANUAL.KEY.NOT_VALID"),
    ("revoked-kid", _token, None, _REVOKED, "MANUAL.KEY.NOT_VALID"),
    (
        "performed-after-evaluation",
        lambda: _token(performed_at="2026-10-15T00:00:00Z"),
        None,
        UNIT_TRUST,
        "MANUAL.TIME.AFTER_EVALUATION",
    ),
    (
        "impossible-date",
        lambda: _token(performed_at="2026-02-30T00:00:00Z"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    (
        "alg-none",
        lambda: compact(_header(alg="none"), _PAYLOAD, signature=b"").encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.SIGNATURE.INVALID",
    ),
    (
        "empty-signature",
        lambda: ".".join([*_parts()[:2], ""]).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.SIGNATURE.INVALID",
    ),
    (
        "tampered-payload",
        lambda: ".".join([_parts()[0], _b64(canonical_bytes(result(outcome="fail"))), _parts()[2]]).encode(
            "ascii"
        ),
        None,
        UNIT_TRUST,
        "MANUAL.SIGNATURE.INVALID",
    ),
    (
        "attestation-typ",
        lambda: sign_compact(_PAYLOAD, MANUAL, typ="dppce-attestation+jws").encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    (
        "x5c-header",
        lambda: compact(_header(x5c=["MIIBTESTONLY"]), _PAYLOAD).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    (
        "wrong-typ-and-bad-signature",
        lambda: compact(_header(typ="dppce-attestation+jws"), _PAYLOAD, signature=bytes(64)).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    (
        "non-canonical-payload",
        lambda: sign_compact(
            json.dumps(result().model_dump(mode="json"), indent=1).encode(), MANUAL, typ=MANUAL_RESULT_TYP
        ).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    (
        "payload-without-outcome",
        lambda: sign_compact(_NO_OUTCOME, MANUAL, typ=MANUAL_RESULT_TYP).encode("ascii"),
        None,
        UNIT_TRUST,
        "MANUAL.RESULT.MALFORMED",
    ),
    ("non-ascii-body", "TEST-ONLY é".encode, None, UNIT_TRUST, "MANUAL.RESULT.MALFORMED"),
    (
        "missing-evidence-item",
        lambda: _token(evidence=list(EVIDENCE[:1])),
        None,
        UNIT_TRUST,
        "MANUAL.EVIDENCE.MISMATCH",
    ),
    (
        "extra-evidence-item",
        lambda: _token(evidence=[*EVIDENCE, "Reviewed by TEST-ONLY person."]),
        None,
        UNIT_TRUST,
        "MANUAL.EVIDENCE.MISMATCH",
    ),
    (
        "reordered-evidence",
        lambda: _token(evidence=list(reversed(EVIDENCE))),
        None,
        UNIT_TRUST,
        "MANUAL.EVIDENCE.MISMATCH",
    ),
    ("body-too-large", lambda: b"", "body_too_large", UNIT_TRUST, "MANUAL.RESULT.TOO_LARGE"),
    ("artifact-unavailable", lambda: b"", "artifact_unavailable", UNIT_TRUST, "MANUAL.RESULT.MISSING"),
]


@pytest.mark.parametrize(
    ("body", "error", "trust", "code"), [r[1:] for r in REFUSALS], ids=[r[0] for r in REFUSALS]
)
def test_check_refuses_and_never_passes(
    body: Callable[[], bytes], error: TransportError | None, trust: TrustBundle, code: str
) -> None:
    refused = run_check(body(), error=error, trust=trust)
    assert (refused.execution_status, refused.reason_code) == (ExecutionStatus.MANUAL_UNAVAILABLE, code)
    assert refused.verdict is Verdict.INCONCLUSIVE
    (observation,) = refused.observations
    assert (observation.kind, observation.record_ids, observation.summary) == ("artifact", ("r0001",), {})
    for text in (*EVIDENCE, "Reviewed by TEST-ONLY person."):
        assert text not in refused.message


def test_check_without_trust_is_an_error() -> None:
    errored = run_check(_token(), trust=None)
    assert (errored.execution_status, errored.reason_code) == (ExecutionStatus.ERROR, "MANUAL.TRUST.MISSING")
    assert errored.verdict is Verdict.ERROR


def test_capability_manifest_lists_manual_review_supported() -> None:
    entry = next(c for c in manifest().capabilities if c.id == "manual.review")
    assert (entry.state, entry.available) == (CapabilityState.SUPPORTED, True)
    assert "does not perform the review" in entry.description


def test_cat018_counts_a_manual_step_as_passable() -> None:
    fact = b.purpose("T-FACT", applicability=b.feature("marking_visible"))
    manual = b.purpose("T-MANUAL", manual=True, stimulus={"check": "manual.review"})
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-FACT", "T-MANUAL")])
    testpacks = {"tp/a": b.purposes_pack(fact, manual)}
    findings = lint(b.catalogue(b.pack(requirement)), {b.PROFILE_ID: b.profile()}, testpacks, ("probe.ok",))
    assert [f.location for f in findings if f.code == "CAT018"] == ["T-FACT"]


# -- end to end on the reference system --------------------------------------------------------


def _expected_evidence(purpose_id: str) -> list[str]:
    purposes = {p.id: p for pack in load_testpacks(ROOT).values() for p in pack.test_purposes}
    return list(purposes[purpose_id].expected_evidence) if purpose_id in purposes else []


def signed_file(directory: Path, purpose_id: str, signer: LocalSigner | None = None, **changes: Any) -> Path:
    """Write a TEST-ONLY manual result for the synthetic reference system."""
    fields: dict[str, Any] = {
        "test_purpose_id": purpose_id,
        "sut_identifier": REFERENCE_SUT,
        "evidence": _expected_evidence(purpose_id),
    }
    key = signer or LocalSigner.from_pem(FIXTURE_MANUAL_KEY, FIXTURE_MANUAL_KID)
    token = issue_manual_result(result(**(fields | changes)), key)
    path = directory / f"TEST-ONLY-{purpose_id}-{len(list(directory.iterdir()))}.jws"
    path.write_text(token + "\n", encoding="ascii")
    return path


def _result(run: RunResult, purpose_id: str) -> TestResult:
    return next(t for t in run.envelope.decision.test_results if t.test_purpose_id == purpose_id)


@pytest.fixture(scope="module")
def passed(tmp_path_factory: pytest.TempPathFactory) -> tuple[ReferenceRig, RunResult]:
    with ReferenceRig(tmp_path_factory.mktemp("manual-pass"), manual={EU_STEP: "pass"}) as rig:
        run = rig.run(mode="exploratory")
    return rig, run


@pytest.fixture(scope="module")
def plain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ReferenceRig]:
    with ReferenceRig(tmp_path_factory.mktemp("manual-plain")) as rig:
        yield rig


@pytest.fixture(scope="module")
def signed_document(passed: tuple[ReferenceRig, RunResult]) -> dict[str, Any]:
    rig, run = passed
    document: dict[str, Any] = json.loads(rig.sign(run).read_bytes())
    return document


@pytest.fixture(scope="module")
def fixture_trust() -> TrustBundle:
    return TrustBundle.model_validate(parse_strict(TRUST.read_bytes()))


def test_run_with_a_manual_result_completes_TP_EU_13_6_MANUAL(
    passed: tuple[ReferenceRig, RunResult], tmp_path: Path
) -> None:
    _, run = passed
    assert run.step(EU_STEP) == {"verdict": "pass", "reason_code": "MANUAL.REVIEW.OK", "status": "completed"}
    decision = run.envelope.decision
    (observation,) = _result(run, EU_STEP).observations
    committed = {c.record_id for c in decision.record_commitments}
    assert observation.record_ids
    assert set(observation.record_ids) <= committed
    assert records_root(decision.record_commitments) == decision.records_root
    assert observation.summary["kid"] == FIXTURE_MANUAL_KID
    with ReferenceRig(tmp_path, manual={EU_STEP: "fail"}) as rig:
        failed = rig.run(mode="exploratory")
    assert failed.step(EU_STEP) == {
        "verdict": "fail",
        "reason_code": "MANUAL.REVIEW.FAILED",
        "status": "completed",
    }


def test_without_the_file_the_step_and_manual_missing_are_unchanged(
    plain: ReferenceRig, tmp_path: Path
) -> None:
    without = plain.run(mode="exploratory")
    assert without.step(EU_STEP) == {
        "verdict": "inconclusive",
        "reason_code": "PLAN.MANUAL_UNAVAILABLE",
        "status": "manual_unavailable",
    }
    stranger = LocalSigner.generate("TEST-ONLY-stranger-manual-key")
    untrusted = plain.run(
        mode="exploratory", extra=["--manual-result", str(signed_file(tmp_path, EU_STEP, stranger))]
    )
    assert untrusted.step(EU_STEP) == {
        "verdict": "inconclusive",
        "reason_code": "MANUAL.KEY.UNTRUSTED",
        "status": "manual_unavailable",
    }
    assert (
        untrusted.envelope.decision.coverage.manual_missing
        == without.envelope.decision.coverage.manual_missing
    )


def test_a_record_for_another_purpose_never_passes_the_intended_step(
    plain: ReferenceRig, tmp_path: Path
) -> None:
    other = "TP-EU-13-6A-MANUAL"
    run = plain.run(mode="exploratory", extra=["--manual-result", str(signed_file(tmp_path, other))])
    assert run.step(EU_STEP)["reason_code"] == "PLAN.MANUAL_UNAVAILABLE"
    assert run.step(EU_STEP)["verdict"] != "pass"
    assert run.step(other) == {"verdict": "pass", "reason_code": "MANUAL.REVIEW.OK", "status": "completed"}


def test_replay_of_a_run_with_a_manual_result_gives_the_same_digest(
    passed: tuple[ReferenceRig, RunResult],
) -> None:
    rig, run = passed
    code, summary = rig.replay(run)
    assert summary["match"] is True
    assert code == run.exit_code
    stored = parse_strict((run.run_dir / "inputs.json").read_bytes())
    assert stored["manual_results"] == [EU_STEP]
    (observation,) = _result(run, EU_STEP).observations
    token = str(observation.summary["jws"])
    assert token not in (run.run_dir / "inputs.json").read_text(encoding="utf-8"), "the recording holds it"


def test_html_shows_role_date_key_outcome_and_record_id(passed: tuple[ReferenceRig, RunResult]) -> None:
    _, run = passed
    html = (run.run_dir / "report.html").read_text(encoding="utf-8")
    (observation,) = _result(run, EU_STEP).observations
    assert "Manual steps" in html
    for value in ("inspector", "2026-10-13T08:00:00Z", FIXTURE_MANUAL_KID, observation.record_ids[0]):
        assert value in html
    decision = run.envelope.decision
    changed = observation.model_copy(update={"summary": {**observation.summary, "role": "<b>x</b>"}})
    results = tuple(
        t.model_copy(update={"observations": (changed,)}) if t.test_purpose_id == EU_STEP else t
        for t in decision.test_results
    )
    page = render(
        run.envelope.model_copy(update={"decision": decision.model_copy(update={"test_results": results})})
    )
    assert "&lt;b&gt;x&lt;/b&gt;" in page
    assert "<b>x</b>" not in page


@pytest.mark.parametrize(
    "mode",
    [
        "record-not-committed",
        "no-jws",
        "outcome-changed",
        "verdict-disagrees",
        "no-manual-key",
        "manual-key-expired",
        "manual-key-revoked",
    ],
)
def test_verifier_manual_results_dimension(
    mode: str, signed_document: dict[str, Any], fixture_trust: TrustBundle
) -> None:
    control = verify(copy.deepcopy(signed_document), fixture_trust, VERIFY_AT)
    outcomes = {d.name: d.outcome for d in control.dimensions}
    assert (outcomes["manual_results"], outcomes["counts"], control.complete) == ("pass", "pass", True)

    document, trust = copy.deepcopy(signed_document), fixture_trust
    step = next(t for t in document["decision"]["test_results"] if t["test_purpose_id"] == EU_STEP)
    observation = step["observations"][0]
    manual_kid = observation["summary"]["kid"]
    if mode == "record-not-committed":
        observation["record_ids"] = ["r9999"]
    elif mode == "no-jws":
        del observation["summary"]["jws"]
    elif mode == "outcome-changed":
        observation["summary"]["outcome"] = "fail"
    elif mode == "verdict-disagrees":
        step["verdict"] = "fail"
    elif mode == "no-manual-key":
        trust = trust.model_copy(update={"keys": tuple(k for k in trust.keys if "manual" not in k.purposes)})
    elif mode == "manual-key-expired":
        keys = tuple(
            k.model_copy(update={"not_after": "2026-10-13T23:00:00Z"}) if k.kid == manual_kid else k
            for k in trust.keys
        )
        trust = trust.model_copy(update={"keys": keys})
    else:
        trust = trust.model_copy(update={"revoked_kids": (manual_kid,)})
    report = verify(document, trust, VERIFY_AT)
    assert {d.name: d.outcome for d in report.dimensions}["manual_results"] == "fail"
    assert not report.complete


def test_verifier_does_not_raise_on_an_impossible_manifest_time(
    signed_document: dict[str, Any], fixture_trust: TrustBundle, tmp_path: Path
) -> None:
    document = copy.deepcopy(signed_document)
    document["decision"]["manifest"]["evaluation_time"] = "2026-02-30T00:00:00Z"
    report = verify_json(json.dumps(document).encode(), fixture_trust, VERIFY_AT)
    assert {d.name: d.outcome for d in report.dimensions}["manual_results"] == "fail"
    assert not report.complete
    envelope = tmp_path / "envelope.json"
    envelope.write_text(json.dumps(document), encoding="utf-8")
    assert verifier_main([str(envelope), "--trust", str(TRUST), "--at", "2026-10-14T00:00:00Z"]) == 4


def test_rc1_envelope_still_verifies_complete(signer: LocalSigner, trust: TrustBundle) -> None:
    raw = (Path(__file__).parent / "fixtures" / "rc1-envelope-decision-v1.json").read_bytes()
    document = json.loads(raw)
    loaded = EvidenceEnvelope.model_validate(document)
    document["signatures"] = [
        sign_envelope(loaded, signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z").signatures[-1]
    ]
    report = verify_json(json.dumps(document).encode(), trust, AT)
    assert report.complete
    assert {d.name: d.outcome for d in report.dimensions}["manual_results"] == "pass"


def test_e13_flip_manual_outcome_fails_on_manual_results(
    signed_document: dict[str, Any], fixture_trust: TrustBundle
) -> None:
    document = copy.deepcopy(signed_document)
    TAMPER["flip_manual_outcome"](document)
    report = verify(document, fixture_trust, VERIFY_AT)
    assert {d.name: d.outcome for d in report.dimensions}["manual_results"] == "fail"
    assert not report.complete
    with pytest.raises(LookupError):
        TAMPER["flip_manual_outcome"](json.loads(make_envelope().model_dump_json(by_alias=True)))


# -- input errors -------------------------------------------------------------------------------


def _arguments(command: str, tmp_path: Path, *, ixit: Path, mode: str, trust: bool) -> list[str]:
    arguments = [
        command,
        "--profile", "battery/ev",
        "--ics", str(FIXTURES / "ev.ics.yaml"),
        "--ixit", str(ixit),
        "--mode", mode,
        "--at", RUN_AT,
    ]  # fmt: skip
    if trust:
        arguments += ["--trust", str(TRUST)]
    if command == "run":
        arguments += ["--out", str(tmp_path / "out"), "--keys", str(tmp_path / "keys")]
    return arguments


INPUT_ERRORS = [
    "ixit-sample-in-the-reserved-namespace",
    "not-a-jws",
    "unknown-test-purpose",
    "not-a-manual-step",
    "two-files-for-one-step",
    "no-trust",
    "excluded-by-the-mode",
    "skipped-by-the-plan",
]


@pytest.mark.parametrize("command", ["plan", "run"])
@pytest.mark.parametrize("case", INPUT_ERRORS)
def test_input_errors_exit_2(
    command: str, case: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = tmp_path / "files"
    files.mkdir()
    ixit, mode, trust, expected = FIXTURES / "ev.ixit.yaml", "exploratory", True, ""
    supplied: list[Path] = []
    if case == "ixit-sample-in-the-reserved-namespace":
        document = yaml.safe_load(ixit.read_text(encoding="utf-8"))
        document["samples"][f"manual/{EU_STEP}"] = "x.jws"
        ixit = tmp_path / "ixit.yaml"
        ixit.write_text(yaml.safe_dump(document), encoding="utf-8")
        expected = "manual/"
    elif case == "not-a-jws":
        supplied = [files / "TEST-ONLY-not-a-token.jws"]
        supplied[0].write_text("TEST-ONLY not a token\n", encoding="ascii")
        expected = "not a manual result"
    elif case == "unknown-test-purpose":
        supplied, expected = [signed_file(files, "TP-NO-SUCH-STEP")], "manual.review"
    elif case == "not-a-manual-step":
        supplied, expected = [signed_file(files, "TP-EU-QR-DECODE")], "manual.review"
    elif case == "two-files-for-one-step":
        supplied, expected = [signed_file(files, EU_STEP), signed_file(files, EU_STEP)], EU_STEP
    elif case == "no-trust":
        # The authorization guard also names a trust bundle; assert the manual-result message.
        supplied, trust = [signed_file(files, EU_STEP)], False
        expected = "a manual result needs a trust bundle"
    elif case == "excluded-by-the-mode":
        supplied, mode, expected = [signed_file(files, EU_STEP)], "illustrative", "MODE.NOT_PERMITTED"
    else:
        supplied, expected = [signed_file(files, "TP-EU-13-6B-MANUAL")], "skipped"
    arguments = _arguments(command, tmp_path, ixit=ixit, mode=mode, trust=trust)
    for path in supplied:
        arguments += ["--manual-result", str(path)]
    assert cli.main(arguments) == 2
    assert expected in capsys.readouterr().err
    assert not (tmp_path / "out").exists(), "no run starts"
