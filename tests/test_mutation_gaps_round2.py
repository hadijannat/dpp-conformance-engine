"""Tests for the verifier and verdict survivors of the mutation run of 2026-10-18.

The run is ``uv run just mutation`` (mutmut 3.8.0) at commit 6602f8c. Each test names, in its
docstring, the surviving mutants that it kills. The record is
``validation/records/mutation-2026-10-18.md``. A verdict reason and an overall reason are
canonical-body fields: a change of their text changes the decision digest and the replay.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from validation.rig import TRUST, ReferenceRig

from dppce.evidence.canonical import parse_strict
from dppce.evidence.envelope import build_decision, sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.recording import record_commitments
from dppce.models import (
    Conflict,
    CoverageSummary,
    EvidenceEnvelope,
    Exclusion,
    ExecutionMode,
    Modality,
    Ratio,
    RequirementResult,
    ReviewStatus,
    TestResult,
    Tri,
    TrustBundle,
    Verdict,
)
from dppce.verdicts import overall_verdict, requirement_verdict
from dppce.verdicts.coverage import RATIO_LABELS
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from tests.support import (
    AT,
    ISSUER,
    make_envelope,
    make_manifest,
    make_record,
    make_requirement_result,
    make_test_result,
)

PASS, FAIL, ERROR = Verdict.PASS, Verdict.FAIL, Verdict.ERROR
INCONCLUSIVE, NA = Verdict.INCONCLUSIVE, Verdict.NOT_APPLICABLE
ILLUSTRATIVE, REVIEWED = ExecutionMode.ILLUSTRATIVE, ExecutionMode.REVIEWED
DRAFT, APPROVED = ReviewStatus.DRAFT, ReviewStatus.APPROVED
SIGNED_AT = "2026-10-13T12:05:00Z"
AT_TEXT = "2026-10-14T00:00:00Z"  # AT as a stamp
EU_STEP = "TP-EU-13-6-MANUAL"


def outcomes(document: Any, trust: TrustBundle) -> dict[str, str]:
    return {d.name: d.outcome for d in verify(document, trust, AT).dimensions}


def details(document: Any, trust: TrustBundle) -> dict[str, str]:
    return {d.name: d.detail for d in verify(document, trust, AT).dimensions}


def as_document(envelope: EvidenceEnvelope) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(envelope.model_dump_json(by_alias=True))
    return document


# -- verdicts: the reason text is a canonical-body field ----------------------------------------


CONFLICT_REASON = (
    "The owner declares the feature as not implemented. A declaration cannot waive a requirement."
)
REQUIREMENT_BRANCHES = [
    # (applicability, conflict, path verdicts, mode, review status) -> (verdict, verdict_reason)
    ((Tri.FALSE, False, [], ILLUSTRATIVE, DRAFT), (NA, "The requirement does not apply.")),
    ((Tri.UNKNOWN, False, [PASS], ILLUSTRATIVE, DRAFT), (INCONCLUSIVE, "The applicability is unknown.")),
    ((Tri.TRUE, True, [PASS], ILLUSTRATIVE, DRAFT), (FAIL, CONFLICT_REASON)),
    ((Tri.TRUE, False, [], ILLUSTRATIVE, DRAFT), (INCONCLUSIVE, "No assessment path is defined.")),
    (
        (Tri.TRUE, False, [NA], ILLUSTRATIVE, DRAFT),
        (INCONCLUSIVE, "No permitted assessment path is declared as implemented."),
    ),
    ((Tri.TRUE, False, [FAIL, PASS], ILLUSTRATIVE, DRAFT), (FAIL, "A valid failing observation exists.")),
    (
        (Tri.TRUE, False, [PASS], REVIEWED, DRAFT),
        (INCONCLUSIVE, "The interpretation is not approved. Reviewed mode cannot claim a pass."),
    ),
    (
        (Tri.TRUE, False, [PASS], REVIEWED, APPROVED),
        (PASS, "Every required step of an assessment path passed."),
    ),
    (
        (Tri.TRUE, False, [ERROR, INCONCLUSIVE], ILLUSTRATIVE, DRAFT),
        (ERROR, "An execution defect prevented the assessment."),
    ),
    (
        (Tri.TRUE, False, [INCONCLUSIVE], ILLUSTRATIVE, DRAFT),
        (INCONCLUSIVE, "The assessment evidence is missing or insufficient."),
    ),
]


@pytest.mark.parametrize(("inputs", "expected"), REQUIREMENT_BRANCHES)
def test_aggregate_requirement_reason_text_is_stable(
    inputs: tuple[Tri, bool, list[Verdict], ExecutionMode, ReviewStatus], expected: tuple[Verdict, str]
) -> None:
    """The verdict and the exact ``verdict_reason`` of each branch (aggregate.py stores it).

    Kills dppce.verdicts.aggregate.x_requirement_verdict__mutmut_2, _3, _4, _6, _7, _8, _9, _10,
    _11, _13, _14, _15, _19, _20, _21, _30, _31, _32, _37, _38, _39, _40, _41, and _42.
    """
    assert requirement_verdict(*inputs) == expected


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (
            (),
            (INCONCLUSIVE, "No applicable mandatory requirement was assessed. An empty run cannot pass."),
        ),
        (("fail", "error"), (FAIL, "At least one applicable mandatory requirement failed.")),
        (
            ("error", "inconclusive"),
            (ERROR, "At least one applicable mandatory requirement had an execution error."),
        ),
        (
            ("inconclusive", "pass"),
            (INCONCLUSIVE, "At least one applicable mandatory requirement is inconclusive."),
        ),
        (("pass",), (PASS, "Every applicable mandatory requirement in the selected catalogue passed.")),
    ],
)
def test_aggregate_overall_reason_text_is_stable(
    verdicts: tuple[str, ...], expected: tuple[Verdict, str]
) -> None:
    """The overall verdict and the exact ``overall_reason`` of each branch.

    Kills dppce.verdicts.aggregate.x_overall_verdict__mutmut_6, _7, _8, _12, _13, _14, _15, _16,
    _17, _19, _20, and _21.
    """
    results = [make_requirement_result(i, v) for i, v in enumerate(verdicts, start=1)]
    assert overall_verdict(results) == expected


# -- verifier: the counts dimension recomputes the report --------------------------------------


def report(
    requirements: list[RequirementResult],
    tests: list[TestResult],
    *,
    mode: ExecutionMode = ILLUSTRATIVE,
    conflicts: tuple[Conflict, ...] = (),
    exclusions: tuple[Exclusion, ...] = (),
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An unsigned report whose counts follow from its results. ``coverage`` replaces fields.

    Every applicable result here has a true path with completed steps, so the execution ratio
    is all of them. An excluded requirement counts as illustrative, draft, and automated.
    """
    excluded = sum(1 for e in exclusions if e.kind == "requirement")
    applicable = [r for r in requirements if r.applicability is Tri.TRUE]
    mandatory = [r for r in applicable if r.modality is Modality.MANDATORY]
    total = len(requirements) + excluded

    def counts(values: list[str], extra: str) -> dict[str, int]:
        return dict(sorted(Counter(values + [extra] * excluded).items()))

    fields: dict[str, Any] = {
        "scope_statement": "test scope",
        "total_requirements": total,
        "by_authority_class": counts([r.authority_class.value for r in requirements], "illustrative"),
        "by_review_status": counts([r.review_status.value for r in requirements], "draft-needs-review"),
        "by_applicability": counts([r.applicability.value for r in requirements], "excluded"),
        "by_testability": counts([r.testability.value for r in requirements], "automated"),
        "by_verdict": counts([r.verdict.value for r in requirements], "excluded"),
        "implementation": Ratio(numerator=total, denominator=total, of=RATIO_LABELS["implementation"]),
        "execution": Ratio(
            numerator=len(applicable), denominator=len(applicable), of=RATIO_LABELS["execution"]
        ),
        "passing": Ratio(
            numerator=sum(1 for r in mandatory if r.verdict is PASS),
            denominator=len(mandatory),
            of=RATIO_LABELS["passing"],
        ),
        "placeholders": 0,
        "unknown_applicability": 0,
        "excluded": excluded,
        "manual_missing": 0,
    } | (coverage or {})
    overall, reason = overall_verdict(requirements)
    decision = build_decision(
        manifest=make_manifest().model_copy(update={"mode": mode}),
        overall=overall,
        overall_reason=reason,
        requirement_results=requirements,
        test_results=tests,
        exclusions=exclusions,
        conflicts=conflicts,
        coverage=CoverageSummary(**fields),
        record_commitments=record_commitments([make_record(1)]),
    )
    return as_document(EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision))


def passing_path(index: int = 1) -> dict[str, Any]:
    return {"path_id": "default", "applicability": "true", "verdict": "pass", "steps": [f"TP-{index:03d}"]}


def three() -> tuple[list[RequirementResult], list[TestResult]]:
    verdicts = ("pass", "fail", "pass")
    return (
        [make_requirement_result(i, v) for i, v in enumerate(verdicts, start=1)],
        [make_test_result(i, v) for i, v in enumerate(verdicts, start=1)],
    )


EXCLUDED = (Exclusion(kind="requirement", id="ILL-900", reason_code="PLAN.EXCLUDED", reason="test"),)


def consistent(case: str) -> dict[str, Any]:
    if case == "a path that does not apply":
        paths = [{"path_id": "a", "applicability": "false", "verdict": "not_applicable", "steps": []}]
        requirement = make_requirement_result(1, "pass", paths=[*paths, passing_path()])
        return report([requirement], [make_test_result(1, "pass")])
    if case == "a declared conflict":
        reason = requirement_verdict(Tri.TRUE, True, [PASS], ILLUSTRATIVE, DRAFT)[1]
        requirement = make_requirement_result(1, "fail", verdict_reason=reason, paths=[passing_path()])
        conflict = Conflict(requirement_id="ILL-001", declared="not implemented", explanation="test")
        return report([requirement], [make_test_result(1, "pass")], conflicts=(conflict,))
    if case == "reviewed mode without approval":
        reason = requirement_verdict(Tri.TRUE, False, [PASS], REVIEWED, DRAFT)[1]
        requirement = make_requirement_result(
            1, "inconclusive", verdict_reason=reason, claim_level="none", paths=[passing_path()]
        )
        return report([requirement], [make_test_result(1, "pass")], mode=REVIEWED)
    if case == "a bucket with a zero count":
        zero = {"by_authority_class": {"guidance": 0, "illustrative": 1}}
        return report([make_requirement_result(1, "pass")], [make_test_result(1, "pass")], coverage=zero)
    assert case == "an excluded placeholder"
    requirements, tests = three()
    coverage: dict[str, Any] = {
        "by_review_status": {"draft-needs-review": 3, "placeholder": 1},
        "placeholders": 1,
    }
    return report(requirements, tests, exclusions=EXCLUDED, coverage=coverage)


@pytest.mark.parametrize(
    "case",
    [
        "a path that does not apply",
        "a declared conflict",
        "reviewed mode without approval",
        "a bucket with a zero count",
        "an excluded placeholder",
    ],
)
def test_verify_counts_accept_a_consistent_report(case: str, trust: TrustBundle) -> None:
    """A report whose values follow from its results passes the counts dimension.

    Kills dppce.verifier.verify.x__verdicts_follow__mutmut_8 (a path that does not apply),
    x__verdicts_follow__mutmut_16 (a declared conflict), x__verdicts_follow__mutmut_18 (reviewed
    mode), and x__coverage_follows__mutmut_28 and _29 (a bucket with a zero count). The excluded
    placeholder is the control of the placeholder case of the next test.
    """
    assert outcomes(consistent(case), trust)["counts"] == "pass"


def inconsistent(case: str) -> dict[str, Any]:
    requirements, tests = three()
    if case == "placeholder count differs from its review status bucket":
        coverage: dict[str, Any] = {"by_review_status": {"draft-needs-review": 3, "placeholder": 1}}
        return report(requirements, tests, exclusions=EXCLUDED, coverage=coverage | {"placeholders": 0})
    if case == "authority classes do not fit the results":
        return report(requirements, tests, coverage={"by_authority_class": {"guidance": 3}})
    if case == "testabilities do not fit the results":
        return report(requirements, tests, coverage={"by_testability": {"manual": 3}})
    assert case == "passing numerator differs"
    passing = Ratio(numerator=0, denominator=3, of=RATIO_LABELS["passing"])
    return report(requirements, tests, coverage={"passing": passing})


@pytest.mark.parametrize(
    "case",
    [
        "placeholder count differs from its review status bucket",
        "authority classes do not fit the results",
        "testabilities do not fit the results",
        "passing numerator differs",
    ],
)
def test_verify_counts_refuse_an_inconsistent_report(case: str, trust: TrustBundle) -> None:
    """One stated value that does not follow from the results fails the counts dimension.

    Kills dppce.verifier.verify.x__coverage_follows__mutmut_62 (placeholder count),
    x__coverage_follows__mutmut_75 (authority classes), x__coverage_follows__mutmut_91
    (testabilities), and x__counts__mutmut_36 (passing numerator).
    """
    assert outcomes(inconsistent(case), trust)["counts"] == "fail"


# -- verifier: signatures, keys, timestamps, and status -----------------------------------------


@pytest.mark.parametrize("end", ["not_before", "not_after"])
def test_verify_key_validity_includes_both_ends(
    end: str, signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """A key is trusted at the first and at the last instant of its validity period.

    Kills dppce.verifier.verify.x__key_state__mutmut_6 (not_before) and
    x__key_state__mutmut_7 (not_after).
    """
    key = trust.keys[0].model_copy(update={end: AT_TEXT})
    bounded = trust.model_copy(update={"keys": (key,)})
    assert outcomes(as_document(signed), bounded)["issuer_trust"] == "pass"


def test_verify_signature_search_passes_over_an_unknown_key(signer: LocalSigner, trust: TrustBundle) -> None:
    """A signature by a key that the bundle does not hold does not stop the search.

    Kills dppce.verifier.verify.x__verified__mutmut_18.
    """
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    first = sign_envelope(make_envelope(), stranger, issuer=ISSUER, signed_at=SIGNED_AT)
    both = sign_envelope(first, signer, issuer=ISSUER, signed_at=SIGNED_AT)
    assert len(both.signatures) == 2
    assert outcomes(as_document(both), trust)["signature"] == "pass"


def test_verify_signature_search_passes_over_a_signature_that_does_not_bind(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """A trusted signature over a different decision body does not stop the search.

    Kills dppce.verifier.verify.x__verified__mutmut_51.
    """
    other = sign_envelope(make_envelope(("fail",)), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    good = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    envelope = good.model_copy(update={"signatures": (other.signatures[0], good.signatures[0])})
    assert outcomes(as_document(envelope), trust)["signature"] == "pass"


def test_verify_timestamp_that_is_absent_and_optional_is_not_checked(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """With no timestamp evidence and no requirement for it, the dimension is not checked.

    Kills dppce.verifier.verify.x__timestamps__mutmut_5.
    """
    assert not trust.require_timestamp
    assert outcomes(as_document(signed), trust)["timestamp"] == "not_checked"


def test_verify_sixteen_timestamp_tokens_are_within_the_limit(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """Exactly MAX_TOKENS tokens are each read: the reason code is that of the first bad token.

    Kills dppce.verifier.verify.x__timestamps__mutmut_19.
    """
    document = as_document(signed)
    document["timestamp_evidence"] = ["AAAA"] * 16
    assert outcomes(document, trust)["timestamp"] == "fail"
    assert details(document, trust)["timestamp"].startswith("TIMESTAMP.TOKEN.MALFORMED:")
    document["timestamp_evidence"] = ["AAAA"] * 17
    assert details(document, trust)["timestamp"].startswith("TIMESTAMP.EVIDENCE.TOO_MANY:")


@pytest.mark.parametrize("status_as_of", [AT_TEXT, "2026-10-07T00:00:00Z"])
def test_verify_status_snapshot_age_includes_both_ends(
    status_as_of: str, signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """A snapshot of age zero and one of exactly the maximum age are both fresh.

    Kills dppce.verifier.verify.x__status__mutmut_15 and _17 (age zero), and
    x__status__mutmut_18 (age of exactly seven days, the maximum).
    """
    snapshot = trust.model_copy(update={"status_as_of": status_as_of, "status_max_age_days": 7})
    assert outcomes(as_document(signed), snapshot)["status"] == "pass"


def test_verify_states_no_digest_for_an_invalid_structure(trust: TrustBundle) -> None:
    """The report of a document that is not an envelope states the digest as unavailable.

    Kills dppce.verifier.verify.x_verify__mutmut_81 and _82.
    """
    assert verify({}, trust, AT).decision_digest == "unavailable"


# -- verifier: completed manual steps -----------------------------------------------------------


@pytest.fixture(scope="module")
def manual_document(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    with ReferenceRig(tmp_path_factory.mktemp("manual-round2"), manual={EU_STEP: "pass"}) as rig:
        run = rig.run(mode="exploratory")
    document: dict[str, Any] = json.loads(rig.sign(run).read_bytes())
    return document


@pytest.fixture(scope="module")
def fixture_trust() -> TrustBundle:
    return TrustBundle.model_validate(parse_strict(TRUST.read_bytes()))


def manual_observation(document: dict[str, Any]) -> dict[str, Any]:
    step = next(t for t in document["decision"]["test_results"] if t["test_purpose_id"] == EU_STEP)
    observation: dict[str, Any] = step["observations"][0]
    return observation


def test_verify_manual_step_with_exactly_its_records_committed_passes(
    manual_document: dict[str, Any], fixture_trust: TrustBundle
) -> None:
    """The records of a manual step may be all the committed records.

    Kills dppce.verifier.verify.x__manual_results__mutmut_33.
    """
    document = copy.deepcopy(manual_document)
    referenced = set(manual_observation(document)["record_ids"])
    decision = document["decision"]
    decision["record_commitments"] = [
        c for c in decision["record_commitments"] if c["record_id"] in referenced
    ]
    assert {c["record_id"] for c in decision["record_commitments"]} == referenced
    assert outcomes(document, fixture_trust)["manual_results"] == "pass"


def test_verify_manual_step_without_records_fails(
    manual_document: dict[str, Any], fixture_trust: TrustBundle
) -> None:
    """A signed manual result that names no record does not bind its step.

    Kills dppce.verifier.verify.x__manual_results__mutmut_26.
    """
    assert outcomes(copy.deepcopy(manual_document), fixture_trust)["manual_results"] == "pass"
    document = copy.deepcopy(manual_document)
    manual_observation(document)["record_ids"] = []
    assert outcomes(document, fixture_trust)["manual_results"] == "fail"


# -- verifier: the command line -----------------------------------------------------------------


@pytest.mark.parametrize("left_out", ["--trust", "--at"])
def test_verifier_main_requires_the_trust_bundle_and_the_time(
    left_out: str, tmp_path: Path, signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """Without --trust or --at the verifier stops with exit status 2.

    Kills dppce.verifier.__main__.x_main__mutmut_21, _25, and _29 (--trust), and
    x_main__mutmut_34, _37, and _41 (--at).
    """
    envelope = tmp_path / "envelope.json"
    envelope.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    bundle = tmp_path / "trust.json"
    bundle.write_text(trust.model_dump_json(), encoding="utf-8")
    options = {"--trust": str(bundle), "--at": AT_TEXT}
    del options[left_out]
    arguments = [str(envelope)] + [item for pair in options.items() for item in pair]
    with pytest.raises(SystemExit) as stopped:
        verifier_main(arguments)
    assert stopped.value.code == 2
