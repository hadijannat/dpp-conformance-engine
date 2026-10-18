"""The run core: execution of a plan through an ``Acquirer`` and the decision body.

Expected values come from docs/explanation/architecture.md: section 6 (a planned status is
not executed), section 7.1 (a check that raises is an error, never a fail), section 10 (a
replayed request that differs is an execution error), and section 11.1 (the decision digest).
The checks and the acquirer here are fakes. Nothing reaches a network.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
from collections.abc import Iterator, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from dppce.evidence.envelope import decision_digest
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.models import (
    IXIT,
    Authorization,
    CapabilityState,
    CheckOutcome,
    DecisionBody,
    ExecutionMode,
    ExecutionStatus,
    Model,
    Requirement,
    Scope,
    Severity,
    TestPurpose,
    TestResult,
    TrustBundle,
    Verdict,
)
from dppce.orchestrator.run import (  # noqa: TID251 - the run core is the unit under test
    RunInputs,
    check_infos,
    evaluate,
    execute,
    make_plan,
)
from dppce.testdefs import registry
from dppce.verdicts import (
    aggregate,
    claim_level,
    overall_verdict,
    path_verdict,
    requirement_verdict,
    step_verdict,
)
from tests.core import builders as b
from tests.support import AT, make_record

COMPLETED, ERROR = ExecutionStatus.COMPLETED, ExecutionStatus.ERROR
SENTINEL = "SENTINEL-payload-7f3a"
URL = "http://127.0.0.1/dpp/1"
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)+$")
# An existing capability that is supported and has no optional dependency.
CAPABILITY = "data.rules"
CALLS: list[str] = []


def completed(context: registry.CheckContext, *, passed: bool, unreachable: bool = False) -> CheckOutcome:
    CALLS.append(context.purpose.id)
    return CheckOutcome(
        status=COMPLETED,
        passed=passed,
        unreachable=unreachable,
        reason_code="TESTS.CORE.OK" if passed else "TESTS.CORE.NOT_OK",
        message="A synthetic outcome.",
        observations=(context.observation(0, kind="derived", summary={"passed": passed}),),
    )


@registry.register("tests_core.passes", capability=CAPABILITY)
def _passes(context: registry.CheckContext) -> CheckOutcome:
    return completed(context, passed=True)


@registry.register("tests_core.fails", capability=CAPABILITY)
def _fails(context: registry.CheckContext) -> CheckOutcome:
    return completed(context, passed=False)


@registry.register("tests_core.unreachable", capability=CAPABILITY)
def _unreachable(context: registry.CheckContext) -> CheckOutcome:
    return completed(context, passed=False, unreachable=True)


@registry.register("tests_core.raises", capability=CAPABILITY)
def _raises(context: registry.CheckContext) -> CheckOutcome:
    CALLS.append(context.purpose.id)
    raise RuntimeError(f"the payload held {SENTINEL}")


class _FetchParams(Model):
    """The planner validates parameters. Its defaults equal the ones that ``_fetches`` reads."""

    method: str = "GET"
    url: str = URL
    role: str = "anonymous"
    artifact: bool = False


@registry.register("tests_core.fetches", capability=CAPABILITY, params=_FetchParams)
def _fetches(context: registry.CheckContext) -> CheckOutcome:
    """Ask for one record, then report a pass whatever came back."""
    params = context.params
    request = Request(
        str(params.get("method", "GET")), str(params.get("url", URL)), str(params.get("role", "anonymous"))
    )
    record = (
        context.acquirer.artifact("sample") if params.get("artifact") else context.acquirer.fetch(request)
    )
    assert record.record_id
    return completed(context, passed=True)


@registry.register("tests_core.orphan", capability="tests_core.no_such_capability")
def _orphan(context: registry.CheckContext) -> CheckOutcome:
    return completed(context, passed=True)


class FakeAcquirer:
    """Serves prepared records in order. It has no transport."""

    def __init__(self, prepared: Sequence[Record] = ()) -> None:
        self._prepared = list(prepared)
        self._served: list[Record] = []

    def fetch(self, request: Request) -> Record:
        record = self._prepared[len(self._served)]
        self._served.append(record)
        return record

    def artifact(self, name: str) -> Record:
        return self.fetch(Request("READ", f"artifact:{name}", "local"))

    def records(self) -> tuple[Record, ...]:
        return tuple(self._served)


@pytest.fixture(autouse=True)
def _no_calls_yet() -> Iterator[None]:
    CALLS.clear()
    yield
    CALLS.clear()


def step(test_id: str, check: str, requirement_id: str = "R-1", **changes: Any) -> TestPurpose:
    return b.purpose(
        test_id, requirements=[requirement_id], stimulus={"check": f"tests_core.{check}"}, **changes
    )


def one_path(requirement_id: str, *tests: str, **changes: Any) -> Requirement:
    return b.requirement(requirement_id, assessment_paths=[b.path("p1", *tests)], **changes)


def inputs_for(
    requirements: Sequence[Requirement], purposes: Sequence[TestPurpose], tmp_path: Path, **changes: Any
) -> RunInputs:
    fields: dict[str, Any] = {
        "mode": ExecutionMode.EXPLORATORY,
        "profile": b.profile(),
        "catalogue": b.catalogue(b.pack(*requirements)),
        "testpacks": {"tp/a": b.purposes_pack(*purposes)},
        "ics": b.ics(),
        "ixit": IXIT(schema_version="dppce.ixit/1"),
        "data_root": tmp_path,
        "evaluation_time": AT,
    }
    return RunInputs(**(fields | changes))


def run_one(purpose: TestPurpose, tmp_path: Path, acquirer: Any = None, **changes: Any) -> TestResult:
    inputs = inputs_for([one_path("R-1", purpose.id)], [purpose], tmp_path, **changes)
    results = execute(make_plan(inputs), inputs, acquirer or FakeAcquirer())
    assert list(results) == [purpose.id]
    return results[purpose.id]


# --- Completed checks ----------------------------------------------------------------------


def test_a_check_that_passes_gives_a_completed_step_with_verdict_pass(tmp_path: Path) -> None:
    result = run_one(step("T-1", "passes", severity="critical"), tmp_path)
    assert CALLS == ["T-1"]
    assert (result.execution_status, result.verdict) == (COMPLETED, Verdict.PASS)
    assert (result.reason_code, result.message) == ("TESTS.CORE.OK", "A synthetic outcome.")
    assert (result.check, result.requirement_ids) == ("tests_core.passes", ("R-1",))
    assert result.severity.value == "critical"
    (observation,) = result.observations
    assert (observation.test_purpose_id, observation.kind) == ("T-1", "derived")
    assert observation.acquired_at == "2026-10-14T00:00:00Z", "a check reads the clock from its context only"


def test_a_check_that_does_not_pass_follows_the_verdict_rules_of_its_test_purpose(tmp_path: Path) -> None:
    assert run_one(step("T-1", "fails"), tmp_path).verdict is Verdict.FAIL
    lenient = step("T-1", "fails", verdict_rules={"on_check_failed": "inconclusive"})
    assert run_one(lenient, tmp_path).verdict is Verdict.INCONCLUSIVE


def test_an_unreachable_system_is_inconclusive_unless_an_approved_test_method_says_fail(
    tmp_path: Path,
) -> None:
    """ADR 0010 and review finding V-02: the rule of a test purpose is not enough.

    The first form of this test took ``fail`` from a draft requirement in exploratory mode.
    The contract gives ``fail`` only to an approved test method, so that case is now asserted
    as ``inconclusive`` and the ``fail`` case uses an approved requirement in reviewed mode.
    """
    default = run_one(step("T-1", "unreachable"), tmp_path)
    assert (default.execution_status, default.verdict) == (COMPLETED, Verdict.INCONCLUSIVE)
    strict = step("T-1", "unreachable", verdict_rules={"on_unreachable": "fail"})
    draft = run_one(strict, tmp_path)
    assert (draft.execution_status, draft.verdict) == (COMPLETED, Verdict.INCONCLUSIVE)
    approved = one_path(
        "R-1",
        "T-1",
        authority_class="guidance",
        source=b.CITED,
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
    )
    inputs = inputs_for([approved], [strict], tmp_path, mode=ExecutionMode.REVIEWED)
    reviewed = execute(make_plan(inputs), inputs, FakeAcquirer())["T-1"]
    assert (reviewed.execution_status, reviewed.verdict) == (COMPLETED, Verdict.FAIL)


# --- A check that raises -------------------------------------------------------------------


def test_a_check_that_raises_is_an_error_with_the_engine_reason_code(tmp_path: Path) -> None:
    result = run_one(step("T-1", "raises"), tmp_path)
    assert CALLS == ["T-1"], "the check did run"
    assert result.execution_status is ERROR
    assert result.reason_code == "ENGINE.CHECK_EXCEPTION"
    assert result.verdict is Verdict.ERROR, "a check that raises never gives fail"
    assert result.observations == ()


def test_the_message_of_a_check_that_raised_does_not_hold_the_exception_text(tmp_path: Path) -> None:
    purposes = [step("T-1", "raises")]
    inputs = inputs_for([one_path("R-1", "T-1")], purposes, tmp_path)
    decision = evaluate(inputs, FakeAcquirer())
    (result,) = decision.test_results
    assert result.message.strip()
    assert SENTINEL not in result.message
    assert "the payload held" not in result.message
    assert SENTINEL not in decision.model_dump_json(), "the exception text reaches no part of the decision"


def test_a_check_that_raises_makes_the_run_an_error_and_not_a_failure(tmp_path: Path) -> None:
    purposes = [step("T-1", "raises"), step("T-2", "passes", "R-2")]
    inputs = inputs_for([one_path("R-1", "T-1"), one_path("R-2", "T-2")], purposes, tmp_path)
    decision = evaluate(inputs, FakeAcquirer())
    assert CALLS == ["T-1", "T-2"], "the run goes on after a check raises"
    assert {r.requirement_id: r.verdict for r in decision.requirement_results} == {
        "R-1": Verdict.ERROR,
        "R-2": Verdict.PASS,
    }
    assert decision.overall is Verdict.ERROR
    assert decision.verdict_counts["fail"] == 0


# --- A recording that does not match -------------------------------------------------------

MISMATCHES = [
    ("a-different-url", {"url": "http://127.0.0.1/dpp/other"}),
    ("a-different-method", {"method": "HEAD"}),
    ("a-different-role", {"role": "auditor"}),
    ("an-artifact-instead-of-a-request", {"artifact": True}),
]


@pytest.mark.parametrize("params", [m[1] for m in MISMATCHES], ids=[m[0] for m in MISMATCHES])
def test_a_replayed_request_that_differs_from_the_recorded_one_is_an_execution_error(
    tmp_path: Path, params: dict[str, Any]
) -> None:
    purpose = b.purpose("T-1", stimulus={"check": "tests_core.fetches", "params": params})
    result = run_one(purpose, tmp_path, ReplayAcquirer([make_record(1, url=URL)]))
    assert CALLS == ["T-1"], "the check ran and reported a pass"
    assert (result.execution_status, result.reason_code) == (ERROR, "REPLAY.RECORDING_MISMATCH")
    assert result.verdict is Verdict.ERROR


def test_a_request_beyond_the_end_of_the_recording_is_a_mismatch(tmp_path: Path) -> None:
    result = run_one(step("T-1", "fetches"), tmp_path, ReplayAcquirer([]))
    assert (result.execution_status, result.reason_code) == (ERROR, "REPLAY.RECORDING_MISMATCH")


def test_a_replayed_request_that_equals_the_recorded_one_is_served(tmp_path: Path) -> None:
    replay = ReplayAcquirer([make_record(1, url=URL)])
    result = run_one(step("T-1", "fetches"), tmp_path, replay)
    assert (result.execution_status, result.verdict, result.reason_code) == (
        COMPLETED,
        Verdict.PASS,
        "TESTS.CORE.OK",
    )
    assert replay.complete()


def test_a_mismatch_is_reported_for_the_step_that_made_the_request_only(tmp_path: Path) -> None:
    purposes = [
        step("T-1", "fetches"),
        b.purpose(
            "T-2", stimulus={"check": "tests_core.fetches", "params": {"url": "http://127.0.0.1/dpp/x"}}
        ),
        step("T-3", "passes"),
    ]
    inputs = inputs_for([one_path("R-1", "T-1", "T-2", "T-3")], purposes, tmp_path)
    replay = ReplayAcquirer([make_record(1, url=URL), make_record(2)])
    results = execute(make_plan(inputs), inputs, replay)
    assert [results[t].reason_code for t in ("T-1", "T-2", "T-3")] == [
        "TESTS.CORE.OK",
        "REPLAY.RECORDING_MISMATCH",
        "TESTS.CORE.OK",
    ]
    assert not replay.complete()


def test_a_mismatch_record_from_any_acquirer_is_an_execution_error(tmp_path: Path) -> None:
    mismatch = dataclasses.replace(make_record(1, url=URL), status=None, error="recording_mismatch")
    result = run_one(step("T-1", "fetches"), tmp_path, FakeAcquirer([mismatch]))
    assert (result.execution_status, result.reason_code) == (ERROR, "REPLAY.RECORDING_MISMATCH")
    other = dataclasses.replace(make_record(1, url=URL), status=None, error="timeout")
    assert run_one(step("T-1", "fetches"), tmp_path, FakeAcquirer([other])).reason_code == "TESTS.CORE.OK"


# --- A planned status is never executed ----------------------------------------------------

NOT_EXECUTED = [
    ("manual", step("T-1", "passes", manual=True), {}, ExecutionStatus.MANUAL_UNAVAILABLE),
    ("blocked", step("T-1", "passes", requires_scope="write"), {}, ExecutionStatus.BLOCKED),
    ("step-unknown", step("T-1", "passes", applicability=b.feature("open")), {}, ExecutionStatus.SKIPPED),
    ("capability-not-in-manifest", step("T-1", "orphan"), {}, ExecutionStatus.UNSUPPORTED),
    ("check-not-registered", step("T-1", "never_registered"), {}, ExecutionStatus.UNSUPPORTED),
    (
        "parent-not-applicable",
        step("T-1", "passes"),
        {"ics": b.ics(features={"needed": False})},
        ExecutionStatus.SKIPPED,
    ),
]


@pytest.mark.parametrize(
    ("purpose", "changes", "status"), [n[1:] for n in NOT_EXECUTED], ids=[n[0] for n in NOT_EXECUTED]
)
def test_a_step_with_a_planned_status_is_never_executed(
    tmp_path: Path, purpose: TestPurpose, changes: dict[str, Any], status: ExecutionStatus
) -> None:
    requirement = one_path("R-1", "T-1", applicability=b.feature("needed") if changes else b.ALWAYS)
    inputs = inputs_for([requirement], [purpose], tmp_path, **changes)
    plan = make_plan(inputs)
    assert [s.planned_status for s in plan.steps] == [status]
    acquirer = FakeAcquirer()
    (result,) = execute(plan, inputs, acquirer).values()
    assert CALLS == [], "the check function was not called"
    assert acquirer.records() == ()
    assert result.execution_status is status
    assert result.verdict is Verdict.INCONCLUSIVE, "a step that did not run is never a pass"
    assert REASON_CODE.match(result.reason_code)
    assert result.message.strip()
    decision = evaluate(inputs, FakeAcquirer())
    assert CALLS == []
    assert decision.overall is Verdict.INCONCLUSIVE
    assert decision.verdict_counts["pass"] == 0


def test_a_valid_grant_of_the_scope_lets_a_blocked_step_run(tmp_path: Path) -> None:
    purpose = step("T-1", "passes", requires_scope="write")
    grant = Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-authorization",
        issuer="urn:example:owner",
        subject="urn:example:test-lab",
        sut_identifier="urn:example:sut",
        endpoints=("http://127.0.0.1",),
        methods=("POST",),
        roles=("anonymous",),
        scopes=(Scope.WRITE,),
        not_before="2026-01-01T00:00:00Z",
        not_after="2027-01-01T00:00:00Z",
        max_requests=1,
    )
    assert run_one(purpose, tmp_path, authorization=grant).verdict is Verdict.PASS
    assert CALLS == ["T-1"]
    other = grant.model_copy(update={"scopes": (Scope.TAMPER,)})
    assert run_one(purpose, tmp_path, authorization=other).execution_status is ExecutionStatus.BLOCKED
    assert CALLS == ["T-1"], "a grant of a different scope does not run the step"


def test_a_step_of_the_plan_that_has_no_test_purpose_is_not_run(tmp_path: Path) -> None:
    inputs = inputs_for([one_path("R-1", "T-1", "T-404")], [step("T-1", "passes")], tmp_path)
    results = execute(make_plan(inputs), inputs, FakeAcquirer())
    assert CALLS == ["T-1"]
    missing = results["T-404"]
    assert missing.execution_status is not COMPLETED
    assert missing.verdict is Verdict.INCONCLUSIVE
    assert evaluate(inputs, FakeAcquirer()).overall is Verdict.INCONCLUSIVE


def test_the_registry_maps_each_check_to_the_state_of_its_capability() -> None:
    infos = check_infos()
    assert infos["tests_core.passes"].state is CapabilityState.SUPPORTED
    assert infos["tests_core.passes"].available
    orphan = infos["tests_core.orphan"]
    assert (orphan.state, orphan.available) == (CapabilityState.UNSUPPORTED, False)
    assert "tests_core.never_registered" not in infos
    with pytest.raises(ValueError, match="registered twice"):
        registry.register("tests_core.passes", capability=CAPABILITY)(_passes)


# --- evaluate(): the decision body ---------------------------------------------------------


def mixed_inputs(tmp_path: Path, **changes: Any) -> RunInputs:
    requirements = [
        one_path("R-1", "T-FETCH", "T-PASS"),
        one_path("R-2", "T-MANUAL"),
        one_path("R-3", "T-FAIL", modality="recommended"),
        b.requirement("R-4", review_status="withdrawn"),
    ]
    purposes = [
        step("T-PASS", "passes"),
        step("T-MANUAL", "passes", "R-2", manual=True),
        step("T-FAIL", "fails", "R-3"),
        step("T-FETCH", "fetches"),
    ]
    return inputs_for(requirements, purposes, tmp_path, **changes)


def recorded() -> list[Record]:
    return [dataclasses.replace(make_record(1, url=URL), acquired_at="2026-10-13T09:30:00Z")]


def test_evaluate_builds_the_decision_for_a_mixed_catalogue(tmp_path: Path) -> None:
    decision = evaluate(mixed_inputs(tmp_path), ReplayAcquirer(recorded()))
    assert CALLS == ["T-FAIL", "T-FETCH", "T-PASS"], "the steps run in the order of their identifiers"
    assert [(r.requirement_id, r.verdict.value) for r in decision.requirement_results] == [
        ("R-1", "pass"),
        ("R-2", "inconclusive"),
        ("R-3", "fail"),
    ]
    assert [
        (t.test_purpose_id, t.execution_status.value, t.verdict.value) for t in decision.test_results
    ] == [
        ("T-FAIL", "completed", "fail"),
        ("T-FETCH", "completed", "pass"),
        ("T-MANUAL", "manual_unavailable", "inconclusive"),
        ("T-PASS", "completed", "pass"),
    ]
    # R-3 fails but is only recommended. R-2 is mandatory and waits for a manual review.
    assert decision.overall is Verdict.INCONCLUSIVE
    assert decision.overall_reason.strip()
    assert [(e.kind, e.id, e.reason_code) for e in decision.exclusions] == [
        ("requirement", "R-4", "STATUS.WITHDRAWN")
    ]
    assert decision.conflicts == ()
    assert decision.verdict_counts == {
        "pass": 1,
        "fail": 1,
        "inconclusive": 1,
        "not_applicable": 0,
        "error": 0,
    }
    assert decision.results_count == 3 + 4
    assert [c.record_id for c in decision.record_commitments] == ["r0001"]


def test_evaluate_counts_the_coverage_of_a_mixed_catalogue(tmp_path: Path) -> None:
    coverage = evaluate(mixed_inputs(tmp_path), ReplayAcquirer(recorded())).coverage
    assert coverage.total_requirements == 4
    # R-1 and R-3 have a path of executable steps. R-2 needs a manual review. R-4 has no path.
    assert (coverage.implementation.numerator, coverage.implementation.denominator) == (2, 4)
    # R-1, R-2, R-3 are applicable. Every step of a path completed for R-1 and R-3.
    assert (coverage.execution.numerator, coverage.execution.denominator) == (2, 3)
    # R-1 and R-2 are applicable and mandatory. R-1 passed.
    assert (coverage.passing.numerator, coverage.passing.denominator) == (1, 2)
    assert (
        coverage.excluded,
        coverage.manual_missing,
        coverage.placeholders,
        coverage.unknown_applicability,
    ) == (
        1,
        1,
        0,
        0,
    )
    assert "pack/a" in coverage.scope_statement
    assert "Synthetic scope." in coverage.scope_statement


def test_evaluate_states_the_run_in_the_manifest(tmp_path: Path) -> None:
    inputs = mixed_inputs(tmp_path, image_digest="sha256:" + "0" * 64)
    manifest = evaluate(inputs, ReplayAcquirer(recorded())).manifest
    assert (manifest.mode, manifest.profile_id) == (ExecutionMode.EXPLORATORY, b.PROFILE_ID)
    assert manifest.evaluation_time == "2026-10-14T00:00:00Z"
    assert manifest.sut == inputs.ics.sut
    assert (manifest.acquisition.first, manifest.acquisition.last) == ("2026-10-13T09:30:00Z",) * 2
    assert manifest.image_digest == "sha256:" + "0" * 64
    assert manifest.catalogue_hash == inputs.catalogue.hash()
    assert manifest.sources_hash == inputs.catalogue.sources_hash()
    assert manifest.pack_hashes == inputs.catalogue.pack_hashes()
    assert list(manifest.testpack_hashes) == ["tp/a"]
    assert manifest.seeds == {}, "the evaluation draws no random number"
    assert manifest.trust_policy_version == inputs.ixit.trust.policy_version
    text = " ".join(manifest.limitations)
    assert "not a certificate" in text
    assert "not a statement of legal compliance" in text
    assert "exploratory" in text.lower()
    live = evaluate(mixed_inputs(tmp_path), FakeAcquirer([make_record(1)])).manifest
    assert live.acquisition.first == "2026-10-13T12:00:00Z"
    nothing = evaluate(
        inputs_for([one_path("R-1", "T-1")], [step("T-1", "passes")], tmp_path), FakeAcquirer()
    )
    assert (nothing.manifest.acquisition.first, nothing.manifest.acquisition.last) == (None, None)


def test_evaluate_takes_the_trust_policy_version_from_the_operator_bundle(tmp_path: Path) -> None:
    bundle = TrustBundle(schema_version="dppce.trust/1", policy_version="operator-7")
    with_bundle = evaluate(mixed_inputs(tmp_path, trust=bundle), ReplayAcquirer(recorded()))
    assert with_bundle.manifest.trust_policy_version == "operator-7"


@pytest.mark.parametrize("mode", list(ExecutionMode))
def test_each_mode_states_its_own_limitation(tmp_path: Path, mode: ExecutionMode) -> None:
    inputs = inputs_for([one_path("R-1", "T-1")], [step("T-1", "passes")], tmp_path, mode=mode)
    decision = evaluate(inputs, FakeAcquirer())
    assert decision.manifest.mode is mode
    assert any(mode.value in limitation.lower() for limitation in decision.manifest.limitations)
    # The requirement is an illustrative draft: reviewed mode excludes it, the other modes run it.
    expected = Verdict.INCONCLUSIVE if mode is ExecutionMode.REVIEWED else Verdict.PASS
    assert decision.overall is expected


# --- evaluate(): the decision digest -------------------------------------------------------


def digest_of(inputs: RunInputs, records: Sequence[Record]) -> tuple[str, DecisionBody]:
    decision = evaluate(inputs, ReplayAcquirer(records))
    return decision_digest(decision), decision


def test_the_same_inputs_and_records_give_the_same_decision_digest(tmp_path: Path) -> None:
    records = recorded()
    first_digest, first = digest_of(mixed_inputs(tmp_path), records)
    second_digest, second = digest_of(mixed_inputs(tmp_path), records)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", first_digest)
    assert first_digest == second_digest
    assert first == second
    assert (first.results_root, first.records_root) == (second.results_root, second.records_root)
    live_digest = decision_digest(evaluate(mixed_inputs(tmp_path), FakeAcquirer(records)))
    assert live_digest == first_digest, "a live run and a replay of its records share one code path"


def test_a_change_in_an_input_or_in_a_record_changes_the_decision_digest(tmp_path: Path) -> None:
    records = recorded()
    reference, _ = digest_of(mixed_inputs(tmp_path), records)
    later = mixed_inputs(tmp_path, evaluation_time=AT + timedelta(seconds=1))
    other_ics = mixed_inputs(tmp_path, ics=b.ics(features={"export": True}))
    other_mode = mixed_inputs(tmp_path, mode=ExecutionMode.ILLUSTRATIVE)
    digests = {digest_of(inputs, records)[0] for inputs in (later, other_ics, other_mode)}
    assert len(digests) == 3
    assert reference not in digests
    other_body = [dataclasses.replace(records[0], body=b'{"changed":true}')]
    assert digest_of(mixed_inputs(tmp_path), other_body)[0] != reference
    other_salt = [dataclasses.replace(records[0], salt=bytes(32))]
    assert digest_of(mixed_inputs(tmp_path), other_salt)[0] != reference, "the commitment is salted"


# --- Severity is a label only (D1-11) ------------------------------------------------------


def test_no_verdict_function_reads_severity(tmp_path: Path) -> None:
    for function in (
        step_verdict,
        path_verdict,
        requirement_verdict,
        overall_verdict,
        claim_level,
        aggregate,
    ):
        assert "severity" not in inspect.signature(function).parameters, function.__name__
    inputs = mixed_inputs(tmp_path)
    plan = make_plan(inputs)
    results = execute(plan, inputs, ReplayAcquirer(recorded()))
    assert {r.execution_status for r in results.values()} >= {COMPLETED}, "some steps executed"
    requirements = {r.id: r for p in inputs.catalogue.packs.values() for r in p.requirements}
    reference = aggregate(plan, requirements, results)
    for severity in Severity:
        relabeled = {k: r.model_copy(update={"severity": severity}) for k, r in results.items()}
        assert aggregate(plan, requirements, relabeled) == reference, severity
