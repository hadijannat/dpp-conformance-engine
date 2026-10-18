"""Execute a plan and build the decision body.

One code path serves a live run and a replay. Only the ``Acquirer`` differs: the policy
transport for a live run, the replay acquirer for a recording. That is why a replay of the
same recording gives the same decision digest.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Final

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce import __version__
from dppce.adapters.capabilities import manifest as capability_manifest
from dppce.catalogue import Catalogue, sanitized_ixit
from dppce.catalogue.lint import params_problem
from dppce.evidence.canonical import digest
from dppce.evidence.envelope import build_decision
from dppce.evidence.manual import MANUAL_CHECK
from dppce.evidence.recording import record_commitments
from dppce.infrastructure.clock import utc_stamp
from dppce.infrastructure.interfaces import Acquirer
from dppce.models import (
    ICS,
    IXIT,
    AcquisitionWindow,
    AuthorityClass,
    Authorization,
    CapabilityState,
    CheckOutcome,
    DecisionBody,
    ExecutionMode,
    ExecutionStatus,
    InputHashes,
    IssuerStatement,
    Plan,
    Profile,
    Requirement,
    ReviewStatus,
    RunManifest,
    Severity,
    TestPack,
    TestPurpose,
    TestResult,
    TrustBundle,
    VerdictRules,
)
from dppce.orchestrator.plan import CheckInfo, PlanError, build_plan
from dppce.testdefs import registry
from dppce.verdicts import aggregate, overall_verdict, step_verdict
from dppce.verdicts.coverage import summarize

_PINNED: Final = ("pydantic", "pyyaml", "jsonschema", "rfc8785", "cryptography", "joserfc")
_OPTIONAL: Final = ("zxing-cpp", "pillow", "aas-test-engines")

_LIMITATIONS: Final = (
    "This document is a conformance test report. It is not a certificate.",
    "The report covers the selected catalogue only. It is not a statement of legal compliance.",
    "The report does not establish that declared product data are true or that a product is safe.",
    "Digital consistency does not prove physical authenticity.",
    "A valid signature does not prove that the signed attributes are true.",
)
_MODE_LIMITATIONS: Final = {
    ExecutionMode.ILLUSTRATIVE: "Illustrative mode: the rules are synthetic. No normative claim is made.",
    ExecutionMode.EXPLORATORY: "Exploratory mode: the run can use interpretations that no human approved. "
    "The results are diagnostic. They are not requirement-conformance claims.",
    ExecutionMode.REVIEWED: "Reviewed mode: claims cover only requirements with a documented human approval, "
    "inside the stated scope of each approved pack. Human review is not accreditation.",
}


@dataclass(frozen=True)
class RunInputs:
    """Everything that decides the outcome of an evaluation, apart from the acquired records."""

    mode: ExecutionMode
    profile: Profile
    catalogue: Catalogue
    testpacks: Mapping[str, TestPack]
    ics: ICS
    ixit: IXIT
    data_root: Path
    evaluation_time: datetime
    trust: TrustBundle | None = None
    authorization: Authorization | None = None
    issuer: IssuerStatement = field(default_factory=IssuerStatement)
    image_digest: str | None = None
    # Test purposes with a manual result that the operator supplied (--manual-result).
    manual_results: frozenset[str] = frozenset()


def check_infos() -> dict[str, CheckInfo]:
    """Map each registered check to the state and availability of its capability."""
    capabilities = {c.id: c for c in capability_manifest().capabilities}
    infos: dict[str, CheckInfo] = {}
    for name in registry.names():
        spec = registry.get(name)
        capability = capabilities.get(spec.capability) if spec else None
        infos[name] = CheckInfo(
            state=capability.state if capability else CapabilityState.UNSUPPORTED,
            available=bool(capability and capability.available),
        )
    return infos


def _params_problems(inputs: RunInputs) -> list[str]:
    """Each selected test purpose whose parameters do not fit its registered check (section 8)."""
    models = registry.param_models()
    problems: list[str] = []
    for name in inputs.profile.testpacks:
        if name not in inputs.testpacks:
            continue  # build_plan reports a missing test pack
        for purpose in sorted(inputs.testpacks[name].test_purposes, key=lambda p: p.id):
            check = purpose.stimulus.check
            if check in models and (problem := params_problem(models[check], purpose.stimulus.params)):
                problems.append(
                    f"test purpose {purpose.id}: the parameters do not fit the check '{check}': {problem}"
                )
    return problems


def make_plan(inputs: RunInputs) -> Plan:
    if problems := _params_problems(inputs):
        raise PlanError("; ".join(problems))
    granted = frozenset(inputs.authorization.scopes) if inputs.authorization else frozenset()
    return build_plan(
        mode=inputs.mode,
        profile=inputs.profile,
        packs=inputs.catalogue.packs,
        testpacks=inputs.testpacks,
        ics=inputs.ics,
        checks=check_infos(),
        granted_scopes=granted,
        manual_results=inputs.manual_results,
    )


def _purposes(inputs: RunInputs) -> dict[str, TestPurpose]:
    return {
        purpose.id: purpose
        for name in inputs.profile.testpacks
        for purpose in inputs.testpacks[name].test_purposes
    }


def _requirements(inputs: RunInputs) -> dict[str, Requirement]:
    return {r.id: r for name in inputs.profile.packs for r in inputs.catalogue.packs[name].requirements}


def _approved_method(
    mode: ExecutionMode, purpose: TestPurpose | None, requirements: dict[str, Requirement]
) -> bool:
    """A test method counts as approved in reviewed mode, when every requirement that it names is
    approved and normative. A purpose that also names a draft is not, even if it runs for an
    approved requirement whose path lists it."""
    if mode is not ExecutionMode.REVIEWED or purpose is None or not purpose.requirements:
        return False
    named = [requirements.get(r) for r in purpose.requirements]
    return all(
        r is not None
        and r.review_status is ReviewStatus.APPROVED
        and r.authority_class is not AuthorityClass.ILLUSTRATIVE
        for r in named
    )


def execute(plan: Plan, inputs: RunInputs, acquirer: Acquirer) -> dict[str, TestResult]:
    """Run each planned step in identifier order and return one result per step."""
    purposes = _purposes(inputs)
    requirements = _requirements(inputs)
    results: dict[str, TestResult] = {}
    for step in plan.steps:
        purpose = purposes.get(step.test_purpose_id)
        spec = registry.get(step.check)
        if step.planned_status is not None or purpose is None or spec is None:
            status = step.planned_status or ExecutionStatus.NOT_RUN
            outcome = CheckOutcome(
                status=status,
                reason_code=f"PLAN.{status.value.upper()}",
                message=step.planned_reason or "The step has no executable check.",
            )
        else:
            before = len(acquirer.records())
            context = registry.CheckContext(
                purpose=purpose,
                ics=inputs.ics,
                ixit=inputs.ixit,
                profile=inputs.profile,
                acquirer=acquirer,
                evaluation_time=inputs.evaluation_time,
                data_root=inputs.data_root,
                trust=inputs.trust,
                authorization=inputs.authorization,
            )
            try:
                outcome = spec.fn(context)
            except Exception as exc:
                # A defect in a check is an execution error. It is never a fail of the system.
                # The exception text can quote payload data, so only its type is reported.
                outcome = CheckOutcome(
                    status=ExecutionStatus.ERROR,
                    reason_code="ENGINE.CHECK_EXCEPTION",
                    message=f"The check raised {type(exc).__name__}.",
                )
            if any(r.error == "recording_mismatch" for r in acquirer.records()[before:]):
                outcome = CheckOutcome(
                    status=ExecutionStatus.ERROR,
                    reason_code="REPLAY.RECORDING_MISMATCH",
                    message="The replayed request differs from the recorded one. The inputs changed.",
                )
        rules = purpose.verdict_rules if purpose else VerdictRules()
        if rules.on_unreachable == "fail" and not _approved_method(plan.mode, purpose, requirements):
            # A connectivity failure does not prove a breach. Only an approved test method may
            # say that it does (section 9).
            rules = rules.model_copy(update={"on_unreachable": "inconclusive"})
        results[step.test_purpose_id] = TestResult(
            test_purpose_id=step.test_purpose_id,
            requirement_ids=purpose.requirements if purpose else (),
            check=step.check,
            applicability=step.applicability,
            applicability_reason=step.applicability_reason,
            execution_status=outcome.status,
            verdict=step_verdict(outcome.status, outcome.passed, outcome.unreachable, rules),
            severity=purpose.severity if purpose else Severity.MAJOR,
            reason_code=outcome.reason_code,
            message=outcome.message,
            observations=outcome.observations,
        )
    return results


def _dependency_versions() -> dict[str, str]:
    versions = {name: metadata.version(name) for name in _PINNED}
    for name in _OPTIONAL:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return dict(sorted(versions.items()))


def bound_files(profile: Profile, data_root: Path) -> dict[str, str]:
    """sha256 of the raw bytes of each file that the profile binds, keyed by its path."""
    named = (profile.api_contract, profile.access_policy, profile.item_schema, profile.model_schema)
    bound: dict[str, str] = {}
    for path in sorted({p for p in (*named, *profile.rule_packs) if p}):
        try:
            bound[path] = "sha256:" + hashlib.sha256((data_root / path).read_bytes()).hexdigest()
        except OSError:
            # The check that needs the file is blocked anyway. The manifest says so honestly.
            bound[path] = "unavailable"
    return bound


def input_hashes(
    profile: Profile, catalogue: Catalogue, testpacks: Mapping[str, TestPack], bound: Mapping[str, str]
) -> InputHashes:
    """The digests that the manifest, inputs.json, and the replay input check share (section 10.1)."""
    return InputHashes(
        profile=digest(profile),
        sources=catalogue.sources_hash(),
        packs=catalogue.pack_hashes(),
        testpacks={name: digest(pack) for name, pack in sorted(testpacks.items())},
        bound_files=dict(bound),
    )


def _manifest(inputs: RunInputs, acquirer: Acquirer) -> RunManifest:
    acquired = sorted(r.acquired_at for r in acquirer.records())
    hashes = input_hashes(
        inputs.profile, inputs.catalogue, inputs.testpacks, bound_files(inputs.profile, inputs.data_root)
    )
    return RunManifest(
        engine_version=__version__,
        dependency_versions=_dependency_versions(),
        image_digest=inputs.image_digest,
        mode=inputs.mode,
        profile_id=inputs.profile.id,
        profile_hash=hashes.profile,
        catalogue_hash=inputs.catalogue.hash(),
        # The selected subsets. The planner refuses a selected pack or test pack that is not loaded.
        pack_hashes={name: hashes.packs[name] for name in sorted(inputs.profile.packs)},
        testpack_hashes={name: hashes.testpacks[name] for name in sorted(inputs.profile.testpacks)},
        sources_hash=hashes.sources,
        ics_hash=digest(inputs.ics),
        ixit_sanitized_hash=digest(sanitized_ixit(inputs.ixit)),
        authorization_ref=inputs.ixit.authorization_ref,
        sut=inputs.ics.sut,
        evaluation_time=utc_stamp(inputs.evaluation_time),
        acquisition=AcquisitionWindow(
            first=acquired[0] if acquired else None, last=acquired[-1] if acquired else None
        ),
        # The evaluation uses no randomness. Salts are drawn at acquisition and live in the recording.
        seeds={},
        trust_policy_version=inputs.trust.policy_version
        if inputs.trust
        else inputs.ixit.trust.policy_version,
        issuer=inputs.issuer,
        limitations=(*_LIMITATIONS, _MODE_LIMITATIONS[inputs.mode]),
        bound_files=hashes.bound_files,
    )


def evaluate(inputs: RunInputs, acquirer: Acquirer) -> DecisionBody:
    """Plan, execute, aggregate, and assemble the canonical decision body."""
    plan = make_plan(inputs)
    test_results = execute(plan, inputs, acquirer)
    requirements = _requirements(inputs)
    requirement_results = aggregate(plan, requirements, test_results)
    infos = check_infos()
    executable = frozenset(
        purpose.id
        for purpose in _purposes(inputs).values()
        # A manual review is never executable by a capability, also with a supplied result.
        if not purpose.manual
        and purpose.stimulus.check != MANUAL_CHECK
        and (info := infos.get(purpose.stimulus.check)) is not None
        and info.available
        and info.state in (CapabilityState.SUPPORTED, CapabilityState.EXPERIMENTAL)
    )
    selected = [inputs.catalogue.packs[name] for name in inputs.profile.packs]
    scope = " ".join(f"[{p.pack_id} {p.version}] {p.scope_statement}" for p in selected)
    coverage = summarize(
        scope_statement=scope,
        requirements=list(requirements.values()),
        plan=plan,
        results=requirement_results,
        test_results=test_results,
        executable_tests=executable,
    )
    overall, reason = overall_verdict(requirement_results)
    return build_decision(
        manifest=_manifest(inputs, acquirer),
        overall=overall,
        overall_reason=reason,
        requirement_results=requirement_results,
        test_results=list(test_results.values()),
        exclusions=plan.exclusions,
        conflicts=plan.conflicts,
        coverage=coverage,
        record_commitments=record_commitments(acquirer.records()),
    )
