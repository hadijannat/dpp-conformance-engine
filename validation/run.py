"""Run the method validation and write a dated record to ``validation/records/``.

Usage: ``uv run python -m validation.run``

The run seeds each fault of ``validation/fault-catalogue.yaml`` into the local reference
system, for each profile of the fault (by default the battery profiles), and compares the
outcome with the outcome that the catalogue stated before the checks existed. It also runs the
valid controls of the battery and family profiles, the boundary cases, the evidence faults, and
five replays for each control.

Every figure in the record has a numerator and a denominator. The record describes this
software against a synthetic reference system. It is not evidence about a real DPP system,
and no person has reviewed or signed it: the engine never fills ``human_review_and_signature``.
"""

from __future__ import annotations

import copy
import json
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, Final

from dppce import __version__
from dppce.evidence.canonical import parse_strict
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.recording import read_recording
from dppce.infrastructure.keys import FileDataKeyProvider
from dppce.models import DecisionBody, EvidenceEnvelope, ExecutionStatus, TrustBundle, Verdict
from dppce.verifier import verify
from validation import cases
from validation.evidence_cases import SETUP, TAMPER, change_redirect_status
from validation.rig import LAB, REPORT_KEY, REPORT_KID, TRUST, ReferenceRig, RunResult

RECORDS = Path(__file__).resolve().parent / "records"
VERIFY_AT = datetime(2026, 10, 14, tzinfo=UTC)
AFTER_KEY_EXPIRY = datetime(2037, 1, 1, tzinfo=UTC)
REPLAYS = 5
# ponytail: the engine never fills these; a person signs the record outside the engine (D8-14).
HUMAN_REVIEW: Final[dict[str, Any]] = {
    "human_review_and_signature": None,
    "human_review_and_signature_note": (
        "The engine never fills this field. A person who reviews this record signs it outside "
        "the engine and keeps the signature in the records of the laboratory. "
        "The value null means that this file holds no such review or signature."
    ),
}


def _git() -> dict[str, Any]:
    def run(*arguments: str) -> str:
        done = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)  # noqa: S603, S607 - fixed arguments, local repository
        return done.stdout.strip()

    return {
        "commit": run("rev-parse", "HEAD") or None,
        "uncommitted_changes": bool(run("status", "--porcelain")),
    }


def _environment() -> dict[str, Any]:
    names = ("pydantic", "pyyaml", "jsonschema", "rfc8785", "cryptography", "joserfc", "zxing-cpp", "pillow")
    return {
        "engine_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": {name: metadata.version(name) for name in names},
        "git": _git(),
        "container_image": "not used",
    }


def _control_findings(decision: DecisionBody) -> dict[str, Any]:
    """The fields of a control row that judge the run of the unmodified reference system.

    A step that stops completing must not drop out of the metric: it counts against the control.
    A planned skip (PLAN.SKIPPED) is not a step of the run.
    """
    executed = [t for t in decision.test_results if t.execution_status is ExecutionStatus.COMPLETED]
    not_passed = [t.test_purpose_id for t in executed if t.verdict is not Verdict.PASS]
    not_completed = [
        t.test_purpose_id
        for t in decision.test_results
        if t.execution_status is not ExecutionStatus.COMPLETED and t.reason_code != "PLAN.SKIPPED"
    ]
    overall = decision.overall.value
    return {
        "overall": overall,
        "executed_steps": len(executed),
        "executed_steps_not_passed": not_passed,
        "steps_not_completed": not_completed,
        "as_expected": overall == Verdict.PASS.value and not not_passed and not not_completed,
    }


def _control(
    work: Path, ident: str, profile: str, setup: dict[str, Any]
) -> tuple[dict[str, Any], RunResult, ReferenceRig]:
    """Run one control on the unmodified reference system and replay it."""
    with ReferenceRig(work / ident / profile, profile, **setup) as rig:
        run = rig.run()
        code, replay = rig.replay(run, times=REPLAYS)
    row = {
        "id": ident,
        "profile": rig.profile,
        **_control_findings(run.envelope.decision),
        "replays": REPLAYS,
        "replay_digests_equal": bool(replay["match"]),
        "decision_digest": replay["expected_digest"],
        "replay_exit_code": code,
    }
    return row, run, rig


def _controls(work: Path) -> tuple[list[dict[str, Any]], EvidenceEnvelope | None, Path | None]:
    rows: list[dict[str, Any]] = []
    first: tuple[EvidenceEnvelope, Path] | None = None
    # A TEST-ONLY manual result, so that the signed control holds a completed manual step (E-13).
    baseline = {"manual": {"TP-MANUAL-001": "pass"}}
    plan = [("C-BASELINE", profile, baseline) for profile in cases.profiles()]
    plan += [(control.id, control.profile, control.rig) for control in cases.controls()]
    for ident, profile, setup in plan:
        row, run, rig = _control(work, ident, profile, setup)
        if first is None:
            first = (EvidenceEnvelope.model_validate_json(rig.sign(run).read_bytes()), run.run_dir)
        rows.append(row)
    return rows, first[0] if first else None, first[1] if first else None


def _sut_cases(work: Path, group: list[cases.Case], label: str, all_profiles: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in group:
        for profile in case.profiles if all_profiles else [case.profile or case.profiles[0]]:
            directory = work / f"{label}-{case.id}" / profile
            with ReferenceRig(directory, profile, faults=case.faults, **case.rig) as rig:
                run = rig.run(**({"at": case.at} if case.at else {}))
            if case.test_purpose is not None:
                if all(t.test_purpose_id != case.test_purpose for t in run.envelope.decision.test_results):
                    # A case that runs nothing would vanish from the figures, so it stops the run.
                    raise cases.CatalogueError(
                        f"{case.id}: the test purpose {case.test_purpose} is not planned under {profile}; "
                        f"the case names the profiles {', '.join(case.profiles)}"
                    )
                step = run.step(case.test_purpose)
                observed = {"verdict": step["verdict"], "reason_code": step["reason_code"]}
            else:
                assert case.requirement is not None
                observed = {"verdict": run.requirement(case.requirement)}
            rows.append(
                {
                    "id": case.id,
                    "profile": rig.profile,
                    "target": case.test_purpose or case.requirement,
                    "expected": case.expected,
                    "observed": observed,
                    "as_expected": observed == case.expected,
                }
            )
    return rows


def _evidence(signed: EvidenceEnvelope, trust: TrustBundle, run_dir: Path) -> list[dict[str, Any]]:
    document = json.loads(signed.model_dump_json(by_alias=True))
    rows: list[dict[str, Any]] = []
    for entry in cases.load()["evidence_faults"]:
        name, dimension = entry["tamper"], entry["dimension"]
        at, subject = VERIFY_AT, copy.deepcopy(document)
        bundle, status_list, opening = trust, None, None
        try:
            if name in SETUP:
                prepared = SETUP[name](signed, LocalSigner.from_pem(REPORT_KEY, REPORT_KID), trust, at)
                subject, bundle, status_list = prepared.document, prepared.trust, prepared.status_list
            elif name == "untrusted_key":
                stranger = LocalSigner.generate("TEST-ONLY-untrusted-report-key")
                unsigned = signed.model_copy(update={"signatures": ()})
                resigned = sign_envelope(unsigned, stranger, issuer=LAB, signed_at="2026-10-13T12:05:00Z")
                subject = json.loads(resigned.model_dump_json(by_alias=True))
            elif name == "expired_key":
                at = AFTER_KEY_EXPIRY
            elif name == "change_redirect_status":
                # The rig keeps the data key beside the run directory.
                keys = FileDataKeyProvider(run_dir.parent / "keys")
                opening = change_redirect_status(signed.decision, read_recording(run_dir / "recording", keys))
            else:
                TAMPER[name](subject)
        except LookupError as exc:
            rows.append(
                {
                    "id": entry["id"],
                    "tamper": name,
                    "dimension": dimension,
                    "state": "not_run",
                    "reason": str(exc),
                }
            )
            continue
        report = verify(subject, bundle, at, status_list=status_list, opening=opening)
        outcome = next(d.outcome for d in report.dimensions if d.name == dimension)
        rows.append(
            {
                "id": entry["id"],
                "tamper": name,
                "dimension": dimension,
                "state": "run",
                "observed_outcome": outcome,
                "verification_complete": report.complete,
                "as_expected": outcome == "fail" and not report.complete,
            }
        )
    return rows


def _ratio(numerator: int, denominator: int, of: str) -> dict[str, Any]:
    return {"numerator": numerator, "denominator": denominator, "of": of}


def main() -> int:
    started = datetime.now(UTC).replace(microsecond=0)
    trust = TrustBundle.model_validate(parse_strict(TRUST.read_bytes()))
    with tempfile.TemporaryDirectory(prefix="dppce-validation-") as tmp:
        work = Path(tmp)
        controls, signed, run_dir = _controls(work)
        faults = _sut_cases(work, cases.sut_faults(), "fault", all_profiles=True)
        boundary = _sut_cases(work, cases.boundary_cases(), "boundary", all_profiles=False)
        control_report = (
            verify(json.loads(signed.model_dump_json(by_alias=True)), trust, VERIFY_AT) if signed else None
        )
        evidence = _evidence(signed, trust, run_dir) if signed and run_dir else []

    control_steps = sum(c["executed_steps"] for c in controls)
    false_positives = sum(len(c["executed_steps_not_passed"]) for c in controls)
    evidence_run = [e for e in evidence if e["state"] == "run"]
    metrics = {
        "fault_detection": _ratio(
            sum(1 for f in faults if f["as_expected"]),
            len(faults),
            "seeded fault and profile combinations detected for the intended reason",
        ),
        "false_positives_on_controls": _ratio(
            false_positives, control_steps, "executed control steps that did not pass"
        ),
        "controls": _ratio(
            sum(1 for c in controls if c["as_expected"]),
            len(controls),
            "valid controls that passed with every planned step completed",
        ),
        "boundary_cases": _ratio(
            sum(1 for b in boundary if b["as_expected"]),
            len(boundary),
            "boundary cases with the expected outcome",
        ),
        "evidence_faults": _ratio(
            sum(1 for e in evidence_run if e["as_expected"]),
            len(evidence_run),
            "evidence faults that were run and failed on the named dimension",
        ),
        "evidence_faults_not_run": len(evidence) - len(evidence_run),
        "replays": _ratio(
            sum(1 for c in controls if c["replay_digests_equal"]) * REPLAYS,
            len(controls) * REPLAYS,
            "replays with the same decision digest",
        ),
        "control_verification_complete": bool(control_report and control_report.complete),
    }
    as_expected = (
        metrics["fault_detection"]["numerator"] == metrics["fault_detection"]["denominator"]
        and false_positives == 0
        and metrics["controls"]["numerator"] == metrics["controls"]["denominator"]
        and metrics["boundary_cases"]["numerator"] == metrics["boundary_cases"]["denominator"]
        and metrics["evidence_faults"]["numerator"] == metrics["evidence_faults"]["denominator"]
        and metrics["replays"]["numerator"] == metrics["replays"]["denominator"]
        and metrics["control_verification_complete"]
    )
    record = {
        "schema_version": "dppce.validationrecord/1",
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "The checks of the illustrative pack, the evidence envelope, and the verifier of this "
        "engine version, against the synthetic local reference system, for three battery profiles "
        "and the family profiles that the controls and the faults name.",
        "fixtures": "fixtures/reference (synthetic; generated by scripts/gen_fixtures.py) and "
        "validation/fault-catalogue.yaml",
        "fault_catalogue_version": cases.load()["version"],
        "environment": _environment(),
        "reviewer": None,
        "reviewer_note": "No person has reviewed this record. It is the output of an automated run.",
        **HUMAN_REVIEW,
        "limitations": [
            "The reference system is synthetic and was written by the same project as the engine.",
            "A detection here shows that a check finds a fault of a known kind. "
            "It does not show that the check finds every fault of that kind.",
            "The faults are seeded one at a time. Interactions between faults are not validated.",
            "QR images are clean synthetic images. Print quality and worn labels are not validated.",
            "No real DPP system, registry, or third-party service was contacted.",
            "This record supports method validation. It is not accreditation. "
            "It gives no technology readiness level.",
        ],
        "all_outcomes_as_expected": as_expected,
        "metrics": metrics,
        "controls": controls,
        "sut_faults": faults,
        "boundary_cases": boundary,
        "evidence_faults": evidence,
    }
    RECORDS.mkdir(exist_ok=True)
    path = RECORDS / f"method-validation-{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    for name, value in metrics.items():
        shown = (
            f"{value['numerator']} of {value['denominator']} {value['of']}"
            if isinstance(value, dict)
            else value
        )
        print(f"{name}: {shown}")
    print(f"all outcomes as expected: {as_expected}\nrecord: {path}")
    return 0 if as_expected else 1


if __name__ == "__main__":
    sys.exit(main())
