"""Run the method validation and write a dated record to ``validation/records/``.

Usage: ``uv run python -m validation.run``

The run seeds each fault of ``validation/fault-catalogue.yaml`` into the local reference
system, for each battery profile, and compares the outcome with the outcome that the
catalogue stated before the checks existed. It also runs the valid controls, the boundary
cases, the evidence faults, and five replays for each profile.

Every figure in the record has a numerator and a denominator. The record describes this
software against a synthetic reference system. It is not evidence about a real DPP system,
and no person has reviewed it unless the ``reviewer`` field says so.
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
from typing import Any

from dppce import __version__
from dppce.evidence.canonical import parse_strict
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import EvidenceEnvelope, ExecutionStatus, TrustBundle, Verdict
from dppce.verifier import verify
from validation import cases
from validation.evidence_cases import TAMPER
from validation.rig import LAB, TRUST, ReferenceRig

RECORDS = Path(__file__).resolve().parent / "records"
VERIFY_AT = datetime(2026, 10, 14, tzinfo=UTC)
AFTER_KEY_EXPIRY = datetime(2037, 1, 1, tzinfo=UTC)
REPLAYS = 5


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


def _controls(work: Path) -> tuple[list[dict[str, Any]], EvidenceEnvelope | None, Path | None]:
    rows: list[dict[str, Any]] = []
    first: tuple[EvidenceEnvelope, Path] | None = None
    for profile in cases.profiles():
        with ReferenceRig(work / f"control-{profile}", profile) as rig:
            run = rig.run()
            executed = [
                t
                for t in run.envelope.decision.test_results
                if t.execution_status is ExecutionStatus.COMPLETED
            ]
            not_passed = [t.test_purpose_id for t in executed if t.verdict is not Verdict.PASS]
            code, replay = rig.replay(run, times=REPLAYS)
            if first is None:
                first = (EvidenceEnvelope.model_validate_json(rig.sign(run).read_bytes()), run.run_dir)
        rows.append(
            {
                "profile": f"battery/{profile}",
                "overall": run.envelope.decision.overall.value,
                "executed_steps": len(executed),
                "executed_steps_not_passed": not_passed,
                "replays": REPLAYS,
                "replay_digests_equal": bool(replay["match"]),
                "decision_digest": replay["expected_digest"],
                "replay_exit_code": code,
            }
        )
    return rows, first[0] if first else None, first[1] if first else None


def _sut_cases(work: Path, group: list[cases.Case], label: str, all_profiles: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in group:
        for profile in cases.profiles() if all_profiles else [case.profile or "ev"]:
            directory = work / f"{label}-{case.id}-{profile}"
            with ReferenceRig(directory, case.profile or profile, faults=case.faults, **case.rig) as rig:
                run = rig.run(**({"at": case.at} if case.at else {}))
            if case.test_purpose is not None:
                step = run.step(case.test_purpose)
                observed = {"verdict": step["verdict"], "reason_code": step["reason_code"]}
            else:
                assert case.requirement is not None
                observed = {"verdict": run.requirement(case.requirement)}
            rows.append(
                {
                    "id": case.id,
                    "profile": f"battery/{case.profile or profile}",
                    "target": case.test_purpose or case.requirement,
                    "expected": case.expected,
                    "observed": observed,
                    "as_expected": observed == case.expected,
                }
            )
    return rows


def _evidence(signed: EvidenceEnvelope, trust: TrustBundle) -> list[dict[str, Any]]:
    document = json.loads(signed.model_dump_json(by_alias=True))
    rows: list[dict[str, Any]] = []
    for entry in cases.load()["evidence_faults"]:
        name, dimension = entry["tamper"], entry["dimension"]
        at, subject = VERIFY_AT, copy.deepcopy(document)
        try:
            if name == "untrusted_key":
                stranger = LocalSigner.generate("TEST-ONLY-untrusted-report-key")
                unsigned = signed.model_copy(update={"signatures": ()})
                resigned = sign_envelope(unsigned, stranger, issuer=LAB, signed_at="2026-10-13T12:05:00Z")
                subject = json.loads(resigned.model_dump_json(by_alias=True))
            elif name == "expired_key":
                at = AFTER_KEY_EXPIRY
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
        report = verify(subject, trust, at)
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
        controls, signed, _ = _controls(work)
        faults = _sut_cases(work, cases.sut_faults(), "fault", all_profiles=True)
        boundary = _sut_cases(work, cases.boundary_cases(), "boundary", all_profiles=False)
        control_report = (
            verify(json.loads(signed.model_dump_json(by_alias=True)), trust, VERIFY_AT) if signed else None
        )
        evidence = _evidence(signed, trust) if signed else []

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
        and metrics["boundary_cases"]["numerator"] == metrics["boundary_cases"]["denominator"]
        and metrics["evidence_faults"]["numerator"] == metrics["evidence_faults"]["denominator"]
        and metrics["replays"]["numerator"] == metrics["replays"]["denominator"]
        and metrics["control_verification_complete"]
    )
    record = {
        "schema_version": "dppce.validationrecord/1",
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "The checks of the illustrative pack, the evidence envelope, and the verifier of this "
        "engine version, against the synthetic local reference system, for three battery profiles.",
        "fixtures": "fixtures/reference (synthetic; generated by scripts/gen_fixtures.py) and "
        "validation/fault-catalogue.yaml",
        "fault_catalogue_version": cases.load()["version"],
        "environment": _environment(),
        "reviewer": None,
        "reviewer_note": "No person has reviewed this record. It is the output of an automated run.",
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
