"""End to end against the local reference system: plan, run, record, replay, report, sign, verify.

Expected outcomes come from validation/fault-catalogue.yaml, which was written before the
checks existed. A seeded fault counts as detected only if the named test purpose gives the
expected verdict with the expected reason code. A negative fixture that fails as expected is a
passing software test.

The fast suite runs every case on one profile. `just validate` runs the full matrix.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from validation import cases
from validation.rig import ReferenceRig

from dppce.models import ExecutionStatus, Modality, Tri, Verdict

pytestmark = pytest.mark.qr  # the reference rig reads QR images


def test_control_the_unmodified_reference_system_passes(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        run = rig.run()
    executed = [
        t for t in run.envelope.decision.test_results if t.execution_status is ExecutionStatus.COMPLETED
    ]
    assert len(executed) >= 13, "every check of the contract ran"
    assert [(t.test_purpose_id, t.verdict.value) for t in executed if t.verdict is not Verdict.PASS] == []
    assert run.envelope.decision.overall is Verdict.PASS
    assert run.exit_code == 0
    assert (run.run_dir / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")


@pytest.mark.parametrize("case", cases.sut_faults(), ids=lambda c: c.id)
def test_each_seeded_fault_is_detected_for_the_intended_reason(case: cases.Case, tmp_path: Path) -> None:
    assert case.test_purpose is not None
    with ReferenceRig(tmp_path, case.profile or "ev", faults=case.faults, **case.rig) as rig:
        run = rig.run(**({"at": case.at} if case.at else {}))
    step = run.step(case.test_purpose)
    assert (step["verdict"], step["reason_code"]) == (case.expected["verdict"], case.expected["reason_code"])
    hit = [
        r
        for r in run.envelope.decision.requirement_results
        if any(case.test_purpose in p.steps for p in r.paths)
    ]
    applicable = [r for r in hit if r.applicability is Tri.TRUE]
    assert applicable, "the fault hits at least one applicable requirement"
    assert all(r.verdict is Verdict.FAIL for r in applicable)
    # The overall outcome uses mandatory requirements only (architecture contract, section 7.4).
    mandatory = any(r.modality is Modality.MANDATORY for r in applicable)
    assert run.envelope.decision.overall is (Verdict.FAIL if mandatory else Verdict.PASS)
    assert run.exit_code == (1 if mandatory else 0), "exit code 1 means that the system under test failed"


@pytest.mark.parametrize("case", cases.boundary_cases(), ids=lambda c: c.id)
def test_boundary_cases_are_not_reported_as_something_they_are_not(case: cases.Case, tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, case.profile or "ev", faults=case.faults, **case.rig) as rig:
        run = rig.run(**({"at": case.at} if case.at else {}))
    if case.test_purpose is not None:
        step = run.step(case.test_purpose)
        assert (step["verdict"], step["reason_code"]) == (
            case.expected["verdict"],
            case.expected["reason_code"],
        )
    else:
        assert case.requirement is not None
        assert run.requirement(case.requirement) == case.expected["verdict"]


def test_an_unreachable_system_is_inconclusive_and_never_a_failure(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, serve=False) as rig:
        run = rig.run()
    assert run.envelope.decision.verdict_counts["fail"] == 0, "a connectivity failure does not prove a breach"
    assert run.envelope.decision.overall is Verdict.INCONCLUSIVE
    assert run.exit_code == 5


def test_replay_reproduces_the_verdicts_and_the_decision_digest(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        run = rig.run()
    code, summary = rig.replay(run, times=5)  # the server is stopped: replay needs no system under test
    assert summary["match"] is True
    assert summary["replay_digests"] == [summary["expected_digest"]] * 5
    assert code == 0


def test_two_live_runs_differ_only_where_they_must(tmp_path: Path) -> None:
    """Fresh salts make the commitments differ. The verdicts do not."""
    with ReferenceRig(tmp_path) as rig:
        first, second = rig.run(), rig.run()
    a, b = first.envelope.decision, second.envelope.decision
    assert [r.verdict for r in a.requirement_results] == [r.verdict for r in b.requirement_results]
    assert a.records_root != b.records_root, "randomness is never weakened to make a live run repeat"


def test_sign_then_verify_and_then_detect_a_change(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        run = rig.run()
        envelope = rig.sign(run)
        code, report = rig.verify(envelope)
        assert (code, report["complete"]) == (0, True)
        envelope.write_text(
            envelope.read_text(encoding="utf-8").replace('"overall":"pass"', '"overall":"fail"')
        )
        code, report = rig.verify(envelope)
    assert (code, report["complete"]) == (4, False), "exit code 4 means that verification failed"


def test_the_recording_holds_no_clear_text_of_what_was_observed(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path) as rig:
        run = rig.run()
    stored = b"".join(p.read_bytes() for p in (run.run_dir / "recording").rglob("*") if p.is_file())
    for secret in (b"CANARY-7f3a-supplier", b"Example Battery Works", b"127.0.0.1", b"/dpp/"):
        assert secret not in stored
    envelope = (run.run_dir / "envelope.json").read_bytes()
    assert b"CANARY-7f3a-supplier" not in envelope, "a report carries commitments, not restricted payloads"


@pytest.mark.validation
@pytest.mark.parametrize("profile", cases.profiles())
def test_validation_each_profile_passes_and_replays_five_times(profile: str, tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, profile) as rig:
        run = rig.run()
    assert run.envelope.decision.overall is Verdict.PASS
    code, summary = rig.replay(run, times=5)
    assert (code, summary["match"]) == (0, True)


@pytest.mark.validation
@pytest.mark.parametrize("profile", cases.profiles())
@pytest.mark.parametrize("case", cases.sut_faults(), ids=lambda c: c.id)
def test_validation_each_fault_on_each_profile(case: cases.Case, profile: str, tmp_path: Path) -> None:
    assert case.test_purpose is not None
    with ReferenceRig(tmp_path, profile, faults=case.faults, **case.rig) as rig:
        step = rig.run().step(case.test_purpose)
    assert (step["verdict"], step["reason_code"]) == (case.expected["verdict"], case.expected["reason_code"])
