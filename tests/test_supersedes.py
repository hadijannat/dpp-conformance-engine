"""A selected approved entry excludes the shipped draft that it supersedes (section 6, step 1).

The approved entry is a TEST-ONLY fixture in a temporary directory. No review took place.
The shipped draft pack is not changed. The run reads only a declared identifier. It sends no request.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from dppce import cli
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.resources import data_root
from dppce.models import EvidenceEnvelope, TrustBundle
from dppce.verifier import verify
from tests.core import builders as b
from tests.support import AT, ISSUER
from tests.test_import_testpack import CITED, FIXTURES, IXIT, _snapshot

DRAFT, RID, TID = "EUBAT-13-6", "TEST-ONLY-R-SUCC", "TEST-ONLY-TP-SUCC"
PACK, TESTPACK = "test-only/successor", "test-only/successor-tests"
CODE = "STATUS.SUPERSEDED_BY_SELECTED"
SHIPPED = Path("catalogue/packs/eu-battery-draft.yaml")


def _fixture_pair(tmp_path: Path, *, approved: bool = True) -> tuple[Path, Path]:
    status: dict[str, Any] = (
        {"review_status": "approved", "approval": b.TEST_ONLY_APPROVAL} if approved else {}
    )
    requirement = b.requirement(
        RID,
        source=CITED,
        authority_class="guidance",
        supersedes=[DRAFT],
        assessment_paths=[b.path("default", TID)],
        **status,
    )
    purpose = b.purpose(
        TID,
        requirements=[RID],
        permitted_modes=["exploratory", "reviewed"],
        stimulus={"check": "identifier.parse"},
        requires_scope="none",
    )
    pack, testpack = tmp_path / "imports" / "pack.yaml", tmp_path / "imports" / "testpack.yaml"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text(b.pack(requirement, pack_id=PACK).model_dump_json(by_alias=True), encoding="utf-8")
    testpack.write_text(
        b.purposes_pack(purpose, testpack_id=TESTPACK).model_dump_json(by_alias=True), encoding="utf-8"
    )
    return pack, testpack


def _arguments(tmp_path: Path, mode: str, *, approved: bool = True, select: bool = True) -> list[str]:
    pack, testpack = _fixture_pair(tmp_path, approved=approved)
    ixit = tmp_path / "ixit.json"
    ixit.write_text(json.dumps(IXIT), encoding="utf-8")
    selected = ["--pack", PACK, "--testpack", TESTPACK] if select else []
    return [
        "--mode", mode, "--profile", "battery/ev",
        "--ics", str(FIXTURES / "ev.ics.yaml"), "--ixit", str(ixit), "--at", "2026-10-13T12:00:00Z",
        "--import-pack", str(pack), "--import-testpack", str(testpack), *selected,
    ]  # fmt: skip


def _plan(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    code = cli.main(["plan", "--json", *arguments])
    plan: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert code == 0
    return plan


def _exclusion(plan: dict[str, Any], ident: str) -> dict[str, Any] | None:
    found = [e for e in plan["exclusions"] if (e["kind"], e["id"]) == ("requirement", ident)]
    return found[0] if found else None


@pytest.mark.parametrize("mode", ["exploratory", "reviewed"])
def test_a_selected_approved_successor_excludes_the_shipped_draft(
    mode: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = _plan(_arguments(tmp_path, mode), capsys)
    exclusion = _exclusion(plan, DRAFT)
    assert exclusion is not None
    assert exclusion["reason_code"] == CODE
    assert RID in exclusion["reason"]
    assessed = [r["requirement_id"] for r in plan["requirements"]]
    assert DRAFT not in assessed
    assert RID in assessed
    step = next(s for s in plan["steps"] if s["test_purpose_id"] == TID)
    assert step["planned_status"] is None, "the step of the successor executes"
    if mode == "reviewed":
        assert assessed == [RID]


@pytest.mark.parametrize(("approved", "select"), [(True, False), (False, True)])
def test_without_pack_or_without_approval_the_draft_is_planned_as_before(
    approved: bool, select: bool, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exploratory = _plan(_arguments(tmp_path, "exploratory", approved=approved, select=select), capsys)
    assert DRAFT in [r["requirement_id"] for r in exploratory["requirements"]]
    assert all(e["reason_code"] != CODE for e in exploratory["exclusions"])
    if not select:
        reviewed = _plan(_arguments(tmp_path, "reviewed", approved=approved, select=select), capsys)
        exclusion = _exclusion(reviewed, DRAFT)
        assert exclusion is not None
        assert exclusion["reason_code"] == "MODE.NOT_APPROVED"


def test_a_reviewed_run_counts_the_draft_and_leaves_the_shipped_pack_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], signer: LocalSigner, trust: TrustBundle
) -> None:
    # Reviewed mode only: an exploratory run would execute EU steps against the IXIT host (rule 3).
    shipped = data_root() / SHIPPED
    digest, before = hashlib.sha256(shipped.read_bytes()).hexdigest(), _snapshot(data_root())
    run, keys = tmp_path / "run", tmp_path / "keys"
    code = cli.main(
        [
            "run",
            *_arguments(tmp_path, "reviewed"),
            "--out",
            str(run),
            "--keys",
            str(keys),
            "--create-data-key",
        ]
    )
    capsys.readouterr()
    envelope = json.loads((run / "envelope.json").read_text(encoding="utf-8"))
    decision = envelope["decision"]
    excluded = [e for e in decision["exclusions"] if e["kind"] == "requirement"]
    assert decision["coverage"]["excluded"] == len(excluded)
    assert {"id": DRAFT, "reason_code": CODE} in [{k: e[k] for k in ("id", "reason_code")} for e in excluded]

    replayed = cli.main(["replay", "--json", "--run", str(run), "--keys", str(keys)])
    assert json.loads(capsys.readouterr().out)["match"] is True
    assert replayed == code
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == digest, "the planner never writes a pack"
    assert _snapshot(data_root()) == before

    signed = sign_envelope(
        EvidenceEnvelope.model_validate(envelope), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z"
    )
    report = verify(json.loads(signed.model_dump_json(by_alias=True)), trust, AT)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    assert (outcomes["structure"], outcomes["ordering"], outcomes["counts"]) == ("pass", "pass", "pass")
