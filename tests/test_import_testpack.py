"""Import a test pack from the command line, so a reviewed run needs no copied data root.

The approved requirement is a TEST-ONLY fixture in a temporary directory. No review took place.
The run reads only a declared identifier. It sends no request.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dppce import cli
from dppce.infrastructure.resources import data_root
from tests.core import builders as b

FIXTURES = Path("fixtures/reference")
RID, TID = "TEST-ONLY-R-001", "TEST-ONLY-TP-001"
PACK, TESTPACK = "test-only/reviewed", "test-only/reviewed-tests"
# A synthetic project source: a normative class on it is not a legal obligation (CAT009).
CITED = {**b.CITED, "source_id": "dppce-illustrative"}
IXIT = {
    "schema_version": "dppce.ixit/1",
    "endpoints": {"api": "https://id.example.test"},
    "samples": {"identifier": "https://id.example.test/01/09506000134352/21/EV0001"},
}


def _fixture_pair(tmp_path: Path, purpose_id: str = TID) -> tuple[Path, Path]:
    requirement = b.requirement(
        RID,
        source=CITED,
        authority_class="guidance",
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
        assessment_paths=[b.path("default", purpose_id)],
    )
    purpose = b.purpose(
        purpose_id,
        requirements=[RID],
        permitted_modes=["reviewed"],
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


def _imports(pack: Path, testpack: Path) -> list[str]:
    return ["--import-pack", str(pack), "--import-testpack", str(testpack)]


def _plan_arguments(tmp_path: Path, pack: Path, testpack: Path) -> list[str]:
    ixit = tmp_path / "ixit.json"
    ixit.write_text(json.dumps(IXIT), encoding="utf-8")
    return [
        "--mode", "reviewed", "--profile", "battery/ev",
        "--ics", str(FIXTURES / "ev.ics.yaml"), "--ixit", str(ixit), "--at", "2026-10-13T12:00:00Z",
        *_imports(pack, testpack), "--pack", PACK, "--testpack", TESTPACK,
    ]  # fmt: skip


def _snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        str(p.relative_to(root)): p.read_bytes() if p.is_file() else None
        for name in ("catalogue", "profiles", "testpacks")
        for p in sorted((root / name).rglob("*"))
    }


def test_the_lint_accepts_an_imported_pack_and_test_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(["catalogue", "lint", "--json", *_imports(*_fixture_pair(tmp_path))])
    findings = json.loads(capsys.readouterr().out)
    # Without the test pack, the path of the requirement names an undefined test purpose (CAT003).
    assert [f for f in findings if f["severity"] == "error"] == []
    assert not [f for f in findings if f["location"].startswith((PACK, TESTPACK, TID))]
    assert code == 0


def test_a_reviewed_plan_selects_the_imported_test_pack_without_a_copied_data_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(["plan", "--json", *_plan_arguments(tmp_path, *_fixture_pair(tmp_path))])
    plan = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [r["requirement_id"] for r in plan["requirements"]] == [RID]
    step = next(s for s in plan["steps"] if s["test_purpose_id"] == TID)
    assert (step["check"], step["planned_status"]) == ("identifier.parse", None), "the step executes"


def test_a_purpose_id_that_a_shipped_test_pack_defines_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, testpack = _fixture_pair(tmp_path, purpose_id="TP-CARRIER-001")
    code = cli.main(["catalogue", "lint", "--json", *_imports(pack, testpack)])
    findings = json.loads(capsys.readouterr().out)
    assert [f["code"] for f in findings if f["location"] == f"{TESTPACK}/TP-CARRIER-001"] == ["CAT016"]
    assert code == 2
    run_command = [
        "run",
        "--out",
        str(tmp_path / "run"),
        "--keys",
        str(tmp_path / "keys"),
        "--create-data-key",
    ]
    for command in (["plan"], run_command):
        assert cli.main([*command, *_plan_arguments(tmp_path, pack, testpack)]) == 2
        assert "TP-CARRIER-001 is defined more than once" in capsys.readouterr().err
    assert not (tmp_path / "run").exists()


def test_a_run_records_the_imported_test_pack_and_replay_rebuilds_the_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(data_root())
    pack, testpack = _fixture_pair(tmp_path)
    run, keys = tmp_path / "run", tmp_path / "keys"
    code = cli.main(
        [
            "run",
            *_plan_arguments(tmp_path, pack, testpack),
            "--out",
            str(run),
            "--keys",
            str(keys),
            "--create-data-key",
        ]
    )
    capsys.readouterr()
    envelope = json.loads((run / "envelope.json").read_text(encoding="utf-8"))
    assert TESTPACK in envelope["decision"]["manifest"]["testpack_hashes"]
    stored = json.loads((run / "inputs.json").read_text(encoding="utf-8"))
    assert (stored["import_testpacks"], stored["extra_testpacks"]) == ([str(testpack.resolve())], [TESTPACK])

    replayed = cli.main(["replay", "--json", "--run", str(run), "--keys", str(keys)])
    summary = json.loads(capsys.readouterr().out)
    assert summary["match"] is True
    assert replayed == code
    assert _snapshot(data_root()) == before, "the engine writes nothing under the data root"
