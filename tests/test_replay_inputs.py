"""The record of run inputs and the input check of a replay (gaps D1-06, D7-10).

Expected values come from docs/explanation/architecture.md, section 10.1. The runs use the
reviewed mode with a TEST-ONLY approved fixture in a temporary directory: no review took
place, and the run reads only a declared identifier. It sends no request.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Literal

import jsonschema
import pytest

from dppce import cli, schemas
from dppce.evidence.canonical import canonical_bytes, digest, parse_strict
from dppce.models import EvidenceEnvelope, RunInputsRecord
from tests.core import builders as b

ROOT = Path(__file__).resolve().parent.parent
ICS = ROOT / "fixtures" / "reference" / "ev.ics.yaml"
RID, TID = "TEST-ONLY-R-001", "TEST-ONLY-TP-001"
PACK, TESTPACK = "test-only/reviewed", "test-only/reviewed-tests"
CITED = {**b.CITED, "source_id": "dppce-illustrative"}
RULES = "profiles/battery/rules/illustrative-rules.yaml"
# A file that no profile binds. Only the parameter of a test purpose names it.
PARAM_FILE = "testpacks/data/TEST-ONLY-replay.schema.json"
IXIT = {
    "schema_version": "dppce.ixit/1",
    "endpoints": {"api": "https://id.example.test"},
    "samples": {"identifier": "https://id.example.test/01/09506000134352/21/EV0001"},
}
Imports = Literal["select", "load", "none"]


def write_pair(
    directory: Path, title: str | None = None, stimulus: dict[str, Any] | None = None
) -> tuple[Path, Path]:
    """Write the TEST-ONLY pack and test pack. ``title`` changes a model field of both."""
    changed = {"title": title} if title else {}
    requirement = b.requirement(
        RID,
        source=CITED,
        authority_class="guidance",
        review_status="approved",
        approval=b.TEST_ONLY_APPROVAL,
        assessment_paths=[b.path("default", TID)],
        **changed,
    )
    purpose = b.purpose(
        TID,
        requirements=[RID],
        permitted_modes=["reviewed"],
        stimulus=stimulus or {"check": "identifier.parse"},
        requires_scope="none",
        **changed,
    )
    pack, testpack = directory / "pack.yaml", directory / "testpack.yaml"
    directory.mkdir(parents=True, exist_ok=True)
    pack.write_text(b.pack(requirement, pack_id=PACK).model_dump_json(by_alias=True), encoding="utf-8")
    testpack.write_text(
        b.purposes_pack(purpose, testpack_id=TESTPACK).model_dump_json(by_alias=True), encoding="utf-8"
    )
    return pack, testpack


class Run:
    """One run on a copied data root ``tmp/root-a``. Nothing here contacts a host."""

    def __init__(
        self,
        tmp_path: Path,
        imports: Imports = "select",
        trust: Path | None = None,
        stimulus: dict[str, Any] | None = None,
    ) -> None:
        self.root = tmp_path / "root-a"
        for name in ("catalogue", "profiles", "testpacks"):
            shutil.copytree(ROOT / name, self.root / name)
        self.imports_dir = tmp_path / "imports"
        self.pack, self.testpack = write_pair(self.imports_dir, stimulus=stimulus)
        if stimulus is not None:
            (self.root / PARAM_FILE).write_text("{}\n", encoding="utf-8")
        ixit = tmp_path / "ixit.json"
        ixit.write_text(json.dumps(IXIT), encoding="utf-8")
        self.dir, self.keys = tmp_path / "run", tmp_path / "keys"
        arguments = [
            "run", "--mode", "reviewed", "--profile", "battery/ev", "--ics", str(ICS),
            "--ixit", str(ixit), "--at", "2026-10-13T12:00:00Z", "--data-root", str(self.root),
            "--out", str(self.dir), "--keys", str(self.keys), "--create-data-key",
        ]  # fmt: skip
        if imports != "none":
            arguments += ["--import-pack", str(self.pack), "--import-testpack", str(self.testpack)]
        if imports == "select":
            arguments += ["--pack", PACK, "--testpack", TESTPACK]
        if trust is not None:
            arguments += ["--trust", str(trust)]
        self.code = cli.main(arguments)
        self.envelope = EvidenceEnvelope.model_validate_json((self.dir / "envelope.json").read_bytes())

    def replay(self, *extra: str, run: Path | None = None) -> int:
        return cli.main(["replay", "--run", str(run or self.dir), "--keys", str(self.keys), *extra])


def _json(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(capsys.readouterr().out)
    return document


def test_run_writes_a_version_3_record_that_round_trips(tmp_path: Path) -> None:
    run = Run(tmp_path)
    raw = (run.dir / "inputs.json").read_bytes()
    record = RunInputsRecord.model_validate(parse_strict(raw))
    assert record.schema_version == "dppce.runinputs/3"
    assert canonical_bytes(record) + b"\n" == raw
    jsonschema.Draft202012Validator(schemas.load("runinputs")).validate(json.loads(raw))
    assert record.data_root == str(run.root.resolve())
    hashes, manifest = record.input_hashes, run.envelope.decision.manifest
    assert hashes is not None
    assert hashes.profile == manifest.profile_hash
    assert hashes.sources == manifest.sources_hash
    assert hashes.bound_files == manifest.bound_files
    assert RULES in hashes.bound_files
    assert {n: hashes.packs[n] for n in manifest.pack_hashes} == manifest.pack_hashes
    assert {n: hashes.testpacks[n] for n in manifest.testpack_hashes} == manifest.testpack_hashes
    assert PACK in hashes.packs
    assert TESTPACK in hashes.testpacks
    assert digest({"sources": hashes.sources, "packs": hashes.packs}) == manifest.catalogue_hash


def test_replay_after_moving_the_run_directory_uses_the_recorded_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path)
    moved = tmp_path / "elsewhere" / "run"
    moved.parent.mkdir()
    shutil.move(run.dir, moved)
    capsys.readouterr()
    code = run.replay("--json", run=moved)
    summary = _json(capsys)
    assert summary["match"] is True
    assert code == run.code
    assert summary["data_root"] == str(run.root.resolve())
    assert summary["input_check"] == "pass"


def test_a_moved_data_root_is_named_and_then_found_with_data_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path)
    root_b = tmp_path / "root-b"
    shutil.move(run.root, root_b)
    capsys.readouterr()
    assert run.replay() == 2
    error = capsys.readouterr().err
    assert "REPLAY.DATA_ROOT.MISSING" in error
    assert str(run.root.resolve()) in error
    assert "--data-root" in error
    code = run.replay("--json", "--data-root", str(root_b))
    summary = _json(capsys)
    assert (code, summary["match"], summary["input_check"]) == (run.code, True, "pass")
    assert summary["data_root"] == str(root_b)


def _change_bound_file(run: Run) -> str:
    with (run.root / RULES).open("ab") as handle:
        handle.write(b"# changed after the run\n")
    return f"bound file {RULES}"


def _change_test_pack(run: Run) -> str:
    write_pair(run.imports_dir, title="A changed method")
    return f"test pack {TESTPACK}"


def _change_unselected_pack(run: Run) -> str:
    write_pair(run.imports_dir, title="A changed requirement")
    return f"requirement pack {PACK}"


def _change_profile(run: Run) -> str:
    profile = run.root / "profiles" / "battery" / "ev.yaml"
    text = profile.read_text(encoding="utf-8")
    assert "product_category: ev\n" in text
    # The ICS declares 'ev', so check_ics would refuse this profile if the replay reached it.
    profile.write_text(text.replace("product_category: ev\n", "product_category: industrial\n"), "utf-8")
    return "profile"


@pytest.mark.parametrize(
    ("change", "imports"),
    [
        (_change_bound_file, "select"),
        (_change_test_pack, "select"),
        (_change_unselected_pack, "load"),
        (_change_profile, "select"),
    ],
)
def test_a_changed_input_stops_the_replay_before_it_evaluates(
    change: Any,
    imports: Imports,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run = Run(tmp_path, imports)
    label = change(run)

    def never(*_: object) -> None:
        raise AssertionError("the replay evaluated a changed input")

    monkeypatch.setattr(cli, "evaluate", never)
    capsys.readouterr()
    assert run.replay() == 2
    error = capsys.readouterr().err
    assert "REPLAY.INPUT.CHANGED" in error
    assert label in error
    assert "the ICS does not fit the profile" not in error


def test_a_changed_file_that_a_test_purpose_parameter_names_stops_the_replay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Section 9.2 (OD-07): each file that a test purpose names in a parameter is a bound file."""
    run = Run(tmp_path, stimulus={"check": "data.jsonschema", "params": {"schema": PARAM_FILE}})
    manifest = run.envelope.decision.manifest
    assert manifest.bound_files is not None
    assert manifest.bound_files[PARAM_FILE].startswith("sha256:")
    with (run.root / PARAM_FILE).open("ab") as handle:
        handle.write(b"\n")
    capsys.readouterr()
    assert run.replay() == 2
    error = capsys.readouterr().err
    assert "REPLAY.INPUT.CHANGED" in error
    assert f"bound file {PARAM_FILE}" in error


def _as_version_1(run: Run, *, rc1: bool) -> None:
    path = run.dir / "inputs.json"
    document = json.loads(path.read_bytes())
    del document["data_root"], document["input_hashes"]
    document["schema_version"] = "dppce.runinputs/1"
    if rc1:
        # 0.1.0rc1 wrote no test-pack and no manual-result fields. This run has none to write.
        for name in ("import_testpacks", "extra_testpacks", "manual_results"):
            assert document.pop(name) == []
    path.write_bytes(canonical_bytes(document) + b"\n")


@pytest.mark.parametrize("rc1", [False, True], ids=["main", "rc1"])
def test_a_version_1_record_from_main_and_from_rc1_still_replays(
    rc1: bool, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Synthetic layouts: the key sets of the writers at v0.1.0rc1 and at 6a3ea6c."""
    run = Run(tmp_path, "none")
    _as_version_1(run, rc1=rc1)
    capsys.readouterr()
    code = run.replay("--json", "--data-root", str(run.root))
    summary = _json(capsys)
    assert (code, summary["match"], summary["input_check"]) == (run.code, True, "not_run")
    assert run.replay("--data-root", str(run.root)) == run.code
    assert "REPLAY.INPUT.NOT_RECORDED" in capsys.readouterr().out


def test_a_version_2_record_with_a_version_1_trust_bundle_replays_to_the_same_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The step from dppce.runinputs/2 to version 3 changes only the embedded trust bundle."""
    run = Run(
        tmp_path, "none", trust=ROOT / "fixtures" / "reference" / "trust" / "TEST-ONLY-trust-bundle.json"
    )
    path = run.dir / "inputs.json"
    document = json.loads(path.read_bytes())
    trust = document["trust"]
    for name in ("revoked_certificates", "revoked_keys", "timestamp_anchors"):
        assert trust.pop(name) == []
    trust.update(schema_version="dppce.trust/1", revoked_serials=[], revoked_kids=[])
    document["schema_version"] = "dppce.runinputs/2"
    path.write_bytes(canonical_bytes(document) + b"\n")
    capsys.readouterr()
    code = run.replay("--json")
    summary = _json(capsys)
    assert (code, summary["match"], summary["input_check"]) == (run.code, True, "pass")
    assert run.envelope.decision.manifest.trust_policy_version == "TEST-ONLY-reference-1"


def test_a_migrated_record_still_detects_a_changed_bound_file_by_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Section 9.2: with no input hashes, only the decision digest comparison applies."""
    run = Run(tmp_path, "none")
    _as_version_1(run, rc1=False)
    _change_bound_file(run)
    capsys.readouterr()
    code = run.replay("--json", "--data-root", str(run.root))
    summary = _json(capsys)
    assert (code, summary["match"], summary["input_check"]) == (4, False, "not_run")


def _v1_with_data_root(raw: bytes) -> bytes:
    document = json.loads(raw)
    del document["input_hashes"]
    document["schema_version"] = "dppce.runinputs/1"
    return canonical_bytes(document) + b"\n"


def _v2_without_mode(raw: bytes) -> bytes:
    document = json.loads(raw)
    del document["mode"]
    return canonical_bytes(document) + b"\n"


@pytest.mark.parametrize(
    "damage",
    [lambda _: b"[1]", lambda _: b"{not json", _v1_with_data_root, _v2_without_mode],
    ids=["not-an-object", "malformed", "migration-refused", "validation-failed"],
)
def test_a_damaged_record_of_run_inputs_is_an_input_error(
    damage: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path, "none")
    path = run.dir / "inputs.json"
    path.write_bytes(damage(path.read_bytes()))
    capsys.readouterr()
    assert run.replay("--data-root", str(run.root)) == 2
    assert "is not a valid record of run inputs" in capsys.readouterr().err
