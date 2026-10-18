"""Record openings and inclusion proofs (gap D6-08; architecture sections 10.2, 11.2, and 11.4).

An opening discloses the salt and the plaintext of one record. A proof discloses one result.
The verifier checks each against the envelope, never against a root that the file states.
Every key is TEST-ONLY. Live runs use the reference rig on loopback only.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import secrets
import shutil
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from validation.rig import TRUST, ReferenceRig, RunResult

from dppce import cli
from dppce.evidence import disclosure, merkle
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.envelope import records_root, result_keys, results_root
from dppce.evidence.recording import commit, commitment_of, read_recording, record_commitments, record_to_json
from dppce.infrastructure.keys import FileDataKeyProvider
from dppce.models import EvidenceEnvelope, InclusionProof, OpenedRecord, RecordOpening, TrustBundle
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from tests.support import AT, make_artifact, make_envelope, make_record
from tests.test_cli_keys import limited

AT_TEXT = "2026-10-14T00:00:00Z"
NOT_CHECKED = "Not checked because the root of the report does not match its body."
NOT_ORDERED = "Not checked because the dimension ordering does not pass: an index is a position in key order."
DIMENSIONS = [
    "structure",
    "ordering",
    "results_root",
    "records_root",
    "counts",
    "signature",
    "issuer_trust",
    "signers",
    "manual_results",
    "status",
    "validity",
    "timestamp",
]

Run = Callable[..., tuple[int, str, str]]


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Run:
    def call(*arguments: str) -> tuple[int, str, str]:
        capsys.readouterr()
        try:
            code = cli.main(list(arguments))
        except SystemExit as exc:
            code = int(exc.code or 0)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return call


def _canonical(path: Path, document: Any) -> Path:
    path.write_bytes(canonical_bytes(document) + b"\n")
    return path


def _verify(
    run: Run, envelope: Path, trust: Path, *more: str
) -> tuple[int, dict[str, tuple[str, str]], bool]:
    code, out, err = run(
        "verify", "--envelope", str(envelope), "--trust", str(trust), "--at", AT_TEXT, *more, "--json"
    )
    assert out, err
    report = json.loads(out)
    return code, {d["name"]: (d["outcome"], d["detail"]) for d in report["dimensions"]}, report["complete"]


def _edited(source: Path, target: Path, edit: Callable[[dict[str, Any]], None]) -> Path:
    document = json.loads(source.read_text(encoding="utf-8"))
    edit(document)
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


def _wrong_results_root(document: dict[str, Any]) -> None:
    document["decision"]["results_root"] = "0" * 64


def _wrong_records_root(document: dict[str, Any]) -> None:
    document["decision"]["records_root"] = "0" * 64


def _extra_member(document: dict[str, Any]) -> None:
    document["surprise"] = 1


STRUCTURE = "ENVELOPE.BODY.INVALID: the envelope fails these checks: structure"


def _duplicate_key(source: Path, target: Path) -> Path:
    """The envelope with a repeated key: not strict JSON, so it fails ``structure``."""
    text = source.read_text(encoding="utf-8")
    target.write_text('{"schema_version": "dppce.envelope/1", ' + text[1:], encoding="utf-8")
    return target


# -- the commitment plaintext -------------------------------------------------------------------------


def test_opened_record_round_trips_the_committed_plaintext() -> None:
    records = [
        make_record(1),
        dataclasses.replace(
            make_record(2, body=bytes(range(256))),
            status=None,
            error="timeout",
            redirects=("http://127.0.0.1/a", "http://127.0.0.1/b"),
        ),
        make_artifact("qr_image", error="artifact_unavailable", index=3),
    ]
    for record in records:
        plain = record_to_json(record, with_salt=False)
        assert canonical_bytes(OpenedRecord.model_validate(plain)) == canonical_bytes(plain)
        assert commitment_of(record.salt, canonical_bytes(plain)) == commit(record)


# -- prove --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("verdicts", [("pass",), ("pass", "fail"), ("pass", "fail", "pass")], ids=len)
def test_prove_exports_a_proof_that_merkle_verify_inclusion_accepts(
    run: Run, tmp_path: Path, verdicts: tuple[str, ...]
) -> None:
    envelope = make_envelope(verdicts)
    path = tmp_path / "envelope.json"
    path.write_text(envelope.model_dump_json(by_alias=True), encoding="utf-8")
    decision = envelope.decision
    keys = result_keys(decision.requirement_results, decision.test_results)
    for index, key in enumerate(keys):
        out = tmp_path / f"proof-{index}.json"
        code, stdout, err = run(
            "prove", "--envelope", str(path), "--result", key, "--out", str(out), "--json"
        )
        assert code == 0, err
        assert json.loads(stdout) == {"written": str(out), "key": key, "index": index, "size": len(keys)}
        proof = InclusionProof.model_validate_json(out.read_bytes())
        assert out.read_bytes() == canonical_bytes(proof) + b"\n"
        assert (proof.label, proof.key, proof.index, proof.size) == ("results", key, index, len(keys))
        assert merkle.verify_inclusion(
            "results",
            canonical_bytes(proof.leaf),
            index=proof.index,
            size=proof.size,
            proof=[bytes.fromhex(h) for h in proof.path],
            expected_root=bytes.fromhex(decision.results_root),
        )


def test_a_single_record_opening_has_an_empty_path_and_verifies() -> None:
    record = make_record(1)
    commitments = record_commitments([record])
    base = make_envelope().decision
    decision = base.model_copy(
        update={"record_commitments": commitments, "records_root": records_root(commitments)}
    )
    opening = disclosure.open_record(decision, record)
    assert (opening.proof.size, opening.proof.path) == (1, ())
    outcome, detail = disclosure.check_opening_file(
        canonical_bytes(opening), decision, {"results": True, "records": True}, ordered=True
    )
    assert (outcome, detail.startswith("OPENING.RECORD.OK")) == ("pass", True), detail


def _signed_files(signed: EvidenceEnvelope, trust: TrustBundle, tmp_path: Path) -> tuple[Path, Path]:
    envelope, bundle = tmp_path / "signed.json", tmp_path / "trust.json"
    envelope.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    bundle.write_text(trust.model_dump_json(), encoding="utf-8")
    return envelope, bundle


def _standalone(
    capsys: pytest.CaptureFixture[str], *arguments: str
) -> tuple[int, dict[str, tuple[str, str]]]:
    capsys.readouterr()
    code = verifier_main(list(arguments))
    report = json.loads(capsys.readouterr().out)
    return code, {d["name"]: (d["outcome"], d["detail"]) for d in report["dimensions"]}


def test_the_standalone_verifier_checks_a_proof(
    run: Run,
    signed: EvidenceEnvelope,
    trust: TrustBundle,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    envelope, bundle = _signed_files(signed, trust, tmp_path)
    proof = tmp_path / "proof.json"
    assert run("prove", "--envelope", str(envelope), "--result", "T:TP-001", "--out", str(proof))[0] == 0
    common = [str(envelope), "--trust", str(bundle), "--at", AT_TEXT]
    code, dims = _standalone(capsys, *common, "--proof", str(proof))
    assert code == 0
    assert dims["proof"][0] == "pass"
    assert dims["proof"][1].startswith("PROOF.LEAF.OK"), dims["proof"]
    assert "T:TP-001" in dims["proof"][1]
    assert list(dims) == [*DIMENSIONS, "proof"]
    code, cli_dims, complete = _verify(run, envelope, bundle, "--proof", str(proof))
    assert (code, cli_dims["proof"], complete) == (0, dims["proof"], True)

    good = json.loads(proof.read_text(encoding="utf-8"))

    def changed(name: str, edit: Callable[[dict[str, Any]], None]) -> Path:
        document = json.loads(json.dumps(good))
        edit(document)
        return _canonical(tmp_path / f"{name}.json", document)

    cases: list[tuple[Path, tuple[str, ...]]] = [
        (changed("verdict", lambda d: d["leaf"].update(verdict="fail")), ("PROOF.PATH.INVALID",)),
        (changed("root", lambda d: d.update(root="1" * 64)), ("PROOF.REPORT.MISMATCH",)),
        (
            changed("digest", lambda d: d.update(decision_digest="sha256:" + "2" * 64)),
            ("PROOF.REPORT.MISMATCH",),
        ),
        (changed("size", lambda d: d.update(size=d["size"] + 1)), ("PROOF.REPORT.MISMATCH",)),
        (changed("index", lambda d: d.update(index=d["index"] - 1)), ("PROOF.PATH.INVALID",)),
        (changed("path", lambda d: d["path"].__setitem__(0, "3" * 64)), ("PROOF.PATH.INVALID",)),
        (changed("text-index", lambda d: d.update(index=str(d["index"]))), ("PROOF.FILE.MALFORMED",)),
        (changed("version", lambda d: d.update(schema_version="dppce.proof/2")), ("PROOF.FILE.MALFORMED",)),
    ]
    not_json = tmp_path / "not-json.json"
    not_json.write_text("{", encoding="utf-8")
    large = tmp_path / "large.json"
    large.write_bytes(b" " * (1024 * 1024 + 1))
    cases += [(not_json, ("PROOF.FILE.MALFORMED",)), (large, ("PROOF.FILE.TOO_LARGE",))]
    for path, codes in cases:
        code, dims = _standalone(capsys, *common, "--proof", str(path))
        assert code == 4, path.name
        outcome, detail = dims["proof"]
        assert outcome == "fail", (path.name, detail)
        assert detail.startswith(codes), (path.name, detail)


def test_proof_is_not_checked_when_the_results_root_fails(
    run: Run, signed: EvidenceEnvelope, trust: TrustBundle, tmp_path: Path
) -> None:
    envelope, bundle = _signed_files(signed, trust, tmp_path)
    proof = tmp_path / "proof.json"
    assert run("prove", "--envelope", str(envelope), "--result", "R:ILL-001", "--out", str(proof))[0] == 0
    broken = _edited(envelope, tmp_path / "broken.json", _wrong_results_root)
    code, dims, complete = _verify(run, broken, bundle, "--proof", str(proof))
    assert dims["results_root"][0] == "fail"
    assert dims["proof"] == ("not_checked", NOT_CHECKED)
    assert (code, complete) == (4, False)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    _, dims, _ = _verify(run, broken, bundle, "--proof", str(malformed))
    assert dims["proof"][0] == "fail"
    assert dims["proof"][1].startswith("PROOF.FILE.MALFORMED")
    unstructured = _edited(envelope, tmp_path / "unstructured.json", _extra_member)
    code, dims, complete = _verify(run, unstructured, bundle, "--proof", str(proof))
    assert dims["proof"][0] == "not_checked"
    assert (code, complete) == (4, False)
    # Only the root of its own tree gates a proof. The changed records root changes the digest.
    other_root = _edited(envelope, tmp_path / "other-root.json", _wrong_records_root)
    code, dims, complete = _verify(run, other_root, bundle, "--proof", str(proof))
    assert (dims["results_root"][0], dims["records_root"][0]) == ("pass", "fail")
    assert dims["proof"][0] == "fail"
    assert dims["proof"][1].startswith("PROOF.REPORT.MISMATCH"), dims["proof"]
    assert (code, complete) == (4, False)


def _dimensions(decision: Any, trust: TrustBundle, **files: bytes) -> dict[str, tuple[str, str]]:
    envelope = EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision)
    report = verify(json.loads(envelope.model_dump_json(by_alias=True)), trust, AT, **files)
    return {d.name: (d.outcome, d.detail) for d in report.dimensions}


def test_proof_is_not_checked_when_the_ordering_fails(trust: TrustBundle) -> None:
    # The index of a leaf is its position in ascending key order. A root over an unordered list
    # can still match, so a proof against it would place a result where the order does not.
    base = make_envelope().decision
    swapped = (base.test_results[1], base.test_results[0], *base.test_results[2:])
    unordered = base.model_copy(
        update={"test_results": swapped, "results_root": results_root(base.requirement_results, swapped)}
    )
    proof = canonical_bytes(disclosure.prove(unordered, "T:TP-001"))
    dims = _dimensions(unordered, trust, proof=proof)
    assert (dims["ordering"][0], dims["results_root"][0]) == ("fail", "pass")
    assert dims["proof"] == ("not_checked", NOT_ORDERED)


def test_opening_is_not_checked_when_the_records_are_out_of_order(trust: TrustBundle) -> None:
    base = make_envelope().decision
    first, second = make_record(1), make_record(2)
    commitments = record_commitments([first, second])[::-1]
    records = base.model_copy(
        update={"record_commitments": commitments, "records_root": records_root(commitments)}
    )
    opening = canonical_bytes(disclosure.open_record(records, first))
    dims = _dimensions(records, trust, opening=opening)
    assert (dims["ordering"][0], dims["records_root"][0]) == ("fail", "pass")
    assert dims["opening"] == ("not_checked", NOT_ORDERED)
    # A file that is not a document still fails first, as with a root that does not match.
    dims = _dimensions(records, trust, opening=b"[]")
    assert dims["opening"][0] == "fail"
    assert dims["opening"][1].startswith("OPENING.FILE.MALFORMED")


def test_prove_refusals(run: Run, tmp_path: Path) -> None:
    envelope = tmp_path / "envelope.json"
    envelope.write_text(make_envelope().model_dump_json(by_alias=True), encoding="utf-8")
    out = tmp_path / "proof.json"
    code, _, err = run("prove", "--envelope", str(envelope), "--result", "R:NOT-THERE", "--out", str(out))
    assert (code, "PROVE.RESULT.UNKNOWN" in err) == (2, True), err
    broken = _edited(envelope, tmp_path / "broken.json", _wrong_results_root)
    code, _, err = run("prove", "--envelope", str(broken), "--result", "R:ILL-001", "--out", str(out))
    assert (code, "ENVELOPE.BODY.INVALID" in err) == (2, True), err
    assert not out.exists()
    duplicate = _duplicate_key(envelope, tmp_path / "duplicate.json")
    code, _, err = run("prove", "--envelope", str(duplicate), "--result", "R:ILL-001", "--out", str(out))
    assert (code, STRUCTURE in err) == (2, True), err
    assert not out.exists()
    out.write_text("{}\n", encoding="utf-8")
    code, _, err = run("prove", "--envelope", str(envelope), "--result", "R:ILL-001", "--out", str(out))
    assert (code, "PROVE.OUTPUT.EXISTS" in err, out.read_text(encoding="utf-8")) == (2, True, "{}\n"), err


def test_verification_without_supplied_files_is_unchanged(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    report = verify(json.loads(signed.model_dump_json(by_alias=True)), trust, AT)
    assert [d.name for d in report.dimensions] == DIMENSIONS
    assert report.complete is True


# -- open ---------------------------------------------------------------------------------------------


class Runs(NamedTuple):
    work: Path
    first: RunResult
    second: RunResult
    signed: Path

    @property
    def keys(self) -> Path:
        return self.work / "keys"


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> Runs:
    work = tmp_path_factory.mktemp("rig")
    with ReferenceRig(work) as rig:
        first, second = rig.run(), rig.run()
        signed = rig.sign(first)
    return Runs(work, first, second, signed)


def _open(run: Run, runs: Runs, out: Path, *more: str, record: str = "r0001") -> tuple[int, str, str]:
    arguments = ["open", "--run", str(runs.first.run_dir), "--keys", str(runs.keys), "--record", record]
    return run(*arguments, "--out", str(out), *more)


@pytest.mark.qr
def test_open_writes_salt_and_plaintext_with_a_warning(run: Run, runs: Runs, tmp_path: Path) -> None:
    out = tmp_path / "opening.json"
    code, stdout, err = _open(run, runs, out)
    assert code == 0, err
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert err.startswith("WARNING")
    assert "plaintext" in err
    assert stdout.strip() == f"wrote {out}"
    opening = RecordOpening.model_validate_json(out.read_bytes())
    assert out.read_bytes() == canonical_bytes(opening) + b"\n"
    (record,) = [
        r
        for r in read_recording(runs.first.run_dir / "recording", FileDataKeyProvider(runs.keys))
        if r.record_id == "r0001"
    ]
    assert opening.record.model_dump(mode="json") == record_to_json(record, with_salt=False)
    assert opening.salt == base64.b64encode(record.salt).decode("ascii")
    assert opening.proof.root == runs.first.envelope.decision.records_root

    second = tmp_path / "opening-2.json"
    code, stdout, err = _open(run, runs, second, "--json")
    assert code == 0, err
    document = json.loads(stdout)
    assert (document["written"], document["record_id"]) == (str(second), "r0001")
    assert "plaintext" in document["warning"]


@pytest.mark.qr
def test_a_failed_open_leaves_no_plaintext_and_has_warned_first(run: Run, runs: Runs, tmp_path: Path) -> None:
    out = tmp_path / "opening.json"
    arguments = ["open", "--run", str(runs.first.run_dir), "--keys", str(runs.keys), "--record", "r0001"]
    done = limited(64, *arguments, "--out", str(out))
    assert done.returncode == 2, done.stderr
    assert done.stderr.startswith("WARNING"), done.stderr
    assert not out.exists(), out.stat().st_size
    code, _, err = _open(run, runs, out)
    assert code == 0, err


@pytest.mark.qr
def test_the_verifier_checks_an_opening(
    run: Run, runs: Runs, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    opening = tmp_path / "opening.json"
    assert _open(run, runs, opening)[0] == 0
    code, dims, complete = _verify(run, runs.signed, TRUST, "--opening", str(opening))
    assert (code, complete) == (0, True), dims
    assert dims["opening"][0] == "pass"
    assert dims["opening"][1].startswith("OPENING.RECORD.OK")
    assert "r0001" in dims["opening"][1]
    standalone = [str(runs.signed), "--trust", str(TRUST), "--at", AT_TEXT, "--opening", str(opening)]
    assert _standalone(capsys, *standalone) == (0, dims)

    good = json.loads(opening.read_text(encoding="utf-8"))

    def changed(name: str, edit: Callable[[dict[str, Any]], None]) -> Path:
        document = json.loads(json.dumps(good))
        edit(document)
        return _canonical(tmp_path / f"{name}.json", document)

    def flip_body(document: dict[str, Any]) -> None:
        body = bytearray(base64.b64decode(document["record"]["body"]) or b"\x00")
        body[0] ^= 1
        document["record"]["body"] = base64.b64encode(bytes(body)).decode("ascii")

    def forge(document: dict[str, Any]) -> None:
        # A consistent forgery: a changed body, and a leaf commitment made with the disclosed salt.
        flip_body(document)
        disclosed = base64.b64decode(document["salt"])
        document["proof"]["leaf"]["commitment"] = commitment_of(
            disclosed, canonical_bytes(document["record"])
        )

    salt = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    cases = [
        (changed("forged", forge), "PROOF.PATH.INVALID"),
        (changed("body", flip_body), "OPENING.COMMITMENT.MISMATCH"),
        (changed("salt", lambda d: d.update(salt=salt)), "OPENING.COMMITMENT.MISMATCH"),
        (changed("path", lambda d: d["proof"]["path"].__setitem__(0, "0" * 64)), "PROOF.PATH.INVALID"),
        (changed("extra", lambda d: d.update(surprise=1)), "OPENING.FILE.MALFORMED"),
    ]
    for path, reason in cases:
        code, dims, complete = _verify(run, runs.signed, TRUST, "--opening", str(path))
        assert (code, complete, dims["opening"][0]) == (4, False, "fail"), (path.name, dims["opening"])
        assert dims["opening"][1].startswith(reason), (path.name, dims["opening"])

    other = runs.second.run_dir / "envelope.json"
    _, dims, _ = _verify(run, other, TRUST, "--opening", str(opening))
    assert dims["opening"][0] == "fail"
    assert dims["opening"][1].startswith("PROOF.REPORT.MISMATCH")

    unstructured = _edited(runs.signed, tmp_path / "unstructured.json", _extra_member)
    _, dims, _ = _verify(run, unstructured, TRUST, "--opening", str(opening))
    assert dims["opening"][0] == "not_checked"
    broken = _edited(runs.signed, tmp_path / "broken.json", _wrong_records_root)
    _, dims, complete = _verify(run, broken, TRUST, "--opening", str(opening))
    assert dims["records_root"][0] == "fail"
    assert dims["opening"] == ("not_checked", NOT_CHECKED)
    assert complete is False


@pytest.mark.qr
def test_open_refusals(run: Run, runs: Runs, tmp_path: Path) -> None:
    out = tmp_path / "opening.json"
    code, _, err = _open(run, runs, out, record="r9999")
    assert (code, "OPEN.RECORD.UNKNOWN" in err) == (2, True), err
    other = runs.second.run_dir / "envelope.json"
    code, _, err = _open(run, runs, out, "--envelope", str(other))
    assert (code, "OPEN.RECORD.NOT_IN_REPORT" in err) == (2, True), err
    broken = _edited(runs.signed, tmp_path / "broken.json", _wrong_results_root)
    code, _, err = _open(run, runs, out, "--envelope", str(broken))
    assert (code, "ENVELOPE.BODY.INVALID" in err) == (2, True), err
    assert not out.exists()
    duplicate = _duplicate_key(runs.signed, tmp_path / "duplicate.json")
    code, _, err = _open(run, runs, out, "--envelope", str(duplicate))
    assert (code, STRUCTURE in err) == (2, True), err
    assert not out.exists()

    copy = tmp_path / "copy"
    shutil.copytree(runs.first.run_dir, copy)
    sealed = copy / "recording" / "records" / "r0001.enc"
    data = bytearray(sealed.read_bytes())
    data[-1] ^= 1
    sealed.write_bytes(bytes(data))
    code, _, err = run(
        "open", "--run", str(copy), "--keys", str(runs.keys), "--record", "r0001", "--out", str(out)
    )
    assert code == 2, err
    assert not out.exists()

    out.write_text("{}\n", encoding="utf-8")
    code, _, err = _open(run, runs, out)
    assert (code, "OPEN.OUTPUT.EXISTS" in err, out.read_text(encoding="utf-8")) == (2, True, "{}\n"), err
