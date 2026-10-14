"""Tests for the gaps that mutation testing of the verdict and evidence code found.

Each test kills one or more surviving mutants of ``uv run just mutation`` (mutmut 3.8.0, run of
2026-10-14). A survivor that only changes the text of an error message is not covered here:
no behavior depends on it. The survivors that stay are listed in the mutation record.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import date
from pathlib import Path
from typing import Any

import pytest

import tests.core.test_run_core as core  # registers the synthetic tests_core.* checks
from dppce.evidence import merkle
from dppce.evidence.canonical import MAX_SAFE_INTEGER, CanonicalizationError, canonical_bytes
from dppce.evidence.envelope import build_decision, records_root, results_root
from dppce.evidence.jws import LocalSigner, SignatureError, sign_compact, verify_compact
from dppce.evidence.recording import (
    commit,
    purge_expired,
    read_recording,
    record_to_json,
    write_recording,
)
from dppce.infrastructure.interfaces import Record
from dppce.models import IXIT, ClaimLevel, Conflict, Exclusion, ExecutionMode, Verdict
from dppce.orchestrator.run import (  # noqa: TID251 - the run core is the unit under test
    RunInputs,
    execute,
    make_plan,
)
from dppce.verdicts import aggregate
from dppce.verdicts.coverage import summarize
from tests.core import builders as b
from tests.support import AT, make_envelope, make_record, make_requirement_result, make_test_result

TYP = "dpp+jws"


# -- verdicts: what the requirement result says about a step -------------------------------------


def run(
    requirement: Any, *purposes: Any, tmp_path: Path, mode: ExecutionMode = ExecutionMode.EXPLORATORY
) -> Any:
    inputs = RunInputs(
        mode=mode,
        profile=b.profile(),
        catalogue=b.catalogue(b.pack(requirement)),
        testpacks={"tp/a": b.purposes_pack(*purposes)},
        ics=b.ics(),
        ixit=IXIT(schema_version="dppce.ixit/1"),
        data_root=tmp_path,
        evaluation_time=AT,
    )
    plan = make_plan(inputs)
    results = execute(plan, inputs, core.FakeAcquirer())
    return plan, results, aggregate(plan, {requirement.id: requirement}, results)


def test_a_failing_step_is_retained_with_its_own_reason_code(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1", "T-2")])
    failing = b.purpose("T-1", stimulus={"check": "tests_core.fails"})
    passing = b.purpose("T-2", stimulus={"check": "tests_core.passes"})
    _, _, (result,) = run(requirement, failing, passing, tmp_path=tmp_path)
    assert result.verdict is Verdict.FAIL
    assert result.retained == ("p1/T-1: fail (TESTS.CORE.NOT_OK)",)


def test_a_step_with_no_result_is_retained_as_missing() -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    inputs = RunInputs(
        mode=ExecutionMode.EXPLORATORY,
        profile=b.profile(),
        catalogue=b.catalogue(b.pack(requirement)),
        testpacks={"tp/a": b.purposes_pack(b.purpose("T-1", stimulus={"check": "tests_core.passes"}))},
        ics=b.ics(),
        ixit=IXIT(schema_version="dppce.ixit/1"),
        data_root=Path(),
        evaluation_time=AT,
    )
    (result,) = aggregate(make_plan(inputs), {"R-1": requirement}, {})
    assert (result.verdict, result.retained) == (
        Verdict.INCONCLUSIVE,
        ("p1/T-1: inconclusive (RESULT.MISSING)",),
    )


def test_aggregate_gives_an_illustrative_requirement_the_illustrative_claim_level(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", assessment_paths=[b.path("p1", "T-1")])
    assert requirement.authority_class.value == "illustrative"
    _, _, (result,) = run(
        requirement, b.purpose("T-1", stimulus={"check": "tests_core.passes"}), tmp_path=tmp_path
    )
    assert result.claim_level is ClaimLevel.ILLUSTRATIVE


def test_coverage_counts_exclusions_under_the_key_excluded(tmp_path: Path) -> None:
    requirement = b.requirement("R-1", authority_class="guidance", source=b.CITED)  # not illustrative
    plan, results, aggregated = run(requirement, tmp_path=tmp_path, mode=ExecutionMode.ILLUSTRATIVE)
    coverage = summarize(
        scope_statement="synthetic",
        requirements=[requirement],
        plan=plan,
        results=aggregated,
        test_results=results,
        executable_tests=frozenset(),
    )
    assert coverage.excluded == 1
    assert coverage.by_verdict.get("excluded") == 1
    assert coverage.by_applicability.get("excluded") == 1


# -- Merkle tree: a proof that does not fit is refused --------------------------------------------


LEAVES = [f"leaf-{i}".encode() for i in range(5)]


def test_an_inclusion_proof_for_each_leaf_verifies_and_nothing_else_does() -> None:
    expected = merkle.root("results", LEAVES)
    for index, leaf in enumerate(LEAVES):
        proof = merkle.inclusion_proof("results", LEAVES, index)
        assert merkle.verify_inclusion(
            "results", leaf, index=index, size=len(LEAVES), proof=proof, expected_root=expected
        )
        for wrong_index in (index + 1, len(LEAVES), -1):
            assert not merkle.verify_inclusion(
                "results", leaf, index=wrong_index, size=len(LEAVES), proof=proof, expected_root=expected
            )
        assert not merkle.verify_inclusion(
            "results", leaf, index=index, size=len(LEAVES), proof=(*proof, proof[0]), expected_root=expected
        ), "a proof that is too long"
        if proof:
            assert not merkle.verify_inclusion(
                "results", leaf, index=index, size=len(LEAVES), proof=proof[:-1], expected_root=expected
            ), "a proof that is too short"


def test_an_index_outside_the_tree_has_no_proof_and_a_label_must_be_alphanumeric() -> None:
    with pytest.raises(IndexError):
        merkle.inclusion_proof("results", LEAVES, len(LEAVES))
    for label in ("with-dash", "with space", "café"):
        with pytest.raises(ValueError, match="label"):
            merkle.root(label, LEAVES)


def test_the_results_root_binds_each_requirement_result_and_each_test_result() -> None:
    base = results_root([make_requirement_result(1, "pass")], [make_test_result(1, "pass")])
    assert base != results_root([make_requirement_result(1, "fail")], [make_test_result(1, "pass")])
    assert base != results_root([make_requirement_result(1, "pass")], [make_test_result(1, "fail")])


def test_a_decision_lists_exclusions_and_conflicts_in_a_fixed_order() -> None:
    template = make_envelope(("pass",)).decision
    exclusions = [
        Exclusion.model_validate(
            {"kind": kind, "id": ident, "reason_code": "MODE.NOT_APPROVED", "reason": "r"}
        )
        for kind, ident in (("test_purpose", "T-2"), ("requirement", "R-9"), ("requirement", "R-1"))
    ]
    decision = build_decision(
        manifest=template.manifest,
        overall=template.overall,
        overall_reason=template.overall_reason,
        requirement_results=template.requirement_results,
        test_results=template.test_results,
        exclusions=exclusions,
        conflicts=(),
        coverage=template.coverage,
        record_commitments=template.record_commitments,
    )
    assert [(e.kind, e.id) for e in decision.exclusions] == [
        ("requirement", "R-1"),
        ("requirement", "R-9"),
        ("test_purpose", "T-2"),
    ]


# -- canonical form -------------------------------------------------------------------------------


def test_the_canonical_form_checks_values_inside_lists_and_keeps_the_exact_integer_range() -> None:
    for document in ({"a": [1.5]}, {"a": [[{"b": 0.5}]]}, [1, 2.0]):
        with pytest.raises(CanonicalizationError):
            canonical_bytes(document)
    assert canonical_bytes({"a": [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER]}) == (
        f'{{"a":[{MAX_SAFE_INTEGER},{-MAX_SAFE_INTEGER}]}}'.encode()
    )
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"a": [MAX_SAFE_INTEGER + 1]})


# -- signatures -----------------------------------------------------------------------------------


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_a_public_key_has_32_byte_coordinates_as_rfc_7518_requires() -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    jwk = signer.public_jwk()
    assert len(_b64u_decode(jwk["x"])) == len(_b64u_decode(jwk["y"])) == 32


def test_a_token_part_that_cannot_be_decoded_is_malformed() -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    header, _, signature = sign_compact(b'{"a":1}', signer, typ=TYP).split(".")
    # The first two fail the base64url check of the engine; the third reaches the library.
    for token in (f"{header}.%%%.{signature}", f"{header}.e30.%%%", f"{header}.a.{signature}"):
        with pytest.raises(SignatureError) as caught:
            verify_compact(token, signer.public_jwk(), typ=TYP)
        assert caught.value.code == "MALFORMED"


def test_a_key_that_the_library_refuses_is_not_processable_and_not_a_bad_signature() -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    token = sign_compact(b'{"a":1}', signer, typ=TYP)
    off_curve = signer.public_jwk() | {"y": signer.public_jwk()["x"]}  # x == y is not a point of P-256
    with pytest.raises(SignatureError) as caught:
        verify_compact(token, off_curve, typ=TYP)
    assert caught.value.code == "NOT_PROCESSABLE"


# -- recordings -----------------------------------------------------------------------------------


class _StrictKeys:
    """A key provider that knows one key identifier only, so that the identifier must be right."""

    def data_key(self, key_id: str) -> bytes:
        assert key_id == "TEST-ONLY-data-key", key_id
        return bytes(range(32))

    def default_key_id(self) -> str:
        return "TEST-ONLY-data-key"


def test_a_commitment_is_the_published_construction_without_the_salt() -> None:
    """Architecture section 10: HMAC-SHA256(salt, "dppce.record.v1" || 0x00 || plaintext)."""
    record = make_record(1)
    plaintext = canonical_bytes(record_to_json(record, with_salt=False))
    expected = hmac.new(record.salt, b"dppce.record.v1\x00" + plaintext, hashlib.sha256).hexdigest()
    assert commit(record) == expected
    assert "salt" not in json.loads(plaintext)


def test_a_record_with_a_transport_error_survives_the_round_trip(tmp_path: Path) -> None:
    record = Record(**{**make_record(1).__dict__, "status": None, "error": "timeout", "body": b""})
    write_recording(tmp_path / "r", [record], _StrictKeys(), created=date(2026, 10, 1), retention_days=30)
    (restored,) = read_recording(tmp_path / "r", _StrictKeys())
    assert (restored.error, restored.status, restored.body) == ("timeout", None, b"")


def _expired(path: Path, records: int = 1) -> None:
    write_recording(
        path,
        [make_record(i + 1) for i in range(records)],
        _StrictKeys(),
        created=date(2026, 1, 1),
        retention_days=30,
    )


def test_purge_keeps_a_recording_whose_records_directory_holds_anything_but_its_files(tmp_path: Path) -> None:
    runs, today = tmp_path / "runs", date(2026, 10, 13)
    _expired(runs / "nested")
    (runs / "nested" / "records" / "folder").mkdir()
    _expired(runs / "linked-file")
    os.symlink(tmp_path, runs / "linked-file" / "records" / "r0009.enc")
    outside = tmp_path / "outside-records"
    outside.mkdir()
    _expired(runs / "linked-dir", records=0)
    (runs / "linked-dir" / "records").rmdir()
    os.symlink(outside, runs / "linked-dir" / "records")
    _expired(runs / "missing", records=1)
    for sealed in (runs / "missing" / "records").iterdir():
        sealed.unlink()
    (runs / "missing" / "records").rmdir()
    result = purge_expired(runs, today, _StrictKeys(), delete=True)
    assert result.expired == ()
    assert {path.name for path, _ in result.kept} == {"nested", "linked-file", "linked-dir", "missing"}
    assert outside.is_dir()


def test_purge_deletes_an_empty_recording_and_never_follows_a_linked_run_directory(tmp_path: Path) -> None:
    runs, today = tmp_path / "runs", date(2026, 10, 13)
    _expired(runs / "empty", records=0)
    (runs / "empty" / "records").rmdir()  # a recording with no record needs no records directory
    elsewhere = tmp_path / "elsewhere"
    _expired(elsewhere / "target")
    os.symlink(elsewhere / "target", runs / "linked")
    result = purge_expired(runs, today, _StrictKeys(), delete=True)
    assert result.expired == (runs / "empty",)
    assert (elsewhere / "target" / "recording.json").is_file(), "a link is never followed"


def test_a_public_key_may_carry_its_identifier_use_and_algorithm() -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    token = sign_compact(b'{"a":1}', signer, typ=TYP)
    described = signer.public_jwk() | {"kid": "TEST-ONLY-k", "use": "sig", "alg": "ES256"}
    assert verify_compact(token, described, typ=TYP) == b'{"a":1}'
    with pytest.raises(SignatureError) as caught:
        verify_compact(token, described | {"d": "private part"}, typ=TYP)
    assert caught.value.code == "KEY"


# -- known answers: the published constructions, computed here without the engine -----------------


def _published_root(label: str, leaves: list[bytes]) -> bytes:
    """Architecture section 11.2, written out again so that a change of the engine shows."""
    prefix = b"dppce.merkle.v1\x00" + label.encode("ascii") + b"\x00"

    def sha(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def subtree(items: list[bytes]) -> bytes:
        if len(items) == 1:
            return sha(prefix + b"\x00" + items[0])
        split = 1
        while split * 2 < len(items):
            split *= 2
        return sha(prefix + b"\x01" + subtree(items[:split]) + subtree(items[split:]))

    return subtree(leaves) if leaves else sha(prefix + b"\x02")


def test_the_roots_are_the_published_construction_with_their_labels() -> None:
    for count in range(8):
        leaves = LEAVES[:count] + [b"x"] * max(0, count - len(LEAVES))
        assert merkle.root("results", leaves) == _published_root("results", leaves), count
    requirements = [make_requirement_result(i, "pass") for i in (1, 2)]
    tests_ = [make_test_result(i, "pass") for i in (1, 2, 3)]
    leaves = [canonical_bytes(r) for r in requirements] + [canonical_bytes(t) for t in tests_]
    assert results_root(requirements, tests_) == _published_root("results", leaves).hex()
    commitments = make_envelope(("pass", "fail")).decision.record_commitments
    assert (
        records_root(commitments)
        == _published_root("records", [canonical_bytes(c) for c in commitments]).hex()
    )


def test_every_proof_of_every_tree_up_to_nine_leaves_verifies_and_a_changed_one_does_not() -> None:
    for size in range(1, 10):
        leaves = [f"leaf-{i}".encode() for i in range(size)]
        expected = merkle.root("records", leaves)
        for index in range(size):
            proof = merkle.inclusion_proof("records", leaves, index)

            def check(
                leaf: bytes, at: int, path: tuple[bytes, ...], *, size: int = size, root: bytes = expected
            ) -> bool:
                return merkle.verify_inclusion(
                    "records", leaf, index=at, size=size, proof=path, expected_root=root
                )

            assert check(leaves[index], index, proof), (size, index)
            assert not check(b"other", index, proof)
            for position in range(len(proof)):
                changed = bytes([proof[position][0] ^ 1]) + proof[position][1:]
                assert not check(leaves[index], index, (*proof[:position], changed, *proof[position + 1 :]))
            if size > 1:
                other = (index + 1) % size
                assert not check(leaves[index], other, proof), (size, index, other)


def test_a_decision_lists_conflicts_in_requirement_order() -> None:
    template = make_envelope(("pass",)).decision
    conflicts = [
        Conflict(requirement_id=ident, declared="declared false", explanation="synthetic")
        for ident in ("R-9", "R-1", "R-5")
    ]
    decision = build_decision(
        manifest=template.manifest,
        overall=template.overall,
        overall_reason=template.overall_reason,
        requirement_results=template.requirement_results,
        test_results=template.test_results,
        exclusions=(),
        conflicts=conflicts,
        coverage=template.coverage,
        record_commitments=template.record_commitments,
    )
    assert [c.requirement_id for c in decision.conflicts] == ["R-1", "R-5", "R-9"]


def test_purge_keeps_a_recording_with_an_extra_record_file_or_a_directory_in_place_of_one(
    tmp_path: Path,
) -> None:
    runs, today = tmp_path / "runs", date(2026, 10, 13)
    _expired(runs / "extra-file")
    (runs / "extra-file" / "records" / "r0009.enc").write_bytes(b"not part of the index")
    _expired(runs / "dir-as-record")
    (runs / "dir-as-record" / "records" / "r0001.enc").unlink()
    (runs / "dir-as-record" / "records" / "r0001.enc").mkdir()
    (runs / "dir-as-record" / "records" / "r0001.enc" / "notes.txt").write_text("keep")
    result = purge_expired(runs, today, _StrictKeys(), delete=True)
    assert result.expired == ()
    assert {path.name for path, _ in result.kept} == {"extra-file", "dir-as-record"}
