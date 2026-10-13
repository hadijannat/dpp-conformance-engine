"""Merkle tree, encrypted recording, signing, and standalone verification.

The tamper cases are the evidence faults E-01 to E-12 of validation/fault-catalogue.yaml.
Each must fail on the dimension that the catalogue names.
"""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from dppce.evidence import merkle
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner, SignatureError, sign_compact, verify_compact
from dppce.evidence.recording import RecordingError, commit, read_recording, write_recording
from dppce.models import EvidenceEnvelope, TrustBundle
from dppce.verifier import verify, verify_json
from tests.support import AT, ISSUER, make_envelope, make_record


class _Keys:
    def data_key(self, key_id: str) -> bytes:
        return bytes(range(32))

    def default_key_id(self) -> str:
        return "TEST-ONLY-data-key"


def _outcomes(document: Any, trust: TrustBundle, at: datetime = AT) -> tuple[dict[str, str], bool]:
    report = verify(document, trust, at)
    return {d.name: d.outcome for d in report.dimensions}, report.complete


# -- canonical JSON ---------------------------------------------------------------------------


def test_canonical_form_sorts_keys_and_is_compact() -> None:
    assert (
        canonical_bytes({"b": [1, "x", None, True], "a": {"z": -5}})
        == b'{"a":{"z":-5},"b":[1,"x",null,true]}'
    )


@pytest.mark.parametrize("bad", [{"x": 1.5}, {"x": 2**53}, {1: "a"}, {"x": {1, 2}}, {"x": float("nan")}])
def test_canonical_form_rejects_floats_large_integers_and_non_json(bad: Any) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(bad)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', "{not json"])
def test_strict_parse_rejects_what_two_parsers_can_read_differently(raw: str) -> None:
    with pytest.raises(CanonicalizationError):
        parse_strict(raw)


# -- Merkle tree ------------------------------------------------------------------------------


@pytest.mark.parametrize("size", range(34))
def test_every_inclusion_proof_verifies_and_a_wrong_leaf_does_not(size: int) -> None:
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    root = merkle.root("results", leaves)
    for index, leaf in enumerate(leaves):
        proof = merkle.inclusion_proof("results", leaves, index)
        check = {"index": index, "size": size, "proof": proof, "expected_root": root}
        assert merkle.verify_inclusion("results", leaf, **check)
        assert not merkle.verify_inclusion("results", b"other", **check)
        assert not merkle.verify_inclusion("records", leaf, **check), "the label separates the trees"


def test_tree_edge_cases() -> None:
    assert merkle.root("results", []) != merkle.root("records", []), "the empty tree is domain-separated"
    assert merkle.root("results", [b"a"]) == merkle.leaf_hash("results", b"a"), "one leaf is its own root"
    three, padded = [b"a", b"b", b"c"], [b"a", b"b", b"c", b"c"]
    assert merkle.root("results", three) != merkle.root("results", padded), "an odd level is not padded"
    assert merkle.root("results", [b"a", b"b"]) != merkle.root("results", [b"b", b"a"]), "order matters"
    assert merkle.leaf_hash("results", b"x") != merkle.root("results", [b"", b""]), "leaf and node differ"


# -- recording --------------------------------------------------------------------------------


def test_recording_round_trip_keeps_payloads_out_of_clear_text(tmp_path: Path) -> None:
    records = [make_record(1), make_record(2, b'{"secret":"CANARY-value"}', "http://sut.internal/dpp/2")]
    directory = tmp_path / "recording"
    index = write_recording(directory, records, _Keys(), created=date(2026, 10, 13), retention_days=30)
    assert index.delete_after == "2026-11-12"
    assert read_recording(directory, _Keys()) == tuple(records)
    stored = b"".join(p.read_bytes() for p in directory.rglob("*") if p.is_file())
    for secret in (b"CANARY-value", b"sut.internal", base64.b64encode(b'{"secret":"CANARY-value"}')):
        assert secret not in stored


def test_a_changed_or_swapped_record_is_detected(tmp_path: Path) -> None:
    directory = tmp_path / "recording"
    write_recording(
        directory, [make_record(1), make_record(2)], _Keys(), created=date(2026, 10, 13), retention_days=1
    )
    first, second = directory / "records" / "r0001.enc", directory / "records" / "r0002.enc"
    original = first.read_bytes()
    first.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(RecordingError, match="does not authenticate"):
        read_recording(directory, _Keys())
    first.write_bytes(second.read_bytes())  # a valid ciphertext, but of a different record
    with pytest.raises(RecordingError):
        read_recording(directory, _Keys())


def test_a_recording_is_never_overwritten(tmp_path: Path) -> None:
    write_recording(tmp_path / "r", [make_record(1)], _Keys(), created=date(2026, 10, 13), retention_days=1)
    with pytest.raises(RecordingError, match="never overwritten"):
        write_recording(
            tmp_path / "r", [make_record(1)], _Keys(), created=date(2026, 10, 13), retention_days=1
        )


def test_commitment_hides_a_predictable_value() -> None:
    one, two = make_record(1, b"yes"), make_record(1, b"yes")
    assert commit(one) != commit(two), "the same content gives different commitments: the salt differs"
    assert commit(one) == commit(one)


# -- signing ----------------------------------------------------------------------------------


def test_only_the_allowlisted_algorithm_and_type_verify(signer: LocalSigner) -> None:
    token = sign_compact(b"payload", signer, typ="dppce-attestation+jws")
    assert verify_compact(token, signer.public_jwk(), typ="dppce-attestation+jws") == b"payload"
    with pytest.raises(SignatureError, match="type"):
        verify_compact(token, signer.public_jwk(), typ="dppce-authorization+jws")
    with pytest.raises(SignatureError, match="does not verify"):
        verify_compact(token, LocalSigner.generate("other").public_jwk(), typ="dppce-attestation+jws")
    with pytest.raises(SignatureError, match="not a public P-256 key"):
        verify_compact(token, {**signer.public_jwk(), "d": "private-part"}, typ="dppce-attestation+jws")


# -- verification -----------------------------------------------------------------------------


def test_control_an_unmodified_signed_envelope_verifies(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    report = verify_json(signed.model_dump_json(by_alias=True), trust, AT)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    mandatory = (
        "structure",
        "ordering",
        "results_root",
        "records_root",
        "counts",
        "signature",
        "issuer_trust",
    )
    assert all(outcomes[name] == "pass" for name in mandatory)
    assert report.complete


def _decision(document: dict[str, Any]) -> dict[str, Any]:
    decision: dict[str, Any] = document["decision"]
    return decision


def _set_algorithm(document: dict[str, Any], algorithm: str, keep_signature: bool) -> None:
    header, payload, signature = document["signatures"][0].split(".")
    fields = json.loads(base64.urlsafe_b64decode(header + "=="))
    fields["alg"] = algorithm
    forged = base64.urlsafe_b64encode(json.dumps(fields).encode()).rstrip(b"=").decode()
    document["signatures"][0] = f"{forged}.{payload}.{signature if keep_signature else ''}"


_TAMPER: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "E-01 flip_verdict": (
        lambda d: _decision(d)["requirement_results"][1].update(verdict="pass"),
        "signature",
    ),
    "E-02 omit_result": (lambda d: _decision(d)["test_results"].pop(), "results_root"),
    "E-03 duplicate_result": (
        lambda d: _decision(d)["test_results"].append(_decision(d)["test_results"][-1]),
        "ordering",
    ),
    "E-04 reorder_results": (lambda d: _decision(d)["requirement_results"].reverse(), "ordering"),
    "E-05 substitute_result": (
        lambda d: _decision(d)["test_results"][0].update(message="from a different run"),
        "results_root",
    ),
    "E-06 change_scope": (
        lambda d: _decision(d)["manifest"]["sut"].update(identifier="urn:example:other"),
        "signature",
    ),
    "drop_limitation": (lambda d: _decision(d)["manifest"].update(limitations=[]), "signature"),
    "E-08 change_counts": (lambda d: _decision(d)["verdict_counts"].update({"pass": 3, "fail": 0}), "counts"),
    "E-09 substitute_commitment": (
        lambda d: _decision(d)["record_commitments"][0].update(commitment="0" * 64),
        "records_root",
    ),
    "E-11 alg_none": (lambda d: _set_algorithm(d, "none", keep_signature=False), "signature"),
    "alg HS256 confusion": (lambda d: _set_algorithm(d, "HS256", keep_signature=True), "signature"),
    "overall says pass": (lambda d: _decision(d).update(overall="pass"), "counts"),
}


@pytest.mark.parametrize("name", sorted(_TAMPER))
def test_each_tamper_fails_on_the_expected_dimension(
    name: str, signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    mutate, dimension = _TAMPER[name]
    document = json.loads(signed.model_dump_json(by_alias=True))
    mutate(document)
    outcomes, complete = _outcomes(document, trust)
    assert outcomes[dimension] == "fail", outcomes
    assert not complete


def test_e10_a_key_that_only_the_report_supplies_is_not_trusted(trust: TrustBundle) -> None:
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    envelope = sign_envelope(make_envelope(), stranger, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    outcomes, complete = _outcomes(json.loads(envelope.model_dump_json()), trust)
    assert outcomes["issuer_trust"] == "fail"
    assert outcomes["signature"] == "not_checked", "there is no trusted key to verify with"
    assert not complete


def test_e12_an_expired_key_keeps_signature_validity_and_trust_apart(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    outcomes, complete = _outcomes(
        json.loads(signed.model_dump_json()), trust, datetime(2027, 6, 1, tzinfo=UTC)
    )
    assert outcomes["signature"] == "pass"
    assert outcomes["issuer_trust"] == "fail"
    assert not complete


def test_a_revoked_key_and_a_wrong_issuer_are_not_trusted(
    signed: EvidenceEnvelope, trust: TrustBundle, signer: LocalSigner
) -> None:
    document = json.loads(signed.model_dump_json())
    revoked = trust.model_copy(update={"revoked_kids": (trust.keys[0].kid,)})
    assert _outcomes(document, revoked)[0]["issuer_trust"] == "fail"
    other = sign_envelope(
        make_envelope(), signer, issuer="urn:example:impostor", signed_at="2026-10-13T12:05:00Z"
    )
    assert _outcomes(json.loads(other.model_dump_json()), trust)[0]["issuer_trust"] == "fail"


def test_an_unsigned_envelope_is_not_complete(trust: TrustBundle) -> None:
    outcomes, complete = _outcomes(json.loads(make_envelope().model_dump_json()), trust)
    assert outcomes["signature"] == "missing"
    assert not complete


def test_mandatory_status_or_timestamp_evidence_that_is_missing_prevents_completion(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    document = json.loads(signed.model_dump_json())
    needs_status = trust.model_copy(update={"require_status": True})
    outcomes, complete = _outcomes(document, needs_status)
    assert (outcomes["status"], complete) == ("missing", False)
    stale = needs_status.model_copy(update={"status_as_of": "2026-09-01T00:00:00Z"})
    assert _outcomes(document, stale) == (outcomes | {"status": "fail"}, False)
    fresh = needs_status.model_copy(update={"status_as_of": "2026-10-13T00:00:00Z"})
    assert _outcomes(document, fresh)[1] is True
    needs_time = trust.model_copy(update={"require_timestamp": True})
    assert _outcomes(document, needs_time) == (
        outcomes | {"status": "not_checked", "timestamp": "missing"},
        False,
    )


# -- parser differential ----------------------------------------------------------------------


def test_a_repeated_key_cannot_show_one_verdict_to_the_verifier_and_one_to_a_reader(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    raw = signed.model_dump_json(by_alias=True)
    doubled = raw.replace('"verdict":"fail"', '"verdict":"pass","verdict":"fail"', 1)
    assert doubled != raw
    report = verify_json(doubled, trust, AT)
    assert report.dimensions[0].outcome == "fail"
    assert "duplicate object key" in report.dimensions[0].detail
    assert not report.complete


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["decision"].update(results_count="6"),  # a string that lax validation would coerce
        lambda d: d["decision"].update(results_count=6.0),  # a float
        lambda d: d.pop("status_evidence"),  # a field that validation would fill with its default
    ],
)
def test_the_document_must_be_exactly_what_is_verified(
    mutate: Callable[[dict[str, Any]], Any], signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    document = copy.deepcopy(json.loads(signed.model_dump_json(by_alias=True)))
    mutate(document)
    outcomes, complete = _outcomes(document, trust)
    assert outcomes["structure"] == "fail"
    assert not complete
