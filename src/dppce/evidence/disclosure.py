"""Record openings and inclusion proofs: disclose one record or one result of a report.

Formats: docs/explanation/architecture.md, sections 10.2 and 11.2. Checks: section 11.4,
"Record openings and inclusion proofs". A file is checked against the envelope, never against
a root that the file states. No network I/O, no recording, and no data key are needed to check.
"""

from __future__ import annotations

import base64
import hmac
from collections.abc import Mapping
from typing import Final, Literal

from pydantic import ValidationError

from dppce.evidence import merkle
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, is_exact, parse_strict
from dppce.evidence.envelope import decision_digest, result_keys
from dppce.evidence.recording import commit, commitment_of, record_to_json
from dppce.infrastructure.interfaces import Record
from dppce.models import (
    DecisionBody,
    InclusionProof,
    Model,
    OpenedRecord,
    RecordCommitment,
    RecordOpening,
)

Outcome = Literal["pass", "fail", "not_checked"]
MAX_OPENING_BYTES: Final = 64 * 1024 * 1024
MAX_PROOF_BYTES: Final = 1024 * 1024
NOT_CHECKED: Final = "Not checked because the root of the report does not match its body."
NOT_ORDERED: Final = (
    "Not checked because the dimension ordering does not pass: an index is a position in key order."
)


class DisclosureError(ValueError):
    """An opening or a proof cannot be made or does not check. ``code`` is a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _proof(decision: DecisionBody, label: Literal["results", "records"], index: int) -> InclusionProof:
    leaves: list[Model]
    if label == "results":
        leaves = [*decision.requirement_results, *decision.test_results]
        key, root = (
            result_keys(decision.requirement_results, decision.test_results)[index],
            decision.results_root,
        )
    else:
        leaves = list(decision.record_commitments)
        key, root = decision.record_commitments[index].record_id, decision.records_root
    path = merkle.inclusion_proof(label, [canonical_bytes(leaf) for leaf in leaves], index)
    return InclusionProof.model_validate(
        {
            "schema_version": "dppce.proof/1",
            "decision_digest": decision_digest(decision),
            "label": label,
            "key": key,
            "index": index,
            "size": len(leaves),
            "leaf": leaves[index],
            "path": tuple(h.hex() for h in path),
            "root": root,
        }
    )


def prove(decision: DecisionBody, key: str) -> InclusionProof:
    """The inclusion proof of the result ``key`` ("R:" or "T:" plus an identifier)."""
    keys = result_keys(decision.requirement_results, decision.test_results)
    if key not in keys:
        raise DisclosureError("PROVE.RESULT.UNKNOWN", f"the report holds no result with the key {key!r}")
    return _proof(decision, "results", keys.index(key))


def open_record(decision: DecisionBody, record: Record) -> RecordOpening:
    """The salt and the plaintext of ``record``, with the proof of its commitment in the report."""
    ids = [c.record_id for c in decision.record_commitments]
    if record.record_id not in ids:
        raise DisclosureError(
            "OPEN.RECORD.NOT_IN_REPORT", f"the report holds no commitment to the record {record.record_id!r}"
        )
    index = ids.index(record.record_id)
    if not hmac.compare_digest(decision.record_commitments[index].commitment, commit(record)):
        raise DisclosureError(
            "OPEN.RECORD.NOT_IN_REPORT",
            f"the commitment of the record {record.record_id!r} differs from the commitment in the report",
        )
    return RecordOpening(
        schema_version="dppce.opening/1",
        record=OpenedRecord.model_validate(record_to_json(record, with_salt=False)),
        salt=base64.b64encode(record.salt).decode("ascii"),
        proof=_proof(decision, "records", index),
    )


def _parse[M: Model](raw: bytes, model: type[M], limit: int, *, too_large: str, malformed: str) -> M:
    """Strict JSON, then the model, then the exact canonical form. A coerced value fails."""
    if len(raw) > limit:
        raise DisclosureError(too_large, f"the file is larger than {limit} bytes")
    try:
        document = parse_strict(raw)
        parsed = model.model_validate(document)
    except CanonicalizationError as exc:
        raise DisclosureError(malformed, "the file is not strict JSON") from exc
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"])
        raise DisclosureError(
            malformed, f"the file is not a valid document: {first['type']} at {location!r}"
        ) from exc
    if not is_exact(document, parsed):
        raise DisclosureError(
            malformed,
            "the document is not in the exact canonical form of the schema "
            "(a field is missing, a type differs, or a number is not an integer)",
        )
    return parsed


def _check_proof(proof: InclusionProof, decision: DecisionBody) -> None:
    """Steps 3 and 4 of the proof checks. The root and the size come from the report."""
    if proof.label == "results":
        root, size = decision.results_root, decision.results_count
    else:
        root, size = decision.records_root, len(decision.record_commitments)
    if proof.decision_digest != decision_digest(decision) or proof.root != root or proof.size != size:
        raise DisclosureError(
            "PROOF.REPORT.MISMATCH", "the decision digest, the root, or the size differs from the report"
        )
    if not merkle.verify_inclusion(
        proof.label,
        canonical_bytes(proof.leaf),
        index=proof.index,
        size=size,
        proof=[bytes.fromhex(h) for h in proof.path],
        expected_root=bytes.fromhex(root),
    ):
        raise DisclosureError(
            "PROOF.PATH.INVALID",
            f"the path does not lead from the leaf {proof.key!r} to the root of the report",
        )


def check_proof_file(
    raw: bytes, decision: DecisionBody, roots_ok: Mapping[str, bool], *, ordered: bool
) -> tuple[Outcome, str]:
    """The dimension ``proof``. ``roots_ok`` says, for each tree label, whether its root dimension passed.

    ``ordered`` says whether the dimension ``ordering`` passed.
    """
    try:
        proof = _parse(
            raw,
            InclusionProof,
            MAX_PROOF_BYTES,
            too_large="PROOF.FILE.TOO_LARGE",
            malformed="PROOF.FILE.MALFORMED",
        )
        if not roots_ok[proof.label]:
            return "not_checked", NOT_CHECKED
        if not ordered:
            return "not_checked", NOT_ORDERED
        _check_proof(proof, decision)
    except DisclosureError as exc:
        return "fail", f"{exc.code}: {exc}."
    leaf = proof.leaf
    if isinstance(leaf, RecordCommitment):
        kind, verdict = "commitment", ""
    else:
        kind, verdict = "result", f", with the verdict {leaf.verdict.value}"
    return "pass", (
        f"PROOF.LEAF.OK: the {proof.label} tree of the report holds the {kind} {proof.key!r} at index "
        f"{proof.index} of {proof.size}{verdict}."
    )


def check_opening_file(
    raw: bytes, decision: DecisionBody, roots_ok: Mapping[str, bool], *, ordered: bool
) -> tuple[Outcome, str]:
    """The dimension ``opening``: the commitment, then the embedded proof against the report."""
    try:
        opening = _parse(
            raw,
            RecordOpening,
            MAX_OPENING_BYTES,
            too_large="OPENING.FILE.TOO_LARGE",
            malformed="OPENING.FILE.MALFORMED",
        )
        salt = base64.b64decode(opening.salt, validate=True)
        # One string per salt: the pattern of the model still lets the two unused bits vary.
        if base64.b64encode(salt).decode("ascii") != opening.salt:
            raise DisclosureError(
                "OPENING.FILE.MALFORMED", "the salt is not the canonical base64 of 32 bytes"
            )
        if not roots_ok["records"]:
            return "not_checked", NOT_CHECKED
        if not ordered:
            return "not_checked", NOT_ORDERED
        leaf = opening.proof.leaf
        computed = commitment_of(salt, canonical_bytes(opening.record))
        if not isinstance(leaf, RecordCommitment) or not hmac.compare_digest(computed, leaf.commitment):
            raise DisclosureError(
                "OPENING.COMMITMENT.MISMATCH",
                "the salt and the plaintext do not give the commitment of the proof",
            )
        _check_proof(opening.proof, decision)
    except DisclosureError as exc:
        return "fail", f"{exc.code}: {exc}."
    return "pass", (
        f"OPENING.RECORD.OK: the record {opening.record.record_id!r} opens its commitment, and the "
        "records tree of the report holds that commitment."
    )
