"""Build, hash, and sign the decision body.

Implements docs/explanation/architecture.md, sections 11.1 to 11.3.
The same leaf and root functions serve the builder and the standalone verifier.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Final

from dppce.evidence import merkle
from dppce.evidence.canonical import canonical_bytes, digest, parse_strict
from dppce.evidence.jws import header_of, payload_of, sign_compact
from dppce.infrastructure.interfaces import Signer
from dppce.models import (
    Attestation,
    Conflict,
    CoverageSummary,
    DecisionBody,
    EvidenceEnvelope,
    Exclusion,
    RecordCommitment,
    RequirementResult,
    RunManifest,
    SignerRole,
    StatusReference,
    TestResult,
    Verdict,
)

ATTESTATION_TYP: Final = "dppce-attestation+jws"


def result_keys(
    requirement_results: Sequence[RequirementResult], test_results: Sequence[TestResult]
) -> list[str]:
    """Leaf keys in the order the lists are given. The verifier checks that they ascend."""
    return [f"R:{r.requirement_id}" for r in requirement_results] + [
        f"T:{t.test_purpose_id}" for t in test_results
    ]


def results_root(requirement_results: Sequence[RequirementResult], test_results: Sequence[TestResult]) -> str:
    leaves = [canonical_bytes(r) for r in requirement_results] + [canonical_bytes(t) for t in test_results]
    return merkle.root("results", leaves).hex()


def records_root(commitments: Sequence[RecordCommitment]) -> str:
    return merkle.root("records", [canonical_bytes(c) for c in commitments]).hex()


def verdict_counts(requirement_results: Sequence[RequirementResult]) -> dict[str, int]:
    """Count of requirement results per verdict. Every verdict appears, also with count zero."""
    seen = Counter(r.verdict.value for r in requirement_results)
    return {verdict.value: seen.get(verdict.value, 0) for verdict in Verdict}


def build_decision(
    *,
    manifest: RunManifest,
    overall: Verdict,
    overall_reason: str,
    requirement_results: Sequence[RequirementResult],
    test_results: Sequence[TestResult],
    exclusions: Sequence[Exclusion],
    conflicts: Sequence[Conflict],
    coverage: CoverageSummary,
    record_commitments: Sequence[RecordCommitment],
) -> DecisionBody:
    """Assemble the canonical decision body with sorted lists, counts, and roots."""
    requirements = tuple(sorted(requirement_results, key=lambda r: r.requirement_id))
    tests = tuple(sorted(test_results, key=lambda t: t.test_purpose_id))
    commitments = tuple(sorted(record_commitments, key=lambda c: c.record_id))
    return DecisionBody(
        schema_version="dppce.decision/2",
        manifest=manifest,
        overall=overall,
        overall_reason=overall_reason,
        requirement_results=requirements,
        test_results=tests,
        exclusions=tuple(sorted(exclusions, key=lambda e: (e.kind, e.id))),
        conflicts=tuple(sorted(conflicts, key=lambda c: c.requirement_id)),
        coverage=coverage,
        verdict_counts=verdict_counts(requirements),
        results_root=results_root(requirements, tests),
        results_count=len(requirements) + len(tests),
        record_commitments=commitments,
        records_root=records_root(commitments),
    )


def decision_digest(decision: DecisionBody) -> str:
    return digest(decision)


def in_layout_of(decision: DecisionBody, version: str) -> DecisionBody:
    """Return a new body in the layout of ``version``, so that a replay compares like with like.

    A dppce.decision/1 body has no bound_files. A replay of a version 1 run therefore does not
    detect a changed bound file, exactly as version 1 did not.
    """
    if version == "dppce.decision/1" and decision.schema_version != version:
        manifest = decision.manifest.model_copy(update={"bound_files": None})
        return decision.model_copy(update={"schema_version": version, "manifest": manifest})
    return decision


def sign_envelope(
    envelope: EvidenceEnvelope,
    signer: Signer,
    *,
    issuer: str,
    signed_at: str,
    role: SignerRole = "issuer",
    status: StatusReference | None = None,
    valid_until: str | None = None,
    supersedes: str | None = None,
) -> EvidenceEnvelope:
    """Return a copy of the envelope with one more signature over the decision digest.

    It writes ``dppce.attestation/1`` for a plain issuer signature, so that its bytes do not
    change, and ``dppce.attestation/2`` otherwise (section 11.3).
    """
    plain = role == "issuer" and status is None and valid_until is None and supersedes is None
    attestation = Attestation(
        schema_version="dppce.attestation/1" if plain else "dppce.attestation/2",
        decision_digest=decision_digest(envelope.decision),
        results_root=envelope.decision.results_root,
        records_root=envelope.decision.records_root,
        issuer=issuer,
        signed_at=signed_at,
        role=None if plain else role,
        status=status,
        valid_until=valid_until,
        supersedes=supersedes,
    )
    token = sign_compact(canonical_bytes(attestation), signer, typ=ATTESTATION_TYP)
    return envelope.model_copy(update={"signatures": (*envelope.signatures, token)})


def declared_attestation(token: str) -> tuple[str | None, Attestation | None]:
    """Return the key identifier and the attestation that ``token`` declares. NOT verified.

    For display only. ``(None, None)`` if the token cannot be read.
    """
    try:
        return str(header_of(token).get("kid")), Attestation.model_validate(parse_strict(payload_of(token)))
    except (ValueError, RecursionError):
        return None, None
