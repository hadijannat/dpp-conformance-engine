"""Standalone verification of an evidence envelope.

Needs the envelope, an explicit trust bundle, and an explicit evaluation time. It needs
neither the orchestrator nor the system under test, and it does no network I/O.

Implements docs/explanation/architecture.md, section 11.4. Each dimension is reported
separately. The result says nothing new about the tested system.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any, Literal

from pydantic import ValidationError

from dppce.evidence.canonical import CanonicalizationError
from dppce.evidence.envelope import (
    ATTESTATION_TYP,
    decision_digest,
    records_root,
    result_keys,
    results_root,
    verdict_counts,
)
from dppce.evidence.jws import SignatureError, header_of, verify_compact
from dppce.models import (
    Attestation,
    DecisionBody,
    EvidenceEnvelope,
    Modality,
    Tri,
    TrustBundle,
    TrustedKey,
    Verdict,
    VerificationDimension,
    VerificationReport,
)
from dppce.verdicts import overall_verdict

Outcome = Literal["pass", "fail", "missing", "not_checked"]
_STAMP = "%Y-%m-%dT%H:%M:%SZ"
_ALWAYS_MANDATORY = (
    "structure",
    "ordering",
    "results_root",
    "records_root",
    "counts",
    "signature",
    "issuer_trust",
)


def _stamp(value: str) -> datetime:
    return datetime.strptime(value, _STAMP).replace(tzinfo=UTC)


def _ascending(keys: Sequence[Any]) -> bool:
    return all(a < b for a, b in pairwise(keys))


def _ordering(decision: DecisionBody) -> tuple[Outcome, str]:
    lists: dict[str, Sequence[Any]] = {
        "requirement results": [r.requirement_id for r in decision.requirement_results],
        "test results": [t.test_purpose_id for t in decision.test_results],
        "record commitments": [c.record_id for c in decision.record_commitments],
        "exclusions": [(e.kind, e.id) for e in decision.exclusions],
        "conflicts": [c.requirement_id for c in decision.conflicts],
    }
    bad = [name for name, keys in lists.items() if not _ascending(keys)]
    if bad:
        return "fail", f"Not strictly ascending (a duplicate or a reorder): {', '.join(bad)}."
    return "pass", "Every list is strictly ascending by identifier."


def _counts(decision: DecisionBody) -> tuple[Outcome, str]:
    results, coverage = decision.requirement_results, decision.coverage
    excluded = sum(1 for e in decision.exclusions if e.kind == "requirement")
    mandatory = [r for r in results if r.modality is Modality.MANDATORY and r.applicability is Tri.TRUE]
    by_verdict = {k: v for k, v in verdict_counts(results).items() if v}
    if excluded:
        by_verdict["excluded"] = excluded
    checks = {
        "verdict counts": decision.verdict_counts == verdict_counts(results),
        "coverage by verdict": coverage.by_verdict == dict(sorted(by_verdict.items())),
        "coverage total": coverage.total_requirements == len(results) + excluded,
        "excluded count": coverage.excluded == excluded,
        "passing ratio": coverage.passing.denominator == len(mandatory)
        and coverage.passing.numerator == sum(1 for r in mandatory if r.verdict is Verdict.PASS),
        "ratio bounds": all(
            r.numerator <= r.denominator
            for r in (coverage.implementation, coverage.execution, coverage.passing)
        ),
        "overall outcome": decision.overall is overall_verdict(results)[0],
    }
    bad = [name for name, ok in checks.items() if not ok]
    if bad:
        return "fail", f"Stated values differ from the recomputed ones: {', '.join(bad)}."
    return "pass", "Counts, coverage totals, and the overall outcome equal the recomputed values."


def _key_state(key: TrustedKey, trust: TrustBundle, at: datetime) -> str | None:
    """Return why the key is not trusted at ``at``, or None if it is trusted."""
    if "report" not in key.purposes:
        return f"Key '{key.kid}' is not trusted for reports."
    if not _stamp(key.not_before) <= at <= _stamp(key.not_after):
        return f"Key '{key.kid}' is outside its validity period at the evaluation time."
    if key.kid in trust.revoked_kids:
        return f"Key '{key.kid}' is revoked."
    return None


def _signatures(
    envelope: EvidenceEnvelope, digest: str, trust: TrustBundle, at: datetime
) -> tuple[tuple[Outcome, str], tuple[Outcome, str]]:
    """Return the (signature, issuer_trust) outcomes. One good trusted signature is enough."""
    if not envelope.signatures:
        return ("missing", "The envelope has no signature."), (
            "not_checked",
            "There is no signature to attribute.",
        )
    keys = {k.kid: k for k in trust.keys}
    signature: tuple[Outcome, str] = ("not_checked", "No signature names a key in the trust bundle.")
    issuer: tuple[Outcome, str] = (
        "fail",
        "No signature names a key in the trust bundle. A key that only the report supplies is not trusted.",
    )
    for token in envelope.signatures:
        try:
            key = keys.get(str(header_of(token).get("kid")))
            if key is None:
                continue
            attestation = Attestation.model_validate(
                json.loads(verify_compact(token, key.public_jwk, typ=ATTESTATION_TYP))
            )
        except (SignatureError, ValueError) as exc:
            signature = ("fail", f"A signature does not verify: {exc}")
            continue
        bound = (
            attestation.decision_digest == digest
            and attestation.results_root == envelope.decision.results_root
            and attestation.records_root == envelope.decision.records_root
        )
        if not bound:
            signature = ("fail", "A signature verifies but does not bind this decision body.")
            continue
        signature = ("pass", f"Signature by key '{key.kid}' verifies and binds the decision digest.")
        problem = _key_state(key, trust, at)
        if problem is None and attestation.issuer != key.issuer:
            problem = (
                f"The attestation names issuer '{attestation.issuer}', but the key belongs to '{key.issuer}'."
            )
        if problem is None:
            return signature, (
                "pass",
                f"Key '{key.kid}' of issuer '{key.issuer}' is trusted at the evaluation time.",
            )
        issuer = ("fail", problem)
    return signature, issuer


def _status(trust: TrustBundle, at: datetime) -> tuple[Outcome, str]:
    if trust.status_as_of is None:
        return (
            "missing" if trust.require_status else "not_checked"
        ), "No status snapshot is in the trust bundle."
    age = at - _stamp(trust.status_as_of)
    if age < timedelta(0) or age > timedelta(days=trust.status_max_age_days):
        return (
            "fail",
            f"The status snapshot of {trust.status_as_of} is stale or is later than the evaluation time.",
        )
    return (
        "pass",
        f"The status snapshot of {trust.status_as_of} is fresh. Revocation is applied under issuer_trust.",
    )


def _timestamp(envelope: EvidenceEnvelope, trust: TrustBundle) -> tuple[Outcome, str]:
    if not envelope.timestamp_evidence:
        return (
            "missing" if trust.require_timestamp else "not_checked"
        ), "The envelope has no timestamp evidence."
    # ponytail: no RFC 3161 validation yet. Present evidence stays unverified. See BL-004.
    return "not_checked", "Timestamp evidence is present, but this version cannot validate it."


def verify(document: Any, trust: TrustBundle, at: datetime) -> VerificationReport:
    """Verify an envelope given as parsed JSON. ``at`` is the explicit evaluation time."""
    at_text = at.astimezone(UTC).strftime(_STAMP)

    def report(dimensions: dict[str, tuple[Outcome, str]], digest: str) -> VerificationReport:
        mandatory = [
            *_ALWAYS_MANDATORY,
            *(["status"] if trust.require_status else []),
            *(["timestamp"] if trust.require_timestamp else []),
        ]
        return VerificationReport(
            schema_version="dppce.verification/1",
            evaluation_time=at_text,
            decision_digest=digest,
            dimensions=tuple(
                VerificationDimension(name=name, outcome=outcome, detail=detail)
                for name, (outcome, detail) in dimensions.items()
            ),
            complete=all(dimensions[name][0] == "pass" for name in mandatory),
        )

    skipped: tuple[Outcome, str] = ("not_checked", "Not checked because the structure is not valid.")
    names = (*_ALWAYS_MANDATORY[1:], "status", "timestamp")
    try:
        envelope = EvidenceEnvelope.model_validate(document)
        digest = decision_digest(envelope.decision)
    except (ValidationError, CanonicalizationError) as exc:
        first = str(exc).splitlines()[0]
        failed: dict[str, tuple[Outcome, str]] = {
            "structure": ("fail", f"The envelope is not valid: {first}")
        }
        return report(failed | dict.fromkeys(names, skipped), "unavailable")

    decision = envelope.decision
    keys = result_keys(decision.requirement_results, decision.test_results)
    root_ok = results_root(
        decision.requirement_results, decision.test_results
    ) == decision.results_root and decision.results_count == len(keys)
    signature, issuer = _signatures(envelope, digest, trust, at)
    return report(
        {
            "structure": ("pass", "The envelope matches the schema."),
            "ordering": _ordering(decision),
            "results_root": ("pass", f"The root over {len(keys)} results equals the stated root.")
            if root_ok
            else ("fail", "The recomputed results root or count differs from the stated one."),
            "records_root": ("pass", "The root over the record commitments equals the stated root.")
            if records_root(decision.record_commitments) == decision.records_root
            else ("fail", "The recomputed records root differs from the stated one."),
            "counts": _counts(decision),
            "signature": signature,
            "issuer_trust": issuer,
            "status": _status(trust, at),
            "timestamp": _timestamp(envelope, trust),
        },
        digest,
    )
