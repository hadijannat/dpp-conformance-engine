"""Standalone verification of an evidence envelope.

Needs the envelope, an explicit trust bundle, and an explicit evaluation time. It needs
neither the orchestrator nor the system under test, and it does no network I/O.

Implements docs/explanation/architecture.md, section 11.4. Each dimension is reported
separately. The result says nothing new about the tested system.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any, Literal

from pydantic import ValidationError

from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, is_exact, parse_strict
from dppce.evidence.envelope import (
    ATTESTATION_TYP,
    decision_digest,
    records_root,
    result_keys,
    results_root,
    verdict_counts,
)
from dppce.evidence.jws import SignatureError, header_of, verify_compact
from dppce.evidence.manual import MANUAL_CHECK, ManualResultError, verify_manual_result
from dppce.evidence.timestamp import MAX_TOKENS, Stamp, TimestampError, format_time, imprint_of, verify_token
from dppce.models import (
    NOT_ACCREDITED,
    Attestation,
    AuthorityClass,
    DecisionBody,
    EvidenceEnvelope,
    ExecutionStatus,
    IssuerStatement,
    Modality,
    ReviewStatus,
    Testability,
    Tri,
    TrustBundle,
    TrustedKey,
    Verdict,
    VerificationDimension,
    VerificationReport,
)
from dppce.verdicts import claim_level, overall_verdict, path_verdict, requirement_verdict
from dppce.verdicts.coverage import RATIO_LABELS

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
    "manual_results",
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


def _verdicts_follow(decision: DecisionBody) -> bool:
    """True if each path and requirement verdict follows from the test results in the report.

    The signature shows that the issuer made the report. It does not show that the report agrees
    with itself. This derives each verdict again with the published rules.
    """
    tests = {t.test_purpose_id: t.verdict for t in decision.test_results}
    conflicts = {c.requirement_id for c in decision.conflicts}
    for result in decision.requirement_results:
        for path in result.paths:
            # A step with no result in the report is missing evidence, as in the aggregation.
            steps = [tests.get(step, Verdict.INCONCLUSIVE) for step in path.steps]
            if path_verdict(path.applicability, steps) is not path.verdict:
                return False
        derived = requirement_verdict(
            result.applicability,
            result.requirement_id in conflicts,
            [p.verdict for p in result.paths],
            decision.manifest.mode,
            result.review_status,
        )
        # The reason is part of what the reader sees, so it must follow too.
        if derived != (result.verdict, result.verdict_reason):
            return False
    return True


def _coverage_follows(decision: DecisionBody, excluded: int) -> dict[str, bool]:
    """The coverage figures that the report holds enough data to recompute, as in ``summarize``.

    The figures over all requirements (by authority class, review status, testability, the
    implementation ratio, and placeholders) also count excluded requirements, which a report
    lists by identifier only. Those are checked for their totals and bounds.
    """
    results, coverage = decision.requirement_results, decision.coverage
    status = {t.test_purpose_id: t.execution_status for t in decision.test_results}
    applicability = Counter([r.applicability.value for r in results] + ["excluded"] * excluded)
    manual = sum(
        1
        for r in results
        if any(status.get(step) is ExecutionStatus.MANUAL_UNAVAILABLE for p in r.paths for step in p.steps)
    )
    total = coverage.total_requirements
    placeholders = sum(1 for r in results if r.review_status is ReviewStatus.PLACEHOLDER)

    def bucket_fits(counts: dict[str, int], values: list[str], known: set[str]) -> bool:
        # Each known value counts at least the results that have it; the surplus is the excluded.
        seen = Counter(values)
        return (
            set(counts) <= known
            and all(n >= 0 for n in counts.values())
            and all(counts.get(value, 0) >= n for value, n in seen.items())
            and sum(counts.values()) == total
        )

    ratios = {
        "implementation": coverage.implementation,
        "execution": coverage.execution,
        "passing": coverage.passing,
    }
    return {
        "coverage by applicability": coverage.by_applicability == dict(sorted(applicability.items())),
        "unknown applicability": coverage.unknown_applicability
        == sum(1 for r in results if r.applicability is Tri.UNKNOWN),
        "manual steps missing": coverage.manual_missing == manual,
        "placeholder bounds": placeholders <= coverage.placeholders <= placeholders + excluded
        and coverage.placeholders == coverage.by_review_status.get(ReviewStatus.PLACEHOLDER.value, 0),
        "authority classes": bucket_fits(
            coverage.by_authority_class,
            [r.authority_class.value for r in results],
            {e.value for e in AuthorityClass},
        ),
        "review statuses": bucket_fits(
            coverage.by_review_status,
            [r.review_status.value for r in results],
            {e.value for e in ReviewStatus},
        ),
        "testabilities": bucket_fits(
            coverage.by_testability, [r.testability.value for r in results], {e.value for e in Testability}
        ),
        # The implementation ratio needs the catalogue paths, which a report does not hold. Its
        # numerator is checked for its bounds only; its denominator is every known requirement.
        "implementation denominator": coverage.implementation.denominator == total,
        "ratio labels": all(ratios[name].of == label for name, label in RATIO_LABELS.items()),
    }


def _execution_coverage(decision: DecisionBody) -> tuple[int, int]:
    """Recompute the execution ratio: applicable requirements with one completed path."""
    status = {t.test_purpose_id: t.execution_status for t in decision.test_results}
    applicable = [r for r in decision.requirement_results if r.applicability is Tri.TRUE]
    done = sum(
        1
        for r in applicable
        if any(
            p.applicability is Tri.TRUE
            and p.steps
            and all(status.get(step) is ExecutionStatus.COMPLETED for step in p.steps)
            for p in r.paths
        )
    )
    return done, len(applicable)


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
        "overall outcome": (decision.overall, decision.overall_reason) == overall_verdict(results),
        "claim levels": all(
            r.claim_level is claim_level(decision.manifest.mode, r.authority_class, r.review_status)
            for r in results
        ),
        "verdicts follow from the test results": _verdicts_follow(decision),
        "pass and fail only for a completed step": all(
            t.execution_status is ExecutionStatus.COMPLETED
            for t in decision.test_results
            if t.verdict in (Verdict.PASS, Verdict.FAIL)
        ),
        "execution ratio": (coverage.execution.numerator, coverage.execution.denominator)
        == _execution_coverage(decision),
        **_coverage_follows(decision, excluded),
    }
    bad = [name for name, ok in checks.items() if not ok]
    if bad:
        return "fail", f"Stated values differ from the recomputed ones: {', '.join(bad)}."
    # The implementation ratio needs the catalogue and the installed capabilities, which a report
    # does not hold. It is checked for its bounds only.
    return "pass", "Counts, verdicts, coverage totals, and the overall outcome equal the recomputed values."


def _key_state(key: TrustedKey, trust: TrustBundle, at: datetime, when: str) -> str | None:
    """Return why the key is not trusted at ``at``, or None if it is trusted. ``when`` names ``at``."""
    if "report" not in key.purposes:
        return f"Key '{key.kid}' is not trusted for reports."
    if not _stamp(key.not_before) <= at <= _stamp(key.not_after):
        return f"Key '{key.kid}' is outside its validity period at {when}."
    if trust.key_revoked(key.kid, at):
        return f"Key '{key.kid}' is revoked at {when}."
    return None


@dataclass(frozen=True)
class _Signed:
    """A signature that verifies with a key of the trust bundle and binds the decision body."""

    token: str
    key: TrustedKey
    attestation: Attestation


def _verified(
    envelope: EvidenceEnvelope, digest: str, trust: TrustBundle
) -> tuple[tuple[Outcome, str], list[_Signed]]:
    """Return the signature outcome and every signature that verifies and binds, in order.

    Key state is not checked here: ``issuer_trust`` checks it at the key validity time.
    """
    if not envelope.signatures:
        return ("missing", "The envelope has no signature."), []
    keys = {k.kid: k for k in trust.keys}
    failure: tuple[Outcome, str] | None = None
    verified: list[_Signed] = []
    for token in envelope.signatures:
        try:
            key = keys.get(str(header_of(token).get("kid")))
            if key is None:
                continue
            payload = verify_compact(token, key.public_jwk, typ=ATTESTATION_TYP)
            attestation = Attestation.model_validate(parse_strict(payload))
            if canonical_bytes(attestation) != payload:
                raise SignatureError("the signed payload is not a canonical attestation")
        except (SignatureError, ValueError) as exc:
            failure = ("fail", f"A signature does not verify: {exc}")
            continue
        bound = (
            attestation.decision_digest == digest
            and attestation.results_root == envelope.decision.results_root
            and attestation.records_root == envelope.decision.records_root
        )
        if not bound:
            failure = ("fail", "A signature verifies but does not bind this decision body.")
            continue
        verified.append(_Signed(token, key, attestation))
    if verified:
        first = verified[0].key.kid
        return ("pass", f"Signature by key '{first}' verifies and binds the decision digest."), verified
    return failure or ("not_checked", "No signature names a key in the trust bundle."), verified


def _timestamps(
    envelope: EvidenceEnvelope, verified: list[_Signed], trust: TrustBundle, at: datetime
) -> tuple[tuple[Outcome, str], dict[str, datetime]]:
    """Return the timestamp outcome and the earliest good genTime for each signature (ADR 0015)."""
    tokens = envelope.timestamp_evidence
    if not tokens:
        missing: Outcome = "missing" if trust.require_timestamp else "not_checked"
        return (missing, "The envelope has no timestamp evidence."), {}
    if not verified:
        return (
            "not_checked",
            "TIMESTAMP.SIGNATURE.NONE: no signature verifies, so no timestamp can bind one.",
        ), {}
    if len(tokens) > MAX_TOKENS:
        return (
            "fail",
            f"TIMESTAMP.EVIDENCE.TOO_MANY: the envelope holds {len(tokens)} tokens; "
            f"the limit is {MAX_TOKENS}.",
        ), {}
    by_imprint: dict[bytes, list[_Signed]] = {}
    for signed in verified:
        by_imprint.setdefault(imprint_of(signed.token), []).append(signed)
    times: dict[str, datetime] = {}
    good: tuple[Stamp, str] | None = None
    first_error: str | None = None
    for index, text in enumerate(tokens):
        try:
            stamp = verify_token(text, by_imprint.keys(), trust, at)
        except TimestampError as exc:
            # Only TimestampError: any other exception is a defect that the property tests must find.
            first_error = first_error or f"{exc.code}: token {index}: {exc}"
            continue
        for signed in by_imprint[stamp.imprint]:
            if signed.token not in times or stamp.gen_time < times[signed.token]:
                times[signed.token] = stamp.gen_time
        good = good or (stamp, by_imprint[stamp.imprint][0].key.kid)
    if good is None:
        return ("fail", first_error or "TIMESTAMP.TOKEN.MALFORMED: no token can be read."), times
    stamp, kid = good
    return (
        "pass",
        f"TIMESTAMP.OK: A token of the timestamp authority {stamp.tsa_subject!r} states "
        f"{format_time(stamp.gen_time)} for the signature of key '{kid}'.",
    ), times


def _issuer(
    envelope: EvidenceEnvelope,
    verified: list[_Signed],
    times: dict[str, datetime],
    trust: TrustBundle,
    at: datetime,
) -> tuple[Outcome, str]:
    """Return the issuer_trust outcome. The first signature with no problem gives pass.

    Each signature is checked at its key validity time: the earliest genTime of a good token over
    that signature, or else the evaluation time. Each detail names the time used.
    """
    if not envelope.signatures:
        return "not_checked", "There is no signature to attribute."
    statement = envelope.decision.manifest.issuer
    problem: str | None = None
    for signed in verified:
        key, stamped = signed.key, signed.token in times
        valid_at = times.get(signed.token, at)
        when = (
            f"{format_time(valid_at)}, the genTime of a trusted timestamp over its signature"
            if stamped
            else "the evaluation time"
        )
        problem = _key_state(key, trust, valid_at, when)
        if problem is None and signed.attestation.issuer != key.issuer:
            problem = (
                f"The attestation names issuer '{signed.attestation.issuer}', but the key belongs to "
                f"'{key.issuer}'. Key validity was checked at {when}."
            )
        if problem is None and (stated := _issuer_problem(statement, key)) is not None:
            problem = f"{stated} Key validity was checked at {when}."
        if problem is None:
            reference = statement.accreditation_reference
            return (
                "pass",
                f"Key '{key.kid}' of issuer '{key.issuer}' is trusted at {when}, and the "
                "report states that issuer. The verifier does not check the issuer name. Accreditation "
                f"status as declared by the operator: {statement.accreditation_status!r}, reference "
                f"{repr(reference) if reference else 'none'}. The engine does not validate accreditation.",
            )
    return "fail", problem or (
        "No signature names a key in the trust bundle. A key that only the report supplies is not trusted."
    )


def _issuer_problem(statement: IssuerStatement, key: TrustedKey) -> str | None:
    """Bind the stated issuer to the key (ADR 0014). ``repr`` escapes each value of the report."""
    if statement.identifier == "unspecified":
        # Also when a trust bundle names a key with this issuer: a signed report must name its issuer.
        return (
            "ISSUER.STATEMENT.UNSPECIFIED: The report states the issuer 'unspecified'. "
            f"Key '{key.kid}' belongs to {key.issuer!r}."
        )
    if statement.identifier != key.issuer:
        return (
            f"ISSUER.STATEMENT.MISMATCH: The report states the issuer {statement.identifier!r}, "
            f"but key '{key.kid}' belongs to {key.issuer!r}."
        )
    if statement.accreditation_status != NOT_ACCREDITED and not statement.accreditation_reference.strip():
        return (
            "ISSUER.ACCREDITATION.NO_REFERENCE: The report states the accreditation status "
            f"{statement.accreditation_status!r} with no reference."
        )
    return None


def _manual_results(decision: DecisionBody, trust: TrustBundle, at: datetime) -> tuple[Outcome, str]:
    """Bind each completed manual step to a committed record and a performer signature (section 11.4).

    The JWS in the observation is enough: no recording is needed. ``expected_evidence`` is not
    checked here, because the report does not hold the test pack. The engine checks it.
    """
    steps = [
        t
        for t in decision.test_results
        if t.check == MANUAL_CHECK and t.execution_status is ExecutionStatus.COMPLETED
    ]
    if not steps:
        return "pass", "The report holds no completed manual step."
    try:
        evaluated = _stamp(decision.manifest.evaluation_time)
    except ValueError:
        return "fail", "The evaluation time of the manifest is not a valid time."
    committed = {c.record_id for c in decision.record_commitments}
    for t in steps:
        signed = [o for o in t.observations if isinstance(o.summary.get("jws"), str)]
        if len(signed) != 1:
            return "fail", f"{t.test_purpose_id}: the step has no single observation with a signed result."
        (observation,) = signed
        if (
            observation.kind != "artifact"
            or not observation.record_ids
            or not set(observation.record_ids) <= committed
        ):
            return "fail", f"{t.test_purpose_id}: the signed result references no committed record."
        stated_digest = observation.summary.get("test_purpose_digest")
        if not isinstance(stated_digest, str):
            return "fail", f"{t.test_purpose_id}: the step states no digest of its test purpose."
        try:
            # The report holds no test pack, so the signed digest is compared with the stated one.
            result, key = verify_manual_result(
                str(observation.summary["jws"]),
                trust,
                test_purpose_id=t.test_purpose_id,
                test_purpose_digest=stated_digest,
                sut=decision.manifest.sut,
                evaluation_time=evaluated,
                key_valid_at=at,
            )
        except ManualResultError as exc:
            return "fail", f"{t.test_purpose_id}: {exc.code}: {exc}"
        shown = {k: observation.summary.get(k) for k in ("kid", "role", "performed_at", "outcome")}
        if shown != {
            "kid": key.kid,
            "role": result.role,
            "performed_at": result.performed_at,
            "outcome": result.outcome,
        }:
            return "fail", f"{t.test_purpose_id}: the observation differs from the signed result."
        if (result.outcome == "pass") != (t.verdict is Verdict.PASS):
            return "fail", f"{t.test_purpose_id}: the verdict differs from the signed outcome."
    return "pass", f"{len(steps)} manual results verify for the purpose 'manual' and bind their steps."


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


def verify_json(raw: bytes | str, trust: TrustBundle, at: datetime) -> VerificationReport:
    """Verify an envelope given as JSON text. This is the entry point for a file.

    The text is parsed strictly: a repeated object key makes the structure check fail.
    """
    try:
        document = parse_strict(raw)
    except CanonicalizationError as exc:
        document = _Unparseable(str(exc))
    return verify(document, trust, at)


class _Unparseable:
    def __init__(self, reason: str) -> None:
        self.reason = reason


def verify(document: Any, trust: TrustBundle, at: datetime) -> VerificationReport:
    """Verify an envelope given as parsed JSON. ``at`` is the explicit evaluation time.

    Prefer ``verify_json`` for a file: only a strict parse can detect a repeated object key.
    """
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
        if isinstance(document, _Unparseable):
            raise CanonicalizationError(document.reason)
        envelope = EvidenceEnvelope.model_validate(document)
        # The verified model must be exactly the document. No default, no coerced value.
        if not is_exact(document, envelope):
            raise CanonicalizationError(
                "the document is not in the exact canonical form of the schema "
                "(a field is missing, a type differs, or a number is not an integer)"
            )
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
    signature, verified = _verified(envelope, digest, trust)
    timestamp, times = _timestamps(envelope, verified, trust, at)
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
            "issuer_trust": _issuer(envelope, verified, times, trust, at),
            "manual_results": _manual_results(decision, trust, at),
            "status": _status(trust, at),
            "timestamp": timestamp,
        },
        digest,
    )
