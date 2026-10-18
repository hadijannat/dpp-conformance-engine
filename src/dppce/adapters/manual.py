"""Manual adapter: verify the signed result of a manual step. The engine does not perform the review.

Contract: docs/explanation/architecture.md, section 8.1.
"""

from __future__ import annotations

from dppce.adapters.common import completed
from dppce.evidence.canonical import digest
from dppce.evidence.manual import MANUAL_CHECK, SAMPLE_PREFIX, ManualResultError, verify_manual_result
from dppce.models import CheckOutcome, ExecutionStatus
from dppce.testdefs.registry import CheckContext, NoParams, register

_ACCEPTED = (
    "A person signed this result. The engine verified the signature, the key, and the binding to "
    "this step. It did not perform the review."
)


# Explicit: a manual step takes no parameters, and CAT019 refuses any key (section 8).
@register(MANUAL_CHECK, capability="manual.review", params=NoParams)
def review(ctx: CheckContext) -> CheckOutcome:
    record = ctx.acquirer.artifact(SAMPLE_PREFIX + ctx.purpose.id)
    # A refused file puts none of its content in the report: the observation holds the record id only.
    refused = (ctx.observation(0, kind="artifact", records=[record]),)

    def unavailable(code: str, message: str) -> CheckOutcome:
        return CheckOutcome(
            status=ExecutionStatus.MANUAL_UNAVAILABLE, reason_code=code, message=message, observations=refused
        )

    if record.error == "body_too_large":
        return unavailable("MANUAL.RESULT.TOO_LARGE", "The manual result is larger than the limit.")
    if record.error is not None:
        # A replay mismatch is turned into an execution error by the run core.
        return unavailable("MANUAL.RESULT.MISSING", "No manual result is available for this step.")
    if ctx.trust is None:
        return CheckOutcome(
            status=ExecutionStatus.ERROR,
            reason_code="MANUAL.TRUST.MISSING",
            message="A manual result needs a trust bundle that names the key of its performer.",
            observations=refused,
        )
    try:
        token = record.body.decode("ascii").strip()
    except UnicodeDecodeError:
        return unavailable("MANUAL.RESULT.MALFORMED", "The manual result is not a compact JWS.")
    purpose_digest = digest(ctx.purpose)
    try:
        result, key = verify_manual_result(
            token,
            ctx.trust,
            test_purpose_id=ctx.purpose.id,
            test_purpose_digest=purpose_digest,
            sut=ctx.ics.sut,
            evaluation_time=ctx.evaluation_time,
            key_valid_at=ctx.evaluation_time,
        )
    except ManualResultError as exc:
        return unavailable(exc.code, f"The manual result is refused: {exc}")
    expected = ctx.purpose.expected_evidence
    if result.evidence != expected:
        # Counts only: the texts could carry data that the report must not hold.
        message = (
            f"The result lists {len(result.evidence)} evidence items. The test purpose expects "
            f"{len(expected)} items with the same text, in the same order."
        )
        return unavailable("MANUAL.EVIDENCE.MISMATCH", message)
    summary = {
        "jws": token,
        "kid": key.kid,
        "role": result.role,
        "performed_at": result.performed_at,
        "outcome": result.outcome,
        # The verifier has no test pack. It compares the signed digest with this one (section 11.4).
        "test_purpose_digest": purpose_digest,
    }
    observation = ctx.observation(
        0, kind="artifact", records=[record], summary=summary, transformations=("jws_verify",)
    )
    passed = result.outcome == "pass"
    code = "MANUAL.REVIEW.OK" if passed else "MANUAL.REVIEW.FAILED"
    return completed(passed, code, _ACCEPTED, [observation])
