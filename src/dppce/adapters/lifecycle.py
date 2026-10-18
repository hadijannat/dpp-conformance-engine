"""Persistence, registry, and Asset Administration Shell adapters.

Each of these checks states a limit that its verdict must not hide:

- A few observations cannot prove that a passport stays available for the life of a product.
  Changed content is not by itself unlawful: the check compares with the declared update rule.
- A failed or unauthorized registry lookup does not prove that a registration is missing.
- A valid Asset Administration Shell is not a complete DPP conformance statement.
"""

from __future__ import annotations

from datetime import datetime
from itertools import pairwise
from typing import Any

from pydantic import Field

from dppce.adapters.common import (
    MISSING,
    blocked,
    completed,
    dig,
    fetch_once,
    json_object,
    not_200,
    not_done,
    resource_url,
    same_json,
    unusable,
)
from dppce.evidence.canonical import CanonicalizationError, digest, parse_strict
from dppce.infrastructure.clock import parse_instant
from dppce.models import CheckOutcome, ExecutionStatus, Model
from dppce.testdefs.registry import CheckContext, register


@register("persistence.versions", capability="persistence.versions")
def versions(ctx: CheckContext) -> CheckOutcome:
    versions_url = resource_url(ctx, "versions", "PERSISTENCE")
    if isinstance(versions_url, CheckOutcome):
        return versions_url
    item_url = resource_url(ctx, "item", "PERSISTENCE")
    if isinstance(item_url, CheckOutcome):
        return item_url
    history, item = fetch_once(ctx, versions_url), fetch_once(ctx, item_url)
    for record in (history, item):
        if (
            problem := unusable(ctx, record) or not_200(ctx, "PERSISTENCE", record, [history, item])
        ) is not None:
            return problem
    listing, current = json_object(history), json_object(item)
    entries = listing.get("versions") if listing else None
    if not isinstance(entries, list) or not entries or current is None:
        observation = ctx.observation(
            0, kind="exchange", records=[history, item], summary={"status": history.status}
        )
        return completed(
            False, "PERSISTENCE.RESPONSE.NOT_JSON", "The version history is not usable JSON.", [observation]
        )
    problems: list[str] = []
    numbers = [e["version"] for e in entries if isinstance(e, dict) and type(e.get("version")) is int]
    if len(numbers) != len(entries) or any(a >= b for a, b in pairwise(numbers)):
        problems.append("version numbers do not strictly ascend")
    # Instants, not text: an offset or a fraction changes the text order.
    stamps = [_instant(e.get("updated_at") if isinstance(e, dict) else None) for e in entries]
    known = [stamp for stamp in stamps if stamp is not None]
    if len(known) != len(stamps):
        problems.append("an update time is missing or is not an RFC 3339 date-time with an offset")
    elif any(a > b for a, b in pairwise(known)):
        problems.append("an update time goes back")
    last = entries[-1].get("content_digest") if isinstance(entries[-1], dict) else None
    try:
        current_digest: str | None = digest(current)
    except CanonicalizationError:
        current_digest = None
    if current_digest is not None and last != current_digest:
        problems.append("the last digest is not the digest of the current passport")
    summary: dict[str, Any] = {"entries": len(entries), "problems": problems}
    observation = ctx.observation(0, kind="exchange", records=[history, item], summary=summary)
    limit = "A few observations cannot prove lifetime availability."
    if problems:
        message = f"The history breaks the declared update rule: {'; '.join(problems)}. {limit}"
        return completed(False, "PERSISTENCE.UNDECLARED_CHANGE", message, [observation])
    if current_digest is None:
        # The passport holds a number outside the canonical range, so its digest cannot be compared.
        message = "The current passport has no canonical form, so the engine cannot compare its digest."
        return blocked("PERSISTENCE.DIGEST.NOT_COMPARABLE", message)
    return completed(
        True, "PERSISTENCE.OK", f"The version history obeys the declared update rule. {limit}", [observation]
    )


def _instant(value: Any) -> datetime | None:
    try:
        return parse_instant(value) if isinstance(value, str) else None
    except ValueError:
        return None


@register("registry.consistency", capability="registry.mock")
def registry_consistency(ctx: CheckContext) -> CheckOutcome:
    record_url = resource_url(ctx, "registry_record", "REGISTRY")
    if isinstance(record_url, CheckOutcome):
        return record_url
    item_url = resource_url(ctx, "item", "REGISTRY")
    if isinstance(item_url, CheckOutcome):
        return item_url
    lookup = fetch_once(ctx, record_url)
    if (problem := unusable(ctx, lookup)) is not None:
        return problem
    if lookup.status in (401, 403, 404):
        observation = ctx.observation(0, kind="exchange", records=[lookup], summary={"status": lookup.status})
        message = (
            f"The lookup answers {lookup.status}. A failed lookup does not prove a missing registration."
        )
        return completed(False, "REGISTRY.LOOKUP.NOT_CONCLUSIVE", message, [observation], no_answer=True)
    item = fetch_once(ctx, item_url)
    if (problem := unusable(ctx, item)) is not None:
        return problem
    for record in (lookup, item):
        if (problem := not_200(ctx, "REGISTRY", record, [lookup, item])) is not None:
            return problem
    entry, passport = json_object(lookup), json_object(item)
    if entry is None or passport is None:
        observation = ctx.observation(
            0, kind="exchange", records=[lookup, item], summary={"status": lookup.status}
        )
        return completed(
            False,
            "REGISTRY.RESPONSE.NOT_JSON",
            "The registry record or the passport is not usable JSON.",
            [observation],
        )
    pairs = {
        "identifier": (entry.get("identifier", MISSING), dig(passport, "id")),
        "operator_identifier": (
            entry.get("operator_identifier", MISSING),
            dig(passport, "operator.identifier"),
        ),
    }
    # A field absent on either side was not compared, so it cannot agree (rule 7).
    missing = sorted(name for name, pair in pairs.items() if MISSING in pair or None in pair)
    compared = sorted(set(pairs) - set(missing))
    # JSON values, not Python equality: true is not 1.
    different = [name for name in compared if not same_json(*pairs[name])]
    summary = {"compared": compared, "different": different, "missing": missing}
    observation = ctx.observation(0, kind="exchange", records=[lookup, item], summary=summary)
    if different:
        message = f"The registry record differs from the passport in: {', '.join(different)}."
        return completed(False, "REGISTRY.INCONSISTENT", message, [observation])
    if missing:
        message = f"The registry record or the passport has no value for: {', '.join(missing)}."
        return completed(False, "REGISTRY.FIELD.MISSING", message, [observation])
    return completed(
        True,
        "REGISTRY.OK",
        "The registry record agrees with the passport. This was a passive lookup.",
        [observation],
    )


class AasParams(Model):
    artifact: str = Field(
        default="aas_file", min_length=1, description="Name of the IXIT sample that holds the AAS file."
    )


@register("aas.validate", capability="aas.validate", params=AasParams)
def aas_validate(ctx: CheckContext) -> CheckOutcome:
    try:
        from aas_test_engines import file as aas_file  # noqa: PLC0415 - optional dependency of the `aas` extra
    except ImportError:
        message = "aas-test-engines is not installed. Install the 'aas' extra."
        return not_done(ExecutionStatus.UNSUPPORTED, "AAS.DEPENDENCY_MISSING", message)
    record = ctx.acquirer.artifact(str(ctx.params.get("artifact", "aas_file")))
    if record.error is not None:
        return blocked("AAS.SAMPLE.MISSING", "The Asset Administration Shell sample is not available.")
    try:
        # Strict: two parsers must not read one sample in two ways. CanonicalizationError is a ValueError.
        document = parse_strict(record.body)
    except ValueError:
        observation = ctx.observation(0, kind="artifact", records=[record], summary={"json": False})
        message = "The sample is not JSON, or it has a repeated key, NaN, or Infinity."
        return completed(False, "AAS.INVALID", message, [observation])
    valid = bool(aas_file.check_json_data(document).ok())
    observation = ctx.observation(
        0, kind="artifact", records=[record], summary={"valid": valid}, transformations=("aas_test_engines",)
    )
    limit = "A valid Asset Administration Shell is not a complete DPP conformance statement."
    if not valid:
        return completed(
            False, "AAS.INVALID", f"The wrapped validator rejects the file. {limit}", [observation]
        )
    return completed(True, "AAS.VALID", f"The wrapped validator accepts the file. {limit}", [observation])
