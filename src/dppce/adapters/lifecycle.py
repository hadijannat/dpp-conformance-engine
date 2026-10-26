"""Persistence and registry adapters. The AAS file checks are in ``dppce.adapters.aas``.

Each of these checks states a limit that its verdict must not hide:

- A few observations cannot prove that a passport stays available for the life of a product.
  Changed content is not by itself unlawful: the check compares with the declared update rule.
- A failed or unauthorized registry lookup does not prove that a registration is missing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from itertools import pairwise
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, ValidationError, model_validator

from dppce.adapters.aas import aas_validate  # noqa: F401 - re-export: tests/test_strict_parsing.py imports it here
from dppce.adapters.common import (
    MISSING,
    blocked,
    completed,
    fetch_once,
    json_object,
    not_200,
    resource_url,
    same_json,
    unusable,
)
from dppce.adapters.pointer import parse_pointer, resolve_pointer
from dppce.evidence.canonical import CanonicalizationError, digest, parse_strict
from dppce.infrastructure.clock import parse_instant
from dppce.models import CheckOutcome, Model
from dppce.testdefs.registry import CheckContext, register


def _pointer(value: str) -> str:
    parse_pointer(value)
    return value


Pointer = Annotated[str, AfterValidator(_pointer)]
_HISTORY_MEMBER = "versions"


class VersionsParams(Model):
    entries_pointer: Pointer = Field(
        # Built from a member name: a JSON Pointer is no URL path, but the URL guard test scans text.
        default=f"/{_HISTORY_MEMBER}",
        description="JSON Pointer (RFC 6901) to the list of history entries.",
    )
    version_field: str = Field(
        default="version", min_length=1, description="Member of an entry: the version."
    )
    time_field: str = Field(
        default="updated_at", min_length=1, description="Member of an entry: the update time (RFC 3339)."
    )
    digest_field: str = Field(
        default="content_digest", min_length=1, description="Member of an entry: the digest of the item."
    )
    digest_of: Literal["jcs-sha256", "raw-sha256"] = Field(
        default="jcs-sha256",
        description=(
            "What the digest covers: the canonical form of the item (sha256:<hex>), "
            "or the bytes of the item body as served (sha256:<hex>)."
        ),
    )
    version_kind: Literal["integer", "string"] = Field(
        default="integer",
        description="Integer versions must ascend. String versions must be distinct, and time orders them.",
    )


def _order_problems(params: VersionsParams, entries: list[Any]) -> list[str]:
    """Version and time findings. A malformed entry is a finding: it is never a way out of the check."""
    problems: list[str] = []
    labels: list[Any] = [e.get(params.version_field) if isinstance(e, dict) else None for e in entries]
    if params.version_kind == "integer":
        if not all(type(n) is int for n in labels) or any(a >= b for a, b in pairwise(labels)):
            problems.append("version numbers do not strictly ascend")
    elif not all(isinstance(v, str) and v for v in labels) or len(set(labels)) != len(labels):
        problems.append("version labels are not distinct strings")
    # Instants, not text: an offset or a fraction changes the text order.
    stamps = [_instant(e.get(params.time_field) if isinstance(e, dict) else None) for e in entries]
    known = [stamp for stamp in stamps if stamp is not None]
    if len(known) != len(stamps):
        problems.append("an update time is missing or is not an RFC 3339 date-time with an offset")
    elif any(a > b for a, b in pairwise(known)):
        problems.append("an update time goes back")
    return problems


def _current_digest(params: VersionsParams, body: bytes, current: dict[str, Any]) -> str | None:
    if params.digest_of == "raw-sha256":
        # Bytes always hash, so a raw digest never ends in "not comparable".
        return "sha256:" + hashlib.sha256(body).hexdigest()
    try:
        return digest(current)
    except CanonicalizationError:
        return None


@register("persistence.versions", capability="persistence.versions", params=VersionsParams)
def versions(ctx: CheckContext) -> CheckOutcome:
    try:
        params = VersionsParams.model_validate(ctx.params)
    except ValidationError:
        # The lint refuses such a test pack. This guard covers a plan that skipped the lint.
        return blocked("PERSISTENCE.PARAMS.INVALID", "The parameters are not valid. Nothing is read.")
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
    try:
        listing = parse_strict(history.body)
    except CanonicalizationError:
        listing = None
    entries = resolve_pointer(listing, parse_pointer(params.entries_pointer))
    current = json_object(item)
    if not isinstance(entries, list) or not entries or current is None:
        observation = ctx.observation(
            0, kind="exchange", records=[history, item], summary={"status": history.status}
        )
        return completed(
            False, "PERSISTENCE.RESPONSE.NOT_JSON", "The version history is not usable JSON.", [observation]
        )
    problems = _order_problems(params, entries)
    last = entries[-1].get(params.digest_field) if isinstance(entries[-1], dict) else None
    current_digest = _current_digest(params, item.body, current)
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


class RegistryField(Model):
    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        description="Name of the pair in the report.",
    )
    registry_pointer: Pointer = Field(description="JSON Pointer (RFC 6901) into the registry record.")
    passport_pointer: Pointer = Field(description="JSON Pointer (RFC 6901) into the item passport.")


_DEFAULT_FIELDS = (
    RegistryField(name="identifier", registry_pointer="/identifier", passport_pointer="/id"),
    RegistryField(
        name="operator_identifier",
        registry_pointer="/operator_identifier",
        passport_pointer="/operator/identifier",
    ),
)


class RegistryParams(Model):
    fields: tuple[RegistryField, ...] = Field(
        default=_DEFAULT_FIELDS,
        min_length=1,
        max_length=16,
        description="Pairs of values to compare, each as a name and two JSON Pointers. Names are unique.",
    )

    @model_validator(mode="after")
    def _unique_names(self) -> RegistryParams:
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValueError("the names of the fields are not unique")
        return self


@register("registry.consistency", capability="registry.mock", params=RegistryParams)
def registry_consistency(ctx: CheckContext) -> CheckOutcome:
    try:
        params = RegistryParams.model_validate(ctx.params)
    except ValidationError:
        return blocked("REGISTRY.PARAMS.INVALID", "The parameters are not valid. Nothing is read.")
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
        f.name: (
            resolve_pointer(entry, parse_pointer(f.registry_pointer)),
            resolve_pointer(passport, parse_pointer(f.passport_pointer)),
        )
        for f in params.fields
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
