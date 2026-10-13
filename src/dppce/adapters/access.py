"""Access adapter: does the system enforce the access policy that its owner declares?

Policy format: docs/reference/reference-system.md, section 5.2.

The check observes enforcement of a declared policy. It does not decide who has a legal
entitlement to which data. It uses synthetic canaries and belongs in a sandbox only, which is
why the test purpose needs the scope ``access_probe`` from a signed authorization.
"""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import ValidationError, model_validator

from dppce.adapters.common import MISSING, blocked, completed, dig, fetch_once, no_answer
from dppce.catalogue import CatalogueError, load_model
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, Model
from dppce.testdefs.registry import CheckContext, register

# The first leaking channel in this order names the reason code.
_CHANNELS = ("fetch", "export", "search", "error", "html")


class Restricted(Model):
    path: str
    roles: tuple[str, ...]


class Canary(Model):
    path: str
    value: str


class AccessPolicy(Model):
    schema_version: Literal["dppce.accesspolicy/1"]
    policy_id: str
    version: str
    basis: dict[str, str]
    restricted: tuple[Restricted, ...]
    canaries: tuple[Canary, ...] = ()
    channels: dict[str, str]

    @model_validator(mode="after")
    def _known_channels_only(self) -> Self:
        unknown = sorted(set(self.channels) - set(_CHANNELS))
        if unknown:
            raise ValueError(
                f"unknown channels {unknown}: a channel that is not probed must not look covered"
            )
        return self


def _holds_path(node: Any, dotted: str) -> bool:
    """True if any object in the tree holds the dotted path. A channel can nest the passport."""
    if isinstance(node, dict):
        return dig(node, dotted) is not MISSING or any(_holds_path(v, dotted) for v in node.values())
    if isinstance(node, list):
        return any(_holds_path(v, dotted) for v in node)
    return False


@register("access.restricted_fields", capability="access.policy")
def restricted_fields(ctx: CheckContext) -> CheckOutcome:
    role = str(ctx.params.get("role", "anonymous"))
    origin, passport_id = ctx.ixit.endpoints.get("api"), ctx.ixit.samples.get("passport_id")
    if ctx.profile.access_policy is None or not origin or not passport_id:
        return blocked(
            "ACCESS.POLICY.MISSING", "The profile names no access policy, or the IXIT gives no target."
        )
    try:
        policy = load_model(ctx.data_root / ctx.profile.access_policy, AccessPolicy)
    except (CatalogueError, ValidationError):
        return blocked("ACCESS.POLICY.MISSING", "The pinned access policy cannot be read or is not valid.")
    withheld = [r.path for r in policy.restricted if role not in r.roles]
    if not withheld or not policy.channels:
        # Nothing to look for, or nowhere to look. That is not evidence of enforcement.
        message = f"The policy withholds no field from the role '{role}', or it names no channel."
        return blocked("ACCESS.POLICY.NOTHING_TO_PROBE", message)
    canaries = [c for c in policy.canaries if c.path in withheld]
    serial = passport_id.partition("-")[2]
    records: list[Record] = []
    leaks: dict[str, list[str]] = {}
    canary_only: list[str] = []  # not JSON: only a canary value can be found there
    for channel in _CHANNELS:
        template = policy.channels.get(channel)
        if template is None:
            continue
        url = origin.rstrip("/") + template.replace("{id}", passport_id).replace("{serial}", serial)
        record = fetch_once(ctx, url, role)
        if record.error is not None:
            return no_answer(ctx, record)
        if record.truncated:
            return blocked(
                "TRANSPORT.BODY_TRUNCATED", "A body is larger than the limit. A partial body proves nothing."
            )
        records.append(record)
        media_type = (record.header("content-type") or "").split(";")[0].strip().lower()
        document: Any = None
        # Always try to read the body as JSON. The system under test chooses the declared media
        # type, so that label must not decide whether the field paths are checked.
        try:
            document = parse_strict(record.body)
        except CanonicalizationError:
            if media_type == "application/json" or media_type.endswith("+json"):
                # The body claims to be JSON and cannot be read. Field paths cannot be checked.
                message = f"The '{channel}' channel declares JSON, but the body cannot be parsed."
                return blocked("ACCESS.RESPONSE.NOT_JSON", message)
            canary_only.append(channel)
        found = [path for path in withheld if document is not None and _holds_path(document, path)]
        # A canary in the raw bytes is a leak in any format: JSON, HTML, or an error text.
        found += [c.path for c in canaries if c.value.encode("utf-8") in record.body and c.path not in found]
        if found:
            leaks[channel] = sorted(found)
    summary: dict[str, Any] = {
        "policy": f"{policy.policy_id} {policy.version}",
        "role": role,
        "channels_probed": [c for c in _CHANNELS if c in policy.channels],
        "channels_checked_for_canaries_only": canary_only,
        # Field paths only. A field value is never written to an observation.
        "leaks": {channel: list(paths) for channel, paths in leaks.items()},
    }
    observation = ctx.observation(0, kind="exchange", records=records, summary=summary)
    limit = "This shows enforcement of the declared policy. It does not decide a legal entitlement."
    if leaks:
        first = next(c for c in _CHANNELS if c in leaks)
        channels = ", ".join(c for c in _CHANNELS if c in leaks)
        message = f"The role '{role}' receives withheld fields on: {channels}. {limit}"
        return completed(False, f"ACCESS.LEAK.{first.upper()}", message, [observation])
    unmarked = sorted(set(withheld) - {c.path for c in canaries})
    if canary_only and unmarked:
        # On a channel that is not JSON, only a canary value can be found. A withheld field with
        # no canary could be there and stay unseen. That is not evidence of enforcement.
        message = (
            f"The channels {', '.join(canary_only)} are not JSON, and these withheld fields have no "
            f"canary to look for: {', '.join(unmarked)}."
        )
        return blocked("ACCESS.POLICY.NOT_FULLY_CHECKABLE", message)
    return completed(
        True,
        "ACCESS.POLICY.ENFORCED",
        f"No probed channel gives the role '{role}' a withheld field. {limit}",
        [observation],
    )
