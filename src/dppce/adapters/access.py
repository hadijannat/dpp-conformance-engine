"""Access adapter: does the system enforce the access policy that its owner declares?

Policy format: docs/reference/reference-system.md, section 5.2.

The check observes enforcement of a declared policy. It does not decide who has a legal
entitlement to which data. It uses synthetic canaries and belongs in a sandbox only, which is
why the test purpose needs the scope ``access_probe`` from a signed authorization.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self
from urllib.parse import unquote

from pydantic import Field, ValidationError, model_validator

from dppce.adapters.common import (
    MISSING,
    blocked,
    completed,
    dig,
    fetch_once,
    no_answer,
    template_url,
    unusable,
)
from dppce.catalogue import CatalogueError, load_model
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.redaction import REMOVED
from dppce.models import PATH_TEMPLATE_PATTERN, UNKNOWN, CheckOutcome, Model, Profile
from dppce.testdefs.registry import CheckContext, register

ACCESS_CHECK: Final = "access.restricted_fields"
# The reading order. The first leaking channel in this order names the reason code.
_CHANNELS = ("fetch", "export", "search", "error", "html")
_REFUSALS = (401, 403)


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
    # Path templates under the `api` endpoint. A value outside the grammar makes the policy invalid.
    channels: dict[str, Annotated[str, Field(max_length=512, pattern=PATH_TEMPLATE_PATTERN)]]

    @model_validator(mode="after")
    def _known_channels_only(self) -> Self:
        unknown = sorted(set(self.channels) - set(_CHANNELS))
        if unknown:
            raise ValueError(
                f"unknown channels {unknown}: a channel that is not probed must not look covered"
            )
        return self

    @model_validator(mode="after")
    def _one_entry_per_path(self) -> Self:
        # Two entries for one path could withhold it from a role and entitle the same role to it.
        for name, paths in (
            ("restricted", [r.path for r in self.restricted]),
            ("canaries", [c.path for c in self.canaries]),
        ):
            repeated = sorted({p for p in paths if paths.count(p) > 1})
            if repeated:
                raise ValueError(f"'{name}' names these paths more than once: {repeated}")
        return self


def policy_roles(data_root: Path, profile: Profile) -> tuple[str, ...]:
    """Every role that the bound policy names. Empty if the profile binds no readable policy:
    the check then reports the policy itself (ACCESS.POLICY.MISSING)."""
    if profile.access_policy is None:
        return ()
    try:
        policy = load_model(data_root / profile.access_policy, AccessPolicy)
    except (CatalogueError, ValidationError):
        return ()
    return tuple(role for r in policy.restricted for role in r.roles)


def _holds_path(node: Any, dotted: str) -> bool:
    """True if any object in the tree holds the dotted path with a value. A channel can nest
    the passport. A ``null`` value withholds the field. The walk is iterative: a deeply nested
    body must not stop the check."""
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            value = dig(current, dotted)
            if value is not MISSING and value is not None:
                return True
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return False


def _strings(node: Any) -> list[str]:
    """Every string in a parsed JSON value: keys and values."""
    found: list[str] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            found.append(current)
        elif isinstance(current, dict):
            found.extend(current)
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return found


# Byte order marks. UTF-32 first: its little-endian mark begins with the UTF-16 one.
_MARKS = (
    (b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"), (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"),
)  # fmt: skip
_WIDE = ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")


def _decoded(record: Record, media_charset: str | None) -> list[str] | None:
    """Decode a body that is not JSON to text, or return None if it cannot be decoded.

    A byte order mark decides first, then the declared character set, then UTF-8. A wide
    encoding without a mark is decoded in both byte orders. Text with NUL characters is also
    read as a wide encoding: a label can hide UTF-16 that UTF-8 accepts byte for byte.
    """
    body = record.body
    marked = next((name for mark, name in _MARKS if body.startswith(mark)), None)
    name = (marked or media_charset or "utf-8").lower().replace("_", "-")
    declared = [f"{name}-le", f"{name}-be"] if marked is None and name in ("utf-16", "utf-32") else [name]
    texts = _decode_each(body, declared)
    if not texts:
        # The declared reading must work. Other readings only add places to look.
        return None
    if b"\x00" in body:
        texts += _decode_each(body, [wide for wide in _WIDE if wide not in declared])
    return texts


def _decode_each(body: bytes, names: list[str]) -> list[str]:
    texts = []
    for name in names:
        try:
            texts.append(body.decode(name))
        except (UnicodeDecodeError, LookupError):
            continue
    return texts


_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\([\\/\"])")


def _json_unescaped(text: str) -> str:
    """Resolve JSON string escapes, for a value inside a script or a nested JSON string."""
    return _JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2), text)


def _forms(text: str) -> list[str]:
    """The forms in which a value can sit in a text: plain, HTML entities resolved,
    percent-decoded, and JSON escapes resolved, alone and combined."""
    unescaped = html.unescape(text)
    decoded = unquote(text)
    return [
        text, unescaped, decoded, unquote(unescaped), html.unescape(decoded),
        _json_unescaped(text), _json_unescaped(unescaped),
    ]  # fmt: skip


_URL_HEADERS = ("location", "content-location", "link")


def _url_texts(record: Record) -> list[str]:
    """Redirect targets and the URL values of the answer: a value can also leave through them."""
    return [*record.redirects, *(v for k, v in record.headers if k.lower() in _URL_HEADERS)]


def _look(
    record: Record, channel: str, withheld: list[str], canaries: list[Canary]
) -> tuple[list[str], bool] | CheckOutcome:
    """Look for withheld fields in one channel body.

    Returns the leaked field paths and whether the body was JSON, or an outcome if the body
    cannot be searched at all.
    """
    declared = (record.header("content-type") or "").lower()
    media_type = declared.split(";")[0].strip()
    charset = next((p.split("=", 1)[1].strip(' "') for p in declared.split(";")[1:] if "charset=" in p), None)
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
    if document is not None:
        texts = _strings(document)
    else:
        decoded = _decoded(record, charset)
        if decoded is None:
            # Bytes that cannot be decoded cannot be searched. That is not a clean channel.
            message = f"The body of the '{channel}' channel cannot be decoded as text."
            return blocked("ACCESS.RESPONSE.NOT_DECODABLE", message)
        texts = decoded
    texts += _url_texts(record)
    haystack = [form for text in texts for form in _forms(text)]
    found = [path for path in withheld if document is not None and _holds_path(document, path)]
    # A canary is a leak in any format. Look in the raw bytes and in each decoded form.
    found += [
        c.path
        for c in canaries
        if c.path not in found
        and (c.value.encode("utf-8") in record.body or any(c.value in form for form in haystack))
    ]
    return found, document is not None


def _partial_look(
    withheld: list[str], canaries: list[Canary], canary_only: list[str], redacted: list[str]
) -> str | None:
    """Why a look that found no leak was not complete, or None if it was complete."""
    unmarked = sorted(set(withheld) - {c.path for c in canaries})
    if canary_only and unmarked:
        # On a channel that is not JSON, only a canary value can be found. A withheld field with
        # no canary could be there and stay unseen. That is not evidence of enforcement.
        return (
            f"The channels {', '.join(canary_only)} are not JSON, and these withheld fields have no "
            f"canary to look for: {', '.join(unmarked)}."
        )
    if redacted and canaries:
        return (
            f"On the channels {', '.join(redacted)}, a redirect or link URL held a credential-like value "
            "that was removed before recording. A canary there cannot be seen."
        )
    return None


def _bound_policy(ctx: CheckContext) -> AccessPolicy | CheckOutcome:
    """The policy that the profile binds, if it is the one that the ICS names."""
    if ctx.profile.access_policy is None:
        return blocked("ACCESS.POLICY.MISSING", "The profile names no access policy.")
    try:
        policy = load_model(ctx.data_root / ctx.profile.access_policy, AccessPolicy)
    except (CatalogueError, ValidationError):
        return blocked("ACCESS.POLICY.MISSING", "The pinned access policy cannot be read or is not valid.")
    expected = ctx.ics.access.policy
    if expected == UNKNOWN:
        message = "The ICS does not name the access policy that it expects."
        return blocked("ACCESS.POLICY.NOT_DECLARED", message)
    if policy.policy_id != expected:
        message = f"The bound access policy is not the policy '{expected}' that the ICS names."
        return blocked("ACCESS.POLICY.ICS_MISMATCH", message)
    return policy


def _channel_urls(ctx: CheckContext, policy: AccessPolicy, read: list[str]) -> dict[str, str] | CheckOutcome:
    """Every channel URL, built before the first request: a channel without a target sends nothing."""
    urls: dict[str, str] = {}
    for channel in read:
        url = template_url(ctx, "api", policy.channels[channel], "ACCESS")
        if isinstance(url, CheckOutcome):
            return url
        urls[channel] = url
    return urls


def _entitlement(
    record: Record, entitled: list[str], role: str
) -> tuple[str, str, list[str]] | CheckOutcome | None:
    """Judge the fetch answer for the entitled paths.

    Returns a failure (code, message, missing paths), an outcome if the body cannot be judged,
    or None if every entitled path is served.
    """
    if record.status in _REFUSALS:
        # A refusal fails whatever its body: the role gets none of its fields.
        message = (
            f"The fetch channel answered {record.status} to the role '{role}', which the policy gives "
            f"{len(entitled)} fields."
        )
        return "ACCESS.ENTITLEMENT.REFUSED", message, []
    try:
        document = parse_strict(record.body)
    except CanonicalizationError:
        message = (
            f"The fetch body for the role '{role}' is not JSON, so the entitled paths cannot be checked."
        )
        return blocked("ACCESS.RESPONSE.NOT_JSON", message)
    # At the root on purpose: an entitled path inside an unrelated nested object is not served.
    missing = sorted(p for p in entitled if (v := dig(document, p)) is MISSING or v is None)
    if not missing:
        return None
    message = (
        f"The fetch channel answered {record.status}. The role '{role}' does not receive these "
        f"entitled paths: {', '.join(missing)}."
    )
    return "ACCESS.ENTITLEMENT.MISSING", message, missing


def credential_issuer(ctx: CheckContext, role: str) -> str | None:
    """The issuer of the validated authorization that grants the role. Never read from a credential."""
    grant = ctx.authorization
    if role == "anonymous" or grant is None or role not in grant.roles:
        return None
    return grant.issuer


def _named(outcome: CheckOutcome, role: str, issuer: str | None) -> CheckOutcome:
    """Name the probed role and the credential issuer in the outcome. Never the secret."""
    observations = tuple(
        o.model_copy(update={"summary": {**o.summary, "role": role, "credential_issuer": issuer}})
        for o in outcome.observations
    )
    message = f"{outcome.message} Probed role: '{role}'. Credential issuer: {issuer or 'none'}."
    return outcome.model_copy(update={"message": message, "observations": observations})


class RestrictedFieldsParams(Model):
    role: str = Field(default="anonymous", min_length=1, description="Role whose view is probed.")


@dataclass
class _Reading:
    """What the check saw on the channels that it read, in reading order."""

    records: list[Record] = field(default_factory=list)
    leaks: dict[str, list[str]] = field(default_factory=dict)
    canary_only: list[str] = field(default_factory=list)  # not JSON: only a canary can be found there
    redacted: list[str] = field(default_factory=list)  # a redirect or link URL lost a part to redaction
    shortfall: tuple[str, str, list[str]] | None = None  # an entitlement failure on fetch
    problem: CheckOutcome | None = None  # the first answer that cannot be judged
    fetched: Record | None = None

    def keep(self, problem: CheckOutcome) -> None:
        self.problem = self.problem or problem

    def look(self, record: Record, channel: str, withheld: list[str], canaries: list[Canary]) -> None:
        looked = _look(record, channel, withheld, canaries)
        if isinstance(looked, CheckOutcome):
            self.keep(looked)
            return
        found, is_json = looked
        if not is_json:
            self.canary_only.append(channel)
        if any(REMOVED in text for text in _url_texts(record)):
            # Redaction removed a part of a URL before the record existed. A canary could sit
            # there. The search reads the record only, so that a replay gives the same result.
            self.redacted.append(channel)
        if found:
            self.leaks[channel] = sorted(found)


def _read_channels(
    ctx: CheckContext,
    urls: dict[str, str],
    role: str,
    *,
    entitled: list[str],
    withheld: list[str],
    canaries: list[Canary],
) -> _Reading:
    """Read each channel. A problem does not stop the reading: a later leak still counts."""
    seen = _Reading()
    for channel, url in urls.items():
        record = fetch_once(ctx, url, role)
        seen.records.append(record)
        if record.error is not None:
            # A denied or unreachable origin gets no further attempt.
            seen.keep(no_answer(ctx, record))
            break
        bad = unusable(ctx, record)
        if channel == "fetch":
            seen.fetched = record
            # A refusal is judged without its body. Any other answer needs a usable body.
            if entitled and (record.status in _REFUSALS or bad is None):
                judged = _entitlement(record, entitled, role)
                if isinstance(judged, CheckOutcome):
                    seen.keep(judged)
                else:
                    seen.shortfall = judged
        if bad is not None:
            seen.keep(bad)
        elif withheld:
            seen.look(record, channel, withheld, canaries)
    return seen


@register(ACCESS_CHECK, capability="access.policy", params=RestrictedFieldsParams)
def restricted_fields(ctx: CheckContext) -> CheckOutcome:
    role = str(ctx.params.get("role", "anonymous"))
    return _named(_probe(ctx, role), role, credential_issuer(ctx, role))


def _probe(ctx: CheckContext, role: str) -> CheckOutcome:
    policy = _bound_policy(ctx)
    if isinstance(policy, CheckOutcome):
        return policy
    withheld = [r.path for r in policy.restricted if role not in r.roles]
    entitled = [r.path for r in policy.restricted if role in r.roles]
    if not (withheld or entitled) or not policy.channels:
        # Nothing to look for, or nowhere to look. That is not evidence of enforcement.
        message = (
            f"The policy gives no field to the role '{role}' and withholds none, or it names no channel."
        )
        return blocked("ACCESS.POLICY.NOTHING_TO_PROBE", message)
    canaries = [c for c in policy.canaries if c.path in withheld]
    # Only the fetch channel must give content. A role with nothing withheld has no leak to find.
    read = [c for c in _CHANNELS if c in policy.channels and (withheld or c == "fetch")]
    urls = _channel_urls(ctx, policy, read)
    if isinstance(urls, CheckOutcome):
        return urls
    seen = _read_channels(ctx, urls, role, entitled=entitled, withheld=withheld, canaries=canaries)
    leaks, shortfall, fetched = seen.leaks, seen.shortfall, seen.fetched
    summary: dict[str, Any] = {
        "policy": f"{policy.policy_id} {policy.version}",
        "role": role,
        "channels_probed": list(urls)[: len(seen.records)],
        "channels_checked_for_canaries_only": seen.canary_only,
        # Field paths and a status only. A field value is never written to an observation.
        "leaks": {channel: list(paths) for channel, paths in leaks.items()},
        "entitled": sorted(entitled),
        "entitlement_missing": shortfall[2] if shortfall else [],
        "fetch_status": fetched.status if fetched else None,
    }
    observation = ctx.observation(0, kind="exchange", records=seen.records, summary=summary)
    limit = (
        "This shows enforcement of the declared policy. It does not decide a legal entitlement. "
        "A field that is present can still hold a wrong value. "
        "On a channel that is not JSON the check finds a canary only in plain, entity, or percent "
        "form. It cannot find a value that a system hides on purpose."
    )
    if leaks:
        first = next(c for c in _CHANNELS if c in leaks)
        channels = ", ".join(c for c in _CHANNELS if c in leaks)
        message = f"The role '{role}' receives withheld fields on: {channels}. {limit}"
        return completed(False, f"ACCESS.LEAK.{first.upper()}", message, [observation])
    if shortfall is not None:
        code, message, _ = shortfall
        return completed(False, code, f"{message} {limit}", [observation])
    if seen.problem is not None:
        return seen.problem
    if entitled and fetched is None:
        message = f"The policy gives the role '{role}' fields but names no fetch channel."
        return blocked("ACCESS.ENTITLEMENT.NO_FETCH_CHANNEL", message)
    if (gap := _partial_look(withheld, canaries, seen.canary_only, seen.redacted)) is not None:
        return blocked("ACCESS.POLICY.NOT_FULLY_CHECKABLE", gap)
    return completed(
        True,
        "ACCESS.POLICY.ENFORCED",
        f"The role '{role}' receives each entitled field on fetch, and no probed channel gives it "
        f"a withheld field. {limit}",
        [observation],
    )
