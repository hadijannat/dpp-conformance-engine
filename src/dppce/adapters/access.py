"""Access adapter: does the system enforce the access policy that its owner declares?

Policy format: docs/reference/reference-system.md, section 5.2.

The check observes enforcement of a declared policy. It does not decide who has a legal
entitlement to which data. It uses synthetic canaries and belongs in a sandbox only, which is
why the test purpose needs the scope ``access_probe`` from a signed authorization.
"""

from __future__ import annotations

import html
import re
from typing import Any, Literal, Self
from urllib.parse import unquote

from pydantic import ValidationError, model_validator

from dppce.adapters.common import MISSING, blocked, completed, dig, fetch_once, unusable
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
    # A value can also leave through a redirect target or a link of the answer.
    texts += [*record.redirects, *(v for k, v in record.headers if k.lower() in _URL_HEADERS)]
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
        if (problem := unusable(ctx, record)) is not None:
            return problem
        records.append(record)
        looked = _look(record, channel, withheld, canaries)
        if isinstance(looked, CheckOutcome):
            return looked
        found, is_json = looked
        if not is_json:
            canary_only.append(channel)
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
    limit = (
        "This shows enforcement of the declared policy. It does not decide a legal entitlement. "
        "On a channel that is not JSON the check finds a canary only in plain, entity, or percent "
        "form. It cannot find a value that a system hides on purpose."
    )
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
