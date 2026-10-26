"""AAS adapter: positive read probes of an AAS server under a read profile of the AAS API.

The profiles are the read profiles SSP-002 of the AAS Repository and the Submodel Repository
service specifications of IDTA-01002, Specification of the Asset Administration Shell, Part 2,
version 3.0.4. The open OpenAPI files of github.com/admin-shell-io/aas-specs-api at commit
f7bb302f were read on 2026-10-26 (CC BY 4.0). No file is vendored: the response shapes below are
the minimum that the check judges, written by hand.

Every request is a GET through ``ctx.acquirer``, so the transport policy, the authorization, and
the request budget apply. The check sends no write, no negative, and no fuzz request. A fail is
raised at once. An engine limit or a missing answer waits until every probe ran, so that a system
under test cannot turn a fail into a step that is not judged.
"""

from __future__ import annotations

import base64
import contextlib
import re
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import quote

from pydantic import Field, field_validator

from dppce.adapters.common import (
    MISSING,
    SERVER_ERRORS,
    blocked,
    completed,
    effective_url,
    fetch_once,
    is_http_url,
    no_answer,
    unusable,
)
from dppce.adapters.pointer import parse_pointer, resolve_pointer
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.transport import origin_of
from dppce.models import CheckOutcome, ExecutionStatus, JsonValue, Model
from dppce.testdefs.registry import CheckContext, register

ProfileName = Literal["aas-repository-read", "submodel-repository-read"]
# IDTA-01002 Part 2: an Identifiable id has at most 2000 characters.
_MAX_ID: Final = 2000
_MAX_CURSOR: Final = 2048
# The ids that the check asks for as unknown. A conforming repository answers 404.
UNKNOWN_SHELL_PROBE: Final = "urn:example:dppce:TEST-ONLY:unknown-shell"
UNKNOWN_SUBMODEL_PROBE: Final = "urn:example:dppce:TEST-ONLY:unknown-submodel"


@dataclass(frozen=True)
class _Profile:
    specification: str
    collection: str
    model_type: str
    unknown: str


_PROFILES: Final = {
    "aas-repository-read": _Profile(
        "AssetAdministrationShellRepositoryServiceSpecification",
        "shells",
        "AssetAdministrationShell",
        UNKNOWN_SHELL_PROBE,
    ),
    "submodel-repository-read": _Profile(
        "SubmodelRepositoryServiceSpecification", "submodels", "Submodel", UNKNOWN_SUBMODEL_PROBE
    ),
}
# SSP-001 is the full profile, which holds every operation of the read profile SSP-002.
_PROFILE_ID: Final = r"https://admin-shell\.io/aas/API/([0-9]+)/([0-9]+)/{}/SSP-00[12]"

# The closed set of summary.rule values of AAS.API.PROFILE, with the message of each.
RULES: Final = {
    "description_status": "GET /description does not answer 200.",
    "description_shape": "The service description is not an object with a non-empty list of profile strings.",
    "profile_not_declared": "The service description does not declare the read profile of the AAS API 3.0.",
    "list_status": "The list request does not answer 200.",
    "list_shape": (
        "The list answer is not a paged result with paging_metadata and a result list of objects with an id."
    ),
    "paging_limit": "The list answer with limit=1 holds more than one element.",
    "paging_cursor": "The page of the returned cursor repeats an element of the first page.",
    "item_status": "The GET of the declared id does not answer 200.",
    "item_shape": "The element of the declared id does not have that id and the modelType of the profile.",
    "refs_status": "The submodel-refs request does not answer 200.",
    "refs_shape": "The submodel-refs answer is not a paged result of references with keys.",
    "unknown_id_status": "The GET of an unknown id does not answer 404.",
}


class AasApiParams(Model):
    endpoint: str = Field(
        default="aas",
        pattern=r"^[a-z][a-z0-9_]{0,31}$",
        description=(
            "Key of IXIT.endpoints: the base URL of the AAS API, for example https://host/api/v3.0. "
            "A validated authorization must name its origin, or the operator must confirm it."
        ),
    )
    profile: ProfileName = Field(
        default="aas-repository-read",
        description=(
            "The read profile: aas-repository-read (AAS Repository SSP-002) or submodel-repository-read "
            "(Submodel Repository SSP-002) of IDTA-01002 Part 2, version 3.0.4."
        ),
    )
    id_source: str = Field(
        default="aas_shell_id",
        min_length=1,
        max_length=128,
        description=(
            "Name of the IXIT sample that gives the id of a shell, or of a submodel for "
            "submodel-repository-read. Without id_pointer, the sample value is the id."
        ),
    )
    id_pointer: str | None = Field(
        default=None,
        max_length=512,
        description="JSON Pointer into the IXIT sample file id_source. The string there is the id.",
    )
    max_requests: int = Field(
        default=6,
        ge=1,
        le=16,
        description="The most requests that the check sends. The probes of a profile need at most 6.",
    )

    @field_validator("id_pointer")
    @classmethod
    def _pointer(cls, value: str | None) -> str | None:
        if value is not None:
            parse_pointer(value)
        return value


def encoded(ident: str) -> str:
    """IDTA-01002 Part 2: an id in a path is UTF-8, base64url-encoded, without padding."""
    return base64.urlsafe_b64encode(ident.encode("utf-8")).rstrip(b"=").decode("ascii")


class _BrokenError(Exception):
    def __init__(self, rule: str) -> None:
        super().__init__(rule)
        self.rule = rule


class _LimitError(Exception):
    """An engine limit that ends the probes: the version, or the request budget."""

    def __init__(self, status: ExecutionStatus, code: str, message: str) -> None:
        super().__init__(code)
        self.status, self.code, self.message = status, code, message


@dataclass
class _Probes:
    ctx: CheckContext
    base: str
    limit: int
    records: list[Record] = field(default_factory=list)
    seen: list[dict[str, JsonValue]] = field(default_factory=list)
    deferred: CheckOutcome | None = None

    def get(self, probe: str, path: str) -> Record:
        if len(self.seen) >= self.limit:
            message = f"The request budget of {self.limit} ends before the probes of the profile end."
            raise _LimitError(ExecutionStatus.COMPLETED, "AAS.API.BUDGET_EXHAUSTED", message)
        record = fetch_once(self.ctx, self.base + path)
        self.records.append(record)
        self.seen.append({"probe": probe, "status": record.status if record.error is None else None})
        return record

    def defer(self, outcome: CheckOutcome) -> None:
        self.deferred = self.deferred or outcome

    def document(self, probe: str, path: str, rule: str) -> Any:
        """The JSON body of a 200 answer, ``MISSING`` if the answer cannot be judged, or a fail."""
        record = self.get(probe, path)
        if record.error is not None or record.status in SERVER_ERRORS:
            self.defer(no_answer(self.ctx, record))
            return MISSING
        if record.status in (401, 403):
            message = f"The AAS server answers {record.status} to an anonymous read. That proves nothing."
            self.defer(blocked("AAS.API.NOT_CONCLUSIVE", message))
            return MISSING
        if record.status != 200:
            raise _BrokenError(f"{rule}_status")
        if (problem := unusable(self.ctx, record)) is not None:
            self.defer(problem)
            return MISSING
        try:
            return parse_strict(record.body)
        except CanonicalizationError:
            raise _BrokenError(f"{rule}_shape") from None


def _is_paged(document: Any) -> bool:
    if not isinstance(document, dict) or not isinstance(document.get("paging_metadata"), dict):
        return False
    cursor = document["paging_metadata"].get("cursor", MISSING)
    if cursor is not MISSING and not (isinstance(cursor, str) and 1 <= len(cursor) <= _MAX_CURSOR):
        return False
    return isinstance(document.get("result"), list) and all(isinstance(i, dict) for i in document["result"])


def _is_reference(value: Any) -> bool:
    keys = value.get("keys") if isinstance(value, dict) else None
    return (
        isinstance(value, dict)
        and isinstance(value.get("type"), str)
        and isinstance(keys, list)
        and bool(keys)
        and all(
            isinstance(k, dict) and isinstance(k.get("type"), str) and isinstance(k.get("value"), str)
            for k in keys
        )
    )


def _list(probes: _Probes, collection: str) -> None:
    first = probes.document("list", f"/{collection}?limit=1", "list")
    if first is MISSING:
        return
    if not _is_paged(first) or not all(isinstance(i.get("id"), str) for i in first["result"]):
        raise _BrokenError("list_shape")
    if len(first["result"]) > 1:
        raise _BrokenError("paging_limit")
    cursor = first["paging_metadata"].get("cursor")
    if cursor is None:
        return
    # A cursor can hold '+', '/', '=', or '#', so it is percent-encoded.
    second = probes.document("list_cursor", f"/{collection}?limit=1&cursor={quote(cursor, safe='')}", "list")
    if second is MISSING:
        return
    if not _is_paged(second) or not all(isinstance(i.get("id"), str) for i in second["result"]):
        raise _BrokenError("list_shape")
    if len(second["result"]) > 1:
        raise _BrokenError("paging_limit")
    if {i["id"] for i in second["result"]} & {i["id"] for i in first["result"]}:
        raise _BrokenError("paging_cursor")


def _declared(probes: _Probes, profile: _Profile) -> None:
    document = probes.document("description", "/description", "description")
    if document is MISSING:
        return
    profiles = document.get("profiles") if isinstance(document, dict) else None
    if not (isinstance(profiles, list) and profiles and all(isinstance(p, str) for p in profiles)):
        raise _BrokenError("description_shape")
    pattern = re.compile(_PROFILE_ID.format(profile.specification))
    versions = {(m[1], m[2]) for p in profiles if (m := pattern.fullmatch(p))}
    if ("3", "0") in versions:
        return
    if versions:
        named = ", ".join(sorted(".".join(v) for v in versions))
        message = (
            f"The AAS server declares the profile in version {named} only. This engine probes version 3.0."
        )
        raise _LimitError(ExecutionStatus.UNSUPPORTED, "AAS.API.VERSION_UNSUPPORTED", message)
    raise _BrokenError("profile_not_declared")


def _item(probes: _Probes, profile: _Profile, ident: str) -> None:
    path = f"/{profile.collection}/{encoded(ident)}"
    document = probes.document("item", path, "item")
    if document is not MISSING and not (
        isinstance(document, dict)
        and document.get("id") == ident
        and document.get("modelType") == profile.model_type
        and (profile.collection != "shells" or isinstance(document.get("assetInformation"), dict))
    ):
        raise _BrokenError("item_shape")
    if profile.collection != "shells":
        return
    refs = probes.document("submodel_refs", path + "/submodel-refs", "refs")
    if refs is not MISSING and not (_is_paged(refs) and all(_is_reference(r) for r in refs["result"])):
        raise _BrokenError("refs_shape")


def _unknown(probes: _Probes, profile: _Profile) -> None:
    record = probes.get("unknown_id", f"/{profile.collection}/{encoded(profile.unknown)}")
    if record.error is not None or record.status in SERVER_ERRORS:
        probes.defer(no_answer(probes.ctx, record))
    elif record.status in (401, 403):
        message = f"The AAS server answers {record.status} to an anonymous read. That proves nothing."
        probes.defer(blocked("AAS.API.NOT_CONCLUSIVE", message))
    elif record.status != 404:
        raise _BrokenError("unknown_id_status")


def _target(ctx: CheckContext, endpoint: str) -> str | CheckOutcome:
    base = ctx.ixit.endpoints.get(endpoint, "")
    if not is_http_url(base) or "?" in base or "#" in base:
        message = f"The IXIT gives no http or https endpoint '{endpoint}' without a query or a fragment."
        return blocked("AAS.API.NO_TARGET", message)
    base = base.rstrip("/")
    # ADR 0011: the IXIT does not choose the hosts that the engine contacts. With a validated
    # authorization, only an origin that it names is probed. Without one, the transport sends only
    # to an origin that the operator confirmed, and refuses every other one.
    if ctx.authorization is None:
        return base
    origin = origin_of(effective_url(ctx, base)[0])
    named = set()
    for url in ctx.authorization.endpoints:
        with contextlib.suppress(ValueError):
            named.add(origin_of(url))
    if origin not in named:
        message = "The validated authorization does not name the origin of the AAS endpoint. Nothing is sent."
        return blocked("AAS.API.NOT_AUTHORIZED", message)
    return base


def _identifier(ctx: CheckContext, source: str, pointer: str | None) -> tuple[str | None, list[Record]]:
    if pointer is None:
        return ctx.ixit.samples.get(source), []
    record = ctx.acquirer.artifact(source)
    if record.error is not None:
        return None, [record]
    try:
        value = resolve_pointer(parse_strict(record.body), parse_pointer(pointer))
    except (CanonicalizationError, ValueError):
        return None, [record]
    return (value if isinstance(value, str) else None), [record]


@register("aas.api_profile", capability="aas.api_profile", params=AasApiParams)
def api_profile(ctx: CheckContext) -> CheckOutcome:
    try:
        params = AasApiParams.model_validate(dict(ctx.params))
    except ValueError:
        return blocked(
            "AAS.API.PARAMS_INVALID", "The parameters of the check are not valid. Nothing is sent."
        )
    profile = _PROFILES[params.profile]
    base = _target(ctx, params.endpoint)
    if isinstance(base, CheckOutcome):
        return base
    ident, artifacts = _identifier(ctx, params.id_source, params.id_pointer)
    if not (isinstance(ident, str) and 1 <= len(ident) <= _MAX_ID):
        return blocked(
            "AAS.API.ID_MISSING", f"The IXIT sample '{params.id_source}' gives no id. Nothing is sent."
        )
    probes = _Probes(ctx, base, params.max_requests)

    def observed(**extra: JsonValue) -> list[Any]:
        summary: dict[str, JsonValue] = {"profile": params.profile, "probes": list(probes.seen), **extra}
        return [ctx.observation(0, kind="exchange", records=[*artifacts, *probes.records], summary=summary)]

    try:
        _declared(probes, profile)
        _list(probes, profile.collection)
        _item(probes, profile, ident)
        _unknown(probes, profile)
    except _BrokenError as fail:
        message = RULES[fail.rule] + f" The {params.profile} profile of the AAS API 3.0 is broken."
        return completed(False, "AAS.API.PROFILE", message, observed(rule=fail.rule))
    except _LimitError as stop:
        if stop.status is ExecutionStatus.COMPLETED:
            return completed(False, stop.code, stop.message, observed(), no_answer=True)
        return CheckOutcome(
            status=stop.status, reason_code=stop.code, message=stop.message, observations=tuple(observed())
        )
    if probes.deferred is not None:
        return probes.deferred.model_copy(update={"observations": tuple(observed())})
    names = ", ".join(str(p["probe"]) for p in probes.seen)
    message = (
        f"The AAS server answers {len(probes.seen)} read probes as the {params.profile} profile of the AAS "
        f"API 3.0 states: {names}. The check sends no write, no negative, and no fuzz request."
    )
    return completed(True, "AAS.API.OK", message, observed())
