"""Resolver adapter: the GS1 Digital Link resolver surface of the carrier identifier.

The checks judge what the resolver answers to a few fixed GET requests, plus one GET of a linkset
that a Link header of an answer advertises. They never follow a link of a linkset, and they do not
judge the status of a followed redirect hop: the transport does not record it.
A body of an unexpected shape is a fail, never a blocked step, so that a system under test cannot
reshape a wrong answer into one that is not judged.
"""

from __future__ import annotations

import re
from typing import Any, Final
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator

from dppce.adapters.common import (
    LINKSET,
    blocked,
    body_problem,
    carrier_identifier,
    completed,
    fetch_once,
    is_http_url,
    is_linkset,
    json_object,
    media_type,
    no_answer,
    no_reply,
    unusable,
)
from dppce.adapters.identifier import gtin_check_digit_ok
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.redaction import REMOVED, parse_link
from dppce.infrastructure.transport import origin_of
from dppce.models import CheckOutcome, ExecutionStatus, Model, Observation
from dppce.testdefs.registry import CheckContext, NoParams, register

_MAX_RELATIONS: Final = 16
_MAX_RELATION_LENGTH: Final = 2048
# RFC 8288, section 2.1.1: a registered relation name is lower case. Any other relation is a URI.
_REGISTERED: Final = re.compile(r"[a-z][a-z0-9.-]*")
_GTIN: Final = re.compile(r"/01/([0-9]{14})(?=/|$)")
WELL_KNOWN: Final = "/.well-known/gs1resolver"
# The transport errors of a redirect that it does not follow. The record keeps the 3xx status.
_UNFOLLOWED: Final = ("redirect_out_of_scope", "too_many_redirects")
_NO_TARGET: Final = "The carrier identifier is not an http or https URL. There is no resolver to probe."
_NOT_JUDGED: Final = (
    " A Link header advertises a linkset, but its answer cannot be judged, so it is not judged."
)


def _is_relation(value: object) -> bool:
    # "anchor" names the context IRI of a link context object, not a relation (RFC 9264, 4.2.2).
    if not isinstance(value, str) or len(value) > _MAX_RELATION_LENGTH or value == "anchor":
        return False
    return _REGISTERED.fullmatch(value) is not None or is_http_url(value)


class LinksetParams(Model):
    relations: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_RELATIONS,
        description=(
            "Relation types that name the passport, for example the spellings of one link type. "
            "Each is a registered relation name or an http or https IRI. One of them must have a "
            "link in the linkset context of the carrier. No target is fetched."
        ),
    )

    @field_validator("relations")
    @classmethod
    def _relations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(_is_relation(v) for v in value):
            raise ValueError("each entry must be a lower-case relation name or an http or https IRI")
        return value


def _carrier(ctx: CheckContext) -> tuple[str, tuple[str, ...]] | CheckOutcome:
    text, _, transformations, problem = carrier_identifier(ctx)
    if problem is not None or text is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    if not is_http_url(text):
        return blocked("RESOLVER.NO_TARGET", _NO_TARGET)
    return text, transformations


def _with_link_type(url: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&linkType=linkset" if parts.query else "linkType=linkset"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _summary(record: Record, request: str) -> dict[str, Any]:
    # Counts and the media type only: an anchor or an href is text that the system chose.
    return {
        "request": request,
        "status": record.status,
        "media_type": media_type(record),
        "redirects": len(record.redirects),
    }


def _structure_ok(document: dict[str, Any]) -> bool:
    """RFC 9264, section 4.2: a linkset of link context objects whose relations list target objects.

    A target object needs a string ``href``. The other target attributes are not judged.
    """
    if not is_linkset(document):
        return False
    for context in document["linkset"]:
        for name, value in context.items():
            if name == "anchor":
                if not isinstance(value, str):
                    return False
            elif not (
                isinstance(value, list)
                and all(isinstance(t, dict) and isinstance(t.get("href"), str) for t in value)
            ):
                return False
    return True


def _no_reply(record: Record) -> bool:
    # Only a missing answer is tested before the rules. The body rules of ``unusable`` wait until a
    # rule needs the body: otherwise a body coding or a long body would turn a status fail into blocked.
    return no_reply(record)


def _linkset_head_failure(record: Record) -> tuple[str, str] | None:
    """The reason code and message of the first status or media type rule that breaks, or None."""
    if record.status != 200:
        return (
            "RESOLVER.LINKSET.STATUS",
            f"The resolver answers {record.status} to a linkset request, not 200.",
        )
    if media_type(record) != LINKSET:
        return "RESOLVER.LINKSET.MEDIA_TYPE", f"The linkset answer does not have the media type {LINKSET}."
    return None


def _linkset_body_failure(record: Record, carrier: str, relations: list[str]) -> tuple[str, str] | None:
    """The reason code and message of the first body rule that the answer breaks, or None."""
    document = json_object(record)
    if document is None or not _structure_ok(document):
        message = "The linkset answer is not an RFC 9264 linkset of link context objects with target objects."
        return "RESOLVER.LINKSET.STRUCTURE", message
    anchored = [c for c in document["linkset"] if c.get("anchor") == carrier]
    if not anchored:
        return (
            "RESOLVER.LINKSET.ANCHOR",
            "No link context of the linkset has the carrier identifier as its anchor.",
        )
    if not any(isinstance(c.get(r), list) and c[r] for c in anchored for r in relations):
        message = (
            "The link context of the carrier has no link with a relation that the test purpose declares."
        )
        return "RESOLVER.LINKSET.RELATION_MISSING", message
    return None


def _advertised(answers: list[Record]) -> str | None:
    """The first http or https target of a Link with the relation linkset in the answers, or None.

    The record keeps a Link value only in the form that redaction keeps, so this reads that form.
    A relative target is resolved against the final URL of its answer. A target that redaction
    changed is skipped: the record no longer holds the URL that the system advertised.
    """
    for record in answers:
        base = record.redirects[-1] if record.redirects else record.url
        for name, value in record.headers:
            if name.lower() != "link":
                continue
            for target, relations in parse_link(value) or []:
                try:
                    url = urljoin(base, target)
                except ValueError:
                    continue
                if REMOVED in unquote(url):
                    continue
                if "linkset" in relations and is_http_url(url):
                    return url
    return None


@register("resolver.linkset", capability="resolver.linkset", params=LinksetParams)
def linkset(ctx: CheckContext) -> CheckOutcome:
    relations = ctx.params.get("relations")
    if not (
        isinstance(relations, list)
        and 1 <= len(relations) <= _MAX_RELATIONS
        and all(_is_relation(r) for r in relations)
    ):
        return blocked(
            "RESOLVER.PARAMS.INVALID", "The parameter 'relations' is not valid. Nothing is fetched."
        )
    target = _carrier(ctx)
    if isinstance(target, CheckOutcome):
        return target
    carrier, transformations = target
    probes = (("accept", carrier, LINKSET), ("link_type", _with_link_type(carrier), None))
    observations: list[Observation] = []
    answers: list[Record] = []
    for index, (request, url, accept) in enumerate(probes):
        record = fetch_once(ctx, url, accept=accept)
        if _no_reply(record):
            return no_answer(ctx, record)
        answers.append(record)
        observations.append(
            ctx.observation(
                index,
                kind="exchange",
                records=[record],
                summary=_summary(record, request),
                transformations=transformations,
            )
        )
        failure = _linkset_head_failure(record)
        if failure is None:
            if (problem := unusable(ctx, record)) is not None:
                return problem
            failure = _linkset_body_failure(record, carrier, [str(r) for r in relations])
        if failure is not None:
            return completed(False, *failure, observations)
    message = (
        "The resolver answers both linkset requests with a linkset of the carrier identifier that has "
        "a declared relation. Link targets are not fetched, and target attributes are not judged."
    )
    # RFC 9264, section 6: an answer can advertise its linkset in a Link header. It is judged only
    # after both probes pass, and an advertised linkset without a usable answer changes nothing. So a
    # system cannot turn a fail into a missing answer with a broken Link value.
    advertised = _advertised(answers)
    if advertised is None:
        return completed(True, "RESOLVER.LINKSET.OK", message, observations)
    record = fetch_once(ctx, advertised, accept=LINKSET)
    observations.append(
        ctx.observation(
            len(observations),
            kind="exchange",
            records=[record],
            summary=_summary(record, "advertised"),
            transformations=transformations,
        )
    )
    if _no_reply(record):
        return completed(True, "RESOLVER.LINKSET.OK", message + _NOT_JUDGED, observations)
    failure = _linkset_head_failure(record)
    if failure is None:
        if body_problem(record) is not None:
            return completed(True, "RESOLVER.LINKSET.OK", message + _NOT_JUDGED, observations)
        failure = _linkset_body_failure(record, carrier, [str(r) for r in relations])
    if failure is not None:
        return completed(False, *failure, observations)
    return completed(
        True, "RESOLVER.LINKSET.OK", message + " The advertised linkset passes too.", observations
    )


def _is_json(media: str) -> bool:
    return media == "application/json" or media.endswith("+json")


@register("resolver.well_known", capability="resolver.well_known", params=NoParams)
def well_known(ctx: CheckContext) -> CheckOutcome:
    target = _carrier(ctx)
    if isinstance(target, CheckOutcome):
        return target
    carrier, transformations = target
    record = fetch_once(ctx, origin_of(carrier) + WELL_KNOWN)
    if _no_reply(record):
        return no_answer(ctx, record)
    observation = ctx.observation(
        0,
        kind="exchange",
        records=[record],
        summary=_summary(record, "well_known"),
        transformations=transformations,
    )
    # The rules judge the final answer, also after a redirect. Only a redirected file that would
    # pass is blocked, so that a redirect cannot turn a fail into blocked.
    if record.status != 200:
        message = f"The description file path answers {record.status}, not 200."
        return completed(False, "RESOLVER.WELLKNOWN.STATUS", message, [observation])
    if not _is_json(media_type(record)):
        message = "The description file does not have a JSON media type."
        return completed(False, "RESOLVER.WELLKNOWN.MEDIA_TYPE", message, [observation])
    if (problem := unusable(ctx, record)) is not None:
        return problem
    document = json_object(record)
    if document is None:
        message = "The description file is not a JSON object."
        return completed(False, "RESOLVER.WELLKNOWN.NOT_JSON", message, [observation])
    root = document.get("resolverRoot")
    if not (isinstance(root, str) and is_http_url(root) and origin_of(root) == origin_of(carrier)):
        message = "The resolverRoot of the description file is not a URL with the origin of the carrier."
        return completed(False, "RESOLVER.WELLKNOWN.ROOT", message, [observation])
    if record.redirects:
        return CheckOutcome(
            status=ExecutionStatus.BLOCKED,
            reason_code="RESOLVER.WELLKNOWN.REDIRECTED",
            message="The description file path redirects. This check does not pass a redirected file.",
            observations=(observation,),
        )
    message = (
        "The description file names the origin of the carrier as resolverRoot. "
        "The other members of the file are not judged."
    )
    return completed(True, "RESOLVER.WELLKNOWN.OK", message, [observation])


def _invalid_variant(carrier: str) -> str | None:
    """The carrier URL with a wrong GTIN check digit, or None if it has no valid GTIN."""
    parts = urlsplit(carrier)
    match = _GTIN.search(parts.path)
    if match is None or not gtin_check_digit_ok(match[1]):
        return None
    gtin = match[1][:-1] + str((int(match[1][-1]) + 1) % 10)
    path = parts.path[: match.start(1)] + gtin + parts.path[match.end(1) :]
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _conformance_failure(probe: str, record: Record) -> tuple[str, str] | None:
    if probe == "default":
        if not record.redirects:
            return "RESOLVER.CONFORMANCE.NO_REDIRECT", "The resolver does not redirect a default request."
    elif probe == "link_type":
        if record.redirects:
            message = "The resolver redirects a request with linkType=linkset."
            return "RESOLVER.CONFORMANCE.LINKSET_REDIRECTED", message
        if record.status != 200:
            message = f"The resolver answers {record.status} to a request with linkType=linkset, not 200."
            return "RESOLVER.CONFORMANCE.LINKSET_STATUS", message
    elif record.status == 200:
        message = "The resolver answers 200 for an identifier with a wrong GTIN check digit."
        return "RESOLVER.CONFORMANCE.INVALID_ACCEPTED", message
    elif record.status not in (400, 404):
        message = f"The resolver answers {record.status} for an identifier with a wrong GTIN check digit."
        return "RESOLVER.CONFORMANCE.INVALID_STATUS", message + " The check expects 400 or 404."
    return None


@register("resolver.conformance", capability="resolver.conformance", params=NoParams)
def conformance(ctx: CheckContext) -> CheckOutcome:
    target = _carrier(ctx)
    if isinstance(target, CheckOutcome):
        return target
    carrier, transformations = target
    invalid = _invalid_variant(carrier)
    if invalid is None:
        message = "The carrier identifier has no GTIN with a valid check digit, so no invalid variant exists."
        return blocked("RESOLVER.NO_TARGET", message)
    probes = (("default", carrier), ("link_type", _with_link_type(carrier)), ("invalid", invalid))
    observations: list[Observation] = []
    for index, (probe, url) in enumerate(probes):
        record = fetch_once(ctx, url)
        # The rules judge status and redirects only, never the body, so the body rules do not apply.
        # A redirect that the transport does not follow keeps its 3xx status. It is judged for the
        # probes link_type and invalid, so that a system cannot hide a fail behind such a redirect.
        if _no_reply(record) and not (probe != "default" and record.error in _UNFOLLOWED):
            return no_answer(ctx, record)
        observations.append(
            ctx.observation(
                index,
                kind="exchange",
                records=[record],
                summary=_summary(record, probe),
                transformations=transformations,
            )
        )
        if (failure := _conformance_failure(probe, record)) is not None:
            return completed(False, *failure, observations)
    message = (
        "The resolver redirects a default request, answers a linkset request with 200 and no redirect, "
        "and refuses an invalid identifier. Only final statuses are judged, not the status of a redirect hop."
    )
    return completed(True, "RESOLVER.CONFORMANCE.OK", message, observations)
