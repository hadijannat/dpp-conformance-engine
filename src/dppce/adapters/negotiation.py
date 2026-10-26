"""Negotiation adapter: how the carrier URL answers different Accept headers (RFC 9110, section 12).

The check sends five fixed GET requests and judges the final answers. It sends no negotiation
header other than Accept. A transport error or a status from 500 to 599 is no answer. It is
set aside, and it cannot hide a fail that the other answers prove. Rules that read headers run
before rules that read bodies, and an answer that cannot be read is set aside, so that a body
coding or a long body cannot turn a fail into a blocked step.
"""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import Field

from dppce.adapters.common import (
    blocked,
    carrier_identifier,
    completed,
    fetch_once,
    is_http_url,
    media_type,
    no_answer,
    no_reply,
    unusable,
)
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, Model
from dppce.testdefs.registry import CheckContext, register

# (name, Accept value). The order is part of the contract: observation n belongs to probe n.
PROBES: Final = (
    ("json", "application/json"),
    ("html", "text/html"),
    ("json_ld", "application/ld+json"),
    ("weighted", "text/html;q=0.2, application/json;q=0.9"),
    ("unsupported", "application/x-dppce-unsupported"),
)
_MARKUP: Final = re.compile(rb"<[A-Za-z!]")


class NegotiationParams(Model):
    unsupported_answer: Literal["406", "default"] = Field(
        default="default",
        description=(
            "What the carrier does with an Accept value that it cannot serve. 406 requires the status "
            "406. default requires a 200 answer with the default representation."
        ),
    )


def _is_json(media: str) -> bool:
    return media == "application/json" or media.endswith("+json")


def _lists_accept(record: Record) -> bool:
    # Every Vary line counts: a system can send the field twice.
    tokens = {
        token.strip().lower()
        for name, value in record.headers
        if name.lower() == "vary"
        for token in value.split(",")
    }
    return "accept" in tokens or "*" in tokens


def _head_failure(answers: dict[str, Record], unsupported_answer: str) -> tuple[str, str] | None:
    """The reason code and message of the first rule that status, media type, or Vary breaks.

    ``answers`` holds only the requests that got an answer. A rule that needs a missing answer
    does not apply, so a missing answer cannot hide a fail that the other answers prove.
    """
    for name, record in answers.items():
        if name == "unsupported":
            want = 406 if unsupported_answer == "406" else 200
            if record.status != want:
                message = (
                    f"The carrier answers {record.status} to an Accept value it cannot serve, not {want}."
                )
                return "NEGOTIATION.UNSUPPORTED", message
        elif record.status != 200 and not (name != "json" and record.status == 406):
            return "NEGOTIATION.STATUS", f"The carrier answers {record.status} to the {name} request."
    json_answer = answers.get("json")
    if json_answer is not None and json_answer.status == 200 and not _is_json(media_type(json_answer)):
        return (
            "NEGOTIATION.MEDIA_TYPE",
            "The carrier answers an Accept of application/json with another type.",
        )
    weighted = answers.get("weighted")
    if weighted is not None:
        # A 406 for the weighted range is wrong when the same carrier serves JSON with 200.
        refused = weighted.status != 200 and json_answer is not None and json_answer.status == 200
        if refused or (weighted.status == 200 and not _is_json(media_type(weighted))):
            message = "The carrier ignores the weights of Accept: the heavier JSON range gets no JSON."
            return "NEGOTIATION.QUALITY", message
    if _vary_missing(answers, unsupported_answer):
        return (
            "NEGOTIATION.VARY.MISSING",
            "The answers differ by Accept, and an answer does not list Accept in Vary.",
        )
    return None


def _vary_missing(answers: dict[str, Record], unsupported_answer: str) -> bool:
    """Rule 4: answers at one URL differ, and a 200 answer there does not list Accept in Vary.

    The engine can attribute a difference of status or media type to Accept. A body can differ
    for other reasons (a timestamp), so bodies are not compared. A cache keys each URL on its
    own, so Vary is judged per URL. A URL that redirects one request and answers another
    differs too. The engine does not observe the Vary of a redirect hop.
    """
    kinds: dict[str, set[str]] = {}
    served: dict[str, list[Record]] = {}
    for n, r in answers.items():
        if n != "unsupported" or unsupported_answer == "default" or r.status == 406:
            *hops, final = (r.url, *r.redirects)
            for hop in hops:
                kinds.setdefault(hop, set()).add("redirect")
            kinds.setdefault(final, set()).add(f"{r.status} {media_type(r) if r.status == 200 else ''}")
            if r.status == 200:
                served.setdefault(final, []).append(r)
    return any(
        len(seen) > 1 and not all(_lists_accept(r) for r in served.get(url, []))
        for url, seen in kinds.items()
    )


def _parses_as_json(record: Record) -> bool:
    try:
        parse_strict(record.body, decimals=True)
    except CanonicalizationError:
        return False
    return True


def _body_failure(answers: dict[str, Record]) -> str | None:
    """The name of the first request whose body does not fit its media type, or None."""
    for name, record in answers.items():
        media = media_type(record)
        if _is_json(media) and not _parses_as_json(record):
            return name
        if media == "text/html" and (_MARKUP.search(record.body) is None or _parses_as_json(record)):
            return name
    return None


@register("identifier.negotiation", capability="identifier.negotiation", params=NegotiationParams)
def negotiation(ctx: CheckContext) -> CheckOutcome:
    text, _, transformations, problem = carrier_identifier(ctx)
    if problem is not None or text is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    if not is_http_url(text):
        return blocked(
            "NEGOTIATION.NO_TARGET", "The carrier identifier is not an http or https URL. Nothing is sent."
        )
    unsupported_answer = str(ctx.params.get("unsupported_answer", "default"))
    answers: dict[str, Record] = {}
    observations = []
    missing: Record | None = None
    for index, (name, accept) in enumerate(PROBES):
        record = fetch_once(ctx, text, accept=accept)
        if no_reply(record):
            # No answer proves nothing, but it must not hide what the other answers prove.
            missing = missing or record
            continue
        answers[name] = record
        summary = {
            "request": name,
            "status": record.status,
            "media_type": media_type(record),
            "vary_accept": _lists_accept(record),
            "redirects": len(record.redirects),
        }
        observations.append(
            ctx.observation(
                index, kind="exchange", records=[record], summary=summary, transformations=transformations
            )
        )
    if (failure := _head_failure(answers, unsupported_answer)) is not None:
        return completed(False, *failure, observations)
    # A body that cannot be judged (coding, truncation) is set aside, so that it cannot turn
    # a body fail in another answer into blocked.
    usable = {n: r for n, r in answers.items() if r.status == 200 and unusable(ctx, r) is None}
    if (bad := _body_failure(usable)) is not None:
        message = f"The body of the {bad} answer does not fit its declared media type."
        return completed(False, "NEGOTIATION.BODY", message, observations)
    if missing is not None:
        return no_answer(ctx, missing)
    for record in answers.values():
        if record.status == 200 and (problem := unusable(ctx, record)) is not None:
            return problem
    message = (
        "The carrier answered five GET requests that differ only in Accept. Status, media type, "
        "weights, Vary, and the body shape of JSON and HTML answers obey the rules. Accept-Language "
        "and other negotiation headers were not sent, and caching was not judged."
    )
    return completed(True, "NEGOTIATION.OK", message, observations)
