"""Negotiation adapter: how the carrier URL answers different Accept headers (RFC 9110, section 12).

The check sends five fixed GET requests and judges the final answers. It sends no negotiation
header other than Accept. A transport error or a status from 500 to 599 is no answer. Rules that
read headers run before rules that read bodies, so that a body coding or a long body cannot turn
a fail into a blocked step.
"""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import Field

from dppce.adapters.common import (
    SERVER_ERRORS,
    blocked,
    carrier_identifier,
    completed,
    fetch_once,
    is_http_url,
    json_object,
    media_type,
    no_answer,
    unusable,
)
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
    """The reason code and message of the first rule that status, media type, or Vary breaks."""
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
    if answers["json"].status == 200 and not _is_json(media_type(answers["json"])):
        return (
            "NEGOTIATION.MEDIA_TYPE",
            "The carrier answers an Accept of application/json with another type.",
        )
    weighted = answers["weighted"]
    if weighted.status == 200 and not _is_json(media_type(weighted)):
        message = "The carrier ignores the weights of Accept: the heavier JSON range gets another type."
        return "NEGOTIATION.QUALITY", message
    served = [
        r
        for n, r in answers.items()
        if r.status == 200 and (n != "unsupported" or unsupported_answer == "default")
    ]
    if len({(media_type(r), r.body) for r in served}) > 1 and not all(_lists_accept(r) for r in served):
        return (
            "NEGOTIATION.VARY.MISSING",
            "The answers differ by Accept, and an answer does not list Accept in Vary.",
        )
    return None


def _body_failure(answers: dict[str, Record]) -> str | None:
    """The name of the first request whose body does not fit its media type, or None."""
    for name, record in answers.items():
        if record.status != 200:
            continue
        media = media_type(record)
        if _is_json(media) and json_object(record) is None:
            return name
        if media == "text/html" and (_MARKUP.search(record.body) is None or json_object(record) is not None):
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
    for index, (name, accept) in enumerate(PROBES):
        record = fetch_once(ctx, text, accept=accept)
        if record.error is not None or record.status in SERVER_ERRORS:
            return no_answer(ctx, record)
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
    for record in answers.values():
        if record.status == 200 and (problem := unusable(ctx, record)) is not None:
            return problem
    if (bad := _body_failure(answers)) is not None:
        message = f"The body of the {bad} answer does not fit its declared media type."
        return completed(False, "NEGOTIATION.BODY", message, observations)
    message = (
        "The carrier answered five GET requests that differ only in Accept. Status, media type, "
        "weights, Vary, and the body shape of JSON and HTML answers obey the rules. Accept-Language "
        "and other negotiation headers were not sent, and caching was not judged."
    )
    return completed(True, "NEGOTIATION.OK", message, observations)
