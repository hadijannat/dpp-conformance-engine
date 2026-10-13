"""API adapter: compare a response with a pinned, maintainer-supplied OpenAPI contract.

Supported subset of OpenAPI 3.1: path templates, ``get``, the response status, the response
media type, and a JSON Schema with local ``#/components/schemas`` references. Anything else is
reported as ``unsupported``. Fuzzing and negative tests are a separate capability that needs a
signed authorization.
"""

from __future__ import annotations

from typing import Any

from dppce.adapters.common import (
    api_url,
    blocked,
    completed,
    fetch_once,
    json_object,
    not_done,
    schema_errors,
    unusable,
    validator,
)
from dppce.catalogue import CatalogueError, load_data
from dppce.models import CheckOutcome, ExecutionStatus
from dppce.testdefs.registry import CheckContext, register


def _unsupported(message: str) -> CheckOutcome:
    return not_done(ExecutionStatus.UNSUPPORTED, "API.CONTRACT.UNSUPPORTED_FEATURE", message)


@register("api.contract", capability="api.contract")
def contract(ctx: CheckContext) -> CheckOutcome:
    path, method = str(ctx.params.get("path", "")), str(ctx.params.get("method", "get")).lower()
    if ctx.profile.api_contract is None:
        return blocked("API.CONTRACT.MISSING", "The profile names no API contract.")
    try:
        document: Any = load_data(ctx.data_root / ctx.profile.api_contract)
    except CatalogueError:
        return blocked("API.CONTRACT.MISSING", "The pinned API contract cannot be read.")
    if method != "get":
        return _unsupported(f"The method '{method}' is outside the supported subset.")
    try:
        responses = document["paths"][path][method]["responses"]
    except (KeyError, TypeError):
        return _unsupported(f"The contract has no '{method}' operation for '{path}'.")
    prefix = "/dpp/{id}"
    url = api_url(ctx, path[len(prefix) :]) if path.startswith(prefix) else None
    if url is None:
        return blocked("API.CONTRACT.NO_TARGET", "The IXIT gives no API endpoint or no passport identifier.")
    record = fetch_once(ctx, url)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    media_type = (record.header("content-type") or "").split(";")[0].strip().lower()
    summary: dict[str, Any] = {"path": path, "status": record.status, "media_type": media_type}

    def result(passed: bool, code: str, message: str) -> CheckOutcome:
        observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
        return completed(passed, code, message, [observation])

    declared = responses.get(str(record.status))
    if not isinstance(declared, dict):
        return result(False, "API.CONTRACT.STATUS", f"The contract does not declare status {record.status}.")
    content = declared.get("content", {})
    if media_type not in content:
        return result(
            False,
            "API.CONTRACT.CONTENT_TYPE",
            f"The contract does not declare the media type '{media_type}'.",
        )
    schema = content[media_type].get("schema")
    if schema is None:
        return result(
            True,
            "API.CONTRACT.OK",
            "The status and the media type match the contract. It declares no schema.",
        )
    check = validator({**schema, "components": document.get("components", {})})
    if check is None:
        return _unsupported("The contract uses a reference that is not local to the document.")
    body = json_object(record)
    if body is None:
        return result(False, "API.RESPONSE.NOT_JSON", "The response body is not a JSON object.")
    errors = schema_errors(check, body)
    summary["schema_errors"] = errors
    if errors:
        return result(
            False,
            "API.CONTRACT.SCHEMA",
            f"The response has {len(errors)} schema errors against the contract.",
        )
    return result(
        True, "API.CONTRACT.OK", "The status, the media type, and the body match the pinned contract."
    )
