"""API adapter: compare a response with a pinned, maintainer-supplied OpenAPI contract.

Supported subset of OpenAPI 3.1: path templates, ``get``, the response status, the response
media type, and a JSON Schema with local ``#/components/schemas`` references. Anything else is
reported as ``unsupported``. Fuzzing and negative tests are a separate capability that needs a
signed authorization.
"""

from __future__ import annotations

import re
from typing import Any, cast, get_args

from dppce.adapters.common import (
    blocked,
    completed,
    fetch_once,
    json_object,
    media_type,
    not_done,
    resource_url,
    schema_errors,
    unusable,
    validator,
)
from dppce.catalogue import CatalogueError, load_data
from dppce.models import UNKNOWN, CheckOutcome, ExecutionStatus, ResourceName, ResourceTemplate
from dppce.testdefs.registry import CheckContext, register

_RESOURCES: frozenset[str] = frozenset(get_args(ResourceName))


def _unsupported(message: str) -> CheckOutcome:
    return not_done(ExecutionStatus.UNSUPPORTED, "API.CONTRACT.UNSUPPORTED_FEATURE", message)


def _shape(path: str) -> str:
    """A path with every parameter name removed, so that '{passportId}' matches '{id}'."""
    return re.sub(r"\{[^{}/]*\}", "{}", path)


def _marked(document: dict[str, Any], resource: str) -> list[str] | CheckOutcome:
    """The contract paths that the contract marks for the resource (ADR 0011: operator data)."""
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return _unsupported("The contract has no paths.")
    return [
        str(key)
        for key, item in paths.items()
        if isinstance(item, dict) and item.get("x-dppce-resource") == resource
    ]


def _bound_contract(ctx: CheckContext) -> dict[str, Any] | CheckOutcome:
    """The contract that the profile binds, if it is the one that the ICS names."""
    if ctx.profile.api_contract is None:
        return blocked("API.CONTRACT.MISSING", "The profile names no API contract.")
    try:
        document: Any = load_data(ctx.data_root / ctx.profile.api_contract)
    except CatalogueError:
        return blocked("API.CONTRACT.MISSING", "The pinned API contract cannot be read.")
    if not isinstance(document, dict):
        return blocked("API.CONTRACT.MISSING", "The pinned API contract is not a mapping.")
    expected = ctx.ics.api.contract
    if expected == UNKNOWN:
        return blocked("API.CONTRACT.NOT_DECLARED", "The ICS does not name the API contract that it expects.")
    if document.get("x-dppce-contract-id") != expected:
        message = f"The bound API contract is not the contract '{expected}' that the ICS names."
        return blocked("API.CONTRACT.ICS_MISMATCH", message)
    return document


def _operation(
    ctx: CheckContext, document: dict[str, Any], method: str
) -> tuple[ResourceName, ResourceTemplate, Any] | CheckOutcome:
    """The resource, its IXIT template, and the responses of the operation that the contract marks.

    The contract, not the IXIT, selects the operation. The IXIT template must match its path, so
    a supplier cannot point the template at a lenient operation of the same contract.
    """
    name = ctx.params.get("resource", "item")
    resource = cast(ResourceName, name) if isinstance(name, str) and name in _RESOURCES else None
    template = ctx.ixit.resources.get(resource) if resource is not None else None
    if resource is None or template is None:
        return blocked("API.CONTRACT.NO_TARGET", "The IXIT declares no URL template for this resource.")
    named = ctx.params.get("path")
    if named is not None and named != template.path:
        message = f"The test purpose names the path '{named}', but the IXIT template is '{template.path}'."
        return blocked("API.CONTRACT.PATH_MISMATCH", message)
    keys = _marked(document, resource)
    if isinstance(keys, CheckOutcome):
        return keys
    if len(keys) != 1:
        count = "no operation" if not keys else "two operations"
        return _unsupported(f"The contract marks {count} for the resource '{resource}'.")
    if _shape(keys[0]) != _shape(template.path):
        message = f"The IXIT template for '{resource}' does not match the operation that the contract marks."
        return blocked("API.CONTRACT.PATH_MISMATCH", message)
    try:
        responses = document["paths"][keys[0]][method]["responses"]
    except (KeyError, TypeError):
        return _unsupported(f"The contract has no '{method}' operation for '{keys[0]}'.")
    return resource, template, responses


@register("api.contract", capability="api.contract")
def contract(ctx: CheckContext) -> CheckOutcome:
    method = str(ctx.params.get("method", "get")).lower()
    document = _bound_contract(ctx)
    if isinstance(document, CheckOutcome):
        return document
    if method != "get":
        return _unsupported(f"The method '{method}' is outside the supported subset.")
    operation = _operation(ctx, document, method)
    if isinstance(operation, CheckOutcome):
        return operation
    resource, template, responses = operation
    url = resource_url(ctx, resource, "API.CONTRACT")
    if isinstance(url, CheckOutcome):
        return url
    record = fetch_once(ctx, url)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    summary: dict[str, Any] = {
        "path": template.path,
        "resource": resource,
        "status": record.status,
        "media_type": media_type(record),
    }

    def result(passed: bool, code: str, message: str) -> CheckOutcome:
        observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
        return completed(passed, code, message, [observation])

    declared = responses.get(str(record.status))
    if not isinstance(declared, dict):
        return result(False, "API.CONTRACT.STATUS", f"The contract does not declare status {record.status}.")
    content = declared.get("content", {})
    if summary["media_type"] not in content:
        return result(
            False,
            "API.CONTRACT.CONTENT_TYPE",
            f"The contract does not declare the media type '{summary['media_type']}'.",
        )
    schema = content[summary["media_type"]].get("schema")
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
