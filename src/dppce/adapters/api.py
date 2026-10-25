"""API adapter: compare a response with a pinned, maintainer-supplied OpenAPI contract.

Supported subset of OpenAPI 3.1: path templates, ``get``, the response status, the response
media type, and a JSON Schema with local ``#/components/schemas`` references. Anything else is
reported as ``unsupported``. A 3.0 contract is judged through an exact translation of its Schema
Objects; another version gives ``blocked``. Fuzzing and negative tests are a separate capability
that needs a signed authorization.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Literal, cast, get_args
from urllib.parse import unquote, urlsplit

from jsonschema import SchemaError
from pydantic import Field

from dppce.adapters.common import (
    DialectError,
    blocked,
    completed,
    effective_url,
    fetch_once,
    item_url,
    media_type,
    not_done,
    resource_url,
    schema_errors,
    unassertable_formats,
    unusable,
    validator,
)
from dppce.catalogue import CatalogueError, load_data
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.models import UNKNOWN, CheckOutcome, ExecutionStatus, Model, ResourceName, ResourceTemplate
from dppce.testdefs.registry import CheckContext, register

_RESOURCES: frozenset[str] = frozenset(get_args(ResourceName))
_STATUS = re.compile(r"[1-5][0-9]{2}")
# A media type without a range, a parameter, or an upper-case letter: the key is compared exactly.
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")


class ContractParams(Model):
    resource: ResourceName = Field(
        default="item", description="Passport resource whose marked operation is judged."
    )
    path: str | None = Field(
        default=None,
        min_length=1,
        description="Expected IXIT template path. A different template gives blocked.",
    )
    method: Literal["get"] = Field(default="get", description="HTTP method. Only get is supported.")


def _unsupported(message: str) -> CheckOutcome:
    return not_done(ExecutionStatus.UNSUPPORTED, "API.CONTRACT.UNSUPPORTED_FEATURE", message)


_OAS31_DIALECT = "https://spec.openapis.org/oas/3.1/dialect/base"
_DRAFT_2020 = "https://json-schema.org/draft/2020-12/schema"


def _version_gate(document: dict[str, Any]) -> bool | CheckOutcome:
    """True for OpenAPI 3.0.x, False for 3.1.x, or a blocked outcome for any other version.

    A 3.1 contract can change the default dialect of its schemas. The engine applies 2020-12.
    """
    version = document.get("openapi")
    text = version if isinstance(version, str) else ""
    dialect = document.get("jsonSchemaDialect", _OAS31_DIALECT)
    if re.fullmatch(r"3\.1\.[0-9]+", text) and dialect in (_OAS31_DIALECT, _DRAFT_2020):
        return False
    if re.fullmatch(r"3\.0\.[0-9]+", text):
        return True
    message = "The contract is not OpenAPI 3.0.x or 3.1.x with the default schema dialect."
    return blocked("API.CONTRACT.UNSUPPORTED_VERSION", message)


# The fields of an OpenAPI 3.0 Schema Object whose meaning a 2020-12 validator keeps or that it
# translates. "discriminator" and "writeOnly" change validation in 3.0, so they are not here.
_OAS30_FIELDS = frozenset(
    {
        "title",
        "description",
        "default",
        "deprecated",
        "externalDocs",
        "xml",
        "readOnly",
        "example",
        "format",
        "nullable",
        "type",
        "enum",
        "multipleOf",
        "maximum",
        "exclusiveMaximum",
        "minimum",
        "exclusiveMinimum",
        "maxLength",
        "minLength",
        "pattern",
        "maxItems",
        "minItems",
        "uniqueItems",
        "maxProperties",
        "minProperties",
        "required",
        "items",
        "properties",
        "additionalProperties",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
    }
)
_OAS30_TYPES = frozenset({"array", "boolean", "integer", "number", "object", "string"})


class _UntranslatableError(ValueError):
    pass


def _of(value: Any, kind: type) -> Any:
    if not isinstance(value, kind):
        raise _UntranslatableError(kind.__name__)
    return value


def _from_oas30(node: Any) -> dict[str, Any]:  # noqa: PLR0912 - one branch per translated keyword reads as the 3.0 rule list
    """An OpenAPI 3.0 Schema Object as JSON Schema 2020-12 with the same meaning, or _UntranslatableError.

    Only schema positions are walked, so a property named "nullable" stays a property.
    """
    node = _of(node, dict)  # 3.0 has no boolean schema
    if "$ref" in node:
        # 3.0 ignores the siblings of $ref. 2020-12 applies them.
        if len(node) != 1:
            raise _UntranslatableError("$ref with siblings")
        return dict(node)
    if any(not (key in _OAS30_FIELDS or (isinstance(key, str) and key.startswith("x-"))) for key in node):
        raise _UntranslatableError("a field outside the 3.0 Schema Object or the translation")
    out = {k: v for k, v in node.items() if k not in ("nullable", "example")}
    kind = node.get("type")
    if kind is not None and _of(kind, str) not in _OAS30_TYPES:
        raise _UntranslatableError("type")
    # OpenAPI 3.0.3: nullable adds null to an explicit type only. Other keywords still apply.
    if _of(node.get("nullable", False), bool) and kind is not None:
        out["type"] = [kind, "null"]
    for flag, bound in (("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")):
        if flag in node:
            # The draft 04 form: a boolean that modifies its bound, which must be present.
            if bound not in node:
                raise _UntranslatableError(flag)
            if _of(out.pop(flag), bool):
                out[flag] = out.pop(bound)
    for key, value in node.items():
        if key in ("items", "not") or (key == "additionalProperties" and not isinstance(value, bool)):
            out[key] = _from_oas30(value)
        elif key in ("allOf", "anyOf", "oneOf"):
            out[key] = [_from_oas30(part) for part in _of(value, list)]
        elif key == "properties":
            out[key] = {name: _from_oas30(part) for name, part in _of(value, dict).items()}
    return out


def _translated(
    document: dict[str, Any], responses: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | CheckOutcome:
    """The components and the responses with each 3.0 Schema Object translated, or blocked.

    Every component schema is translated, because any of them can be the target of a reference.
    """
    try:
        schemas = _of(_of(document.get("components", {}), dict).get("schemas", {}), dict)
        translated = {name: _from_oas30(schema) for name, schema in schemas.items()}
        found = {
            status: declared
            | {
                "content": {
                    name: media | ({"schema": _from_oas30(media["schema"])} if "schema" in media else {})
                    for name, media in declared.get("content", {}).items()
                }
            }
            for status, declared in responses.items()
        }
    except _UntranslatableError:
        message = (
            "The OpenAPI 3.0 contract uses a schema construct that the engine does not translate exactly."
        )
        return blocked("API.CONTRACT.UNSUPPORTED_VERSION", message)
    return {"schemas": translated}, found


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


def _responses(responses: Any) -> dict[str, dict[str, Any]] | CheckOutcome:
    """The responses of the marked operation, keyed by status text, if the subset covers them.

    The check compares keys exactly. A range such as 2XX, ``default``, a media range, or a
    structure of another type would give a false fail or an exception, so each is unsupported.
    """
    outside = _unsupported("The marked operation declares a response outside the supported subset.")
    if not isinstance(responses, dict):
        return outside
    found: dict[str, dict[str, Any]] = {}
    for key, declared in responses.items():
        # YAML reads an unquoted 200 as an integer. It names the same status.
        status = str(key) if type(key) is int else key
        if not (isinstance(status, str) and _STATUS.fullmatch(status)) or status in found:
            return outside
        # A reference response holds no content key, so it would read as "declares no body".
        if not isinstance(declared, dict) or "$ref" in declared:
            return outside
        content = declared.get("content", {})
        if not isinstance(content, dict):
            return outside
        for name, media in content.items():
            if not (isinstance(name, str) and _MEDIA_TYPE.fullmatch(name) and isinstance(media, dict)):
                return outside
            if not isinstance(media.get("schema", {}), dict):
                return outside
        found[status] = declared
    return found


def _operation(
    ctx: CheckContext, document: dict[str, Any], method: str
) -> tuple[ResourceName, ResourceTemplate, dict[str, dict[str, Any]]] | CheckOutcome:
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
    found = _responses(responses)
    if isinstance(found, CheckOutcome):
        return found
    if formats := unassertable_formats([found, document.get("components")]):
        return _unsupported(f"The contract uses formats that the engine cannot assert: {', '.join(formats)}.")
    return resource, template, found


def _unsafe(segment: str) -> bool:
    """True if a decoded path segment holds a separator or a control character."""
    return any(c in "/\\" or unicodedata.category(c) == "Cc" for c in segment)


def _within(ctx: CheckContext, template: ResourceTemplate, url: str) -> bool:
    """True if a resolved URL is the marked operation under the endpoint of the item template.

    The template already matches the marked operation, so each placeholder matches one segment.
    """
    base, _ = effective_url(ctx, ctx.ixit.endpoints.get(template.endpoint, "").rstrip("/"))
    if not base:
        return False
    # Parse the full URL once. A parsed remainder such as //static/dpp/X reads as a host.
    parts, origin = urlsplit(url), urlsplit(base)
    # ponytail: an exact scheme and netloc; another spelling of the same origin gives blocked, never pass.
    if (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc):
        return False
    # The supported subset has no query parameters: a query would select an undeclared variant.
    if parts.query or parts.fragment:
        return False
    if not parts.path.startswith(origin.path + "/"):
        return False
    rest = parts.path[len(origin.path) :]
    # A server collapses an empty segment and resolves a dot segment, so the path would name another resource.
    # Tomcat and Jetty drop ";params" from a segment before they route, so "..;x" is a dot segment too.
    dots = {".", ".."}
    if "//" in rest or any(unquote(segment).partition(";")[0] in dots for segment in rest.split("/")):
        return False
    # A server may decode a segment before it routes, so an encoded separator or control would
    # name another resource. ponytail: every segment is checked, so a literal %2F in a template blocks too.
    if any(_unsafe(unquote(segment)) for segment in rest.split("/")):
        return False
    pattern = "".join(
        "[^/]+" if part.startswith("{") else re.escape(part)
        for part in re.split(r"(\{[^{}/]*\})", template.path.split("?", 1)[0])
    )
    return re.fullmatch(pattern, rest) is not None


def _target(
    ctx: CheckContext, resource: ResourceName, template: ResourceTemplate, *, resolved: bool
) -> str | CheckOutcome:
    """The URL to judge: from the template, or the resolved item URL if it is the marked operation."""
    if not resolved:
        return resource_url(ctx, resource, "API.CONTRACT")
    url = item_url(ctx, "API.CONTRACT")
    if isinstance(url, str) and not _within(ctx, template, url):
        message = (
            "The resolved URL is not the operation that the contract marks, under the endpoint "
            "of the 'item' template."
        )
        return blocked("API.CONTRACT.PATH_MISMATCH", message)
    return url


@register("api.contract", capability="api.contract", params=ContractParams)
def contract(ctx: CheckContext) -> CheckOutcome:  # noqa: PLR0912 - one branch per documented outcome; the reason-code page reads them here
    method = str(ctx.params.get("method", "get")).lower()
    document = _bound_contract(ctx)
    if isinstance(document, CheckOutcome):
        return document
    openapi_30 = _version_gate(document)
    if isinstance(openapi_30, CheckOutcome):
        return openapi_30
    if method != "get":
        return _unsupported(f"The method '{method}' is outside the supported subset.")
    operation = _operation(ctx, document, method)
    if isinstance(operation, CheckOutcome):
        return operation
    resource, template, responses = operation
    components = document.get("components", {})
    if openapi_30:
        translated = _translated(document, responses)
        if isinstance(translated, CheckOutcome):
            return translated
        components, responses = translated
    resolved = resource == "item" and ctx.ixit.item_target == "resolved"
    url = _target(ctx, resource, template, resolved=resolved)
    if isinstance(url, CheckOutcome):
        return url
    record = fetch_once(ctx, url)
    if (problem := unusable(ctx, record)) is not None:
        return problem
    if record.redirects:
        # The transport followed a redirect. Its status is not recorded, and the body belongs to
        # another URL, so the answer of the marked operation is not available to judge.
        message = "The marked operation answered with a redirect. The engine judges no answer of another URL."
        return blocked("API.CONTRACT.PATH_MISMATCH", message)
    summary: dict[str, Any] = {
        "path": template.path,
        "resource": resource,
        "status": record.status,
        "media_type": media_type(record),
    }
    if resolved:
        summary |= {"item_target": "resolved", "fetched_path": urlsplit(url).path}

    def result(passed: bool, code: str, message: str) -> CheckOutcome:
        observation = ctx.observation(0, kind="exchange", records=[record], summary=summary)
        return completed(passed, code, message, [observation])

    declared = responses.get(str(record.status))
    if declared is None:
        return result(False, "API.CONTRACT.STATUS", f"The contract does not declare status {record.status}.")
    # An empty content map declares no body, like an absent one.
    if not declared.get("content"):
        if summary["media_type"] or record.body:
            return _unsupported(
                f"The contract declares no content for status {record.status}, and the response has one."
            )
        return result(True, "API.CONTRACT.OK", "The status matches the contract. Neither declares a body.")
    content = declared["content"]
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
    malformed = "The contract schema is not a valid JSON Schema, or a local reference does not resolve."
    try:
        check = validator({**schema, "components": components}, openapi_30=openapi_30)
    except DialectError:
        return _unsupported("The contract schema names a dialect other than JSON Schema 2020-12 or draft-07.")
    except SchemaError:
        return _unsupported(malformed)
    if check is None:
        return _unsupported("The contract uses a reference that is not local to the document.")
    try:
        # Any JSON value: a schema can declare an array or a scalar. Exact decimals for the bounds.
        body = parse_strict(record.body, decimals=True)
    except CanonicalizationError:
        return result(False, "API.RESPONSE.NOT_JSON", "The response body is not JSON.")
    try:
        errors = schema_errors(check, body)
    except SchemaError:
        return _unsupported(malformed)
    if errors is None:
        return blocked(
            "API.RESPONSE.TOO_DEEP", "The response body is nested too deeply to validate. It is not judged."
        )
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
