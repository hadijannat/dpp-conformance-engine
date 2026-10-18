"""Regression tests for the agent review of the adapters of 2026-10-18.

Each test reproduces one confirmed finding. Its identifier is in the test name or the comment.
The record is validation/records/review-adapters-2026-10-18.md. This is an agent review, not an
audit. Loopback servers and in-process acquirers only: no test reaches an external host.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.common import resource_url, schema_errors, validator
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import CheckOutcome, ExecutionStatus
from tests.support import make_record, reply
from tests.test_resolved_target import (
    ITEM_PATH,
    PASSPORT,
    RESOLVER_PATH,
    Origin,
    _blocked,
    moved,
    resolved_context,
    served,
    template_mode,
)
from tests.test_url_templates import CONTRACT, REFERENCE, Canned, context, ixit, run, sent, write_data

LENIENT = b'{"anything": true}'


class Answer:
    """An acquirer that answers with one fixed status, content type, and body."""

    def __init__(self, status: int, content_type: str | None, body: bytes) -> None:
        self._status, self._type, self._body = status, content_type, body
        self._records: list[Record] = []

    def fetch(self, request: Request) -> Record:
        headers = () if self._type is None else (("Content-Type", self._type),)
        record = dataclasses.replace(
            make_record(len(self._records) + 1, self._body, request.url), status=self._status, headers=headers
        )
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        raise AssertionError(name)

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)


def _item_get(get: Any, components: dict[str, Any] | None = None) -> dict[str, Any]:
    document = CONTRACT | {"paths": {"/dpp/{id}": {"x-dppce-resource": "item", "get": get}}}
    return document | ({"components": components} if components else {})


def _with_schema(schema: Any) -> dict[str, Any]:
    return _item_get({"responses": {"200": {"content": {"application/json": {"schema": schema}}}}})


# -- api-common-1: the judged fetch must be the marked operation ------------------------------------


class _SecondFetchMoves:
    """Answers /dpp/{ID} with 200 the first time (the resolver exchange) and then with a 303."""

    def __init__(self, loopback: Any, second: str) -> None:
        self.count = 0

        def handle(request: http.server.BaseHTTPRequestHandler) -> None:
            if request.path == RESOLVER_PATH:
                reply(request, 303, b"", {"Location": ITEM_PATH, "Content-Type": "text/plain"})
            elif request.path == ITEM_PATH:
                self.count += 1
                if self.count == 1:
                    reply(request, 200, PASSPORT, {})
                else:
                    reply(request, 303, b"", {"Location": second, "Content-Type": "text/plain"})
            elif request.path == "/static/x.json":
                reply(request, 200, LENIENT, {})
            else:
                reply(request, 404, b"{}", {})

        self.server = loopback(handle)
        self.origin: str = self.server.origin


def test_api_common_1_a_redirect_of_the_marked_operation_is_not_judged_as_its_answer(
    tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback, {ITEM_PATH: moved("/static/x.json"), "/static/x.json": served(LENIENT)})
    outcome = run(template_mode(resolved_context(tmp_path, "api.contract", api.origin)))
    _blocked(outcome, "API.CONTRACT.PATH_MISMATCH")


@pytest.mark.parametrize("where", ["same origin, other path", "other origin, same path"])
def test_api_common_1_a_judged_fetch_that_redirects_off_the_marked_operation_is_refused(
    where: str, tmp_path: Path, loopback: Any
) -> None:
    other = Origin(loopback, {ITEM_PATH: served(LENIENT)})
    second = "/static/x.json" if where.startswith("same") else other.origin + ITEM_PATH
    api = _SecondFetchMoves(loopback, second)
    _blocked(run(resolved_context(tmp_path, "api.contract", api.origin)), "API.CONTRACT.PATH_MISMATCH")


# -- api-common-2: a dot segment from the IXIT --------------------------------------------------------


@pytest.mark.parametrize("passport_id", [".", ".."])
def test_api_common_2_a_dot_segment_identifier_gives_no_template_url(
    passport_id: str, tmp_path: Path
) -> None:
    ctx = context(
        tmp_path, "persistence.versions", the_ixit=ixit(samples={"passport_id": passport_id}, id_parts=None)
    )
    for name in ("item", "model", "versions", "registry_record"):
        outcome = resource_url(ctx, name, "X")  # type: ignore[arg-type]  # the literal names are resources
        assert isinstance(outcome, CheckOutcome)
        assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "X.NO_TARGET")


@pytest.mark.parametrize("passport_id", ["x-..", "..-x", "x-."])
def test_api_common_2_a_dot_segment_identifier_part_gives_no_template_url(
    passport_id: str, tmp_path: Path
) -> None:
    resources = REFERENCE | {"item": {"endpoint": "api", "path": "/p/{gtin}/{serial}"}}
    ctx = context(
        tmp_path,
        "persistence.versions",
        the_ixit=ixit(samples={"passport_id": passport_id}, resources=resources),
    )
    assert isinstance(resource_url(ctx, "item", "X"), CheckOutcome)


@pytest.mark.parametrize("passport_id", [".", ".."])
def test_api_common_2_api_contract_is_blocked_on_a_dot_segment_identifier_and_sends_nothing(
    passport_id: str, tmp_path: Path
) -> None:
    ctx = context(
        tmp_path, "api.contract", the_ixit=ixit(samples={"passport_id": passport_id}, id_parts=None)
    )
    outcome = run(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "API.CONTRACT.NO_TARGET",
    )
    assert sent(ctx) == 0


# -- api-common-3 and api-common-6: contract features outside the subset ------------------------------

JSON_CONTENT = {"content": {"application/json": {}}}


@pytest.mark.parametrize(
    "get",
    [
        {"responses": {"default": JSON_CONTENT}},
        {"responses": {"2XX": JSON_CONTENT}},
        {"responses": {"200": {"content": {"application/*": {}}}}},
        {"responses": {"200": {"content": {"Application/JSON; charset=utf-8": {}}}}},
        {"responses": {"200": {"content": {"application/json": {"schema": True}}}}},
        {"responses": [{"200": {}}]},
        {"responses": {"200": {"content": "xx application/json xx"}}},
        {"responses": {"200": {"content": {"application/json": ["schema"]}}}},
        {"responses": {"200": ["not a response"]}},
    ],
    ids=[
        "default",
        "range",
        "media-range",
        "media-parameters",
        "bool-schema",
        "list-responses",
        "string-content",
        "list-media",
        "list-response",
    ],
)
def test_api_common_3_and_6_a_contract_feature_outside_the_subset_is_unsupported(
    get: Any, tmp_path: Path
) -> None:
    write_data(tmp_path, contract=_item_get(get))
    ctx = context(tmp_path, "api.contract")
    outcome = run(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "API.CONTRACT.UNSUPPORTED_FEATURE",
    )
    assert sent(ctx) == 0, "the contract is checked before anything is fetched"


def test_api_common_3_an_unquoted_status_key_is_the_same_status(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_item_get({"responses": {200: JSON_CONTENT}}))
    outcome = run(context(tmp_path, "api.contract"))
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")


def test_api_common_3_a_status_without_content_needs_no_media_type(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_item_get({"responses": {"204": {"description": "none"}}}))
    outcome = run(context(tmp_path, "api.contract", acquirer=Answer(204, None, b"")))  # type: ignore[arg-type]  # an acquirer double
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")


def test_api_common_3_a_status_without_content_and_a_body_is_not_judged(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_item_get({"responses": {"204": {"description": "none"}}}))
    outcome = run(context(tmp_path, "api.contract", acquirer=Answer(204, "application/json", b"{}")))  # type: ignore[arg-type]  # an acquirer double
    assert outcome.passed is not True


def test_api_common_3_a_real_status_mismatch_still_fails(tmp_path: Path) -> None:
    outcome = run(context(tmp_path, "api.contract", acquirer=Answer(404, "application/json", b"{}")))  # type: ignore[arg-type]  # an acquirer double
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "API.CONTRACT.STATUS",
    )


# -- api-common-4: a JSON body that is not an object ---------------------------------------------------


@pytest.mark.parametrize(
    ("schema", "body"),
    [({"type": "array"}, b"[1, 2]"), ({"type": "string"}, b'"x"'), ({"type": "integer"}, b"7")],
)
def test_api_common_4_a_json_body_that_is_not_an_object_is_judged(
    schema: dict[str, Any], body: bytes, tmp_path: Path
) -> None:
    write_data(tmp_path, contract=_with_schema(schema))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(body)))
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")


def test_api_common_4_a_wrong_json_kind_is_a_schema_error(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_with_schema({"type": "array"}))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(b'{"id": "x"}')))
    assert (outcome.passed, outcome.reason_code) == (False, "API.CONTRACT.SCHEMA")


@pytest.mark.parametrize("body", [b"not json", b'{"a": 1, "a": 2}'])
def test_api_common_4_a_body_that_is_not_strict_json_is_still_not_json(body: bytes, tmp_path: Path) -> None:
    write_data(tmp_path, contract=_with_schema({"type": "array"}))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(body)))
    assert (outcome.passed, outcome.reason_code) == (False, "API.RESPONSE.NOT_JSON")


# -- api-common-5: a deep body and a recursive schema --------------------------------------------------

RECURSIVE_SCHEMA = {"type": "object", "additionalProperties": {"$ref": "#/components/schemas/N"}}


def _nested(depth: int) -> bytes:
    return ('{"a":' * depth + "{}" + "}" * depth).encode()


@pytest.mark.parametrize("depth", [3, 600])
def test_api_common_5_a_deep_body_gets_an_outcome_not_an_exception(depth: int, tmp_path: Path) -> None:
    contract = _item_get(
        {
            "responses": {
                "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/N"}}}}
            }
        },
        components={"schemas": {"N": RECURSIVE_SCHEMA}},
    )
    write_data(tmp_path, contract=contract)
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(_nested(depth))))
    if depth == 3:
        assert outcome.reason_code == "API.CONTRACT.OK"
    else:
        assert (outcome.status, outcome.passed) == (ExecutionStatus.BLOCKED, None)


def test_api_common_5_data_jsonschema_on_a_deep_body_is_not_judged(tmp_path: Path) -> None:
    write_data(tmp_path)
    schema = {
        "$ref": "#/$defs/N",
        "$defs": {"N": {"type": "object", "additionalProperties": {"$ref": "#/$defs/N"}}},
    }
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(_nested(600))))
    assert (outcome.status, outcome.passed) == (ExecutionStatus.BLOCKED, None)


# -- api-common-7: a query that the contract does not declare ------------------------------------------


def test_api_common_7_a_resolved_url_with_a_query_is_refused(tmp_path: Path, loopback: Any) -> None:
    lenient = ITEM_PATH + "?view=lenient"
    api = Origin(loopback, {RESOLVER_PATH: moved(lenient), lenient: served()})
    _blocked(run(resolved_context(tmp_path, "api.contract", api.origin)), "API.CONTRACT.PATH_MISMATCH")
    assert api.hits(lenient) == 1, "only the resolver exchange reached the query variant"


# -- api-common-8 and data-lifecycle-9: format uri -----------------------------------------------------

URI_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id"],
    "properties": {"id": {"type": "string", "format": "uri"}},
}


def test_api_common_8_the_validator_asserts_format_uri() -> None:
    check = validator(URI_SCHEMA)
    assert check is not None
    assert schema_errors(check, {"id": "not a uri"}) == [{"path": "/id", "keyword": "format"}]
    assert schema_errors(check, {"id": "https://id.example.test/dpp/1"}) == []
    assert schema_errors(check, {"id": "urn:example:operator:0001"}) == []


def test_api_common_8_api_contract_never_passes_a_body_that_breaks_format_uri(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_with_schema(URI_SCHEMA))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(b'{"id": "not a uri"}')))
    assert (outcome.passed, outcome.reason_code) == (False, "API.CONTRACT.SCHEMA")


def test_data_lifecycle_9_data_jsonschema_never_passes_a_body_that_breaks_format_uri(tmp_path: Path) -> None:
    write_data(tmp_path)
    (tmp_path / "schema.json").write_text(json.dumps(URI_SCHEMA), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(b'{"id": "not a uri at all"}')))
    assert (outcome.passed, outcome.reason_code) == (False, "DATA.SCHEMA.INVALID")


def test_data_lifecycle_9_a_format_that_the_engine_cannot_assert_is_not_passed(tmp_path: Path) -> None:
    write_data(tmp_path)
    schema = {"properties": {"id": {"type": "string", "format": "iri-reference"}}}
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(b'{"id": "x"}')))
    assert outcome.passed is not True


# -- data-lifecycle-6: data.jsonschema compares numbers exactly ----------------------------------------


@pytest.mark.parametrize(
    ("bound", "body", "expected"),
    [
        ({"maximum": 100}, b'{"soh": 100.00000000000000001}', (False, "DATA.SCHEMA.INVALID")),
        ({"exclusiveMaximum": 100}, b'{"soh": 99.99999999999999999}', (True, "DATA.SCHEMA.OK")),
        ({"maximum": 100}, b'{"soh": 97.5}', (True, "DATA.SCHEMA.OK")),
        ({"type": "integer"}, b'{"soh": 1.0}', (True, "DATA.SCHEMA.OK")),
        ({"type": "integer"}, b'{"soh": 1.5}', (False, "DATA.SCHEMA.INVALID")),
        ({"multipleOf": 0.1}, b'{"soh": 0.3}', (True, "DATA.SCHEMA.OK")),
    ],
)
def test_data_lifecycle_6_a_schema_bound_is_compared_exactly(
    bound: dict[str, Any], body: bytes, expected: tuple[bool, str], tmp_path: Path
) -> None:
    write_data(tmp_path)
    schema = {"type": "object", "properties": {"soh": {"type": "number"} | bound}}
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(body)))
    assert (outcome.passed, outcome.reason_code) == expected
