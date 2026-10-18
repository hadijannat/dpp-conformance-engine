"""Regression tests for the agent review of the adapters of 2026-10-18.

Each test reproduces one confirmed finding. Its identifier is in the test name or the comment.
The record is validation/records/review-adapters-2026-10-18.md. This is an agent review, not an
audit. Loopback servers and in-process acquirers only: no test reaches an external host.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
from pydantic import TypeAdapter, ValidationError

from dppce.adapters.carrier import qr_decode
from dppce.adapters.common import effective_url, resource_url, schema_errors, validator
from dppce.adapters.data import Rule, rule_holds
from dppce.adapters.identifier import consistency, parse_gs1_digital_link, resolve
from dppce.evidence.canonical import canonical_bytes, digest
from dppce.evidence.jws import LocalSigner, sign_compact
from dppce.infrastructure.authorization import AUTHORIZATION_TYP, AuthorizationError, validate_authorization
from dppce.infrastructure.clock import parse_stamp, utc_stamp
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import (
    Attestation,
    Authorization,
    CheckOutcome,
    ExecutionStatus,
    RevokedCertificate,
    RevokedKey,
    StatusList,
    TrustBundle,
    TrustedKey,
    Verdict,
    VerdictRules,
)
from dppce.testdefs.registry import CheckContext
from dppce.verdicts import step_verdict
from tests.support import AT, make_record, reply
from tests.test_adapters_identifier import Resolver, _with_identifier, live
from tests.test_adapters_security import _POLICY, _Canned, _context
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
from tests.test_review_findings import transport as review_transport
from tests.test_server_errors import Status
from tests.test_transport import authorization
from tests.test_url_templates import API, CONTRACT, REFERENCE, Canned, context, ixit, run, sent, write_data

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


# fix-check-3: an empty content map declares no body, like an absent one.
NO_CONTENT = [{"description": "none"}, {"description": "none", "content": {}}]


@pytest.mark.parametrize("declared", NO_CONTENT, ids=["absent", "empty"])
def test_api_common_3_a_status_without_content_needs_no_media_type(
    declared: dict[str, Any], tmp_path: Path
) -> None:
    write_data(tmp_path, contract=_item_get({"responses": {"204": declared}}))
    outcome = run(context(tmp_path, "api.contract", acquirer=Answer(204, None, b"")))  # type: ignore[arg-type]  # an acquirer double
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")


@pytest.mark.parametrize("declared", NO_CONTENT, ids=["absent", "empty"])
def test_api_common_3_a_status_without_content_and_a_body_is_not_judged(
    declared: dict[str, Any], tmp_path: Path
) -> None:
    write_data(tmp_path, contract=_item_get({"responses": {"204": declared}}))
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


@pytest.mark.parametrize("format_name", ["iri-reference", "date-time", "time", "hostname", "regex"])
def test_data_lifecycle_9_a_format_that_the_engine_cannot_assert_is_not_passed(
    format_name: str, tmp_path: Path
) -> None:
    write_data(tmp_path)
    schema = {"properties": {"id": {"type": "string", "format": format_name}}}
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


# -- data and lifecycle: answers by URL --------------------------------------------------------------

PID = "09506000134352-EV0001"
ITEM_URL, VERSIONS_URL, REGISTRY_URL = (
    f"{API}/dpp/{PID}",
    f"{API}/dpp/{PID}/versions",
    f"{API}/registry/{PID}",
)
ITEM: dict[str, Any] = {"id": "x"}
ENTRY = b'{"identifier":"https://id/x","operator_identifier":"urn:op:1"}'


class ByUrl(Canned):
    """Answers each URL with its own status and body. Every other URL is not found."""

    def __init__(self, answers: dict[str, tuple[int, bytes]]) -> None:
        super().__init__()
        self._answers = answers

    def fetch(self, request: Request) -> Record:
        status, body = self._answers.get(request.url, (404, b"{}"))
        record = dataclasses.replace(make_record(len(self._records) + 1, body, request.url), status=status)
        self._records.append(record)
        return record


def _history(*entries: dict[str, Any]) -> bytes:
    return json.dumps({"versions": list(entries)}).encode()


def _entry(version: int, stamp: str | None, content: dict[str, Any] = ITEM) -> dict[str, Any]:
    entry: dict[str, Any] = {"version": version, "content_digest": digest(content)}
    return entry | ({"updated_at": stamp} if stamp is not None else {})


def _versions(
    tmp_path: Path, history: bytes, item: bytes = b'{"id": "x"}', statuses: tuple[int, int] = (200, 200)
) -> CheckOutcome:
    answers = {VERSIONS_URL: (statuses[0], history), ITEM_URL: (statuses[1], item)}
    return run(context(tmp_path, "persistence.versions", acquirer=ByUrl(answers)))


def _not_a_finding(outcome: CheckOutcome) -> None:
    """An answer that the engine cannot judge is never a completed fail against the system."""
    assert outcome.passed is not True
    verdict = step_verdict(outcome.status, outcome.passed, outcome.unreachable, VerdictRules())
    assert verdict is Verdict.INCONCLUSIVE


# -- data-lifecycle-1 and data-lifecycle-7: a refused or missing document ----------------------------

HISTORY = _history(_entry(1, "2026-09-01T08:00:00Z"))


@pytest.mark.parametrize("status", [401, 403, 404])
def test_data_lifecycle_1_versions_does_not_judge_a_refused_item(status: int, tmp_path: Path) -> None:
    outcome = _versions(tmp_path, HISTORY, b'{"error":"unauthorized"}', (200, status))
    assert outcome.reason_code != "PERSISTENCE.UNDECLARED_CHANGE"
    _not_a_finding(outcome)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_data_lifecycle_1_versions_does_not_judge_a_refused_history(status: int, tmp_path: Path) -> None:
    outcome = _versions(tmp_path, b'{"error":"denied"}', statuses=(status, 200))
    assert outcome.reason_code != "PERSISTENCE.RESPONSE.NOT_JSON"
    _not_a_finding(outcome)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_data_lifecycle_1_registry_does_not_judge_a_refused_item(status: int, tmp_path: Path) -> None:
    answers = {REGISTRY_URL: (200, ENTRY), ITEM_URL: (status, b'{"error":"unauthorized"}')}
    outcome = run(context(tmp_path, "registry.consistency", acquirer=ByUrl(answers)))
    assert outcome.reason_code != "REGISTRY.INCONSISTENT"
    _not_a_finding(outcome)


DATA_CHECKS: list[tuple[str, dict[str, Any]]] = [
    ("data.rules", {}),
    ("data.jsonschema", {"document": "item"}),
    ("data.jsonschema", {"document": "model"}),
    ("data.context", {"allowed_contexts": ["https://example.test/c"]}),
]


@pytest.mark.parametrize("status", [401, 403, 404])
@pytest.mark.parametrize(("check", "params"), DATA_CHECKS)
def test_data_lifecycle_7_a_refused_document_is_not_a_data_failure(
    check: str, params: dict[str, Any], status: int, tmp_path: Path
) -> None:
    outcome = run(context(tmp_path, check, params=params, acquirer=Status(status, b'{"error":"x"}')))
    assert outcome.reason_code != "DATA.RESPONSE.NOT_JSON", "the body is JSON"
    _not_a_finding(outcome)
    assert outcome.observations
    assert outcome.observations[0].summary.get("status") == status


def test_data_lifecycle_7_a_200_body_that_is_not_json_is_still_not_json(tmp_path: Path) -> None:
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Status(200, b"<html>")))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "DATA.RESPONSE.NOT_JSON",
    )


# -- data-lifecycle-2 and server-clock-fixes-4: update times are instants ---------------------------


@pytest.mark.parametrize(
    "stamps",
    [
        ("2026-01-01T09:00:00Z", "2026-01-01T10:00:00Z"),
        ("2026-01-01T10:00:00Z", "2026-01-01T10:00:00.5Z"),
        ("2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z"),
        ("2026-01-01T09:00:00Z", "2026-01-01T10:00:00+01:00"),
        ("2026-01-01T10:00:00Z", "2026-01-01T10:00:00.123456789Z"),
        # fix-check-5: RFC 3339 section 5.6 allows a lower-case t and z.
        ("2026-10-18T08:00:00Z", "2026-10-18T08:00:00z"),
        ("2026-10-18T08:00:00Z", "2026-10-18t08:00:01Z"),
    ],
    ids=["forward", "fractional-forward", "equal", "offset-equal", "nanoseconds", "lower-z", "lower-t"],
)
def test_data_lifecycle_2_a_later_or_equal_update_time_passes(
    stamps: tuple[str, str], tmp_path: Path
) -> None:
    history = _history(_entry(1, stamps[0], {"id": "old"}), _entry(2, stamps[1]))
    assert _versions(tmp_path, history).reason_code == "PERSISTENCE.OK"


@pytest.mark.parametrize(
    "stamps",
    [
        ("2026-01-01T09:00:00Z", "2026-01-01T10:00:00+05:00"),
        ("2026-10-10T08:00:00Z", "2026-9-01T08:00:00Z"),
        (None, None),
        ("2026-01-01T09:00:00Z", "not a time"),
        ("2026-01-01T09:00:00", "2026-01-01T10:00:00Z"),
        ("\u0662\u0660\u0662\u0666-01-01T09:00:00Z", "2026-01-01T10:00:00Z"),
    ],
    ids=["offset-back", "unpadded-back", "missing", "unparsable", "no-offset", "non-ascii"],
)
def test_data_lifecycle_2_a_backward_or_invalid_update_time_never_passes(
    stamps: tuple[str | None, str | None], tmp_path: Path
) -> None:
    history = _history(_entry(1, stamps[0], {"id": "old"}), _entry(2, stamps[1]))
    outcome = _versions(tmp_path, history)
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


# -- data-lifecycle-3: a passport that has no canonical form ----------------------------------------


@pytest.mark.parametrize("item", [b'{"id": "x", "soh": 97.5}', b'{"id": "x", "serial": 9007199254740993}'])
def test_data_lifecycle_3_a_passport_without_canonical_form_is_not_an_undeclared_change(
    item: bytes, tmp_path: Path
) -> None:
    stamp, last = "2026-01-01T00:00:00Z", "sha256:" + "0" * 64
    history = _history({"version": 1, "updated_at": stamp, "content_digest": last})
    outcome = _versions(tmp_path, history, item)
    assert (outcome.status, outcome.passed) == (ExecutionStatus.BLOCKED, None)


def test_data_lifecycle_3_a_real_rule_break_still_fails_without_a_digest(tmp_path: Path) -> None:
    history = _history(_entry(2, "2026-01-01T00:00:00Z"), _entry(1, "2026-01-02T00:00:00Z"))
    outcome = _versions(tmp_path, history, b'{"id": "x", "soh": 97.5}')
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


# -- data-lifecycle-4: the registry compares present values as JSON values ---------------------------


def _registry(tmp_path: Path, entry: dict[str, Any], passport: dict[str, Any]) -> CheckOutcome:
    answers = {
        REGISTRY_URL: (200, json.dumps(entry).encode()),
        ITEM_URL: (200, json.dumps(passport).encode()),
    }
    return run(context(tmp_path, "registry.consistency", acquirer=ByUrl(answers)))


@pytest.mark.parametrize(
    ("entry", "passport"),
    [
        ({}, {}),
        ({"identifier": PID}, {"id": PID}),
        ({"identifier": 1, "operator_identifier": 1}, {"id": True, "operator": {"identifier": True}}),
    ],
    ids=["both-empty", "operator-absent-both", "true-is-not-1"],
)
def test_data_lifecycle_4_registry_never_passes_on_absent_or_type_confused_fields(
    entry: dict[str, Any], passport: dict[str, Any], tmp_path: Path
) -> None:
    outcome = _registry(tmp_path, entry, passport)
    assert outcome.passed is False
    assert outcome.reason_code != "REGISTRY.OK"


def test_data_lifecycle_4_registry_passes_when_present_fields_match(tmp_path: Path) -> None:
    entry = {"identifier": PID, "operator_identifier": "op-1"}
    outcome = _registry(tmp_path, entry, {"id": PID, "operator": {"identifier": "op-1"}})
    assert (outcome.passed, outcome.reason_code) == (True, "REGISTRY.OK")


# -- data-lifecycle-5: every @context in the document ------------------------------------------------

ALLOWED = ["https://ok.example.test/ctx"]
EVIL = "https://evil.example.test/ctx"


def _contexts(tmp_path: Path, body: dict[str, Any]) -> CheckOutcome:
    params = {"allowed_contexts": ALLOWED}
    return run(context(tmp_path, "data.context", params=params, acquirer=Canned(json.dumps(body).encode())))


@pytest.mark.parametrize(
    "body",
    [
        {"@context": ALLOWED, "operator": {"@context": EVIL, "name": "x"}},
        {"@context": ALLOWED, "@graph": [{"@context": EVIL, "id": "x"}]},
        {"@context": ALLOWED, "parts": [{"@context": {"x": "https://evil.example.test/v#"}}]},
        {"@context": ALLOWED, "a": {"b": [{"c": {"@context": [ALLOWED[0], EVIL]}}]}},
    ],
    ids=["nested-node", "graph-member", "nested-inline", "deep-list"],
)
def test_data_lifecycle_5_a_nested_foreign_context_is_not_allowed(
    body: dict[str, Any], tmp_path: Path
) -> None:
    outcome = _contexts(tmp_path, body)
    assert (outcome.passed, outcome.reason_code) == (False, "DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"]


def test_data_lifecycle_5_a_nested_allowed_context_still_passes(tmp_path: Path) -> None:
    outcome = _contexts(tmp_path, {"@context": ALLOWED, "operator": {"@context": ALLOWED[0], "name": "x"}})
    assert (outcome.passed, outcome.reason_code) == (True, "DATA.CONTEXT.OK")


# -- data-lifecycle-8: a rule pack that judges nothing -----------------------------------------------

BASIS = {"class": "illustrative"}


def _rules(tmp_path: Path, rules: list[dict[str, Any]]) -> CheckOutcome:
    write_data(tmp_path)
    pack = {"schema_version": "dppce.rulepack/1", "rulepack_id": "t/r", "version": "1", "rules": rules}
    (tmp_path / "rules.json").write_text(json.dumps(pack), encoding="utf-8")
    return run(context(tmp_path, "data.rules", acquirer=Canned(b"{}")))


SWITCHED_OFF = {"fact": "profile.product_category", "op": "eq", "value": "ev"}


@pytest.mark.parametrize(
    "rules",
    [
        [],
        [{"id": "M", "kind": "required_fields", "document": "model", "fields": ["id"], "basis": BASIS}],
        [
            {
                "id": "W",
                "kind": "required_fields",
                "document": "item",
                "fields": ["id"],
                "when": SWITCHED_OFF,
                "basis": BASIS,
            }
        ],
    ],
    ids=["empty-pack", "only-model-rules", "switched-off"],
)
def test_data_lifecycle_8_zero_applied_rules_is_not_a_pass(
    rules: list[dict[str, Any]], tmp_path: Path
) -> None:
    outcome = _rules(tmp_path, rules)
    assert outcome.passed is not True
    assert outcome.reason_code != "DATA.RULES.OK"


@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "required_fields", "fields": []},
        {"kind": "required_fields", "fields": [""]},
        {"kind": "range", "field": "x"},
        {"kind": "unit", "field": "", "allowed": ["Wh"]},
        {"kind": "unit", "field": "u", "allowed": []},
        {"kind": "freshness", "field": "updated_at"},
        {"kind": "relationship", "left": "", "right": "b"},
    ],
    ids=[
        "required-no-fields",
        "required-empty-field",
        "range-no-bounds",
        "unit-empty-field",
        "unit-empty-allowed",
        "freshness-no-limit",
        "relationship-empty-side",
    ],
)
def test_data_lifecycle_8_a_rule_that_cannot_judge_is_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate({"id": "X", "document": "item", "basis": BASIS} | fields)


# -- data-lifecycle-10, server-clock-fixes-5, server-clock-fixes-6: update times for freshness --------

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
FRESH = Rule.model_validate(
    {
        "id": "R-F",
        "kind": "freshness",
        "document": "item",
        "field": "updated_at",
        "max_age_days": 30,
        "basis": BASIS,
    }
)


def test_server_clock_fixes_6_the_freshness_limit_is_inclusive() -> None:
    assert rule_holds(FRESH, {"updated_at": utc_stamp(NOW - timedelta(days=30))}, NOW)
    assert rule_holds(FRESH, {"updated_at": utc_stamp(NOW)}, NOW)


@pytest.mark.parametrize("ahead", [timedelta(seconds=1), timedelta(days=26_000)])
def test_data_lifecycle_10_and_server_clock_fixes_6_a_future_update_time_is_not_fresh(
    ahead: timedelta,
) -> None:
    assert not rule_holds(FRESH, {"updated_at": utc_stamp(NOW + ahead)}, NOW)


NON_CANONICAL = [
    "\u0662\u0660\u0662\u0666-10-10T08:00:00Z",
    "\uff12\uff10\uff12\uff16-10-10T08:00:00Z",
    "2026-1-1T1:1:1Z",
    "2026-10-10T08:00:00z",
    " 2026-10-10T08:00:00Z",
]


def test_server_clock_fixes_5_a_canonical_stamp_round_trips() -> None:
    assert utc_stamp(parse_stamp("2026-10-10T08:00:00Z")) == "2026-10-10T08:00:00Z"


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_server_clock_fixes_5_parse_stamp_refuses_what_utc_stamp_never_writes(text: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        parse_stamp(text)


@pytest.mark.parametrize("text", NON_CANONICAL[:2])
def test_server_clock_fixes_5_the_freshness_rule_fails_a_non_ascii_stamp(text: str) -> None:
    assert not rule_holds(FRESH, {"updated_at": text}, datetime(2026, 10, 18, tzinfo=UTC))


def test_server_clock_fixes_5_the_pinned_item_schema_refuses_a_non_ascii_stamp() -> None:
    # Python reads \\d as any Unicode digit; ECMA-262, the regex dialect of JSON Schema, does not.
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "profiles/battery/schemas/item.schema.json").read_text(encoding="utf-8"))
    check = validator(schema["properties"]["updated_at"])
    assert check is not None
    assert schema_errors(check, "2026-10-10T08:00:00Z") == []
    assert schema_errors(check, NON_CANONICAL[0]) == [{"path": "/", "keyword": "pattern"}]
    assert "\\d" not in (root / "profiles/battery/contracts/reference-api.openapi.yaml").read_text(
        encoding="utf-8"
    )


# The models must refuse what parse_stamp refuses, or an input defect surfaces as an engine error.
MODEL_REFUSES = NON_CANONICAL[:3]


@pytest.mark.parametrize("text", MODEL_REFUSES)
@pytest.mark.parametrize("end", ["not_before", "not_after"])
def test_integration_1_a_signed_authorization_with_a_non_canonical_stamp_is_malformed(
    signer: LocalSigner, trust: TrustBundle, end: str, text: str
) -> None:
    payload = authorization().model_dump(mode="json") | {end: text}
    # Canonical bytes, so that only the stamp can make the payload malformed.
    token = sign_compact(canonical_bytes(payload), signer, typ=AUTHORIZATION_TYP)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(token, trust, AT, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"


@pytest.mark.parametrize("text", MODEL_REFUSES)
@pytest.mark.parametrize("end", ["not_before", "not_after"])
def test_integration_1_a_trusted_key_with_a_non_canonical_stamp_is_refused(
    trust: TrustBundle, end: str, text: str
) -> None:
    key = trust.keys[0].model_dump() | {end: text}
    with pytest.raises(ValidationError):
        TrustBundle.model_validate(trust.model_dump() | {"keys": [key]})


@pytest.mark.parametrize("text", MODEL_REFUSES)
def test_integration_1_a_status_snapshot_with_a_non_canonical_stamp_is_refused(
    trust: TrustBundle, text: str
) -> None:
    with pytest.raises(ValidationError):
        TrustBundle.model_validate(trust.model_dump() | {"status_as_of": text})


# The canonical form, but no such moment. parse_stamp raises on these too (owner decision, 2026-10-18).
IMPOSSIBLE = ["2026-13-45T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-10T24:00:00Z", "2026-12-31T23:59:60Z"]
STAMP_FIELDS = [
    (TrustedKey, "not_before"),
    (TrustedKey, "not_after"),
    (RevokedKey, "revoked_at"),
    (RevokedCertificate, "revoked_at"),
    (TrustBundle, "status_as_of"),
    (Authorization, "not_before"),
    (Authorization, "not_after"),
    (Attestation, "valid_until"),
    (StatusList, "issued_at"),
]


@pytest.mark.parametrize("text", IMPOSSIBLE)
@pytest.mark.parametrize(("model", "name"), STAMP_FIELDS)
def test_integration_2_every_stamp_field_refuses_a_moment_that_does_not_exist(
    model: type[Any], name: str, text: str
) -> None:
    field = model.model_fields[name]
    # A field without its own constraints carries them in its annotation (Stamp | None).
    kind = Annotated[field.annotation, *field.metadata] if field.metadata else field.annotation
    check: TypeAdapter[Any] = TypeAdapter(kind)
    assert check.validate_python("2026-10-10T08:00:00Z") == "2026-10-10T08:00:00Z"
    with pytest.raises(ValidationError):
        check.validate_python(text)


@pytest.mark.parametrize("text", IMPOSSIBLE)
def test_integration_2_a_signed_authorization_with_an_impossible_stamp_is_malformed(
    signer: LocalSigner, trust: TrustBundle, text: str
) -> None:
    payload = authorization().model_dump(mode="json") | {"not_after": text}
    token = sign_compact(canonical_bytes(payload), signer, typ=AUTHORIZATION_TYP)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(token, trust, AT, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"


# -- identifier-carrier-1, -3, -4: a carrier text that is not a usable URL ----------------------------

GS1 = "/01/09506000134352/21/EV0001"
NOT_USABLE = [
    "http://[::1/01/09520123456788/21/12345",
    "https:" + GS1,
    "https://" + GS1,
    "http://127.0.0.1:abc" + GS1,
    "http://127.0.0.1:99999" + GS1,
]


def _carrier(tmp_path: Path, loopback: Any, text: str) -> tuple[CheckContext, Resolver]:
    resolver = Resolver(loopback, b'{"id": "x"}', "application/json")
    return _with_identifier(live(tmp_path, resolver, {}), text), resolver


@pytest.mark.parametrize(
    "text", NOT_USABLE, ids=["bad-ipv6", "no-host", "empty-host", "port-abc", "port-range"]
)
def test_identifier_carrier_1_and_3_resolve_of_a_url_without_a_usable_host_or_port_is_unresolved(
    text: str, tmp_path: Path, loopback: Any
) -> None:
    ctx, resolver = _carrier(tmp_path, loopback, text)
    outcome = resolve(ctx)
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        False,
        "IDENTIFIER.UNRESOLVED",
    )
    assert resolver.server.seen == []


@pytest.mark.parametrize(
    "text", NOT_USABLE, ids=["bad-ipv6", "no-host", "empty-host", "port-abc", "port-range"]
)
def test_identifier_carrier_1_and_3_consistency_of_a_url_without_a_usable_host_or_port_is_blocked(
    text: str, tmp_path: Path, loopback: Any
) -> None:
    ctx, resolver = _carrier(tmp_path, loopback, text)
    outcome = consistency(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "IDENTIFIER.NOT_RESOLVABLE",
    )
    assert resolver.server.seen == []


@pytest.mark.parametrize("bad", ["EV\n00\t01", "EV\r0001", "EV00\t01", "EV0001 "])
def test_identifier_carrier_4_resolve_refuses_a_carrier_that_the_transport_would_rewrite(
    bad: str, tmp_path: Path, loopback: Any
) -> None:
    resolver = Resolver(loopback, b'{"id": "x"}', "application/json")
    ctx = _with_identifier(
        live(tmp_path, resolver, {}), f"{resolver.server.origin}/01/09506000134352/21/{bad}"
    )
    outcome = resolve(ctx)
    assert outcome.passed is not True
    assert resolver.server.seen == [], "no request for a text that the transport would rewrite"
    assert ctx.acquirer.records() == ()


@pytest.mark.parametrize("bad", ["/a\tb", "/a\nb", "/a\rb", "/a\x00b", "/a\x7fb", "/ab "])
def test_identifier_carrier_4_the_transport_refuses_a_url_with_a_control_character(
    bad: str, loopback: Any
) -> None:
    server = loopback(reply)
    record = review_transport().fetch(Request("GET", server.origin + bad))
    assert record.error == "policy_denied"
    assert server.seen == []


# -- identifier-carrier-5: every spelling of the public origin ----------------------------------------

OVERRIDE = "http://127.0.0.1:8443"


def _override(tmp_path: Path) -> CheckContext:
    base = _context(tmp_path, _POLICY, _Canned(b"{}"))
    endpoints = dict(base.ixit.endpoints) | {
        "public_origin": "https://id.example",
        "origin_override": OVERRIDE,
    }
    return dataclasses.replace(base, ixit=base.ixit.model_copy(update={"endpoints": endpoints}))


@pytest.mark.parametrize(
    "url",
    [
        f"https://id.example{GS1}",
        f"HTTPS://id.example{GS1}",
        f"https://ID.EXAMPLE{GS1}",
        f"https://id.example:443{GS1}",
    ],
)
def test_identifier_carrier_5_every_spelling_of_the_public_origin_goes_to_the_override(
    url: str, tmp_path: Path
) -> None:
    assert effective_url(_override(tmp_path), url) == (OVERRIDE + GS1, ("origin_override",))


@pytest.mark.parametrize(
    "url",
    [
        f"https://id.example.evil{GS1}",
        f"https://id.example:8443{GS1}",
        f"http://id.example{GS1}",
        "https://[bad",
    ],
)
def test_identifier_carrier_5_another_origin_is_not_overridden(url: str, tmp_path: Path) -> None:
    assert effective_url(_override(tmp_path), url) == (url, ())


def test_identifier_carrier_5_the_override_keeps_the_query(tmp_path: Path) -> None:
    url = f"https://ID.example{GS1}?linkType=all"
    assert effective_url(_override(tmp_path), url) == (f"{OVERRIDE}{GS1}?linkType=all", ("origin_override",))


# -- identifier-carrier-6: a port is digits only -------------------------------------------------------


@pytest.mark.parametrize("authority", ["a:abc", "a:80:90", "a::1", "a:8a0", "a:99999"])
def test_identifier_carrier_6_a_port_that_is_not_a_number_is_refused(authority: str) -> None:
    assert parse_gs1_digital_link(f"https://{authority}/01/09520123456788/21/12345") is not None


@pytest.mark.parametrize("authority", ["a", "a:8080", "[::1]:8080", "[::1]"])
def test_identifier_carrier_6_a_numeric_port_or_no_port_is_accepted(authority: str) -> None:
    assert parse_gs1_digital_link(f"https://{authority}/01/09520123456788/21/12345") is None


# -- identifier-carrier-2: a hostile carrier image ------------------------------------------------------


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _png(width: int, height: int) -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    idat = _chunk(b"IDAT", zlib.compress(b"\x00"))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", header) + idat + _chunk(b"IEND", b"")


class _Image(_Canned):
    def artifact(self, name: str) -> Record:
        return make_record(1, self._body)


@pytest.mark.qr
@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            _png(20000, 20000),
            "CARRIER.SAMPLE.TOO_LARGE",
        ),  # above the Pillow error limit: DecompressionBombError
        (_png(10000, 10000), "CARRIER.SAMPLE.TOO_LARGE"),  # between the warning and the error limit
        (
            bytes.fromhex(
                "89504e470d0a1a0a0000000d4948445200000028000000280800000000a995e7b10000002b49444154789c"
                "edcab11100300cc240ccfe83652c97743af7e15b699e6e7cfcd41199737444e61c1d91394747649dfa7c5c"
                "077a0118d878ec450000000049454e44ae426082"
            ),
            "CARRIER.SAMPLE.UNREADABLE",  # a wrong IDAT length: SyntaxError("broken PNG file")
        ),
    ],
    ids=["bomb-error", "bomb-warning", "broken-chunk"],
)
def test_identifier_carrier_2_a_hostile_image_is_blocked(body: bytes, code: str, tmp_path: Path) -> None:
    pytest.importorskip("zxingcpp", reason="needs the optional 'qr' extra")
    outcome = qr_decode(_context(tmp_path, _POLICY, _Image(body, "image/png")))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


# -- server-clock-fixes-1 and -2: the credential scrub --------------------------------------------------

SECRET = "TEST-ONLY-tok/en+S3CRET"


@pytest.mark.parametrize(
    "echoed",
    [
        b'{"you_sent":"TEST-ONLY-tok\\/en+S3CRET"}',
        b"TEST-ONLY-tok%2fen%2bS3CRET",
        b"TEST-ONLY-tok/en%2BS3CRET",
        b"TEST-ONLY-tok/en%2bS3CRET",
    ],
    ids=["json-solidus", "lower-hex", "quote-default", "quote-default-lower-hex"],
)
def test_server_clock_fixes_1_an_echoed_credential_in_a_common_encoding_is_removed(
    echoed: bytes, loopback: Any
) -> None:
    server = loopback(lambda r: reply(r, body=echoed, headers={"X-Echo": echoed.decode()}))
    engine = review_transport(credentials={"role0": (server.origin, SECRET)})
    record = engine.fetch(Request("GET", f"{server.origin}/x", role="role0"))
    assert record.status == 200
    assert b"S3CRET" not in record.body
    assert all("S3CRET" not in value for _, value in record.headers)


@pytest.mark.parametrize(
    "tail", [b"TEST-ONLY-tok%2Fen%2BS3CRET", b"TEST-ONLY-tok%2fen%2bS3CRET", b"TEST-ONLY-tok/en+S3CRET"]
)
def test_server_clock_fixes_1_a_credential_cut_by_the_body_limit_leaves_no_head(
    tail: bytes, loopback: Any
) -> None:
    body = b"x" * 1004 + tail
    server = loopback(lambda r: reply(r, body=body))
    engine = review_transport({"max_body_bytes": 1024}, credentials={"role0": (server.origin, SECRET)})
    record = engine.fetch(Request("GET", f"{server.origin}/x", role="role0"))
    assert record.truncated
    assert record.body == b"x" * 1004 + b"<removed>"


def test_server_clock_fixes_2_a_complete_body_ending_in_a_credential_head_is_kept(loopback: Any) -> None:
    body = b"see the key named TEST-ONLY-ab"
    server = loopback(lambda r: reply(r, body=body))
    engine = review_transport(credentials={"role0": (server.origin, "TEST-ONLY-abcdefghijkl")})
    record = engine.fetch(Request("GET", f"{server.origin}/ok"))
    assert record.truncated is False
    assert record.body == body, "only a body that the limit cut may lose a credential head"


# -- fix-check: the check of the fixes of 2026-10-18 -------------------------------------------------


def test_fix_check_1_a_response_reference_is_unsupported(tmp_path: Path) -> None:
    # A reference response has no content key. It must not read as "declares no body".
    contract = _item_get(
        {"responses": {"200": {"$ref": "#/components/responses/Item"}}},
        components={
            "responses": {
                "Item": {"content": {"application/json": {"schema": {"type": "object", "required": ["id"]}}}}
            }
        },
    )
    write_data(tmp_path, contract=contract)
    for acquirer in (Answer(200, None, b""), Answer(200, "application/json", b"{}")):
        ctx = context(tmp_path, "api.contract", acquirer=acquirer)  # type: ignore[arg-type]  # an acquirer double
        outcome = run(ctx)
        assert (outcome.status, outcome.passed, outcome.reason_code) == (
            ExecutionStatus.UNSUPPORTED,
            None,
            "API.CONTRACT.UNSUPPORTED_FEATURE",
        )
        assert sent(ctx) == 0, "the contract is checked before anything is fetched"


MULTIPLE_OF = [
    (2, b'{"x": 1e30}', True),
    (0.01, b'{"x": 1e30}', True),
    (0.5, b'{"x": 12345678901234567890123456789.5}', True),
    (0.1, b'{"x": 0.3}', True),
    (2, b'{"x": 1e999999999}', True),
    (7, b'{"x": 1e30}', False),
    (0.1, b'{"x": 0.35}', False),
    (2, b'{"x": 1e-999999999}', False),
    (0.01, b'{"x": 12345678901234567890123456789.001}', False),
]


@pytest.mark.parametrize(("divisor", "body", "multiple"), MULTIPLE_OF)
def test_fix_check_2_api_contract_judges_multiple_of_exactly(
    divisor: Any, body: bytes, multiple: bool, tmp_path: Path
) -> None:
    schema = {"properties": {"x": {"type": "number", "multipleOf": divisor}}}
    write_data(tmp_path, contract=_with_schema(schema))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(body)))
    assert (outcome.passed, outcome.reason_code) == (
        (True, "API.CONTRACT.OK") if multiple else (False, "API.CONTRACT.SCHEMA")
    )


@pytest.mark.parametrize(("divisor", "body", "multiple"), MULTIPLE_OF)
def test_fix_check_2_data_jsonschema_judges_multiple_of_exactly(
    divisor: Any, body: bytes, multiple: bool, tmp_path: Path
) -> None:
    write_data(tmp_path)
    schema = {"properties": {"x": {"type": "number", "multipleOf": divisor}}}
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(body)))
    assert (outcome.passed, outcome.reason_code) == (
        (True, "DATA.SCHEMA.OK") if multiple else (False, "DATA.SCHEMA.INVALID")
    )


MALFORMED = [
    {"type": 5},
    {"type": "string", "pattern": "["},
    {"type": "object", "properties": []},
]


@pytest.mark.parametrize("schema", [*MALFORMED, {"$ref": "#/components/schemas/Nope"}])
def test_fix_check_4_api_contract_with_a_malformed_schema_is_unsupported(schema: Any, tmp_path: Path) -> None:
    write_data(tmp_path, contract=_with_schema(schema))
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(b'"x"')))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "API.CONTRACT.UNSUPPORTED_FEATURE",
    )


def test_fix_check_4_a_malformed_component_schema_is_unsupported(tmp_path: Path) -> None:
    # check_schema does not descend into components, so each component schema is checked too.
    contract = _item_get(
        {
            "responses": {
                "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}
            }
        },
        components={"schemas": {"A": {"type": "object", "properties": []}}},
    )
    write_data(tmp_path, contract=contract)
    outcome = run(context(tmp_path, "api.contract", acquirer=Canned(b'"x"')))
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        "API.CONTRACT.UNSUPPORTED_FEATURE",
    )


@pytest.mark.parametrize("schema", [*MALFORMED, {"$ref": "#/$defs/Nope"}])
def test_fix_check_4_data_jsonschema_with_a_malformed_schema_is_blocked(schema: Any, tmp_path: Path) -> None:
    write_data(tmp_path)
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(b'{"id": "x"}')))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.MALFORMED",
    )
