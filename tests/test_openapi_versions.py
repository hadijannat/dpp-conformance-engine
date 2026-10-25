"""The OpenAPI version gate of api.contract (architecture section 8).

3.1.x keeps its behavior. A 3.0.x Schema Object is translated to JSON Schema 2020-12 with the
same meaning: nullable, the boolean exclusive bounds, example, and the 3.0 integer. A 3.0
construct outside that translation, a missing version, or another version gives blocked
API.CONTRACT.UNSUPPORTED_VERSION. Nothing is fetched for a contract that the gate refuses.

Oracle: OpenAPI 3.0.3 and 3.1.0, Schema Object (OpenAPI Initiative, Apache-2.0).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from dppce.models import ExecutionStatus
from tests.test_review_adapters import _item_get, _with_schema
from tests.test_url_templates import CONTRACT, Canned, context, run, sent, write_data

ROOT = Path(__file__).resolve().parent.parent
BLOCKED = (ExecutionStatus.BLOCKED, None, "API.CONTRACT.UNSUPPORTED_VERSION")
OK = (ExecutionStatus.COMPLETED, True, "API.CONTRACT.OK")
SCHEMA = (ExecutionStatus.COMPLETED, False, "API.CONTRACT.SCHEMA")
UNSUPPORTED = (ExecutionStatus.UNSUPPORTED, None, "API.CONTRACT.UNSUPPORTED_FEATURE")


def _contract(tmp_path: Path, contract: dict[str, Any], body: bytes = b'{"id": "x"}') -> tuple[Any, ...]:
    write_data(tmp_path, contract=contract)
    ctx = context(tmp_path, "api.contract", acquirer=Canned(body))
    outcome = run(ctx)
    return outcome.status, outcome.passed, outcome.reason_code, sent(ctx)


def _v30(schema: Any, components: dict[str, Any] | None = None, version: str = "3.0.3") -> dict[str, Any]:
    get = {"responses": {"200": {"content": {"application/json": {"schema": schema}}}}}
    return _item_get(get, components) | {"openapi": version}


# -- the gate -------------------------------------------------------------------------------------


def test_the_shipped_contract_is_openapi_3_1_0() -> None:
    contract = yaml.safe_load(
        (ROOT / "profiles" / "battery" / "contracts" / "reference-api.openapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert contract["openapi"] == "3.1.0"


@pytest.mark.parametrize("version", ["3.1.0", "3.1.1", "3.1.10"])
def test_a_3_1_contract_keeps_its_behavior(version: str, tmp_path: Path) -> None:
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
    assert _contract(tmp_path, _with_schema(schema) | {"openapi": version}) == (*OK, 1)
    assert _contract(tmp_path, _with_schema(schema) | {"openapi": version}, b'{"id": 1}') == (*SCHEMA, 1)


@pytest.mark.parametrize(
    "version",
    [
        None,
        "",
        "2.0",
        "3.2.0",
        "3.1",
        "3.0",
        "3.1.0-rc1",
        "3.0.3 ",
        " 3.1.0",
        "v3.1.0",
        "4.0.0",
        3.1,
        3,
        True,
    ],
)
def test_a_missing_or_other_version_is_blocked_and_nothing_is_fetched(version: Any, tmp_path: Path) -> None:
    contract = {k: v for k, v in CONTRACT.items() if k != "openapi"}
    if version is not None:
        contract["openapi"] = version
    assert _contract(tmp_path, contract) == (*BLOCKED, 0)


def test_a_swagger_2_document_is_blocked(tmp_path: Path) -> None:
    contract = {k: v for k, v in CONTRACT.items() if k != "openapi"} | {"swagger": "2.0"}
    assert _contract(tmp_path, contract) == (*BLOCKED, 0)


def test_the_ics_mismatch_keeps_its_precedence_over_the_gate(tmp_path: Path) -> None:
    contract = CONTRACT | {"openapi": "2.0", "x-dppce-contract-id": "another/api"}
    assert _contract(tmp_path, contract)[:3] == (ExecutionStatus.BLOCKED, None, "API.CONTRACT.ICS_MISMATCH")


@pytest.mark.parametrize(
    ("dialect", "expected"),
    [
        ("https://json-schema.org/draft/2020-12/schema", OK),
        ("http://json-schema.org/draft-07/schema#", BLOCKED),
        ("https://spec.openapis.org/oas/3.1/dialect/base", OK),
        (7, BLOCKED),
    ],
)
def test_a_3_1_contract_with_another_default_dialect_is_blocked(
    dialect: Any, expected: tuple[Any, ...], tmp_path: Path
) -> None:
    contract = _with_schema({"type": "object"}) | {"jsonSchemaDialect": dialect}
    assert _contract(tmp_path, contract)[:3] == expected


def test_a_3_1_schema_in_another_dialect_is_unsupported(tmp_path: Path) -> None:
    schema = {"$schema": "http://json-schema.org/draft-04/schema#", "type": "object"}
    assert _contract(tmp_path, _with_schema(schema))[:3] == UNSUPPORTED


@pytest.mark.parametrize(
    "dialect", ["http://json-schema.org/draft-07/schema#", "http://json-schema.org/draft-07/schema"]
)
def test_a_3_1_schema_cannot_switch_the_components_to_draft_07(dialect: str, tmp_path: Path) -> None:
    # draft-07 would ignore the siblings of $ref in Item, which 2020-12 applies.
    components = {
        "schemas": {
            "Base": {"type": "object"},
            "Item": {"$ref": "#/components/schemas/Base", "required": ["id"]},
        }
    }
    get = {
        "responses": {
            "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}
        }
    }
    contract = _item_get(get, components)
    assert _contract(tmp_path, contract, b"{}")[:3] == SCHEMA
    get["responses"]["200"]["content"]["application/json"]["schema"]["$schema"] = dialect
    assert _contract(tmp_path, _item_get(get, components), b"{}")[:3] == UNSUPPORTED


def test_a_3_1_schema_with_a_keyword_that_2020_12_ignores_is_unsupported(tmp_path: Path) -> None:
    schema = {"type": "object", "dependencies": {"id": ["other"]}}
    assert _contract(tmp_path, _with_schema(schema))[:3] == UNSUPPORTED


# -- the 3.0 translation --------------------------------------------------------------------------

NULLABLE = {"type": "object", "properties": {"id": {"type": "string", "nullable": True}}}


@pytest.mark.parametrize("version", ["3.0.0", "3.0.3", "3.0.4"])
@pytest.mark.parametrize(
    ("schema", "body", "expected"),
    [
        (NULLABLE, b'{"id": null}', OK),
        (NULLABLE, b'{"id": "x"}', OK),
        (NULLABLE, b'{"id": 1}', SCHEMA),
        ({"properties": {"id": {"type": "string"}}}, b'{"id": null}', SCHEMA),
        ({"properties": {"id": {"type": "string", "nullable": False}}}, b'{"id": null}', SCHEMA),
        # 3.0.3: nullable adds null to the type only. Other keywords can still refuse null.
        (
            {"properties": {"id": {"type": "string", "nullable": True, "enum": ["a"]}}},
            b'{"id": null}',
            SCHEMA,
        ),
        (
            {"properties": {"id": {"type": "string", "nullable": True, "enum": ["a", None]}}},
            b'{"id": null}',
            OK,
        ),
        # Without a type, nullable has no effect, and null was already allowed.
        ({"properties": {"id": {"nullable": True, "minLength": 2}}}, b'{"id": null}', OK),
        (
            {"properties": {"n": {"type": "number", "maximum": 100, "exclusiveMaximum": True}}},
            b'{"n": 100}',
            SCHEMA,
        ),
        (
            {"properties": {"n": {"type": "number", "maximum": 100, "exclusiveMaximum": True}}},
            b'{"n": 99.9}',
            OK,
        ),
        (
            {"properties": {"n": {"type": "number", "maximum": 100, "exclusiveMaximum": False}}},
            b'{"n": 100}',
            OK,
        ),
        (
            {"properties": {"n": {"type": "number", "minimum": 0, "exclusiveMinimum": True}}},
            b'{"n": 0}',
            SCHEMA,
        ),
        (
            {"properties": {"n": {"type": "number", "minimum": 0, "exclusiveMinimum": True}}},
            b'{"n": 0.1}',
            OK,
        ),
        ({"properties": {"n": {"type": "number", "minimum": 0}}}, b'{"n": 0}', OK),
        ({"properties": {"id": {"type": "string", "example": 5}}}, b'{"id": "x"}', OK),
        # The 3.0 integer is a number without a fraction or an exponent part.
        ({"properties": {"n": {"type": "integer"}}}, b'{"n": 1}', OK),
        ({"properties": {"n": {"type": "integer"}}}, b'{"n": 1.0}', SCHEMA),
        ({"properties": {"n": {"type": "integer"}}}, b'{"n": 1e2}', SCHEMA),
        ({"properties": {"n": {"type": "integer"}}}, b'{"n": true}', SCHEMA),
        ({"properties": {"n": {"type": "number"}}}, b'{"n": 1.0}', OK),
        # A property with the name of a translated keyword is a property, not a keyword.
        ({"required": ["example"], "properties": {"example": {"type": "string"}}}, b'{"id": "x"}', SCHEMA),
        ({"properties": {"nullable": {"type": "string"}}}, b'{"nullable": null}', SCHEMA),
        # Nested positions are translated too.
        ({"type": "array", "items": {"type": "string", "nullable": True}}, b'[null, "a"]', OK),
        ({"allOf": [{"type": "string", "nullable": True}]}, b"null", OK),
        ({"anyOf": [{"type": "integer", "nullable": True}]}, b"null", OK),
        ({"oneOf": [{"type": "integer", "nullable": True}, {"type": "string"}]}, b"null", OK),
        ({"not": {"type": "string", "nullable": True}}, b"null", SCHEMA),
        ({"additionalProperties": {"type": "string", "nullable": True}}, b'{"a": null}', OK),
        ({"additionalProperties": False}, b'{"a": null}', SCHEMA),
        ({"type": "object", "x-vendor": {"const": 1}, "readOnly": True}, b'{"a": 1}', OK),
    ],
)
def test_a_3_0_schema_keeps_its_meaning(
    version: str, schema: dict[str, Any], body: bytes, expected: tuple[Any, ...], tmp_path: Path
) -> None:
    assert _contract(tmp_path, _v30(schema, version=version), body) == (*expected, 1)


def test_a_3_0_component_schema_is_translated(tmp_path: Path) -> None:
    components = {"schemas": {"Item": NULLABLE}}
    contract = _v30({"$ref": "#/components/schemas/Item"}, components)
    assert _contract(tmp_path, contract, b'{"id": null}') == (*OK, 1)
    assert _contract(tmp_path, contract, b'{"id": 1}') == (*SCHEMA, 1)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "discriminator": {"propertyName": "kind"}},
        {"type": "object", "properties": {"secret": {"type": "string", "writeOnly": True}}},
        {"$ref": "#/components/schemas/A", "nullable": True},
        {"$ref": "#/components/schemas/A", "description": "x"},
        {"type": "string", "const": "x"},
        {"type": ["string", "null"]},
        {"type": "null"},
        {"type": "array", "items": True},
        {"type": "array", "items": [{"type": "string"}]},
        {"type": "object", "patternProperties": {"^a": {}}},
        {"$schema": "https://json-schema.org/draft/2020-12/schema"},
        {"type": "number", "exclusiveMaximum": 100},
        {"type": "number", "exclusiveMinimum": True},
        {"type": "string", "nullable": "yes"},
        {"properties": {"a": {"if": {}}}},
        {"allOf": {"type": "string"}},
        {"properties": []},
        # A reference must name a translated root: elsewhere the raw 3.0 form would be read.
        {"$ref": "#/components/schemas/A/type"},
        {"$ref": "#/components"},
        {"$ref": "#/paths"},
        {"$ref": "#"},
    ],
)
def test_a_3_0_construct_outside_the_translation_is_blocked(schema: Any, tmp_path: Path) -> None:
    contract = _v30(schema, {"schemas": {"A": {"type": "object"}}})
    assert _contract(tmp_path, contract) == (*BLOCKED, 0)


def test_a_3_0_reference_into_an_extension_is_blocked(tmp_path: Path) -> None:
    # The extension value is not translated, so 2020-12 would read exclusiveMinimum true as 1.
    components = {
        "schemas": {
            "A": {"type": "object", "x-s": {"type": "number", "minimum": 5, "exclusiveMinimum": True}}
        }
    }
    schema = {"type": "object", "properties": {"n": {"$ref": "#/components/schemas/A/x-s"}}}
    assert _contract(tmp_path, _v30(schema, components), b'{"n": 5}') == (*BLOCKED, 0)


def test_a_3_0_component_outside_the_translation_is_blocked(tmp_path: Path) -> None:
    components = {"schemas": {"Item": {"type": "object"}, "Other": {"type": "object", "discriminator": {}}}}
    assert _contract(tmp_path, _v30({"$ref": "#/components/schemas/Item"}, components)) == (*BLOCKED, 0)


def test_a_3_0_format_that_the_engine_cannot_assert_stays_unsupported(tmp_path: Path) -> None:
    schema = {"properties": {"n": {"type": "integer", "format": "int64"}}}
    assert _contract(tmp_path, _v30(schema)) == (*UNSUPPORTED, 0)


def test_a_3_0_contract_without_a_schema_still_judges_status_and_media_type(tmp_path: Path) -> None:
    contract = _item_get({"responses": {"200": {"content": {"application/json": {}}}}}) | {"openapi": "3.0.3"}
    assert _contract(tmp_path, contract) == (*OK, 1)
