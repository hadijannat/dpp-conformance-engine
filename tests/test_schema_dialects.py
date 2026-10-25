"""Schema dialects and asserted formats of data.jsonschema (architecture section 8).

The engine validates a schema with the rules of the dialect that its ``$schema`` names. A
keyword that the dialect ignores is never ignored silently. Each asserted format follows its
grammar exactly; a format that the engine cannot assert gives blocked, never pass.

Oracles: RFC 3339 section 5.6 and Appendix A, RFC 3986 section 3 and Appendix A, RFC 3987
section 2.2 (IETF). The JSON-Schema-Test-Suite files ``optional/format/*.json`` informed the
edge cases. They are not vendored here.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml

from dppce.adapters.common import schema_errors, unassertable_formats, validator
from dppce.models import ExecutionStatus
from tests.test_url_templates import Canned, context, run, write_data

ROOT = Path(__file__).resolve().parent.parent
DRAFT_07 = "http://json-schema.org/draft-07/schema#"
DRAFT_2020 = "https://json-schema.org/draft/2020-12/schema"
DEPENDENCIES = {"dependencies": {"credit_card": ["billing_address"]}}


def _jsonschema(tmp_path: Path, schema: Any, body: bytes) -> tuple[ExecutionStatus, bool | None, str]:
    write_data(tmp_path)
    (tmp_path / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    outcome = run(context(tmp_path, "data.jsonschema", acquirer=Canned(body)))
    return outcome.status, outcome.passed, outcome.reason_code


def _valid(schema: Any, document: Any) -> bool:
    check = validator(schema)
    assert check is not None
    return schema_errors(check, document) == []


# -- dialects -------------------------------------------------------------------------------------


@pytest.mark.parametrize("uri", [DRAFT_07, DRAFT_07.rstrip("#")])
def test_a_draft_07_schema_enforces_dependencies(uri: str) -> None:
    schema = {"$schema": uri, **DEPENDENCIES}
    assert _valid(schema, {"credit_card": 1, "billing_address": "x"})
    assert not _valid(schema, {"credit_card": 1})


def test_data_jsonschema_fails_a_document_that_breaks_a_draft_07_keyword(tmp_path: Path) -> None:
    """The regression that fault B-09 (reserved, package P2-24) will seed through a test purpose."""
    schema = {"$schema": DRAFT_07, "type": "object", **DEPENDENCIES}
    assert _jsonschema(tmp_path, schema, b'{"credit_card": 1}') == (
        ExecutionStatus.COMPLETED,
        False,
        "DATA.SCHEMA.INVALID",
    )


def test_a_draft_07_schema_ignores_the_siblings_of_ref_as_draft_07_states() -> None:
    schema = {"$schema": DRAFT_07, "definitions": {"a": {}}, "$ref": "#/definitions/a", "type": "string"}
    assert _valid(schema, 1)


def test_a_draft_07_schema_keeps_exact_numbers() -> None:
    schema = {"$schema": DRAFT_07, "multipleOf": 0.1, "type": "integer"}
    assert not _valid({"$schema": DRAFT_07, "multipleOf": 0.1}, Decimal("0.35"))
    assert _valid({"$schema": DRAFT_07, "multipleOf": 0.1}, Decimal("0.3"))
    assert _valid(schema, Decimal("1.0"))
    assert not _valid({"$schema": DRAFT_07, "type": "integer"}, True)


@pytest.mark.parametrize(
    "keyword",
    [
        {"dependencies": {"a": ["b"]}},
        {"additionalItems": False, "items": [{}]},
        {"$recursiveRef": "#"},
        {"$recursiveAnchor": True},
        {"properties": {"x": {"dependencies": {"a": ["b"]}}}},
        {"$defs": {"x": {"additionalItems": False}}},
        {"definitions": {"x": {"dependencies": {"a": ["b"]}}}},
    ],
    ids=[
        "dependencies",
        "additionalItems",
        "recursiveRef",
        "recursiveAnchor",
        "nested",
        "defs",
        "definitions",
    ],
)
@pytest.mark.parametrize("uri", [None, DRAFT_2020, DRAFT_2020 + "#"])
def test_a_2020_12_schema_with_a_keyword_that_2020_12_ignores_is_blocked(
    keyword: dict[str, Any], uri: str | None, tmp_path: Path
) -> None:
    schema = keyword | ({"$schema": uri} if uri else {})
    assert _jsonschema(tmp_path, schema, b'{"a": 1}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.MALFORMED",
    )


@pytest.mark.parametrize(
    "keyword",
    [
        {"prefixItems": [{"type": "string"}]},
        {"dependentRequired": {"a": ["b"]}},
        {"dependentSchemas": {"a": {"required": ["b"]}}},
        {"unevaluatedProperties": False},
        {"unevaluatedItems": False},
        {"contains": {}, "minContains": 2},
        {"contains": {}, "maxContains": 2},
        {"$dynamicRef": "#"},
        {"properties": {"x": {"prefixItems": [{}]}}},
    ],
)
def test_a_draft_07_schema_with_a_keyword_that_draft_07_ignores_is_blocked(
    keyword: dict[str, Any], tmp_path: Path
) -> None:
    schema = {"$schema": DRAFT_07, **keyword}
    assert _jsonschema(tmp_path, schema, b'{"a": 1}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.MALFORMED",
    )


@pytest.mark.parametrize(
    "schema",
    [
        # draft-07 does not walk $defs as a keyword, but a reference reaches it.
        {
            "$schema": DRAFT_07,
            "properties": {"a": {"$ref": "#/$defs/A"}},
            "$defs": {"A": {"type": "array", "prefixItems": [{"type": "string"}]}},
        },
        {"$schema": DRAFT_07, "$ref": "#/$defs/A", "$defs": {"A": {"dependentRequired": {"x": ["y"]}}}},
        {"properties": {"a": {"$ref": "#/x/A"}}, "x": {"A": {"dependencies": {"b": ["c"]}}}},
        # RFC 6901: percent-decode first, then ~1 is "/" and ~0 is "~".
        {"$ref": "#/x/a~1b%25/c~0d", "x": {"a/b%": {"c~d": {"dependencies": {"b": ["c"]}}}}},
        {"$ref": "#/nowhere"},
        {"properties": {"a": {"$ref": "#/x/A"}}, "x": {"A": {"$ref": "#/x/B"}}},
    ],
    ids=[
        "draft-07-defs",
        "draft-07-root-ref",
        "custom-container",
        "escaped-pointer",
        "unresolved",
        "chained",
    ],
)
def test_a_keyword_that_only_a_reference_reaches_is_checked(schema: dict[str, Any], tmp_path: Path) -> None:
    body = b'{"a": [1], "b": 1, "x": 1}'
    assert _jsonschema(tmp_path, schema, body) == (ExecutionStatus.BLOCKED, None, "DATA.SCHEMA.MALFORMED")


def test_a_reference_target_in_another_dialect_is_blocked_with_dialect(tmp_path: Path) -> None:
    schema = {"properties": {"a": {"$ref": "#/x/A"}}, "x": {"A": {"$schema": DRAFT_07, "type": "string"}}}
    assert _jsonschema(tmp_path, schema, b'{"a": "x"}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.DIALECT",
    )


def test_a_reference_cycle_ends(tmp_path: Path) -> None:
    schema = {
        "$defs": {"a": {"properties": {"n": {"$ref": "#/$defs/a"}}}},
        "$ref": "#/$defs/a",
        "type": "object",
    }
    assert _jsonschema(tmp_path, schema, b'{"n": {"n": {}}}') == (
        ExecutionStatus.COMPLETED,
        True,
        "DATA.SCHEMA.OK",
    )


def test_a_property_named_like_an_ignored_keyword_is_not_a_keyword(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "required": ["dependencies"],
        "properties": {"dependencies": {"type": "string"}, "additionalItems": {"const": "x"}},
        "examples": [{"dependencies": "x"}],
    }
    assert _jsonschema(tmp_path, schema, b'{"dependencies": "x"}') == (
        ExecutionStatus.COMPLETED,
        True,
        "DATA.SCHEMA.OK",
    )


@pytest.mark.parametrize(
    "uri",
    [
        "http://json-schema.org/draft-04/schema#",
        "http://json-schema.org/draft-06/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2020-12/schema/",
        "urn:example:my-dialect",
        "",
        7,
        None,
    ],
)
def test_a_schema_in_another_dialect_is_blocked_with_dialect(uri: Any, tmp_path: Path) -> None:
    schema = {"$schema": uri, "type": "object"}
    assert _jsonschema(tmp_path, schema, b'{"a": 1}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.DIALECT",
    )


@pytest.mark.parametrize("root", [None, DRAFT_2020, DRAFT_07])
def test_a_nested_schema_in_another_dialect_is_blocked_with_dialect(root: str | None, tmp_path: Path) -> None:
    other = DRAFT_07 if root == DRAFT_2020 or root is None else DRAFT_2020
    nested = {"$id": "urn:example:nested", "$schema": other, "type": "string"}
    schema = {"properties": {"a": nested}} | ({"$schema": root} if root else {})
    assert _jsonschema(tmp_path, schema, b'{"a": "x"}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.DIALECT",
    )


def test_a_nested_schema_in_the_same_dialect_is_validated(tmp_path: Path) -> None:
    nested = {"$id": "urn:example:nested", "$schema": DRAFT_2020, "type": "string"}
    assert _jsonschema(tmp_path, {"properties": {"a": nested}}, b'{"a": 1}') == (
        ExecutionStatus.COMPLETED,
        False,
        "DATA.SCHEMA.INVALID",
    )


def test_a_draft_07_schema_that_breaks_the_draft_07_metaschema_is_malformed(tmp_path: Path) -> None:
    schema = {"$schema": DRAFT_07, "type": "object", "properties": []}
    assert _jsonschema(tmp_path, schema, b'{"a": 1}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.MALFORMED",
    )


# -- formats --------------------------------------------------------------------------------------

ASSERTED = (
    "date",
    "date-time",
    "duration",
    "email",
    "idn-email",
    "ipv4",
    "ipv6",
    "iri",
    "iri-reference",
    "time",
    "uri",
    "uri-reference",
    "uuid",
)


def test_the_engine_asserts_exactly_these_formats() -> None:
    schema = {"anyOf": [{"format": name} for name in ASSERTED]}
    assert unassertable_formats(schema) == []
    for name in ("hostname", "idn-hostname", "uri-template", "json-pointer", "regex", "int32", "byte"):
        assert unassertable_formats({"format": name}) == [name]


@pytest.mark.parametrize("name", ["hostname", "uri-template", "json-pointer", "relative-json-pointer"])
def test_a_format_that_the_engine_cannot_assert_stays_blocked(name: str, tmp_path: Path) -> None:
    schema = {"properties": {"a": {"type": "string", "format": name}}}
    assert _jsonschema(tmp_path, schema, b'{"a": "x"}') == (
        ExecutionStatus.BLOCKED,
        None,
        "DATA.SCHEMA.UNSUPPORTED_FORMAT",
    )


FORMAT_TABLE: dict[str, tuple[list[str], list[str]]] = {
    "date": (
        ["1963-06-19", "2020-02-29", "2000-02-29", "0400-02-29", "0000-02-29", "0001-01-01", "1582-10-10"],
        [
            "",
            "2021-02-29",
            "1900-02-29",
            "2100-02-29",
            "2020-04-31",
            "2020-01-32",
            "2020-13-01",
            "2020-00-10",
            "2020-01-00",
            "2020-1-01",
            "20200101",
            "+2020-01-01",
            "12020-01-01",
            "2020-01-01T00:00:00Z",
            "2020-01-01\n",
            " 2020-01-01",
            "2020-0\u09ea-01",
            "\uff12020-01-01",
            "2020-W01",
        ],
    ),
    "date-time": (
        [
            "1963-06-19T08:30:06Z",
            "1963-06-19T08:30:06.283185Z",
            "1963-06-19t08:30:06z",
            "1937-01-01T12:00:27.87+00:20",
            "1990-12-31T15:59:50.123-08:00",
            "2026-10-25T12:00:00-00:00",
            "1998-12-31T23:59:60Z",
            "1998-12-31T15:59:60.123-08:00",
            "2017-01-01T00:59:60+01:00",
            "2016-06-30T23:59:60Z",
            "1985-04-12T23:20:50.999999999999999Z",
            "2020-02-29T00:00:00Z",
        ],
        [
            "",
            "1998-12-31T23:59:61Z",
            "1998-12-31T23:58:60Z",
            "1998-12-31T22:59:60Z",
            "1998-12-30T23:59:60Z",
            "2016-06-29T23:59:60Z",
            "2016-12-31T23:59:60+01:00",
            "2016-12-31T24:59:60+01:00",
            "1990-02-31T15:59:59-08:00",
            "1990-12-31T15:59:59-24:00",
            "1990-12-31T10:00:00+10:60",
            "1990-12-31T24:00:00Z",
            "1990-12-31T15:60:00Z",
            "1985-04-12T23:20:50+01",
            "1985-04-12T23:20:50+0100",
            "1985-04-12T23:20:50",
            "1985-04-12T23:20Z",
            "1985-04-12T23:20:50.Z",
            "1985-04-12T23:20:50,5Z",
            "1985-04-12 23:20:50Z",
            "1985-04-12T23:20:50Z\n",
            "1985-04-12T23:20:50Ztail",
            "1963-06-11T0\u09ea:00:00Z",
            "2021-02-29T00:00:00Z",
            "1963-06-19T08:30:06+01:00Z",
        ],
    ),
    "time": (
        [
            "08:30:06Z",
            "08:30:06z",
            "23:20:50.52Z",
            "08:30:06+00:20",
            "12:34:56-00:00",
            "23:59:60Z",
            "23:59:60+00:00",
            "01:29:60+01:30",
            "15:59:60-08:00",
            "00:29:60-23:30",
        ],
        [
            "",
            "12:00:00",
            "12:00:00.52",
            "12:00Z",
            "22:59:60Z",
            "23:58:60Z",
            "23:59:60+01:00",
            "23:59:60-00:30",
            "24:00:00Z",
            "00:60:00Z",
            "00:00:61Z",
            "01:02:03+24:00",
            "01:02:03+00:60",
            "01:02:03Z+00:30",
            "08:30:06+01",
            "08:30:06 PST",
            "08:30:06.Z",
            "8:30:06Z",
            "1\u09e8:00:00Z",
            "08:30:06Z\n",
            "2020-11-28T23:55:45Z",
        ],
    ),
    "duration": (
        [
            "P4DT12H30M5S",
            "P4Y",
            "PT0S",
            "P0D",
            "P1M",
            "PT1M",
            "PT36H",
            "P2W",
            "P1Y2M",
            "P1M2D",
            "PT1H2M",
            "PT1M2S",
            "P1Y2M3DT4H5M6S",
            "P01D",
            "p1dt2h",
        ],
        [
            "",
            "P",
            "PT",
            "P1YT",
            "PT1D",
            "P2D1Y",
            "P1D2H",
            "P2S",
            "P1Y2W",
            "P1WT1H",
            "P1Y2D",
            "PT1H2S",
            "PT0.5S",
            "P1",
            "-P1D",
            "P-1D",
            "P1D\n",
            " P1D",
            "P\u09e8Y",
            "PT1\u017f",
        ],
    ),
    "uri": (
        [
            "http://foo.bar/?baz=qux#quux",
            "https://id.example.test/01/09506000134352/21/EV0001",
            "urn:example:operator:0001",
            "http://foo.bar/?q=Test%20URL-encoded%20stuff",
            "http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com",
            "ldap://[2001:db8::7]/c=GB?objectClass?one",
            "http://[v1.fe80::a+en1]/",
            # ABNF literals are case-insensitive, also the IPvFuture "v".
            "http://[V1.x]/",
            "http://[::ffff:192.0.2.1]/",
            "http://999.999.999.999/",
            "mailto:John.Doe@example.com",
            "tel:+1-816-555-1212",
            "file:/etc/hosts",
            "http://example.com:/",
            "a:",
        ],
        [
            "",
            "abc",
            "/abc",
            "//foo.bar/",
            "1http://example.com",
            "ht_tp://example.com",
            "bar,baz:foo",
            "http:// shouldfail.com",
            "http://example.com/%",
            "http://example.com/%A",
            "http://example.com/%6G",
            "https://example.org/foobar\u00ae.txt",
            "https://example.org/foo bar.txt",
            "https://example.org/a\\b",
            'https://example.org/a"b',
            "https://example.org/a<b>",
            "https://example.org/a{b}",
            "https://example.org/a|b",
            "http://example.com:abc/path",
            "https://[@example.org/test.txt",
            "http://[::ffff:01.2.3.4]",
            "http://[fe80::1%25eth0]/",
            "http:/[::1]",
            "http://2001:db8::1/",
            "http://a@b@example.com/",
            "http://foo.bar/\n",
        ],
    ),
}
# A reference adds the relative forms to the absolute ones.
FORMAT_TABLE["uri-reference"] = (
    [
        *FORMAT_TABLE["uri"][0],
        "",
        "abc",
        "/abc",
        "//foo.bar/?baz=qux#quux",
        "//",
        "?query=1",
        "#fragment",
        "./this:that",
    ],
    [
        "/%zz",
        "/%A",
        "/%",
        '/a"b',
        "/[::1]",
        "#frag\\ment",
        "/foobar\u00ae.txt",
        "//example.com:abc/p",
        "//a@b@example.com/",
        "//[::ffff:192.168.0.01]/p",
        "1:b",
        "/p\n",
    ],
)
FORMAT_TABLE["iri"] = (
    [
        *FORMAT_TABLE["uri"][0],
        "http://\u0192\u00f8\u00f8.\u00df\u00e5r/?\u2202\u00e9\u0153=\u03c0\u00eex#\u03c0\u00ee\u00fcx",
        "https://example.org/foobar\u00ae.txt",
        "http://example.org/\U00010300",
        "http://example.org/?q=\U000f0000",
        "http://[2001:db8::1]",
    ],
    [
        "",
        "/abc",
        "\u00e2\u03c0\u03c0",
        "http://example.org/%",
        "http://example.org/%6G",
        "http://example.org/a b",
        "http://example.org/\u00e9\n",
        "http://example.org/#\U000f0000",
        "http://example.org/\ue000",
        "http://[::ffff:192.168.0.01]",
        "http://2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "http://example.org/\ufdd0",
        "http://example.org/\ud800",
    ],
)
FORMAT_TABLE["iri-reference"] = (
    [
        *FORMAT_TABLE["iri"][0],
        *FORMAT_TABLE["uri-reference"][0],
        "\u00e2\u03c0\u03c0",
        "/\u00e2\u03c0\u03c0/\U00010300",
        "//\u0192\u00f8\u00f8.\u00df\u00e5r/?\u2202\u00e9\u0153=\u03c0\u00eex",
        "#\u0192r\u00e4gm\u00eant",
        "?q=\U000f0000",
    ],
    [
        "/%6G",
        "/%A",
        "/%",
        "#\u0192r\u00e4g\\m\u00eant",
        "//[::ffff:192.168.0.01]/p",
        "/\u00e2\u03c0\u03c0\n",
        "#\U000f0000",
        "1:b",
    ],
)


def _cases(valid: bool) -> list[Any]:
    return [
        pytest.param(name, value, id=f"{name}-{index}")
        for name, table in FORMAT_TABLE.items()
        for index, value in enumerate(table[0] if valid else table[1])
    ]


@pytest.mark.parametrize(("name", "value"), _cases(valid=True))
def test_a_valid_value_conforms_to_its_format(name: str, value: str) -> None:
    assert _valid({"format": name}, value), (name, value)


@pytest.mark.parametrize(("name", "value"), _cases(valid=False))
def test_an_invalid_value_breaks_its_format(name: str, value: str) -> None:
    assert not _valid({"format": name}, value), (name, value)


@pytest.mark.parametrize("name", ASSERTED)
@pytest.mark.parametrize("value", [1, None, True, [], {}])
def test_a_format_judges_strings_only(name: str, value: Any) -> None:
    assert _valid({"format": name}, value)


def test_a_draft_07_schema_asserts_the_same_formats() -> None:
    assert not _valid({"$schema": DRAFT_07, "format": "date-time"}, "1998-12-31T23:59:61Z")
    assert _valid({"$schema": DRAFT_07, "format": "date-time"}, "1998-12-31T23:59:60Z")


def test_data_jsonschema_fails_a_document_that_breaks_date_time(tmp_path: Path) -> None:
    schema = {"properties": {"updated_at": {"type": "string", "format": "date-time"}}}
    assert _jsonschema(tmp_path, schema, b'{"updated_at": "2026-02-30T00:00:00Z"}') == (
        ExecutionStatus.COMPLETED,
        False,
        "DATA.SCHEMA.INVALID",
    )
    assert _jsonschema(tmp_path, schema, b'{"updated_at": "2026-02-28T00:00:00Z"}') == (
        ExecutionStatus.COMPLETED,
        True,
        "DATA.SCHEMA.OK",
    )


# -- regression: every shipped schema keeps its outcome ---------------------------------------------

# The schemas shipped at 4990be0. A later profile family states its own dialect and formats.
SHIPPED_SCHEMAS = sorted((ROOT / "profiles" / "battery").rglob("*.schema.json"))
CONTRACT = ROOT / "profiles" / "battery" / "contracts" / "reference-api.openapi.yaml"


@pytest.mark.parametrize("path", SHIPPED_SCHEMAS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_each_shipped_schema_builds_in_its_dialect_and_asserts_all_its_formats(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema.get("$schema") == DRAFT_2020
    assert validator(schema) is not None
    assert unassertable_formats(schema) == []


@pytest.mark.parametrize("kind", ["items", "models"])
@pytest.mark.parametrize("category", ["ev", "lmt", "industrial"])
def test_each_reference_document_still_matches_its_shipped_schema_and_contract(
    kind: str, category: str
) -> None:
    document = json.loads(
        (ROOT / "fixtures" / "reference" / kind / f"{category}.json").read_text(encoding="utf-8")
    )
    name = "item" if kind == "items" else "model"
    schema = json.loads(
        (ROOT / "profiles" / "battery" / "schemas" / f"{name}.schema.json").read_text("utf-8")
    )
    assert _valid(schema, document)
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    ref = {"$ref": f"#/components/schemas/{name.capitalize()}", "components": contract["components"]}
    assert _valid(ref, document)


def test_the_shipped_contract_schemas_build_and_assert_all_their_formats() -> None:
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert contract["openapi"] == "3.1.0"
    assert validator({"$ref": "#/components/schemas/Item", "components": contract["components"]}) is not None
    assert unassertable_formats(contract) == []
