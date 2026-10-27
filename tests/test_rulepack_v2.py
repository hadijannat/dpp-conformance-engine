"""Rule pack version 2 and the context sources of data.context (package P2-26, OD-11).

Expected values come from docs/explanation/architecture.md, section 8, and
docs/reference/reference-system.md, sections 5.1 and 5.4. A system under test must not turn a
fail into blocked by reshaping its document: a present value of the wrong type for a rule is a
fail. A version 1 pack keeps loading and keeps its outcomes. No test contacts a host.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.data import Rule, RulePack, param_files, rule_holds
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import REMOVED, redact_response_headers
from tests.support import make_record
from tests.test_data_document_source import ALLOWED, blocked, check, failed, passed, verdict
from tests.test_url_templates import Canned

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = "fixtures/rules/TEST-ONLY-web-rules-v2.yaml"
NOW = datetime(2026, 10, 14, tzinfo=UTC)
BASIS = {"class": "illustrative"}
JSONLD_CONTEXT = "http://www.w3.org/ns/json-ld#context"


def rule(kind: str, **fields: Any) -> dict[str, Any]:
    return {"id": f"R-{kind}", "kind": kind, "document": "item", "basis": BASIS} | fields


def pack(*rules: dict[str, Any], version: str = "dppce.rulepack/2") -> dict[str, Any]:
    return {"schema_version": version, "rulepack_id": "test/v2", "version": "1", "rules": list(rules)}


def holds(spec: dict[str, Any], document: Any) -> bool:
    return rule_holds(Rule.model_validate(spec), document, NOW)


def judge(
    tmp_path: Path, body: dict[str, Any], *rules: dict[str, Any], version: str = "dppce.rulepack/2"
) -> Any:
    (tmp_path / "v2.json").write_text(json.dumps(pack(*rules, version=version)), encoding="utf-8")
    return check(tmp_path, "data.rules", Canned(json.dumps(body).encode()), rule_pack="v2.json")


# -- version 1 stays as it is -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        rule("pattern", path="/id", pattern="[a-z]+"),
        rule("forbidden", path="/secret"),
        rule("equals", path="/a", value="x"),
        rule("each", path="/list", rule={"kind": "forbidden", "path": "/x"}),
        # A key of version 2 on a kind of version 1 is refused too: version 1 had no such key.
        rule("unit", field="u", allowed=["Wh"], path="/u"),
    ],
    ids=["pattern", "forbidden", "equals", "each", "v2-key"],
)
def test_a_version_1_pack_with_a_kind_or_a_key_of_version_2_is_refused(
    tmp_path: Path, spec: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        RulePack.model_validate(pack(spec, version="dppce.rulepack/1"))
    outcome = judge(tmp_path, {"id": "x"}, spec, version="dppce.rulepack/1")
    assert verdict(outcome) == blocked("DATA.RULES.MISSING")


def test_a_version_1_pack_keeps_loading_and_keeps_its_outcome(tmp_path: Path) -> None:
    spec = rule("range", field="soh", min=0, max=100)
    assert verdict(judge(tmp_path, {"soh": 101}, spec, version="dppce.rulepack/1")) == failed(
        "DATA.RANGE.VIOLATED"
    )
    assert verdict(judge(tmp_path, {"soh": 99}, spec, version="dppce.rulepack/1")) == passed("DATA.RULES.OK")


def test_a_version_2_pack_runs_the_kinds_of_version_1_with_dotted_fields(tmp_path: Path) -> None:
    spec = rule("unit", field="capacity.unit", allowed=["Wh"])
    assert verdict(judge(tmp_path, {"capacity": {"unit": "kWh"}}, spec)) == failed("DATA.UNIT.INVALID")


# -- pattern ------------------------------------------------------------------------------------------

SERIAL = rule("pattern", path="/serial", pattern="EV[0-9]{4}")


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"serial": "EV0001"}, True),
        ({"serial": "EV00012"}, False),  # the pattern matches the whole value
        ({"serial": "xEV0001"}, False),
        ({"serial": "EV000" + chr(0x0661)}, False),  # an ARABIC-INDIC DIGIT ONE is not [0-9]
        ({"serial": 1}, False),  # a present value of the wrong type is a fail
        ({"serial": None}, False),
        ({"serial": ["EV0001"]}, False),
        ({}, True),  # an absent field is judged by required_fields only
    ],
)
def test_pattern_matches_the_whole_string_value(document: dict[str, Any], expected: bool) -> None:
    assert holds(SERIAL, document) is expected


def test_an_ascii_class_escape_matches_ascii_only() -> None:
    assert holds(rule("pattern", path="/n", pattern=r"\d{2}"), {"n": "12"})
    assert not holds(rule("pattern", path="/n", pattern=r"\d{2}"), {"n": "1" + chr(0x0662)})


def test_a_value_longer_than_max_length_fails_the_rule_and_is_not_blocked(tmp_path: Path) -> None:
    long_value = rule("pattern", path="/n", pattern="a*", max_length=8)
    assert holds(long_value, {"n": "a" * 8})
    assert not holds(long_value, {"n": "a" * 9})
    # The default bound is 256 characters. A system cannot pad a value to dodge the rule.
    padded = {"serial": "EV0001" + " " * 300}
    assert verdict(judge(tmp_path, padded, SERIAL)) == failed("DATA.PATTERN.MISMATCH")


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+",  # a nested quantifier
        "(a|a)*",  # a quantified alternation
        "(ab)+",  # any quantified group
        "(?:ab){2}",
        r"(a)\1",  # a backreference
        r"\k",
        "(?=a)a",  # lookaround
        "(?!a)b",
        "(?<=a)b",
        "(?i)a",  # an inline flag
        "(?P<n>a)",  # a named group
        "(?>a)",  # an atomic group
        "a+?",  # a lazy quantifier
        "a++",  # a possessive quantifier
        "a{1001}",  # a repeat above the limit
        "a{3,2}",
        "a{",  # an unescaped brace that is not a quantifier
        "[a-z",  # an unterminated class
        "[[a]",  # a nested set
        "(a",
        "a)",
        "*a",
        r"\bword",  # an escape outside the accepted set
        "a*b*c*d*",  # more than three variable quantifiers
        "(a|a)" * 20 + "b",  # a chain of alternations: each "|" doubles the backtracking
        "(|a)(|a)(|a)(|a)b",
        "a" * 257,  # a pattern above 256 characters
        "",
    ],
)
def test_a_backtracking_prone_or_unknown_construct_is_refused(pattern: str) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("pattern", path="/n", pattern=pattern))


@pytest.mark.parametrize(
    "pattern",
    [
        "[A-Z]{2}[0-9]{4}",
        "(?:ab|cd)x",
        "^a$",
        r"urn:example:[a-z]+:[0-9]{4}",
        r"https://id\.example\.test/01/[0-9]{14}/21/EV[0-9]{4}",
        r"[\w.-]+@example\.test",
        r"[^\s]{1,16}",
        "a?b?c",
        "[]a]",
    ],
)
def test_a_pattern_of_the_accepted_subset_loads(pattern: str) -> None:
    Rule.model_validate(rule("pattern", path="/n", pattern=pattern))


@pytest.mark.parametrize(
    "spec",
    [rule("pattern", pattern="a*"), rule("pattern", path="", pattern="a*"), rule("equals", value="x")],
    ids=["pattern-no-path", "pattern-root", "equals-no-path"],
)
def test_a_rule_on_the_root_of_the_document_is_refused(spec: dict[str, Any]) -> None:
    """The root is an object, so the rule would break for every document."""
    with pytest.raises(ValidationError):
        Rule.model_validate(spec)


def test_a_fixed_count_is_not_a_variable_quantifier() -> None:
    Rule.model_validate(rule("pattern", path="/n", pattern="a{2}b{3,3}c{1000}d*e+f?"))  # three variable
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("pattern", path="/n", pattern="a{2}b{3,}d*e+f?"))  # four variable


def test_an_alternative_counts_as_a_variable_choice() -> None:
    Rule.model_validate(rule("pattern", path="/n", pattern=r"(a|b)[0-9]*x?[|]\|"))  # three choices
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("pattern", path="/n", pattern="(a|b)(c|d)[0-9]*x?"))  # four choices


def test_max_length_has_an_engine_limit() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("pattern", path="/n", pattern="a*", max_length=513))
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("pattern", path="/n", pattern="a*", max_length=0))


# -- forbidden ----------------------------------------------------------------------------------------

FORBIDDEN = rule("forbidden", path="/restricted/usage_log")


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({}, True),
        ({"restricted": {}}, True),
        ({"restricted": {"usage_log": "x"}}, False),
        ({"restricted": {"usage_log": None}}, False),  # a null field is present
        ({"restricted": {"usage_log": {}}}, False),
        ({"restricted": "text"}, True),  # the pointer does not resolve, so the field is absent
    ],
)
def test_forbidden_fails_when_the_field_is_present(document: dict[str, Any], expected: bool) -> None:
    assert holds(FORBIDDEN, document) is expected


def test_forbidden_needs_a_field() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("forbidden", path=""))
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("forbidden"))


# -- equals -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"g": "item"}, True),
        ({"g": "Item"}, False),  # exact text: no case folding
        ({"g": "item "}, False),
        ({"g": 1}, False),
        ({"g": None}, False),
        ({}, True),
    ],
)
def test_equals_compares_with_a_constant(document: dict[str, Any], expected: bool) -> None:
    assert holds(rule("equals", path="/g", value="item"), document) is expected


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"a": {"u": "Wh"}, "b": {"u": "Wh"}}, True),
        ({"a": {"u": "Wh"}, "b": {"u": "kWh"}}, False),
        ({"a": {"u": "Wh"}, "b": {"u": 1}}, False),
        ({"a": {"u": "Wh"}}, True),  # one side absent: not judged, as for relationship
        ({"b": {"u": "Wh"}}, True),
    ],
)
def test_equals_compares_with_another_pointer(document: dict[str, Any], expected: bool) -> None:
    assert holds(rule("equals", path="/a/u", other="/b/u"), document) is expected


@pytest.mark.parametrize(
    "fields",
    [{}, {"value": "x", "other": "/b"}, {"value": 1}, {"other": "b"}],
    ids=["neither", "both", "not-a-string", "not-a-pointer"],
)
def test_equals_needs_exactly_one_string_or_pointer(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("equals", path="/a", **fields))


# -- each ---------------------------------------------------------------------------------------------

CONTEXTS = rule(
    "each", path="/@context", rule={"kind": "pattern", "path": "", "pattern": "https://[a-z.]+/c"}
)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"@context": ["https://a.test/c", "https://b.test/c"]}, True),
        ({"@context": ["https://a.test/c", "https://b.test/x"]}, False),
        ({"@context": ["https://a.test/c", 1]}, False),
        ({"@context": []}, True),
        ({"@context": "https://a.test/c"}, False),  # a present value that is not an array is a fail
        ({}, True),
    ],
)
def test_each_applies_the_rule_to_every_element(document: dict[str, Any], expected: bool) -> None:
    assert holds(CONTEXTS, document) is expected


def test_each_reads_the_paths_of_its_rule_from_the_element() -> None:
    cells = rule("each", path="/cells", rule={"kind": "required_fields", "fields": ["id", "chem.name"]})
    assert holds(cells, {"cells": [{"id": 1, "chem": {"name": "x"}}]})
    assert not holds(cells, {"cells": [{"id": 1, "chem": {"name": "x"}}, {"id": 2}]})
    assert not holds(cells, {"cells": ["text"]})
    ranged = rule("each", path="/v", rule={"kind": "range", "field": "n", "max": 5})
    assert not holds(ranged, {"v": [{"n": 6}]})


def test_a_failed_each_rule_gives_the_code_of_its_rule(tmp_path: Path) -> None:
    body = {"@context": ["https://a.test/x"]}
    outcome = judge(tmp_path, body, CONTEXTS)
    assert verdict(outcome) == failed("DATA.PATTERN.MISMATCH")
    assert outcome.observations[0].summary["failed_rules"] == ["R-each"]


@pytest.mark.parametrize(
    "spec",
    [
        rule(
            "each",
            path="/a",
            rule={"kind": "each", "path": "/b", "rule": {"kind": "forbidden", "path": "/c"}},
        ),
        rule("each", path="", rule={"kind": "forbidden", "path": "/c"}),
        rule("each", path="/a"),
        rule("each", path="/a", rule={"kind": "pattern", "path": "", "pattern": "(a+)+"}),
        rule("each", path="/a", rule={"kind": "forbidden", "path": "/c", "id": "X"}),
    ],
    ids=["nested-each", "root", "no-rule", "bad-inner", "inner-id"],
)
def test_an_each_rule_that_cannot_judge_is_refused(spec: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(spec)


@pytest.mark.parametrize("pointer", ["a/b", "/a~2", "/" + "a" * 600])
def test_a_malformed_pointer_is_refused(pointer: str) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate(rule("forbidden", path=pointer))


# -- precedence and the shipped pack -------------------------------------------------------------------


def test_the_kinds_of_version_1_come_first_and_the_new_kinds_follow_in_order(tmp_path: Path) -> None:
    body = {"serial": "x", "secret": 1, "g": "y", "soh": 101}
    eq = rule("equals", path="/g", value="item")
    forbidden = rule("forbidden", path="/secret")
    ranged = rule("range", field="soh", max=100)
    assert verdict(judge(tmp_path, body, eq, SERIAL, forbidden, ranged)) == failed("DATA.RANGE.VIOLATED")
    assert verdict(judge(tmp_path, body, eq, SERIAL, forbidden)) == failed("DATA.FIELD.FORBIDDEN")
    assert verdict(judge(tmp_path, body, eq, SERIAL)) == failed("DATA.PATTERN.MISMATCH")
    assert verdict(judge(tmp_path, body, eq)) == failed("DATA.EQUALITY.VIOLATED")


def shipped() -> RulePack:
    return RulePack.model_validate(yaml.safe_load((ROOT / SHIPPED).read_text(encoding="utf-8")))


def ev_passport() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (ROOT / "fixtures/reference/items/ev.json").read_text(encoding="utf-8")
    )
    return document


def test_the_shipped_pack_uses_each_kind_of_version_2_and_holds_on_the_reference_passport() -> None:
    loaded = shipped()
    assert loaded.schema_version == "dppce.rulepack/2"
    assert {r.kind for r in loaded.rules} >= {"pattern", "forbidden", "equals", "each"}
    assert all(rule_holds(r, ev_passport(), NOW) for r in loaded.rules)


def test_the_shipped_pack_fails_the_seeded_passports_of_f79_and_f80() -> None:
    by_kind = {r.kind: r for r in shipped().rules}
    other = ev_passport()
    other["id"] = other["id"].rsplit("/", 1)[0] + "/OTHER0001"  # the flag id_mismatch (F-79)
    assert not rule_holds(by_kind["pattern"], other, NOW)
    leaked = copy.deepcopy(ev_passport())
    leaked["restricted"] = {"usage_log": "CANARY"}  # the flag leak_usage_log_anonymous (F-80)
    assert not rule_holds(by_kind["forbidden"], leaked, NOW)


# -- data.context: the Link header -----------------------------------------------------------------------


class Linked(Canned):
    """Canned with extra response headers, as the transport records them after redaction."""

    def __init__(
        self, body: bytes, headers: tuple[tuple[str, str], ...], media: str = "application/json"
    ) -> None:
        super().__init__(body)
        self._headers = (("Content-Type", media), *headers)

    def fetch(self, request: Request) -> Record:
        record = replace(make_record(1, self._body, request.url), headers=self._headers)
        self._records.append(record)
        return record


def link(target: str, relation: str = JSONLD_CONTEXT) -> tuple[str, str]:
    return ("Link", f'<{target}>; rel="{relation}"')


def contexts(tmp_path: Path, acquirer: Canned, **params: Any) -> Any:
    return check(tmp_path, "data.context", acquirer, **({"allowed_contexts": ALLOWED} | params))


BODY = b'{"@context": "https://example.test/ctx", "id": "x"}'
PLAIN = b'{"id": "x"}'


def test_a_link_context_on_the_allowlist_passes_and_names_the_context(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(PLAIN, (link(ALLOWED[0]),)))
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")
    assert outcome.observations[0].summary["contexts"] == 1


def test_a_link_context_outside_the_allowlist_fails(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(BODY, (link("https://other.test/ctx"),)))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == ["https://other.test/ctx"]


def test_a_relative_link_target_is_resolved_against_the_document_url(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(PLAIN, (link("/ctx"),)))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == ["https://id.example.test/ctx"]


def test_a_link_with_another_relation_is_not_a_context(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(BODY, (link("https://other.test/x", "linkset"),)))
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


def test_a_json_ld_answer_ignores_the_link_context(tmp_path: Path) -> None:
    """JSON-LD 1.1, section 6.1: a processor ignores the header for application/ld+json."""
    acquirer = Linked(BODY, (link("https://other.test/ctx"),), media="application/ld+json")
    assert verdict(contexts(tmp_path, acquirer)) == passed("DATA.CONTEXT.OK")
    assert verdict(
        contexts(tmp_path, Linked(PLAIN, (link(ALLOWED[0]),), media="application/ld+json"))
    ) == failed("DATA.CONTEXT.MISSING")


def test_a_link_value_that_redaction_removed_is_not_judged_and_never_passes(tmp_path: Path) -> None:
    unreadable = Linked(BODY, (("Link", REMOVED),))
    assert verdict(contexts(tmp_path, unreadable)) == blocked("DATA.CONTEXT.LINK_UNREADABLE")
    redacted = Linked(BODY, (link("https://example.test/ctx?token=%3Cremoved%3E"),))
    assert verdict(contexts(tmp_path, redacted)) == blocked("DATA.CONTEXT.LINK_UNREADABLE")
    # A fail in the body comes first, so a reshaped header cannot hide it.
    foreign = b'{"@context": "https://other.test/ctx"}'
    assert verdict(contexts(tmp_path, Linked(foreign, (("Link", REMOVED),)))) == failed(
        "DATA.CONTEXT.NOT_ALLOWED"
    )


def test_the_transport_record_keeps_the_link_context_that_the_check_reads(tmp_path: Path) -> None:
    raw = (("Link", f'<https://other.test/ctx>; rel="{JSONLD_CONTEXT}"'),)
    outcome = contexts(tmp_path, Linked(BODY, redact_response_headers(raw)))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


def test_without_a_link_context_the_summary_keeps_its_keys(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(BODY, (link("https://x.test/", "next"),)))
    assert set(outcome.observations[0].summary) == {"document", "contexts", "not_allowed"}
    assert outcome.observations[0].summary["contexts"] == 1


# -- data.context: @import in a pinned context ------------------------------------------------------------

A, B, C = "https://example.test/ctx", "https://example.test/b", "https://example.test/c"


def pin(tmp_path: Path, name: str, document: Any) -> str:
    (tmp_path / name).write_text(json.dumps(document), encoding="utf-8")
    return name


def test_an_import_of_a_pinned_context_must_be_on_the_allowlist(tmp_path: Path) -> None:
    files = {A: pin(tmp_path, "a.json", {"@context": {"@import": "https://other.test/ctx", "x": "y"}})}
    outcome = contexts(tmp_path, Canned(BODY), context_files=files)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == ["https://other.test/ctx"]


def test_an_import_is_followed_only_into_a_pinned_context(tmp_path: Path) -> None:
    allowed = [A, B, C]
    a = pin(tmp_path, "a.json", {"@context": {"@import": B}})
    b = pin(
        tmp_path,
        "b.json",
        {"@context": [C, {"t": {"@id": "x:t", "@context": {"@import": "https://other.test/d"}}}]},
    )
    # B is pinned, so its scoped @import is read. C is allowed and not pinned: judged by its URL only.
    outcome = contexts(tmp_path, Canned(BODY), allowed_contexts=allowed, context_files={A: a, B: b})
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == ["https://other.test/d"]
    assert verdict(
        contexts(tmp_path, Canned(BODY), allowed_contexts=allowed, context_files={A: a})
    ) == passed("DATA.CONTEXT.OK")


def test_an_import_cycle_ends(tmp_path: Path) -> None:
    files = {
        A: pin(tmp_path, "a.json", {"@context": {"@import": B}}),
        B: pin(tmp_path, "b.json", {"@context": {"@import": A}}),
    }
    outcome = contexts(tmp_path, Canned(BODY), allowed_contexts=[A, B], context_files=files)
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


def test_a_link_context_follows_its_pinned_imports_too(tmp_path: Path) -> None:
    files = {A: pin(tmp_path, "a.json", {"@context": {"@import": "https://other.test/ctx"}})}
    outcome = contexts(tmp_path, Linked(PLAIN, (link(A),)), context_files=files)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


@pytest.mark.parametrize(
    "content",
    ["[1, 2]", "not json", '{"@context": {"@import": 1}}'],
    ids=["not-an-object", "not-json", "import-not-a-string"],
)
def test_a_pinned_context_that_cannot_be_read_blocks_the_check(tmp_path: Path, content: str) -> None:
    (tmp_path / "a.json").write_text(content, encoding="utf-8")
    acquirer = Canned(BODY)
    outcome = contexts(tmp_path, acquirer, context_files={A: "a.json"})
    assert verdict(outcome) == blocked("DATA.CONTEXT.FILE_INVALID")
    assert acquirer.records() == ()  # the pinned files are read before the document is fetched


def test_a_missing_pinned_context_blocks_the_check(tmp_path: Path) -> None:
    assert verdict(contexts(tmp_path, Canned(BODY), context_files={A: "absent.json"})) == blocked(
        "DATA.CONTEXT.FILE_INVALID"
    )


@pytest.mark.parametrize(
    "files",
    [{"https://other.test/ctx": "a.json"}, {A: "../a.json"}, {A: "/abs.json"}],
    ids=["not-allowed", "dot-dot", "absolute"],
)
def test_context_files_must_be_allowed_contexts_under_the_data_root(
    tmp_path: Path, files: dict[str, str]
) -> None:
    assert verdict(contexts(tmp_path, Canned(BODY), context_files=files)) == blocked("DATA.PARAMS.INVALID")


def test_the_run_binds_each_pinned_context_file() -> None:
    params = {"allowed_contexts": [A, B], "context_files": {A: "ctx/a.json", B: "ctx/b.json"}}
    assert param_files("data.context", params) == ("ctx/a.json", "ctx/b.json")
    assert param_files("data.context", {"allowed_contexts": [A]}) == ()
    assert param_files("data.context", {"context_files": {A: "../x"}}) == ()
    assert param_files("data.rules", {"rule_pack": SHIPPED}) == (SHIPPED,)
