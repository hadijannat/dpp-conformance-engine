"""Field maps of persistence.versions and registry.consistency (package P2-06).

JSON Pointers follow RFC 6901. The defaults keep the behavior of the base version. Loopback and
in-process answers only: no test reaches an external host.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.common import MISSING
from dppce.adapters.pointer import parse_pointer, resolve_pointer
from dppce.catalogue.lint import params_problem
from dppce.models import CheckOutcome, ExecutionStatus
from dppce.testdefs import registry
from tests.test_review_adapters import ITEM_URL, REGISTRY_URL, VERSIONS_URL, ByUrl
from tests.test_url_templates import context, run

STAMP = "2026-09-01T08:00:00Z"
LATER = "2026-09-02T08:00:00Z"
ITEM_BODY = b'{"id": "x", "n": 1.5}'  # a float: the passport has no canonical form


def _models() -> dict[str, Any]:
    return registry.param_models()


def _problem(check: str, params: dict[str, Any]) -> str | None:
    return params_problem(_models()[check], params)


def _raw(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _versions(tmp_path: Path, history: Any, params: dict[str, Any], item: bytes = ITEM_BODY) -> CheckOutcome:
    answers = {VERSIONS_URL: (200, json.dumps(history).encode()), ITEM_URL: (200, item)}
    return run(context(tmp_path, "persistence.versions", params=params, acquirer=ByUrl(answers)))


def _registry(tmp_path: Path, entry: Any, passport: Any, params: dict[str, Any]) -> CheckOutcome:
    answers = {
        REGISTRY_URL: (200, json.dumps(entry).encode()),
        ITEM_URL: (200, json.dumps(passport).encode()),
    }
    return run(context(tmp_path, "registry.consistency", params=params, acquirer=ByUrl(answers)))


# -- RFC 6901 -----------------------------------------------------------------------------------

RFC_DOCUMENT = {
    "foo": ["bar", "baz"],
    "": 0,
    "a/b": 1,
    "c%d": 2,
    "e^f": 3,
    "g|h": 4,
    "i\\j": 5,
    'k"l': 6,
    " ": 7,
    "m~n": 8,
}


@pytest.mark.parametrize(
    ("pointer", "value"),
    [
        ("", RFC_DOCUMENT),
        ("/foo", ["bar", "baz"]),
        ("/foo/0", "bar"),
        ("/", 0),
        ("/a~1b", 1),
        ("/c%d", 2),
        ("/e^f", 3),
        ("/g|h", 4),
        ("/i\\j", 5),
        ('/k"l', 6),
        ("/ ", 7),
        ("/m~0n", 8),
    ],
)
def test_the_examples_of_rfc_6901_resolve(pointer: str, value: Any) -> None:
    assert resolve_pointer(RFC_DOCUMENT, parse_pointer(pointer)) == value


@pytest.mark.parametrize("pointer", ["foo", "/a~", "/a~2", "/~", "\n", "/" + "a" * 600])
def test_a_malformed_pointer_is_refused(pointer: str) -> None:
    with pytest.raises(ValueError, match="pointer"):
        parse_pointer(pointer)


@pytest.mark.parametrize(
    "pointer",
    [
        "/foo/2",
        "/foo/-",
        "/foo/01",
        "/foo/+1",
        "/foo/a",
        "/nope",
        "/foo/0/x",
        "/m~0n/x",
        "/foo/" + chr(0x661),
    ],
)
def test_a_pointer_that_does_not_resolve_gives_missing(pointer: str) -> None:
    assert resolve_pointer(RFC_DOCUMENT, parse_pointer(pointer)) is MISSING


def test_an_array_index_is_not_a_member_name() -> None:
    assert resolve_pointer({"0": "x"}, parse_pointer("/0")) == "x"
    assert resolve_pointer(["x"], parse_pointer("/0")) == "x"
    assert resolve_pointer(["x"], parse_pointer("/00")) is MISSING


# -- the parameter models -----------------------------------------------------------------------


def test_both_checks_have_closed_models_with_today_defaults() -> None:
    assert _problem("persistence.versions", {}) is None
    assert _problem("registry.consistency", {}) is None
    assert _problem("persistence.versions", {"digest_of": "raw-sha256", "version_kind": "string"}) is None
    assert _models()["persistence.versions"].model_config.get("extra") == "forbid"
    assert _models()["registry.consistency"].model_config.get("extra") == "forbid"


@pytest.mark.parametrize(
    ("check", "params", "key"),
    [
        ("persistence.versions", {"entries_pointer": "versions"}, "entries_pointer"),
        ("persistence.versions", {"entries_pointer": "/a~9"}, "entries_pointer"),
        ("persistence.versions", {"digest_of": "md5"}, "digest_of"),
        ("persistence.versions", {"version_kind": "float"}, "version_kind"),
        ("persistence.versions", {"time_field": ""}, "time_field"),
        ("persistence.versions", {"digest_field": 7}, "digest_field"),
        ("persistence.versions", {"documnet": "item"}, "documnet"),
        ("registry.consistency", {"fields": []}, "fields"),
        ("registry.consistency", {"fields": "identifier"}, "fields"),
        (
            "registry.consistency",
            {"fields": [{"name": "a", "registry_pointer": "/a", "passport_pointer": "a"}]},
            "passport_pointer",
        ),
        (
            "registry.consistency",
            {"fields": [{"name": "a", "registry_pointer": "/a", "passport_pointer": "/a", "extra": 1}]},
            "extra",
        ),
        (
            "registry.consistency",
            {"fields": [{"name": "a", "registry_pointer": "/a", "passport_pointer": "/a"}] * 2},
            "fields",
        ),
        (
            "registry.consistency",
            {
                "fields": [
                    {"name": f"f{i}", "registry_pointer": "/a", "passport_pointer": "/a"} for i in range(17)
                ]
            },
            "fields",
        ),
    ],
)
def test_an_invalid_parameter_is_refused(check: str, params: dict[str, Any], key: str) -> None:
    problem = _problem(check, params)
    assert problem is not None
    assert key in problem


# -- persistence.versions -----------------------------------------------------------------------


def test_the_default_keeps_the_jcs_comparison(tmp_path: Path) -> None:
    from dppce.evidence.canonical import digest  # noqa: PLC0415 - only this test needs it

    item = {"id": "x"}
    history = {"versions": [{"version": 1, "updated_at": STAMP, "content_digest": digest(item)}]}
    outcome = _versions(tmp_path, history, {}, json.dumps(item).encode())
    assert (outcome.passed, outcome.reason_code) == (True, "PERSISTENCE.OK")


def test_a_third_party_layout_passes_with_its_field_map(tmp_path: Path) -> None:
    history = {
        "data": {
            "history": [
                {"rev": "a1", "modified": STAMP, "hash": "sha256:" + "0" * 64},
                {"rev": "a2", "modified": LATER, "hash": _raw(ITEM_BODY)},
            ]
        }
    }
    params = {
        "entries_pointer": "/data/history",
        "version_field": "rev",
        "time_field": "modified",
        "digest_field": "hash",
        "digest_of": "raw-sha256",
        "version_kind": "string",
    }
    outcome = _versions(tmp_path, history, params)
    assert (outcome.passed, outcome.reason_code) == (True, "PERSISTENCE.OK")


def test_a_raw_digest_compares_a_body_without_a_canonical_form(tmp_path: Path) -> None:
    history = {"versions": [{"version": 1, "updated_at": STAMP, "content_digest": _raw(ITEM_BODY)}]}
    outcome = _versions(tmp_path, history, {"digest_of": "raw-sha256"})
    assert (outcome.status, outcome.passed) == (ExecutionStatus.COMPLETED, True)


def test_a_stale_raw_digest_fails_and_is_never_blocked(tmp_path: Path) -> None:
    history = {"versions": [{"version": 1, "updated_at": STAMP, "content_digest": _raw(b"{}")}]}
    outcome = _versions(tmp_path, history, {"digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


def test_a_pointer_to_nothing_gives_the_not_json_outcome(tmp_path: Path) -> None:
    history = {"versions": [{"version": 1, "updated_at": STAMP, "content_digest": _raw(ITEM_BODY)}]}
    outcome = _versions(tmp_path, history, {"entries_pointer": "/nope", "digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.RESPONSE.NOT_JSON")


def test_the_history_may_be_the_root_array(tmp_path: Path) -> None:
    history = [{"version": 1, "updated_at": STAMP, "content_digest": _raw(ITEM_BODY)}]
    outcome = _versions(tmp_path, history, {"entries_pointer": "", "digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (True, "PERSISTENCE.OK")


@pytest.mark.parametrize(
    "versions",
    [["a", "a"], ["a", 2], ["", "b"]],
    ids=["repeated", "mixed-type", "empty"],
)
def test_string_versions_must_be_distinct_strings(tmp_path: Path, versions: list[Any]) -> None:
    stamps = (STAMP, LATER)
    history = {
        "versions": [
            {"version": v, "updated_at": s, "content_digest": _raw(ITEM_BODY)}
            for v, s in zip(versions, stamps, strict=True)
        ]
    }
    outcome = _versions(tmp_path, history, {"version_kind": "string", "digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


def test_a_string_version_is_not_accepted_as_an_integer(tmp_path: Path) -> None:
    history = {"versions": [{"version": "1", "updated_at": STAMP, "content_digest": _raw(ITEM_BODY)}]}
    outcome = _versions(tmp_path, history, {"digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


def test_added_members_cannot_turn_a_fail_into_a_non_finding(tmp_path: Path) -> None:
    # The system adds a member with a float and a deep value. The break stays a fail.
    entry = {"version": 1, "updated_at": STAMP, "content_digest": _raw(b"{}")}
    history = {"versions": [entry], "extra": {"deep": [[[[1]]]]}}
    outcome = _versions(tmp_path, history, {"digest_of": "raw-sha256"})
    assert (outcome.passed, outcome.reason_code) == (False, "PERSISTENCE.UNDECLARED_CHANGE")


# -- registry.consistency -----------------------------------------------------------------------

THIRD: dict[str, Any] = {
    "fields": [
        {"name": "identifier", "registry_pointer": "/identifier", "passport_pointer": "/id"},
        {"name": "passport_url", "registry_pointer": "/passport_url", "passport_pointer": "/id"},
    ]
}


def test_the_default_fields_keep_today_behavior(tmp_path: Path) -> None:
    entry = {"identifier": "https://id/x", "operator_identifier": "urn:op:1"}
    passport = {"id": "https://id/x", "operator": {"identifier": "urn:op:1"}}
    assert _registry(tmp_path, entry, passport, {}).reason_code == "REGISTRY.OK"
    passport["operator"]["identifier"] = "urn:op:2"
    outcome = _registry(tmp_path, entry, passport, {})
    assert (outcome.passed, outcome.reason_code) == (False, "REGISTRY.INCONSISTENT")


def test_a_declared_third_pair_that_agrees_passes(tmp_path: Path) -> None:
    entry = {"identifier": "https://id/x", "passport_url": "https://id/x"}
    outcome = _registry(tmp_path, entry, {"id": "https://id/x"}, THIRD)
    assert (outcome.passed, outcome.reason_code) == (True, "REGISTRY.OK")


def test_a_declared_pair_that_differs_fails(tmp_path: Path) -> None:
    entry = {"identifier": "https://id/x", "passport_url": "https://id/other"}
    outcome = _registry(tmp_path, entry, {"id": "https://id/x"}, THIRD)
    assert (outcome.passed, outcome.reason_code) == (False, "REGISTRY.INCONSISTENT")
    assert outcome.observations[0].summary["different"] == ["passport_url"]


def test_pointers_reach_nested_and_array_members(tmp_path: Path) -> None:
    params = {
        "fields": [
            {"name": "operator", "registry_pointer": "/data/operator/0/id", "passport_pointer": "/op/id"}
        ]
    }
    entry = {"data": {"operator": [{"id": "urn:op:1"}]}}
    assert _registry(tmp_path, entry, {"op": {"id": "urn:op:1"}}, params).reason_code == "REGISTRY.OK"


def test_a_pointer_to_nothing_is_a_missing_field(tmp_path: Path) -> None:
    entry = {"identifier": "https://id/x"}
    outcome = _registry(tmp_path, entry, {"id": "https://id/x"}, THIRD)
    assert (outcome.passed, outcome.reason_code) == (False, "REGISTRY.FIELD.MISSING")
    assert outcome.observations[0].summary["missing"] == ["passport_url"]


def test_a_difference_wins_over_a_missing_field(tmp_path: Path) -> None:
    entry = {"identifier": "https://id/other"}
    outcome = _registry(tmp_path, entry, {"id": "https://id/x"}, THIRD)
    assert (outcome.passed, outcome.reason_code) == (False, "REGISTRY.INCONSISTENT")


def test_the_root_pointer_compares_the_whole_document(tmp_path: Path) -> None:
    params = {"fields": [{"name": "whole", "registry_pointer": "", "passport_pointer": ""}]}
    assert _registry(tmp_path, {"a": 1}, {"a": 1}, params).reason_code == "REGISTRY.OK"
    assert _registry(tmp_path, {"a": True}, {"a": 1}, params).reason_code == "REGISTRY.INCONSISTENT"


@pytest.mark.parametrize(
    ("check", "params", "code"),
    [
        ("persistence.versions", {"entries_pointer": "x"}, "PERSISTENCE.PARAMS.INVALID"),
        ("registry.consistency", {"fields": []}, "REGISTRY.PARAMS.INVALID"),
    ],
)
def test_invalid_params_that_skip_the_lint_block_before_any_request(
    tmp_path: Path, check: str, params: dict[str, Any], code: str
) -> None:
    acquirer = ByUrl({})
    outcome = run(context(tmp_path, check, params=params, acquirer=acquirer))
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, code)
    assert acquirer.records() == ()
