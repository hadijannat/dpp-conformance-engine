"""The generated reason-code catalogue: extraction from source text, and the committed page."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

# The generator sets COLUMNS at import time; keep the test process environment unchanged.
with mock.patch.dict(os.environ):
    gen = importlib.import_module("scripts.gen_reference_docs")

ROOT = Path(__file__).resolve().parent.parent


def _sites(source: str, families: dict[str, tuple[str, ...]] | None = None) -> list[Any]:
    return list(gen.extract_reason_codes({"pkg.m": source}, families or {}))


def _codes(sites: list[Any]) -> list[str]:
    return [s.code for s in sites]


def test_a_literal_code_is_extracted_and_a_docstring_is_not() -> None:
    sites = _sites('def f(ctx):\n    """Gives X.Y.Z."""\n    return completed(True, "A.B.OK", "m")\n')
    assert _codes(sites) == ["A.B.OK"]
    site = sites[0]
    assert (site.effect, site.function, site.module) == ("pass", "f", "pkg.m")


def test_a_code_at_the_end_of_a_sentence_is_extracted() -> None:
    assert _codes(_sites('def f():\n    text = "The result is X.Y.Z."\n    return text\n')) == ["X.Y.Z"]


def test_a_code_in_a_message_f_string_is_extracted() -> None:
    sites = _sites('def f(x):\n    raise E(f"A.B.C: {x}")\n')
    assert _codes(sites) == ["A.B.C"]
    assert sites[0].effect is None


@pytest.mark.parametrize(
    ("call", "effect"),
    [
        ('completed(False, "A.FAIL", "m")', "fail; inconclusive under a non-default verdict rule"),
        (
            'completed(False, "A.GONE", "m", no_answer=True)',
            "inconclusive; fail under a non-default verdict rule",
        ),
        ('blocked("A.BLOCKED", "m")', "inconclusive"),
        ('not_done(ExecutionStatus.UNSUPPORTED, "A.UNSUP", "m")', "inconclusive"),
        ('CheckOutcome(status=ExecutionStatus.ERROR, reason_code="A.ERR", message="m")', "error"),
        (
            'completed(ok, "A.MAYBE", "m")',
            "fail or pass; inconclusive or pass under a non-default verdict rule",
        ),
    ],
)
def test_the_call_fixes_the_effect(call: str, effect: str) -> None:
    sites = _sites(f"def f(ctx, ok):\n    return {call}\n")
    assert len(sites) == 1
    assert sites[0].effect == effect


def test_a_code_chosen_through_a_variable_has_no_effect() -> None:
    sites = _sites('def f(ok):\n    code = "A.OK" if ok else "A.NO"\n    return completed(ok, code, "m")\n')
    assert sorted(_codes(sites)) == ["A.NO", "A.OK"]
    assert [s.effect for s in sites] == [None, None]


def test_an_area_parameter_expands_at_each_call_site() -> None:
    sources = {
        "pkg.common": (
            "def template_url(ctx, t, area):\n"
            '    return blocked(f"{area}.NO_TARGET", "m")\n'
            "def resource_url(ctx, r, area):\n"
            "    return template_url(ctx, r, area)\n"
        ),
        "pkg.data": 'def g(ctx):\n    area = "DATA"\n    return resource_url(ctx, "item", area)\n',
        "pkg.api": 'def h(ctx):\n    return resource_url(ctx, "item", "API.CONTRACT")\n',
    }
    sites = gen.extract_reason_codes(sources, {})
    found = {(s.code, s.module, s.function, s.effect) for s in sites}
    assert ("DATA.NO_TARGET", "pkg.data", "g", "inconclusive") in found
    assert ("API.CONTRACT.NO_TARGET", "pkg.api", "h", "inconclusive") in found
    assert "API.CONTRACT" not in {s.code for s in sites}


def test_a_local_constant_fills_a_composed_code() -> None:
    source = 'def f(ctx):\n    area = "DATA"\n    return completed(False, f"{area}.RESPONSE.NOT_JSON", "m")\n'
    assert _codes(_sites(source)) == ["DATA.RESPONSE.NOT_JSON"]


def test_a_family_expands_and_an_unknown_composition_is_refused() -> None:
    source = 'def f(c):\n    return completed(False, f"X.LEAK.{c.upper()}", "m")\n'
    assert _codes(_sites(source, {"X.LEAK.*": ("A", "B")})) == ["X.LEAK.A", "X.LEAK.B"]
    with pytest.raises(ValueError, match="unresolved composed reason code"):
        _sites(source)


def test_the_check_name_comes_from_the_register_decorator() -> None:
    source = '@register("demo.check", capability="demo")\ndef f(ctx):\n    return completed(True, "DEMO.OK", "m")\n'
    assert [s.check for s in _sites(source)] == ["demo.check"]


def test_the_shipped_catalogue() -> None:
    sites = gen.extract_reason_codes(gen.source_modules(), gen.code_families())
    codes = {s.code for s in sites}
    assert all(gen.CODE.fullmatch(c) for c in codes)
    assert not any("*" in c for c in codes)
    for expected in (
        "ACCESS.LEAK.EXPORT",
        "PLAN.SKIPPED",
        "DATA.NO_TARGET",
        "INTEGRITY.NO_TARGET",
        "ACCESS.NO_TARGET",
        "DATA.RESPONSE.NOT_JSON",
        "DATA.SCHEMA.OK",
        "ENGINE.CHECK_EXCEPTION",
        "TRANSPORT.UNREACHABLE",
        "REPLAY.INPUT.CHANGED",
        "PATH.NO_STEP",
        "ISSUER.STATEMENT.MISMATCH",
    ):
        assert expected in codes, expected
    assert "API.CONTRACT" not in codes
    assert {s.effect for s in sites if s.code == "DATA.SCHEMA.OK"} == {"pass"}


def test_the_code_families_are_pinned() -> None:
    # PLAN.* follows ExecutionStatus. A new member fails here and forces a review of the planner.
    families = gen.code_families()
    assert families["PLAN.*"] == ("NOT_RUN", "SKIPPED", "BLOCKED", "UNSUPPORTED", "MANUAL_UNAVAILABLE")
    assert families["ACCESS.LEAK.*"] == ("FETCH", "EXPORT", "SEARCH", "ERROR", "HTML")


def test_the_reason_code_page_is_current() -> None:
    page = (ROOT / "docs" / "reference" / "reason-codes.md").read_text(encoding="utf-8")
    assert page == gen.reason_codes_page(), "run `uv run just reference`"
