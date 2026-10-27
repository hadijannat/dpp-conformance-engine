"""Every example ICS and IXIT under profiles/family/examples/ loads, lints, and plans on loopback.

The operator guide names each example. The deferred dataspace and OAuth 2.0 integrations are
named as interface_only capabilities in the capability manifest; no check uses them, so a run
plans no step for them.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from dppce import cli
from dppce.adapters.capabilities import manifest
from dppce.catalogue import load_catalogue, load_model, load_profiles, load_testpacks
from dppce.catalogue.lint import lint
from dppce.models import ICS, IXIT, CapabilityState
from dppce.testdefs import registry

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "profiles" / "family" / "examples"
GUIDE = ROOT / "docs" / "how-to" / "test-a-real-system.md"
ICS_FILES = sorted(EXAMPLES.glob("*.ics.yaml"))
DEFERRED = ("dataspace.protocol", "dataspace.catalog", "access.oauth2")


def _plan(ics: Path, ixit: Path, profile: str) -> dict[str, Any]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main(["plan", "--profile", profile, "--ics", str(ics), "--ixit", str(ixit), "--json"])
    assert code == 0, captured.getvalue()
    return json.loads(captured.getvalue())  # type: ignore[no-any-return] # json.loads gives Any


def test_each_family_profile_has_an_example() -> None:
    profiles = {p for p in load_profiles(ROOT) if p.startswith("family/")}
    declared = {load_model(path, ICS).profile for path in ICS_FILES}
    assert profiles <= declared
    for path in ICS_FILES:
        assert path.with_name(path.name.replace(".ics.", ".ixit.")).is_file(), path.name


@pytest.mark.parametrize("ics_path", ICS_FILES, ids=lambda p: p.name)
def test_an_example_loads_and_plans(ics_path: Path) -> None:
    ixit_path = ics_path.with_name(ics_path.name.replace(".ics.", ".ixit."))
    ics, ixit = load_model(ics_path, ICS), load_model(ixit_path, IXIT)
    # Every sample file that the IXIT names sits next to it, except the one that the operator supplies.
    for name, sample in ixit.samples.items():
        if sample.endswith((".json", ".xml", ".aasx", ".jws", ".jwt")) and name != "aas_json":
            assert (EXAMPLES / sample).is_file(), (name, sample)
    plan = _plan(ics_path, ixit_path, ics.profile)
    assert plan["profile_id"] == ics.profile
    assert plan["conflicts"] == []
    assert plan["steps"], "the example selects at least one step"


def test_the_examples_lint_without_error() -> None:
    findings = lint(
        load_catalogue(ROOT), load_profiles(ROOT), load_testpacks(ROOT), registry.param_models(), ROOT
    )
    assert [f for f in findings if f.severity == "error"] == []


@pytest.mark.parametrize("capability_id", DEFERRED)
def test_a_deferred_integration_is_a_named_interface_only_capability(capability_id: str) -> None:
    by_id = {c.id: c for c in manifest().capabilities}
    entry = by_id[capability_id]
    assert entry.state is CapabilityState.INTERFACE_ONLY
    assert entry.acceptance_criteria.strip(), "the criteria say what must be true before a state change"


def test_the_guide_names_each_example_and_each_family() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    for path in EXAMPLES.glob("*.yaml"):
        assert path.name in text, path.name
    for profile in ("family/web", "family/gs1-resolver", "family/aas", "family/credentials"):
        assert f"`{profile}`" in text, profile
    assert "dataspace" in text.lower()
    for capability_id in DEFERRED:
        assert f"`{capability_id}`" in text, capability_id
