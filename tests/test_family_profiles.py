"""Family profiles and family test packs: load, lint, plan, and run against the reference system.

A laboratory that tests a GS1 resolver, an AAS file, a credential, or a plain web passport
must not need a battery profile. Each family profile selects the family requirement pack and
the family test packs. A step of another family is not applicable, never a fail.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from dppce import cli
from dppce.catalogue import load_catalogue, load_profiles, load_testpacks
from dppce.catalogue.lint import lint
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import AuthorityClass, Compare, EvidenceEnvelope, ReviewStatus, Verdict
from dppce.models.expr import All
from dppce.testdefs import registry

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "profiles" / "family" / "examples"
FIXTURES = ROOT / "fixtures" / "reference"
TRUST = FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"
PACK = "family/illustrative"
# family name -> (profile id, test pack id, test purpose prefix, requirement prefix)
FAMILIES = {
    "web": ("family/web", "family/web-core", "TP-WEB-", "FAM-WEB-"),
    "gs1-resolver": ("family/gs1-resolver", "family/gs1-resolver-core", "TP-GS1-", "FAM-GS1-"),
    "aas": ("family/aas", "family/aas-core", "TP-AAS-", "FAM-AAS-"),
    "credentials": ("family/credentials", "family/credentials-core", "TP-VC-", "FAM-VC-"),
}
FAMILY_TESTPACKS = {testpack for _, testpack, _, _ in FAMILIES.values()}


def _cli(arguments: list[str]) -> tuple[int, Any]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main([*arguments, "--json"])
    text = captured.getvalue().strip()
    return code, json.loads(text) if text else None


def _gate(expression: object) -> str | None:
    """The profile that an expression requires with a top-level ``profile.id eq`` term, if any."""
    terms = expression.all if isinstance(expression, All) else (expression,)
    for term in terms:
        if isinstance(term, Compare) and term.fact == "profile.id" and term.op.value == "eq":
            return str(term.value)
    return None


def test_each_family_profile_and_test_pack_loads() -> None:
    profiles, testpacks = load_profiles(ROOT), load_testpacks(ROOT)
    catalogue = load_catalogue(ROOT)
    assert PACK in catalogue.packs
    for profile_id, testpack_id, _, _ in FAMILIES.values():
        profile = profiles[profile_id]
        assert testpack_id in testpacks
        # Only the family pack: the battery packs read battery facts that a family profile lacks.
        assert profile.packs == (PACK,)
        assert set(profile.testpacks) == FAMILY_TESTPACKS
        assert profile.facts == {}, "a family profile declares no battery fact"
        assert (profile.item_schema, profile.api_contract) == (None, None)
        assert profile.roles == ("anonymous",)
    # The examples sit one level deeper, so that load_profiles does not read them as profiles.
    assert all(path.parent == EXAMPLES for path in EXAMPLES.glob("*.yaml"))


def test_the_family_files_lint_without_error() -> None:
    findings = lint(
        load_catalogue(ROOT), load_profiles(ROOT), load_testpacks(ROOT), registry.param_models(), ROOT
    )
    assert [f for f in findings if f.severity == "error"] == []
    family = [
        f for f in findings if f.location.startswith(("family/", "TP-WEB-", "TP-GS1-", "TP-AAS-", "TP-VC-"))
    ]
    assert family == [], "the family files give no finding at all"
    code, _ = _cli(["catalogue", "lint"])
    assert code == 0


def test_each_family_step_and_requirement_gates_on_its_own_profile() -> None:
    """Every family profile selects every family test pack, so each entry names its family."""
    testpacks = load_testpacks(ROOT)
    requirements = {r.id: r for r in load_catalogue(ROOT).packs[PACK].requirements}
    for profile_id, testpack_id, tp_prefix, requirement_prefix in FAMILIES.values():
        purposes = testpacks[testpack_id].test_purposes
        assert purposes, testpack_id
        for purpose in purposes:
            assert purpose.id.startswith(tp_prefix), purpose.id
            assert _gate(purpose.applicability) == profile_id, purpose.id
            assert purpose.stimulus.check in registry.names(), purpose.id
            assert purpose.stimulus.check != "api.contract", "a family profile pins no API contract"
            for requirement_id in purpose.requirements:
                assert requirement_id.startswith(requirement_prefix), (purpose.id, requirement_id)
                # The same expression, so that a step that does not apply leaves a requirement
                # that does not apply, never a requirement with an empty path.
                assert requirements[requirement_id].applicability == purpose.applicability
    for requirement in requirements.values():
        assert requirement.authority_class is AuthorityClass.ILLUSTRATIVE
        assert requirement.review_status is not ReviewStatus.APPROVED
        assert requirement.approval is None
        assert any("no normative statement" in i.text for i in requirement.interpretations), requirement.id
        assert [len(p.tests) for p in requirement.assessment_paths] == [1], requirement.id


def _example(tmp_path: Path, family: str, origin: str) -> tuple[Path, Path]:
    # The sample files of an example IXIT are relative to it, so they go next to the copy.
    shutil.copytree(EXAMPLES, tmp_path, dirs_exist_ok=True)
    ics = tmp_path / f"{family}.ics.yaml"
    ics.write_bytes((EXAMPLES / f"{family}.ics.yaml").read_bytes())
    ixit = yaml.safe_load((EXAMPLES / f"{family}.ixit.yaml").read_text(encoding="utf-8"))
    ixit["endpoints"]["origin_override"] = origin
    path = tmp_path / f"{family}.ixit.yaml"
    path.write_text(yaml.safe_dump(ixit, sort_keys=False), encoding="utf-8")
    return ics, path


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_dppce_plan_works_for_each_family_example(family: str) -> None:
    profile_id, _, tp_prefix, _ = FAMILIES[family]
    code, plan = _cli(
        [
            "plan",
            "--profile", profile_id,
            "--ics", str(EXAMPLES / f"{family}.ics.yaml"),
            "--ixit", str(EXAMPLES / f"{family}.ixit.yaml"),
        ]
    )  # fmt: skip
    assert code == 0
    assert plan["profile_id"] == profile_id
    assert plan["conflicts"] == []
    steps = plan["steps"]
    assert steps
    assert all(s["test_purpose_id"].startswith(tp_prefix) for s in steps), steps
    assert all(s["check"] != "unavailable" for s in steps), "no path names a step that cannot run"
    others = {
        e["id"]
        for e in plan["exclusions"]
        if e["kind"] == "test_purpose" and not e["id"].startswith(tp_prefix)
    }
    assert others, "the steps of the other families are left out"
    assert all(e["reason_code"] == "STEP.NOT_APPLICABLE" for e in plan["exclusions"] if e["id"] in others)


def _run(tmp_path: Path, family: str) -> tuple[int, EvidenceEnvelope]:
    profile_id = FAMILIES[family][0]
    server = ReferenceServer(FIXTURES)
    with server:
        ics, ixit = _example(tmp_path, family, server.origin)
        out = tmp_path / "run"
        code, _ = _cli(
            [
                "run",
                "--profile", profile_id,
                "--ics", str(ics),
                "--ixit", str(ixit),
                "--trust", str(TRUST),
                "--at", "2026-10-13T12:00:00Z",
                "--out", str(out),
                "--keys", str(tmp_path / "keys"),
                "--create-data-key",
                "--allow-private-host", server.origin,
                "--issuer-name", "dppce test rig (synthetic)",
                "--issuer-id", "urn:example:test-lab",
            ]
        )  # fmt: skip
    return code, EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())


@pytest.mark.parametrize("family", ["web", "gs1-resolver"])
def test_a_family_run_on_the_unmodified_reference_system_has_no_fail(tmp_path: Path, family: str) -> None:
    code, envelope = _run(tmp_path, family)
    decision = envelope.decision
    tp_prefix, requirement_prefix = FAMILIES[family][2], FAMILIES[family][3]
    assert [t.test_purpose_id for t in decision.test_results if t.verdict is Verdict.FAIL] == []
    assert [r.requirement_id for r in decision.requirement_results if r.verdict is Verdict.FAIL] == []
    for result in decision.test_results:
        assert result.test_purpose_id.startswith(tp_prefix), result.test_purpose_id
        if result.verdict is not Verdict.PASS:
            # A step that the reference system cannot serve says why. It is never a pass.
            assert result.verdict is Verdict.INCONCLUSIVE, result.test_purpose_id
            assert result.message.strip(), result.test_purpose_id
    own = [r for r in decision.requirement_results if r.requirement_id.startswith(requirement_prefix)]
    assert own
    assert all(r.verdict is Verdict.PASS for r in own), [(r.requirement_id, r.verdict) for r in own]
    others = [r for r in decision.requirement_results if not r.requirement_id.startswith(requirement_prefix)]
    assert others
    assert all(r.verdict is Verdict.NOT_APPLICABLE for r in others)
    assert (decision.overall, code) == (Verdict.PASS, 0)
