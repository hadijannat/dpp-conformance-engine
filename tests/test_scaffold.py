"""dppce init: draft an ICS and an IXIT for a family profile from the shipped examples.

The drafts are untrusted input (ADR 0011). init writes no confirmation, no secret, no trust
choice, and no authorization. The operator still confirms each of these on the command line.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from dppce import cli
from dppce.catalogue import check_ics, load_ics, load_ixit, load_profiles
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import EvidenceEnvelope, Verdict

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures" / "reference"
TRUST = FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"
FAMILIES = {"web": "TP-WEB-", "gs1-resolver": "TP-GS1-", "aas": "TP-AAS-", "credentials": "TP-VC-"}


def _cli(arguments: list[str]) -> tuple[int, Any]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli.main([*arguments, "--json"])
    text = captured.getvalue().strip()
    return code, json.loads(text) if text else None


def _init(out: Path, family: str, *extra: str) -> tuple[int, Any]:
    return _cli(["init", "--family", family, "--out", str(out), *extra])


def _paths(out: Path, family: str) -> tuple[Path, Path]:
    return out / f"{family}.ics.yaml", out / f"{family}.ixit.yaml"


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_init_drafts_files_that_load_and_plan(tmp_path: Path, family: str) -> None:
    code, result = _init(tmp_path, family)
    assert code == 0
    ics_path, ixit_path = _paths(tmp_path, family)
    assert result["files"] == [str(ics_path), str(ixit_path)]
    for path in (ics_path, ixit_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    ics, profile_id = load_ics(ics_path), f"family/{family}"
    load_ixit(ixit_path)
    assert check_ics(ics, load_profiles(ROOT)[profile_id]) == []
    code, plan = _cli(["plan", "--profile", profile_id, "--ics", str(ics_path), "--ixit", str(ixit_path)])
    assert code == 0
    assert plan["steps"]
    assert all(s["test_purpose_id"].startswith(FAMILIES[family]) for s in plan["steps"])


@pytest.mark.parametrize("family", sorted(FAMILIES))
def test_each_drafted_field_has_a_review_comment(tmp_path: Path, family: str) -> None:
    assert _init(tmp_path, family)[0] == 0
    for path in _paths(tmp_path, family):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not line.strip() or line.lstrip().startswith(("#", "- ")):
                continue
            above = lines[index - 1].strip() if index else ""
            assert above.startswith("# review: "), (path.name, line)


def test_a_gs1_carrier_fills_the_scheme_the_granularity_and_the_origin(tmp_path: Path) -> None:
    carrier = "https://id.acme.test/01/09506000134352/21/EV0001"
    code, result = _init(tmp_path, "gs1-resolver", "--carrier", carrier)
    assert code == 0
    assert result["derived"] == {
        "identifier_scheme": "gs1-digital-link",
        "granularity": "item",
        "public_origin": "https://id.acme.test",
    }
    ics_path, ixit_path = _paths(tmp_path, "gs1-resolver")
    ics, ixit = load_ics(ics_path), load_ixit(ixit_path)
    assert (ics.identifier_scheme, ics.granularity) == ("gs1-digital-link", "item")
    assert ixit.endpoints["public_origin"] == "https://id.acme.test"
    assert ixit.endpoints["api"] == "https://id.acme.test"
    assert ixit.samples["identifier"] == carrier
    # A synthetic sample of the reference system must not stand in for the real system.
    assert "gs1_declared" not in ixit.samples
    assert "passport_id" not in ixit.samples


def test_a_batch_carrier_gives_batch_granularity(tmp_path: Path) -> None:
    code, result = _init(
        tmp_path, "gs1-resolver", "--carrier", "https://id.acme.test/01/09506000134352/10/LOT1"
    )
    assert code == 0
    assert result["derived"]["granularity"] == "batch"


def test_the_family_scheme_wins_when_the_carrier_fits_it(tmp_path: Path) -> None:
    """A GS1 Digital Link URI is also an https URL. The web steps gate on https-url."""
    code, result = _init(tmp_path, "web", "--carrier", "https://id.acme.test/01/09506000134352/21/EV0001")
    assert code == 0
    assert result["derived"]["identifier_scheme"] == "https-url"
    assert load_ics(_paths(tmp_path, "web")[0]).identifier_scheme == "https-url"


def test_a_did_web_carrier_gives_the_did_web_scheme(tmp_path: Path) -> None:
    code, result = _init(tmp_path, "credentials", "--carrier", "did:web:id.acme.test")
    assert code == 0
    assert result["derived"] == {"identifier_scheme": "did-web", "public_origin": "https://id.acme.test"}


def test_an_unparsed_carrier_leaves_the_scheme_unknown(tmp_path: Path) -> None:
    code, result = _init(tmp_path, "web", "--carrier", "urn:isbn:0451450523")
    assert code == 0
    assert result["derived"] == {"identifier_scheme": "unknown"}
    ics_path, _ = _paths(tmp_path, "web")
    assert load_ics(ics_path).identifier_scheme == "unknown"
    assert "review: the engine could not parse the carrier" in ics_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("carrier", ["https://id.acme.test/a b", "https://id.acme.test/\n#x: 1", ""])
def test_a_carrier_with_whitespace_or_a_control_character_is_refused(tmp_path: Path, carrier: str) -> None:
    code, _ = _init(tmp_path, "web", "--carrier", carrier)
    assert code == 2
    assert list(tmp_path.iterdir()) == []


def test_init_writes_no_confirmation_no_secret_and_no_trust_choice(tmp_path: Path) -> None:
    code, result = _init(tmp_path, "credentials", "--carrier", "https://id.acme.test/dpp/1")
    assert code == 0
    ixit = load_ixit(_paths(tmp_path, "credentials")[1])
    assert ixit.authorization_ref is None
    assert ixit.trust.bundle is None
    assert all(identity.secret_ref is None for identity in ixit.identities)
    commands = [step["command"] for step in result["next_steps"]]
    assert any(c.startswith("dppce plan ") for c in commands)
    assert any(c.startswith("dppce run ") for c in commands)
    text = " ".join(commands)
    # Each value that a person decides is a placeholder, never a value that init chose.
    for flag in ("--trust", "--allow-private-host", "--allow-remote-host", "--authorization", "--issuer-id"):
        for value in re.findall(rf"{flag} (\S+)", text):
            assert re.fullmatch(r"<[A-Z-]+>", value), (flag, value)
    assert "TEST-ONLY" not in text
    decided = [step for step in result["next_steps"] if step["decision"]]
    assert any("dppce run " in step["command"] for step in decided)


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    ics_path, ixit_path = _paths(tmp_path, "web")
    ixit_path.write_text("mine\n", encoding="utf-8")
    code, _ = _init(tmp_path, "web")
    assert code == 2
    assert ixit_path.read_text(encoding="utf-8") == "mine\n"
    assert not ics_path.exists(), "init writes neither file if one of them exists"
    ixit_path.chmod(0o644)
    code, _ = _init(tmp_path, "web", "--force")
    assert code == 0
    load_ixit(ixit_path)
    assert stat.S_IMODE(ixit_path.stat().st_mode) == 0o600


def test_the_web_draft_runs_against_the_loopback_reference_system(tmp_path: Path) -> None:
    """The path of the tutorial: init, review, then a first run with explicit confirmations."""
    drafts = tmp_path / "drafts"
    assert _init(drafts, "web")[0] == 0
    ics_path, ixit_path = _paths(drafts, "web")
    server = ReferenceServer(FIXTURES)
    with server:
        # The review step of the tutorial: the test server listens on a free port, not on 8765.
        ixit = yaml.safe_load(ixit_path.read_text(encoding="utf-8"))
        ixit["endpoints"]["origin_override"] = server.origin
        ixit_path.write_text(yaml.safe_dump(ixit, sort_keys=False), encoding="utf-8")
        out = tmp_path / "run"
        code, _ = _cli(
            [
                "run",
                "--profile", "family/web",
                "--ics", str(ics_path),
                "--ixit", str(ixit_path),
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
    envelope = EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())
    assert (envelope.decision.overall, code) == (Verdict.PASS, 0)
