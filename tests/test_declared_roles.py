"""The profile declares a closed set of access roles (gap D5-01, criterion 3).

A role that the access policy, an IXIT identity, the authorization, or a selected test purpose
names must be in that set. Otherwise `plan`, `run`, and `replay` stop with exit code 2. Every
key and token here is TEST-ONLY. Only the loopback reference system answers a request.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from validation.rig import FIXTURES, ROOT, TRUST, ReferenceRig

from dppce import cli
from dppce.catalogue import load_profiles
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import issue_authorization
from dppce.infrastructure.reference_server import ReferenceSystem
from dppce.models import ICS, IXIT, Authorization, TestPurpose
from dppce.testdefs.registry import CheckContext
from tests.core import builders as b
from tests.test_url_templates import Canned, run

AT = "2026-10-13T12:00:00Z"
POLICY = Path("profiles/battery/access/reference-policy.yaml")
PURPOSE = "TEST-ONLY-TP-ROLE"
TESTPACK = "test-only/roles"


def _ixit(tmp_path: Path, *roles: str) -> Path:
    ixit = yaml.safe_load((FIXTURES / "ev.ixit.yaml").read_text(encoding="utf-8"))
    ixit["identities"] += [{"role": role} for role in roles]
    path = tmp_path / "rig" / "ixit.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(ixit), encoding="utf-8")
    return path


def _plan(ixit: Path, *extra: str) -> list[str]:
    return [
        "plan", "--profile", "battery/ev", "--mode", "illustrative", "--at", AT,
        "--ics", str(FIXTURES / "ev.ics.yaml"), "--ixit", str(ixit), *extra,
    ]  # fmt: skip


def _error(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = cli.main(arguments)
    return code, capsys.readouterr().err


def _data_copy(target: Path) -> Path:
    for name in ("catalogue", "profiles", "testpacks"):
        shutil.copytree(ROOT / name, target / name)
    return target


def _edit(path: Path, change: Any) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_an_ixit_identity_with_an_undeclared_role_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = _error(_plan(_ixit(tmp_path, "auditor")), capsys)
    assert code == 2
    assert "does not declare a role" in err
    assert "the IXIT names the role 'auditor'." in err


def test_the_message_shows_an_untrusted_role_in_repr_form(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = _error(_plan(_ixit(tmp_path, "aud\x1bitor")), capsys)
    assert code == 2
    assert "'aud\\x1bitor'" in err
    assert "\x1b" not in err


def test_run_refuses_an_undeclared_role_before_any_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ixit = _ixit(tmp_path, "auditor")
    arguments = _plan(ixit, "--out", str(tmp_path / "out"), "--keys", str(tmp_path / "keys"))
    code, err = _error(["run", *arguments[1:]], capsys)
    assert code == 2
    assert "the IXIT names the role 'auditor'." in err
    assert not (tmp_path / "out").exists()


def test_an_authorization_with_an_undeclared_role_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    owner = LocalSigner.from_pem(
        FIXTURES / "authorization" / "TEST-ONLY-owner.key.pem", "TEST-ONLY-owner-key-1"
    )
    grant = Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-roles-authorization",
        issuer="urn:example:operator:0001",
        subject="urn:example:test-lab",
        sut_identifier="urn:example:sut:reference-dpp",
        endpoints=("http://127.0.0.1:8765",),
        methods=("GET",),
        roles=("anonymous", "auditor"),
        scopes=("read", "access_probe"),
        not_before="2026-01-01T00:00:00Z",
        not_after="2036-01-01T00:00:00Z",
        max_requests=10,
    )
    token = tmp_path / "TEST-ONLY-authorization.jws"
    token.write_text(issue_authorization(grant, owner) + "\n", encoding="ascii")
    arguments = _plan(_ixit(tmp_path), "--trust", str(TRUST), "--authorization", str(token))
    code, err = _error(arguments, capsys)
    assert code == 2
    assert "the authorization names the role 'auditor'." in err


@pytest.mark.parametrize(
    "changes",
    [
        {"roles": ["auditor"]},
        {"stimulus": {"check": "access.restricted_fields", "params": {"role": "auditor"}}},
    ],
    ids=["roles", "params.role"],
)
def test_a_selected_test_purpose_with_an_undeclared_role_is_an_input_error(
    changes: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    purpose = b.purpose(PURPOSE, requirements=["ILL-ACCESS-001"], **changes)
    testpack = tmp_path / "imports" / "testpack.yaml"
    testpack.parent.mkdir()
    testpack.write_text(
        b.purposes_pack(purpose, testpack_id=TESTPACK).model_dump_json(by_alias=True), encoding="utf-8"
    )
    ixit = _ixit(tmp_path)
    code, err = _error(_plan(ixit, "--import-testpack", str(testpack), "--testpack", TESTPACK), capsys)
    assert code == 2
    assert f"test purpose {PURPOSE} names the role 'auditor'." in err
    # Control: an imported test pack that is not selected is not read.
    code, err = _error(_plan(ixit, "--import-testpack", str(testpack)), capsys)
    assert "auditor" not in err
    assert code != 2


def test_a_bound_policy_with_an_undeclared_role_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = _data_copy(tmp_path / "data")
    _edit(data / POLICY, lambda p: p["restricted"].append({"path": "restricted.audit", "roles": ["auditor"]}))
    code, err = _error(_plan(_ixit(tmp_path), "--data-root", str(data)), capsys)
    assert code == 2
    assert "the access policy names the role 'auditor'." in err


@pytest.mark.qr  # the reference rig reads QR images
def test_a_policy_that_is_not_valid_is_reported_by_the_check_not_as_an_input_error(tmp_path: Path) -> None:
    data = _data_copy(tmp_path / "data")
    # One path twice makes the policy not valid. Its undeclared role is then not read.
    twice = {"path": "restricted.supplier_reference", "roles": ["auditor"]}
    _edit(data / POLICY, lambda p: p["restricted"].append(twice))
    with ReferenceRig(tmp_path, data_root=data) as rig:
        run = rig.run()
    assert run.exit_code != 2
    assert run.step("TP-ACCESS-001") == {
        "verdict": "inconclusive",
        "reason_code": "ACCESS.POLICY.MISSING",
        "status": "blocked",
    }


@pytest.mark.qr
@pytest.mark.parametrize("version", [1, 2])
def test_replay_refuses_a_role_that_the_current_profile_does_not_declare(
    version: int, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A version 2 record holds input hashes, so the replay input check refuses the changed
    profile first. A version 1 record has no hashes, so the role check refuses it."""
    with ReferenceRig(tmp_path / "rig") as rig:
        run = rig.run()
    if version == 1:
        record = run.run_dir / "inputs.json"
        document = json.loads(record.read_bytes())
        del document["data_root"], document["input_hashes"]
        document["schema_version"] = "dppce.runinputs/1"
        # A version 1 record embeds a dppce.trust/1 bundle. The rig's bundle revokes nothing.
        trust = document["trust"]
        for name in ("revoked_certificates", "revoked_keys", "timestamp_anchors"):
            assert trust.pop(name) == []
        trust.update(schema_version="dppce.trust/1", revoked_serials=[], revoked_kids=[])
        record.write_bytes(canonical_bytes(document) + b"\n")
    data = _data_copy(tmp_path / "data")
    profile = data / "profiles" / "battery" / "ev.yaml"
    _edit(profile, lambda p: p.update(roles=[r for r in p["roles"] if r != "legitimate_interest"]))
    capsys.readouterr()
    arguments = ["replay", "--run", str(run.run_dir), "--keys", str(tmp_path / "rig" / "keys")]
    code, err = _error([*arguments, "--data-root", str(data)], capsys)
    assert code == 2
    if version == 1:
        assert "names the role 'legitimate_interest'." in err
    else:
        assert "REPLAY.INPUT.CHANGED: these inputs differ from the run: profile;" in err


@pytest.mark.parametrize(
    ("check", "params", "code"),
    [("data.jsonschema", {"document": "item"}, "DATA.SCHEMA.OK"), ("api.contract", {}, "API.CONTRACT.OK")],
)
def test_the_pinned_schema_and_contract_admit_the_legitimate_interest_view(
    check: str, params: dict[str, Any], code: str
) -> None:
    """The reference system gives this role restricted.usage_log. A control that reads that
    credentialed view must not fail on the bound item schema or the bound API contract."""
    ixit = IXIT.model_validate(yaml.safe_load((FIXTURES / "ev.ixit.yaml").read_text(encoding="utf-8")))
    view = ReferenceSystem(FIXTURES).item(ixit.samples["passport_id"], "legitimate_interest")
    assert "usage_log" in view["restricted"]
    purpose = TestPurpose.model_validate(
        {
            "id": "TP-X",
            "title": "t",
            "requirements": ["R"],
            "profiles": ["*"],
            "applicability": {"const": "true"},
            "stimulus": {"check": check, "params": params},
            "permitted_modes": ["illustrative"],
        }
    )
    ctx = CheckContext(
        purpose=purpose,
        ics=ICS.model_validate(yaml.safe_load((FIXTURES / "ev.ics.yaml").read_text(encoding="utf-8"))),
        ixit=ixit,
        profile=load_profiles(ROOT)["battery/ev"],
        acquirer=Canned(json.dumps(view).encode()),
        evaluation_time=datetime(2026, 10, 13, tzinfo=UTC),
        data_root=ROOT,
    )
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, code), outcome.message
