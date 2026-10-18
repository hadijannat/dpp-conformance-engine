"""URL templates of the IXIT and the bound contract and policy (gaps D3-01 and D5-04).

The IXIT declares a path template per fetched resource. A template is a path under an endpoint
that the IXIT names: it can never change the scheme, the host, or the port. A resource with no
template is blocked; the engine has no default path. The ICS names the contract and the policy
that it expects, and a different bound file blocks the check.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml
from pydantic import ValidationError

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.common import resource_url, template_url
from dppce.catalogue import load_model, sanitized_ixit
from dppce.evidence.canonical import canonical_bytes, digest
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import (
    ICS,
    IXIT,
    CheckOutcome,
    ExecutionMode,
    ExecutionStatus,
    Profile,
    ResourceName,
    TestPurpose,
    TrustBundle,
)
from dppce.orchestrator.run import RunInputs, evaluate  # noqa: TID251 - a run shows the manifest
from dppce.testdefs import registry
from dppce.testdefs.registry import CheckContext
from tests.core import builders as b
from tests.support import AT, make_manifest, make_record

ROOT = Path(__file__).resolve().parent.parent
ADAPTERS = ROOT / "src" / "dppce" / "adapters"
API = "https://id.example.test"
REFERENCE: dict[str, Any] = {
    "item": {"endpoint": "api", "path": "/dpp/{id}"},
    "model": {"endpoint": "api", "path": "/dpp/{id}/model"},
    "signed": {"endpoint": "api", "path": "/dpp/{id}/signed"},
    "versions": {"endpoint": "api", "path": "/dpp/{id}/versions"},
    "registry_record": {"endpoint": "registry", "path": "/registry/{id}"},
}
SPLIT: dict[str, Any] = {"separator": "-", "names": ["gtin", "serial"]}
CONTRACT: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {"title": "test", "version": "1"},
    "x-dppce-contract-id": "test/api",
    "paths": {
        "/dpp/{id}": {
            "x-dppce-resource": "item",
            "get": {"responses": {"200": {"content": {"application/json": {}}}}},
        },
        "/dpp/{id}/model": {
            "x-dppce-resource": "model",
            "get": {"responses": {"200": {"content": {"application/json": {}}}}},
        },
    },
}
POLICY: dict[str, Any] = {
    "schema_version": "dppce.accesspolicy/1",
    "policy_id": "test/policy",
    "version": "1",
    "basis": {"class": "illustrative"},
    "restricted": [{"path": "restricted.secret", "roles": ["authority"]}],
    "canaries": [{"path": "restricted.secret", "value": "CANARY-test"}],
    "channels": {"fetch": "/dpp/{id}"},
}
RULES: dict[str, Any] = {
    "schema_version": "dppce.rulepack/1",
    "rulepack_id": "test/rules",
    "version": "1",
    "rules": [],
}


class Canned:
    """An acquirer that answers every request with one JSON body and records each request."""

    def __init__(self, body: bytes = b'{"id": "x"}') -> None:
        self._body = body
        self._records: list[Record] = []

    def fetch(self, request: Request) -> Record:
        record = make_record(len(self._records) + 1, self._body, request.url)
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        raise AssertionError(f"no artifact is read ({name})")

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)


def ixit(**changes: Any) -> IXIT:
    fields: dict[str, Any] = {
        "schema_version": "dppce.ixit/1",
        "endpoints": {"api": API, "registry": API},
        "samples": {"passport_id": "09506000134352-EV0001"},
        "resources": REFERENCE,
        "id_parts": SPLIT,
    }
    return IXIT.model_validate(fields | changes)


def write_data(root: Path, *, contract: Any = None, policy: dict[str, Any] | None = None) -> None:
    (root / "contract.yaml").write_text(
        yaml.safe_dump(CONTRACT if contract is None else contract), encoding="utf-8"
    )
    (root / "policy.yaml").write_text(yaml.safe_dump(policy or POLICY), encoding="utf-8")
    (root / "schema.json").write_text("{}", encoding="utf-8")
    (root / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")


def context(
    root: Path,
    check: str,
    *,
    params: dict[str, Any] | None = None,
    the_ixit: IXIT | None = None,
    ics_changes: dict[str, Any] | None = None,
    acquirer: Canned | None = None,
    trust: TrustBundle | None = None,
) -> CheckContext:
    if not (root / "contract.yaml").exists():
        write_data(root)
    purpose = TestPurpose.model_validate(
        {
            "id": "TP-X",
            "title": "t",
            "requirements": ["R"],
            "profiles": ["*"],
            "applicability": {"const": "true"},
            "stimulus": {"check": check, "params": params or {}},
            "permitted_modes": ["illustrative"],
        }
    )
    profile = Profile.model_validate(
        {
            "schema_version": "dppce.profile/1",
            "id": "p/x",
            "title": "t",
            "product_category": "x",
            "item_schema": "schema.json",
            "model_schema": "schema.json",
            "rule_packs": ["rules.json"],
            "api_contract": "contract.yaml",
            "access_policy": "policy.yaml",
            "packs": [],
            "testpacks": [],
        }
    )
    ics = ICS.model_validate(
        {
            "schema_version": "dppce.ics/1",
            "sut": {"name": "s", "identifier": "urn:x"},
            "profile": "p/x",
            "api": {"contract": "test/api"},
            "access": {"policy": "test/policy"},
        }
        | (ics_changes or {})
    )
    return CheckContext(
        purpose=purpose,
        ics=ics,
        ixit=the_ixit or ixit(),
        profile=profile,
        acquirer=acquirer or Canned(),
        evaluation_time=datetime(2026, 10, 13, tzinfo=UTC),
        data_root=root,
        trust=trust,
    )


def run(ctx: CheckContext) -> CheckOutcome:
    spec = registry.get(ctx.purpose.stimulus.check)
    assert spec is not None
    return spec.fn(ctx)


def sent(ctx: CheckContext) -> int:
    return len(ctx.acquirer.records())


# -- the IXIT model ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "dpp/{id}",
        "//evil.example/x",
        "https://evil.example/x",
        "/x#f",
        "/x\\y",
        "/x y",
        "/{ID}",
        "/{id",
        "/x\n",
        "/" + "a" * 512,
    ],
)
def test_an_ixit_template_is_a_path_under_its_endpoint(path: str) -> None:
    with pytest.raises(ValidationError):
        ixit(resources={"item": {"endpoint": "api", "path": path}})


def test_an_ixit_template_names_a_declared_endpoint_and_declared_placeholders() -> None:
    with pytest.raises(ValidationError, match="names the endpoint 'elsewhere'"):
        ixit(resources={"item": {"endpoint": "elsewhere", "path": "/dpp/{id}"}})
    with pytest.raises(ValidationError, match="undeclared placeholders"):
        ixit(resources={"item": {"endpoint": "api", "path": "/p/{serial}"}}, id_parts=None)
    assert ixit(resources={"item": {"endpoint": "api", "path": "/p/{gtin}/{serial}"}}).resources


@pytest.mark.parametrize(
    "names", [["gtin", "gtin"], ["id", "serial"], ["gtin"], ["Gtin", "serial"], list("abcdefghi")]
)
def test_id_parts_names_are_distinct_and_never_id(names: list[str]) -> None:
    with pytest.raises(ValidationError):
        ixit(id_parts={"separator": "-", "names": names})


def test_item_target_defaults_to_template_and_refuses_other_values() -> None:
    assert ixit().item_target == "template"
    assert ixit(item_target="template").item_target == "template"
    assert ixit(item_target="resolved").item_target == "resolved"
    for value in ("RESOLVED", "", None):
        with pytest.raises(ValidationError):
            ixit(item_target=value)


def test_the_default_item_target_does_not_change_the_sanitized_ixit() -> None:
    plain = sanitized_ixit(ixit())
    assert "item_target" not in plain
    without = {k: v for k, v in ixit().model_dump(mode="json").items() if k != "item_target"}
    assert digest(plain) == digest(without), "an IXIT without the option keeps its hash"
    resolved = sanitized_ixit(ixit(item_target="resolved"))
    assert resolved["item_target"] == "resolved"
    assert digest(resolved) != digest(plain)


@pytest.mark.parametrize("profile", ["ev", "lmt", "industrial"])
def test_the_reference_fixtures_build_the_reference_urls_byte_for_byte(profile: str, tmp_path: Path) -> None:
    the_ixit = load_model(ROOT / "fixtures" / "reference" / f"{profile}.ixit.yaml", IXIT)
    ident = the_ixit.samples["passport_id"]
    ctx = context(tmp_path, "persistence.versions", the_ixit=the_ixit)
    expected: dict[ResourceName, str] = {
        "item": f"{API}/dpp/{ident}",
        "model": f"{API}/dpp/{ident}/model",
        "signed": f"{API}/dpp/{ident}/signed",
        "versions": f"{API}/dpp/{ident}/versions",
        "registry_record": f"{API}/registry/{ident}",
    }
    assert {name: resource_url(ctx, name, "X") for name in expected} == expected


def test_a_placeholder_value_cannot_change_the_path_structure(tmp_path: Path) -> None:
    the_ixit = ixit(samples={"passport_id": "a/b?c#d@e"}, id_parts=None)
    url = resource_url(context(tmp_path, "persistence.versions", the_ixit=the_ixit), "item", "X")
    assert isinstance(url, str)
    assert url == f"{API}/dpp/a%2Fb%3Fc%23d%40e"
    parts, base = urlsplit(url), urlsplit(API)
    assert (parts.scheme, parts.netloc, parts.query, parts.fragment) == (base.scheme, base.netloc, "", "")


@pytest.mark.parametrize(
    "endpoints",
    [
        {"api": "https://id.example.test/?q=1", "registry": API},
        {"api": "https://id.example.test/#f", "registry": API},
        {"api": "ftp://id.example.test", "registry": API},
        {"api": "https://", "registry": API},
        {"registry": API},
    ],
)
def test_an_endpoint_that_is_not_a_plain_base_url_gives_no_target(
    endpoints: dict[str, str], tmp_path: Path
) -> None:
    # model_copy skips validation. An IXIT whose template names a missing endpoint cannot load,
    # but the helper must refuse it as well.
    the_ixit = ixit().model_copy(update={"endpoints": endpoints})
    ctx = context(tmp_path, "persistence.versions", the_ixit=the_ixit)
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "PERSISTENCE.NO_TARGET")
    assert sent(ctx) == 0


def _trust() -> TrustBundle:
    return TrustBundle(schema_version="dppce.trust/2", policy_version="test")


@pytest.mark.parametrize(
    ("check", "params", "code"),
    [
        ("data.jsonschema", {"document": "item"}, "DATA.NO_TARGET"),
        ("data.jsonschema", {"document": "model"}, "DATA.NO_TARGET"),
        ("data.context", {"allowed_contexts": ["https://ctx.example.test"]}, "DATA.NO_TARGET"),
        ("data.rules", {"document": "item"}, "DATA.NO_TARGET"),
        ("persistence.versions", {}, "PERSISTENCE.NO_TARGET"),
        ("integrity.jws", {}, "INTEGRITY.NO_TARGET"),
        ("registry.consistency", {}, "REGISTRY.NO_TARGET"),
        ("api.contract", {"method": "get"}, "API.CONTRACT.NO_TARGET"),
    ],
)
def test_each_fetching_check_is_blocked_without_a_template_and_sends_nothing(
    check: str, params: dict[str, Any], code: str, tmp_path: Path
) -> None:
    ctx = context(tmp_path, check, params=params, the_ixit=ixit(resources={}), trust=_trust())
    outcome = run(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)
    assert sent(ctx) == 0


@pytest.mark.parametrize("passport_id", ["09506000134352EV0001", "-SER", "0950-"])
def test_an_identifier_that_does_not_split_as_declared_gives_no_target(
    passport_id: str, tmp_path: Path
) -> None:
    resources = REFERENCE | {"item": {"endpoint": "api", "path": "/p/{gtin}/{serial}"}}
    the_ixit = ixit(samples={"passport_id": passport_id}, resources=resources)
    ctx = context(tmp_path, "data.jsonschema", params={"document": "item"}, the_ixit=the_ixit)
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "DATA.NO_TARGET")
    assert "does not split into the declared parts" in outcome.message
    assert sent(ctx) == 0


def test_the_last_identifier_part_keeps_further_separators(tmp_path: Path) -> None:
    resources = REFERENCE | {"item": {"endpoint": "api", "path": "/p/{gtin}/{serial}"}}
    the_ixit = ixit(samples={"passport_id": "a-b-c"}, resources=resources)
    ctx = context(tmp_path, "persistence.versions", the_ixit=the_ixit)
    assert resource_url(ctx, "item", "X") == f"{API}/p/a/b-c"


def test_the_access_check_takes_the_serial_from_the_declared_split(tmp_path: Path) -> None:
    write_data(tmp_path, policy=POLICY | {"channels": {"search": "/search?q={serial}"}})
    the_ixit = ixit(
        samples={"passport_id": "0950.SER-1"}, id_parts={"separator": ".", "names": ["gtin", "serial"]}
    )
    ctx = context(
        tmp_path, "access.restricted_fields", the_ixit=the_ixit, acquirer=Canned(b'{"results": []}')
    )
    outcome = run(ctx)
    assert outcome.reason_code == "ACCESS.POLICY.ENFORCED"
    (record,) = ctx.acquirer.records()
    assert record.url == f"{API}/search?q=SER-1"


def test_an_access_channel_with_an_undeclared_placeholder_gives_no_target(tmp_path: Path) -> None:
    channels = {"fetch": "/dpp/{id}", "search": "/search?q={serial}"}
    write_data(tmp_path, policy=POLICY | {"channels": channels})
    ctx = context(tmp_path, "access.restricted_fields", the_ixit=ixit(id_parts=None))
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.NO_TARGET")
    assert sent(ctx) == 0, "every channel URL is built before the first request"


@pytest.mark.parametrize("channel", ["https://evil.example/x", "//evil.example/x", "/x#f", "x"])
def test_an_access_policy_channel_outside_the_grammar_is_not_loaded(channel: str, tmp_path: Path) -> None:
    write_data(tmp_path, policy=POLICY | {"channels": {"fetch": channel}})
    ctx = context(tmp_path, "access.restricted_fields")
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.POLICY.MISSING")
    assert sent(ctx) == 0


@pytest.mark.parametrize("template", ["/x\n", "x", "//evil.example/x", "/x#f", ""])
def test_template_url_refuses_a_string_that_is_not_a_template(template: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="template"):
        template_url(context(tmp_path, "persistence.versions"), "api", template, "X")


def test_no_adapter_holds_a_url_path_literal() -> None:
    """Criterion 2 of gap D3-01: every fetched URL comes from a template of the IXIT."""
    pattern = re.compile(r"'/dpp/|/registry/|/signed|/versions")
    found = [
        f"{path.name}:{number}"
        for path in sorted(ADAPTERS.glob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if pattern.search(line)
    ]
    assert found == []


# -- api.contract judges the operation that the contract marks ---------------------------------


def _contract_paths(paths: dict[str, Any]) -> dict[str, Any]:
    return CONTRACT | {"paths": paths}


_ANY_200: dict[str, Any] = {"get": {"responses": {"200": {"content": {"application/json": {}}}}}}


def test_api_contract_judges_the_operation_that_the_contract_marks(tmp_path: Path) -> None:
    marked = _contract_paths({"/passports/{passportId}/data": {"x-dppce-resource": "item", **_ANY_200}})
    write_data(tmp_path, contract=marked)
    resources = REFERENCE | {"item": {"endpoint": "api", "path": "/passports/{id}/data"}}
    ctx = context(tmp_path, "api.contract", params={"resource": "item"}, the_ixit=ixit(resources=resources))
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")
    (record,) = ctx.acquirer.records()
    assert record.url == f"{API}/passports/09506000134352-EV0001/data"
    assert outcome.observations[0].summary["resource"] == "item"

    twice = _contract_paths(
        {
            "/passports/{passportId}/data": {"x-dppce-resource": "item", **_ANY_200},
            "/other/{passportId}": {"x-dppce-resource": "item", **_ANY_200},
        }
    )
    write_data(tmp_path, contract=twice)
    ctx = context(tmp_path, "api.contract", the_ixit=ixit(resources=resources))
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        "API.CONTRACT.UNSUPPORTED_FEATURE",
    )
    assert sent(ctx) == 0


def test_api_contract_refuses_a_template_that_names_an_unmarked_operation(tmp_path: Path) -> None:
    lenient = _contract_paths(
        {
            "/dpp/{id}": {"x-dppce-resource": "item", **CONTRACT["paths"]["/dpp/{id}"]},
            "/lenient/{id}": {"get": {"responses": {"200": {"content": {"text/plain": {}}}}}},
        }
    )
    write_data(tmp_path, contract=lenient)
    resources = REFERENCE | {"item": {"endpoint": "api", "path": "/lenient/{id}"}}
    ctx = context(tmp_path, "api.contract", the_ixit=ixit(resources=resources))
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "API.CONTRACT.PATH_MISMATCH")
    assert sent(ctx) == 0


def test_api_contract_without_a_marker_for_the_resource_is_unsupported(tmp_path: Path) -> None:
    write_data(tmp_path, contract=_contract_paths({"/dpp/{id}": _ANY_200}))
    ctx = context(tmp_path, "api.contract")
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        "API.CONTRACT.UNSUPPORTED_FEATURE",
    )
    assert "marks no operation" in outcome.message
    assert sent(ctx) == 0


def test_api_contract_path_parameter_must_equal_the_template_path(tmp_path: Path) -> None:
    ctx = context(tmp_path, "api.contract", params={"path": "/other/{id}", "method": "get"})
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "API.CONTRACT.PATH_MISMATCH")
    assert sent(ctx) == 0
    same = context(tmp_path, "api.contract", params={"path": "/dpp/{id}", "method": "get"})
    assert run(same).reason_code == "API.CONTRACT.OK", "a path that equals the template path is accepted"


@pytest.mark.parametrize("resource", ["registry_record", "nothing", 7])
def test_api_contract_needs_a_resource_with_a_template(resource: Any, tmp_path: Path) -> None:
    resources = {k: v for k, v in REFERENCE.items() if k != "registry_record"}
    ctx = context(tmp_path, "api.contract", params={"resource": resource}, the_ixit=ixit(resources=resources))
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "API.CONTRACT.NO_TARGET")
    assert sent(ctx) == 0


@pytest.mark.parametrize("text", ["- a\n- b\n", "just text\n", "7\n"])
def test_a_contract_file_that_is_not_a_mapping_is_missing(text: str, tmp_path: Path) -> None:
    write_data(tmp_path)
    (tmp_path / "contract.yaml").write_text(text, encoding="utf-8")
    ctx = context(tmp_path, "api.contract")
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "API.CONTRACT.MISSING")
    assert sent(ctx) == 0


@pytest.mark.parametrize(
    ("declared", "contract", "code"),
    [
        ("unknown", CONTRACT, "API.CONTRACT.NOT_DECLARED"),
        ("other/api", CONTRACT, "API.CONTRACT.ICS_MISMATCH"),
        (
            "test/api",
            {k: v for k, v in CONTRACT.items() if k != "x-dppce-contract-id"},
            "API.CONTRACT.ICS_MISMATCH",
        ),
    ],
)
def test_the_ics_must_name_the_bound_contract(
    declared: str, contract: dict[str, Any], code: str, tmp_path: Path
) -> None:
    write_data(tmp_path, contract=contract)
    ctx = context(tmp_path, "api.contract", ics_changes={"api": {"contract": declared}})
    outcome = run(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)
    assert sent(ctx) == 0


@pytest.mark.parametrize(
    ("declared", "code"),
    [("unknown", "ACCESS.POLICY.NOT_DECLARED"), ("other/policy", "ACCESS.POLICY.ICS_MISMATCH")],
)
def test_the_ics_must_name_the_bound_access_policy(declared: str, code: str, tmp_path: Path) -> None:
    ctx = context(tmp_path, "access.restricted_fields", ics_changes={"access": {"policy": declared}})
    outcome = run(ctx)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)
    assert sent(ctx) == 0


# -- the run manifest -------------------------------------------------------------------------


def test_a_manifest_without_bound_files_keeps_its_canonical_form() -> None:
    manifest = make_manifest(bound_files=None)
    assert manifest.bound_files is None
    assert b"bound_files" not in canonical_bytes(manifest)
    assert b'"bound_files":{}' in canonical_bytes(manifest.model_copy(update={"bound_files": {}}))


def test_an_unreadable_bound_file_is_recorded_as_unavailable(tmp_path: Path) -> None:
    write_data(tmp_path)
    inputs = RunInputs(
        mode=ExecutionMode.ILLUSTRATIVE,
        profile=b.profile(item_schema="schema.json", model_schema="missing.json", rule_packs=["rules.json"]),
        catalogue=b.catalogue(b.pack(b.requirement("R-1"))),
        testpacks={"tp/a": b.purposes_pack(b.purpose("T-1"))},
        ics=b.ics(),
        ixit=ixit(),
        data_root=tmp_path,
        evaluation_time=AT,
    )
    bound = evaluate(inputs, Canned()).manifest.bound_files
    assert bound is not None
    assert bound["missing.json"] == "unavailable"
    assert sorted(bound) == ["missing.json", "rules.json", "schema.json"]
    assert bound["schema.json"].startswith("sha256:")
