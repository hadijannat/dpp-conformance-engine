"""Document sources and bound parameter files of the data checks (package P2-24, OD-07).

Expected values come from docs/explanation/architecture.md, section 8 (data check sources) and
section 9.2 (bound files). A system under test must not turn a fail into blocked by reshaping its
documents: each embedded JSON-LD document is judged, and a document that does not parse is a fail.
An unverified credential payload is never judged.

Every key is a TEST-ONLY key made at run time. No test contacts a host.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.data import DocumentParams, RulesParams, SchemaParams
from dppce.models import CheckOutcome, ExecutionStatus, TrustBundle
from dppce.orchestrator.run import bound_files  # noqa: TID251 - the bound files of a run
from tests.core import builders as b
from tests.support import ArtifactAcquirer, make_artifact
from tests.test_jose_profiles import KID, NOW, VC_HEADER, Served, bundle, compact, jwk, p256, vc
from tests.test_url_templates import Canned, context, run, write_data

DRAFT_07 = "http://json-schema.org/draft-07/schema#"
ID_SCHEMA: dict[str, Any] = {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
SUBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["credentialSubject"],
    "properties": {"credentialSubject": {"type": "object", "required": ["id"]}},
}
ALLOWED = ["https://example.test/ctx"]
REQUIRED_NAME: dict[str, Any] = {
    "schema_version": "dppce.rulepack/1",
    "rulepack_id": "test/required-name",
    "version": "1",
    "rules": [
        {
            "id": "R-NAME",
            "kind": "required_fields",
            "document": "item",
            "basis": {"class": "engineering"},
            "fields": ["name"],
        }
    ],
}


def check(
    tmp_path: Path,
    name: str,
    acquirer: Any,
    *,
    profile_schema: Any = None,
    trust: TrustBundle | None = None,
    **params: Any,
) -> CheckOutcome:
    write_data(tmp_path)
    if profile_schema is not None:
        (tmp_path / "schema.json").write_text(json.dumps(profile_schema), encoding="utf-8")
    (tmp_path / "rules.json").write_text(json.dumps(REQUIRED_NAME), encoding="utf-8")
    ctx = context(tmp_path, name, params=params, trust=trust)
    return run(replace(ctx, acquirer=acquirer, evaluation_time=NOW))


def verdict(outcome: CheckOutcome) -> tuple[ExecutionStatus, bool | None, str]:
    return outcome.status, outcome.passed, outcome.reason_code


def failed(code: str) -> tuple[ExecutionStatus, bool | None, str]:
    return ExecutionStatus.COMPLETED, False, code


def passed(code: str) -> tuple[ExecutionStatus, bool | None, str]:
    return ExecutionStatus.COMPLETED, True, code


def blocked(code: str) -> tuple[ExecutionStatus, bool | None, str]:
    return ExecutionStatus.BLOCKED, None, code


# -- the default source keeps today's outcome and summary ----------------------------------------


def test_the_default_source_keeps_the_observation_summary_of_today(tmp_path: Path) -> None:
    """A changed summary key would change the decision digest of every existing recording."""
    body = b'{"@context": "https://example.test/ctx", "id": "x", "name": "n"}'
    schema = check(tmp_path, "data.jsonschema", Canned(body), profile_schema=ID_SCHEMA)
    assert verdict(schema) == passed("DATA.SCHEMA.OK")
    assert set(schema.observations[0].summary) == {"document", "schema", "schema_errors"}
    contexts = check(tmp_path, "data.context", Canned(body), allowed_contexts=ALLOWED)
    assert verdict(contexts) == passed("DATA.CONTEXT.OK")
    assert set(contexts.observations[0].summary) == {"document", "contexts", "not_allowed"}
    rules = check(tmp_path, "data.rules", Canned(body))
    assert verdict(rules) == passed("DATA.RULES.OK")
    assert set(rules.observations[0].summary) == {
        "document",
        "rule_packs",
        "rules_applied",
        "failed_rules",
        "failed_engineering_rules",
    }


@pytest.mark.parametrize("source", ["item", "model"])
def test_the_source_item_or_model_reads_that_resource(tmp_path: Path, source: str) -> None:
    acquirer = Canned(b'{"id": 1}')
    outcome = check(tmp_path, "data.jsonschema", acquirer, profile_schema=ID_SCHEMA, source=source)
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
    path = acquirer.records()[0].url.split("example.test", 1)[1]
    assert path == ("/dpp/09506000134352-EV0001" + ("/model" if source == "model" else ""))
    assert outcome.observations[0].summary["source"] == source


# -- an IXIT sample ------------------------------------------------------------------------------


def test_a_sample_source_reads_the_ixit_sample_and_sends_no_request(tmp_path: Path) -> None:
    acquirer = ArtifactAcquirer({"passport_json": make_artifact("passport_json", b'{"id": 1}')})
    outcome = check(tmp_path, "data.jsonschema", acquirer, profile_schema=ID_SCHEMA, source="passport_json")
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
    assert outcome.observations[0].kind == "artifact"
    good = ArtifactAcquirer({"passport_json": make_artifact("passport_json", b'{"id": "x"}')})
    outcome = check(tmp_path, "data.jsonschema", good, profile_schema=ID_SCHEMA, source="passport_json")
    assert verdict(outcome) == passed("DATA.SCHEMA.OK")


def test_a_missing_sample_is_blocked_and_a_sample_that_is_not_json_fails(tmp_path: Path) -> None:
    outcome = check(tmp_path, "data.rules", ArtifactAcquirer(), source="passport_json")
    assert verdict(outcome) == blocked("DATA.SAMPLE.MISSING")
    broken = ArtifactAcquirer({"passport_json": make_artifact("passport_json", b"{not json")})
    outcome = check(tmp_path, "data.rules", broken, source="passport_json")
    assert verdict(outcome) == failed("DATA.RESPONSE.NOT_JSON")


@pytest.mark.parametrize(
    "params",
    [
        {"source": "manual/result"},
        {"source": ""},
        {"credential": {"profile": "jws"}},
        {"source": "item", "credential": {}},
        {"source": "item", "sample": "view_html"},
        {"sample": "view_html"},
        {"source": "credential_payload", "credential": {"profile": "vc-jose", "key_source": "x5c"}},
    ],
)
def test_the_source_parameters_are_closed(params: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DocumentParams.model_validate(params)


# -- parameter files ------------------------------------------------------------------------------


def test_the_schema_parameter_replaces_the_profile_schema(tmp_path: Path) -> None:
    (tmp_path / "pinned").mkdir()
    (tmp_path / "pinned" / "id.schema.json").write_text(json.dumps(ID_SCHEMA), encoding="utf-8")
    outcome = check(tmp_path, "data.jsonschema", Canned(b'{"id": 1}'), schema="pinned/id.schema.json")
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
    assert outcome.observations[0].summary["schema"] == "pinned/id.schema.json"


def test_the_rule_pack_parameter_replaces_the_profile_rule_packs(tmp_path: Path) -> None:
    other = {
        **REQUIRED_NAME,
        "rulepack_id": "test/other",
        "rules": [{**REQUIRED_NAME["rules"][0], "fields": ["zzz"]}],
    }
    (tmp_path / "other.json").write_text(json.dumps(other), encoding="utf-8")
    outcome = check(tmp_path, "data.rules", Canned(b'{"name": "n"}'), rule_pack="other.json")
    assert verdict(outcome) == failed("DATA.COMPLETENESS.MISSING")
    assert outcome.observations[0].summary["rule_packs"] == ["test/other 1"]


@pytest.mark.parametrize(
    "path", ["../schema.json", "/etc/passwd", "a/../schema.json", "a\\b.json", "", "./schema.json", "a//b"]
)
def test_a_parameter_file_is_a_relative_path_under_the_data_root(path: str) -> None:
    assert SchemaParams.model_validate({"schema": "testpacks/data/a-1.schema.json"})
    assert RulesParams.model_validate({"rule_pack": "profiles/x/rules.yaml"})
    with pytest.raises(ValidationError):
        SchemaParams.model_validate({"schema": path})
    with pytest.raises(ValidationError):
        RulesParams.model_validate({"rule_pack": path})


def test_a_parameter_file_that_leaves_the_data_root_by_a_link_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(ID_SCHEMA), encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.json").symlink_to(outside)
    outcome = check(root, "data.jsonschema", Canned(b'{"id": 1}'), schema="link.json")
    assert verdict(outcome) == blocked("DATA.SCHEMA.MISSING")
    outcome = check(root, "data.rules", Canned(b'{"id": 1}'), rule_pack="link.json")
    assert verdict(outcome) == blocked("DATA.RULES.MISSING")


def test_every_file_that_a_test_purpose_parameter_names_is_a_bound_file(tmp_path: Path) -> None:
    (tmp_path / "s.json").write_text("{}", encoding="utf-8")
    purposes = [
        b.purpose("T-1", stimulus={"check": "data.jsonschema", "params": {"schema": "s.json"}}),
        b.purpose("T-2", stimulus={"check": "data.rules", "params": {"rule_pack": "missing.json"}}),
        b.purpose("T-3", stimulus={"check": "data.context", "params": {"allowed_contexts": ALLOWED}}),
    ]
    bound = bound_files(b.profile(), tmp_path, {"tp/a": b.purposes_pack(*purposes)})
    assert set(bound) == {"s.json", "missing.json"}
    assert bound["s.json"].startswith("sha256:")
    assert bound["missing.json"] == "unavailable"
    # A test pack that the profile does not select binds nothing.
    assert bound_files(b.profile(), tmp_path, {"tp/other": b.purposes_pack(*purposes)}) == {}


# -- the payload of a verified credential ----------------------------------------------------------


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return p256()


@pytest.fixture
def trust(key: ec.EllipticCurvePrivateKey) -> TrustBundle:
    return bundle({KID: jwk(key)})


CREDENTIAL = {"accept": "application/vc+jwt"}


def test_the_payload_of_a_verified_credential_is_judged(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    served = Served(compact(VC_HEADER, vc(), key))
    outcome = check(
        tmp_path, "data.jsonschema", served, profile_schema=SUBJECT_SCHEMA, trust=trust,
        source="credential_payload", credential=CREDENTIAL,
    )  # fmt: skip
    assert verdict(outcome) == passed("DATA.SCHEMA.OK")
    assert served.requests[0].headers == {"Accept": "application/vc+jwt"}
    assert served.requests[0].url.endswith("/dpp/09506000134352-EV0001/signed")
    broken = Served(compact(VC_HEADER, vc(credentialSubject={}), key))
    outcome = check(
        tmp_path, "data.jsonschema", broken, profile_schema=SUBJECT_SCHEMA, trust=trust,
        source="credential_payload", credential=CREDENTIAL,
    )  # fmt: skip
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
    assert outcome.observations[0].summary["source"] == "credential_payload"


def test_an_unverified_credential_payload_is_not_judged(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    header, _, signature = compact(VC_HEADER, vc(), key).split(".")
    tampered = compact(VC_HEADER, vc(credentialSubject={}), key).split(".")[1]
    served = Served(f"{header}.{tampered}.{signature}")
    outcome = check(
        tmp_path, "data.jsonschema", served, profile_schema=SUBJECT_SCHEMA, trust=trust,
        source="credential_payload", credential=CREDENTIAL,
    )  # fmt: skip
    assert verdict(outcome) == blocked("DATA.CREDENTIAL.UNVERIFIED")
    assert "INTEGRITY.JOSE.SIGNATURE" in outcome.message
    assert "integrity.jose" in outcome.message
    assert outcome.observations[0].summary["verification"] == "INTEGRITY.JOSE.SIGNATURE"
    untrusted = check(
        tmp_path, "data.rules", Served(compact(VC_HEADER, vc(), key)),
        source="credential_payload", credential=CREDENTIAL,
    )  # fmt: skip
    assert verdict(untrusted) == blocked("DATA.CREDENTIAL.UNVERIFIED")


def test_a_credential_sample_is_verified_and_sends_no_request(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    served = Served(artifacts={"credential": compact(VC_HEADER, vc(credentialSubject={}), key).encode()})
    outcome = check(
        tmp_path, "data.jsonschema", served, profile_schema=SUBJECT_SCHEMA, trust=trust,
        source="credential_payload", credential={"source": "sample"},
    )  # fmt: skip
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
    assert served.requests == []
    assert outcome.observations[0].kind == "artifact"


def test_a_verified_payload_that_is_not_a_json_object_fails(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    served = Served(compact({"alg": "ES256", "kid": KID}, b"[1]", key))
    outcome = check(
        tmp_path, "data.context", served, trust=trust, allowed_contexts=ALLOWED,
        source="credential_payload", credential={"profile": "jws"},
    )  # fmt: skip
    assert verdict(outcome) == failed("DATA.RESPONSE.NOT_JSON")


# -- JSON-LD embedded in an HTML page ------------------------------------------------------------


def page(*scripts: str, kind: str = "application/ld+json") -> bytes:
    body = "".join(f'<script type="{kind}">{s}</script>' for s in scripts)
    # A script of another type holds markup-like text, which must not end or open a JSON-LD script.
    other = '<script>var x = "<b>";</script>'
    return f"<!doctype html><html><head>{other}{body}</head><body></body></html>".encode()


GOOD = '{"@context": "https://example.test/ctx", "id": "x", "name": "n"}'
BAD = '{"@context": "https://other.test/ctx", "id": 1}'


@pytest.mark.parametrize("scripts", [(GOOD, BAD), (BAD, GOOD)])
def test_every_embedded_document_is_judged_and_one_failing_script_fails(
    tmp_path: Path, scripts: tuple[str, str]
) -> None:
    schema = check(
        tmp_path,
        "data.jsonschema",
        Canned(page(*scripts)),
        profile_schema=ID_SCHEMA,
        source="embedded_jsonld",
    )
    assert verdict(schema) == failed("DATA.SCHEMA.INVALID")
    assert schema.observations[0].summary["documents"] == 2
    contexts = check(
        tmp_path, "data.context", Canned(page(*scripts)), allowed_contexts=ALLOWED, source="embedded_jsonld"
    )
    assert verdict(contexts) == failed("DATA.CONTEXT.NOT_ALLOWED")
    rules = check(tmp_path, "data.rules", Canned(page(*scripts)), source="embedded_jsonld")
    assert verdict(rules) == failed("DATA.COMPLETENESS.MISSING")


def test_embedded_documents_that_all_pass_give_a_pass(tmp_path: Path) -> None:
    body = page(GOOD, f"\n  {GOOD}\n", kind=" Application/LD+JSON ")
    outcome = check(
        tmp_path, "data.jsonschema", Canned(body), profile_schema=ID_SCHEMA, source="embedded_jsonld"
    )
    assert verdict(outcome) == passed("DATA.SCHEMA.OK")
    assert outcome.observations[0].summary["documents"] == 2


def test_a_page_without_embedded_json_ld_fails(tmp_path: Path) -> None:
    outcome = check(
        tmp_path, "data.jsonschema", Canned(page()), profile_schema=ID_SCHEMA, source="embedded_jsonld"
    )
    assert verdict(outcome) == failed("DATA.EMBEDDED.MISSING")
    other = page(GOOD, kind="application/json")
    outcome = check(tmp_path, "data.rules", Canned(other), source="embedded_jsonld")
    assert verdict(outcome) == failed("DATA.EMBEDDED.MISSING")


@pytest.mark.parametrize("broken", ["{not json", "[1]", '{"a": 1, "a": 2}'])
def test_an_embedded_script_that_is_not_one_json_object_fails(tmp_path: Path, broken: str) -> None:
    outcome = check(
        tmp_path,
        "data.jsonschema",
        Canned(page(GOOD, broken)),
        profile_schema=ID_SCHEMA,
        source="embedded_jsonld",
    )
    assert verdict(outcome) == failed("DATA.RESPONSE.NOT_JSON")


def test_a_page_that_is_not_utf_8_fails(tmp_path: Path) -> None:
    body = page(GOOD).replace(b'"n"', b'"\xff"')
    outcome = check(
        tmp_path, "data.jsonschema", Canned(body), profile_schema=ID_SCHEMA, source="embedded_jsonld"
    )
    assert verdict(outcome) == failed("DATA.RESPONSE.NOT_JSON")


def test_too_many_scripts_are_blocked_only_when_none_of_the_judged_ones_fails(tmp_path: Path) -> None:
    many = check(
        tmp_path,
        "data.jsonschema",
        Canned(page(*[GOOD] * 17)),
        profile_schema=ID_SCHEMA,
        source="embedded_jsonld",
    )
    assert verdict(many) == blocked("DATA.EMBEDDED.TOO_LARGE")
    mixed = page(*[GOOD] * 3, BAD, *[GOOD] * 13)
    outcome = check(
        tmp_path, "data.jsonschema", Canned(mixed), profile_schema=ID_SCHEMA, source="embedded_jsonld"
    )
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")


def test_an_embedded_sample_page_is_read_from_the_ixit(tmp_path: Path) -> None:
    acquirer = ArtifactAcquirer({"view_html": make_artifact("view_html", page(BAD))})
    outcome = check(
        tmp_path,
        "data.jsonschema",
        acquirer,
        profile_schema=ID_SCHEMA,
        source="embedded_jsonld",
        sample="view_html",
    )
    assert verdict(outcome) == failed("DATA.SCHEMA.INVALID")
