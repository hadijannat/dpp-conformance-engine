"""The data contracts, the published schemas, and the migrations.

This module adds what tests/test_schemas_and_migrations.py does not cover. The rules come from
docs/explanation/architecture.md: section 5 (five node shapes), section 7.1 (only a completed
check carries a result), and section 11.1 (integers only, one time format).
"""

from __future__ import annotations

import copy
import inspect
import itertools
from typing import Any, cast

import jsonschema
import pytest
from pydantic import ValidationError

from dppce import migrations, models, schemas
from dppce.migrations import MigrationError, migrate
from dppce.models import (
    ICS,
    IXIT,
    SCHEMA_MODELS,
    All,
    AnyOf,
    Authorization,
    CapabilityState,
    CheckOutcome,
    ClaimLevel,
    Compare,
    Const,
    ExecutionMode,
    ExecutionStatus,
    InputHashes,
    IssuerStatement,
    Modality,
    Model,
    Not,
    Observation,
    Plan,
    Ratio,
    Requirement,
    ReviewStatus,
    RoleIdentity,
    RunInputsRecord,
    Scope,
    Stimulus,
    Tri,
    TrustBundle,
    Verdict,
    VerdictRules,
)
from tests.core import builders as b

CONTRACTS = sorted(
    (c for c in vars(models).values() if inspect.isclass(c) and issubclass(c, Model) and c is not Model),
    key=lambda c: c.__name__,
)


def observation(**changes: Any) -> Observation:
    fields: dict[str, Any] = {
        "id": "T-1#0",
        "test_purpose_id": "T-1",
        "kind": "derived",
        "acquired_at": "2026-10-13T12:00:00Z",
    }
    return Observation.model_validate(fields | changes)


def plan() -> Plan:
    return Plan.model_validate(
        {
            "schema_version": "dppce.plan/1",
            "mode": "exploratory",
            "profile_id": b.PROFILE_ID,
            "requirements": [
                {
                    "requirement_id": "R-1",
                    "pack_id": "pack/a",
                    "applicability": "true",
                    "applicability_reason": "synthetic",
                    "paths": [
                        {
                            "path_id": "p1",
                            "applicability": "true",
                            "applicability_reason": "",
                            "tests": ["T-1"],
                        }
                    ],
                }
            ],
            "steps": [
                {
                    "test_purpose_id": "T-1",
                    "check": "probe.ok",
                    "applicability": "true",
                    "applicability_reason": "synthetic",
                }
            ],
            "exclusions": [
                {"kind": "requirement", "id": "R-2", "reason_code": "STATUS.WITHDRAWN", "reason": "x"}
            ],
            "conflicts": [{"requirement_id": "R-1", "declared": "no", "explanation": "synthetic"}],
        }
    )


# One valid instance of each kind of contract that the core tests build.
INSTANCES: dict[str, Model] = {
    "requirement": b.requirement(
        "R-1", assessment_paths=[b.path("p1", "T-1")], declared_support=b.feature("x")
    ),
    "pack": b.pack(b.requirement("R-1", applicability={"all": [{"not": b.feature("x")}, b.ALWAYS]})),
    "purpose": b.purpose("T-1"),
    "testpack": b.purposes_pack(b.purpose("T-1")),
    "profile": b.profile(facts={"capacity_wh": {"type": "integer", "description": "Synthetic."}}),
    "ics": b.ics(characteristics={"capacity_wh": 2500}, features={"export": True}),
    "ixit": IXIT(
        schema_version="dppce.ixit/1", identities=(RoleIdentity(role="auditor", secret_ref="env:X"),)
    ),
    "source": b.source(),
    "plan": plan(),
    "observation": observation(),
    "outcome": CheckOutcome(status=ExecutionStatus.COMPLETED, passed=True, reason_code="A.OK", message="m"),
    "rules": VerdictRules(),
    "ratio": Ratio(numerator=1, denominator=2, of="requirements"),
    "trust": TrustBundle(schema_version="dppce.trust/1", policy_version="test-1"),
    "const": Const(const=Tri.TRUE),
    "compare": Compare(fact="ics.x", op="eq", value=1),
    "all": All(all=(Const(const=Tri.TRUE),)),
    "any": AnyOf(any=(Const(const=Tri.TRUE),)),
    "not": Not(operand=Const(const=Tri.TRUE)),
}


# --- Closed and immutable ------------------------------------------------------------------


def test_every_contract_is_declared_closed_and_frozen() -> None:
    assert len(CONTRACTS) > 50
    for contract in CONTRACTS:
        assert contract.model_config.get("extra") == "forbid", contract.__name__
        assert contract.model_config.get("frozen") is True, contract.__name__


@pytest.mark.parametrize("name", sorted(INSTANCES))
def test_a_contract_rejects_an_unknown_key(name: str) -> None:
    instance = INSTANCES[name]
    document = instance.model_dump(mode="json", by_alias=True)
    assert type(instance).model_validate(document) == instance
    with pytest.raises(ValidationError, match="surprise"):
        type(instance).model_validate({**document, "surprise": 1})


@pytest.mark.parametrize("name", sorted(INSTANCES))
def test_a_contract_is_immutable(name: str) -> None:
    instance = INSTANCES[name]
    field = next(iter(type(instance).model_fields))
    before = instance.model_dump()
    with pytest.raises(ValidationError, match="frozen"):
        setattr(instance, field, getattr(instance, field))
    with pytest.raises(ValidationError, match="surprise"):
        instance.surprise = 1
    assert instance.model_dump() == before


def test_an_unknown_key_is_rejected_at_every_depth() -> None:
    nested = [
        (ICS, b.ics().model_dump(mode="json") | {"sut": {"name": "n", "identifier": "urn:x", "surprise": 1}}),
        (
            Requirement,
            b.requirement().model_dump(mode="json") | {"source": {"source_id": "S", "surprise": 1}},
        ),
        (
            Requirement,
            b.requirement().model_dump(mode="json") | {"applicability": {"const": "true", "surprise": 1}},
        ),
        (IXIT, {"schema_version": "dppce.ixit/1", "network": {"surprise": 1}}),
        (IXIT, {"schema_version": "dppce.ixit/1", "identities": [{"role": "r", "surprise": 1}]}),
    ]
    for contract, document in nested:
        with pytest.raises(ValidationError, match="surprise"):
            contract.model_validate(document)


def test_the_lists_of_a_contract_are_tuples() -> None:
    requirement = INSTANCES["requirement"]
    assert isinstance(requirement, Requirement)
    assert isinstance(requirement.assessment_paths, tuple)
    assert isinstance(requirement.assessment_paths[0].tests, tuple)
    assert isinstance(b.purpose("T-1").requirements, tuple)
    assert isinstance(b.profile().packs, tuple)


# --- The vocabulary of the contract --------------------------------------------------------


def test_the_enumerations_hold_the_values_that_the_contract_names() -> None:
    assert {v.value for v in Tri} == {"true", "false", "unknown"}
    assert {v.value for v in Verdict} == {"pass", "fail", "inconclusive", "not_applicable", "error"}
    assert {v.value for v in ExecutionMode} == {"illustrative", "exploratory", "reviewed"}
    assert {v.value for v in ExecutionStatus} == {
        "completed",
        "not_run",
        "skipped",
        "blocked",
        "unsupported",
        "manual_unavailable",
        "error",
    }
    assert {v.value for v in ReviewStatus} == {
        "placeholder",
        "draft-needs-review",
        "approved",
        "superseded",
        "withdrawn",
    }
    assert {v.value for v in Modality} == {"mandatory", "recommended", "optional"}
    assert {v.value for v in CapabilityState} == {
        "supported",
        "experimental",
        "interface_only",
        "unsupported",
    }
    assert {"illustrative", "diagnostic", "reviewed"} <= {v.value for v in ClaimLevel}
    assert "read" in {v.value for v in Scope}
    assert {v.value for v in models.Op} == {"eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains"}


# --- CheckOutcome --------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "passed"), list(itertools.product(ExecutionStatus, (True, False, None))))
def test_a_check_outcome_carries_a_result_if_and_only_if_the_check_completed(
    status: ExecutionStatus, passed: bool | None
) -> None:
    fields: dict[str, Any] = {"status": status, "passed": passed, "reason_code": "A.B", "message": "m"}
    if (status is ExecutionStatus.COMPLETED) == (passed is not None):
        outcome = CheckOutcome(**fields)
        assert (outcome.status, outcome.passed, outcome.unreachable) == (status, passed, False)
    else:
        with pytest.raises(ValidationError, match="passed"):
            CheckOutcome(**fields)


def test_a_check_outcome_without_a_result_defaults_to_none_and_needs_a_reason() -> None:
    assert CheckOutcome(status=ExecutionStatus.SKIPPED, reason_code="A.B", message="m").passed is None
    with pytest.raises(ValidationError, match="passed"):
        CheckOutcome(status=ExecutionStatus.COMPLETED, reason_code="A.B", message="m")
    with pytest.raises(ValidationError, match="reason_code"):
        CheckOutcome.model_validate({"status": "skipped", "message": "m"})


@pytest.mark.parametrize("outcome", ["pass", "error", "not_applicable", "skip", ""])
def test_a_verdict_rule_maps_a_check_that_did_not_pass_to_fail_or_inconclusive_only(outcome: str) -> None:
    with pytest.raises(ValidationError, match="on_check_failed"):
        VerdictRules.model_validate({"on_check_failed": outcome})
    with pytest.raises(ValidationError, match="on_unreachable"):
        VerdictRules.model_validate({"on_unreachable": outcome})


# --- Times and numbers ---------------------------------------------------------------------


def trusted_key(stamp: str) -> models.TrustedKey:
    return models.TrustedKey(
        kid="TEST-ONLY-key",
        issuer="urn:example:test-lab",
        purposes=("report",),
        public_jwk={},
        not_before=stamp,
        not_after="2027-01-01T00:00:00Z",
    )


def test_an_observation_time_is_a_utc_string_to_the_second() -> None:
    assert observation(acquired_at="2026-10-13T12:00:00Z").acquired_at == "2026-10-13T12:00:00Z"
    assert observation(acquired_at="1999-12-31T23:59:59Z").acquired_at == "1999-12-31T23:59:59Z"
    assert trusted_key("2026-01-01T00:00:00Z").not_before == "2026-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-10-13T12:00:00",
        "2026-10-13T12:00:00+00:00",
        "2026-10-13T12:00:00+02:00",
        "2026-10-13T12:00:00.000Z",
        "2026-10-13T12:00Z",
        "2026-10-13 12:00:00Z",
        "2026-10-13t12:00:00z",
        "2026-10-13",
        "20261013T120000Z",
        " 2026-10-13T12:00:00Z",
        "2026-10-13T12:00:00Z\n",
        "2026-10-13T12:00:00ZZ",
        "",
    ],
)
def test_a_time_in_any_other_format_is_rejected(stamp: str) -> None:
    with pytest.raises(ValidationError, match="acquired_at"):
        observation(acquired_at=stamp)
    with pytest.raises(ValidationError, match="not_before"):
        trusted_key(stamp)


def test_a_canonical_body_holds_no_float() -> None:
    with pytest.raises(ValidationError, match="ratio"):
        b.ics(characteristics={"ratio": 0.5})
    with pytest.raises(ValidationError, match="summary"):
        observation(summary={"share": 0.5})
    with pytest.raises(ValidationError, match="summary"):
        observation(summary={"nested": {"values": [1, 2.5]}})
    with pytest.raises(ValidationError, match="params"):
        Stimulus(check="probe.ok", params={"threshold": 0.1})
    with pytest.raises(ValidationError, match="constants"):
        b.profile(constants={"limit": 1.5})
    kept = observation(summary={"count": 3, "ok": True, "name": "n", "none": None, "list": [1, "a", False]})
    assert kept.summary == {"count": 3, "ok": True, "name": "n", "none": None, "list": [1, "a", False]}
    assert type(kept.summary["ok"]) is bool, "a boolean stays a boolean"
    assert type(b.ics(characteristics={"flag": True}).characteristics["flag"]) is bool
    assert type(b.ics(characteristics={"count": 1}).characteristics["count"]) is int


def test_a_ratio_holds_two_counts_and_a_label() -> None:
    assert Ratio(numerator=0, denominator=0, of="requirements").denominator == 0
    for fields in ({"numerator": -1, "denominator": 1}, {"numerator": 1, "denominator": -1}):
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            Ratio.model_validate({**fields, "of": "requirements"})
    with pytest.raises(ValidationError, match="of"):
        Ratio.model_validate({"numerator": 1, "denominator": 2})


# --- Expressions are data ------------------------------------------------------------------


def test_an_expression_has_five_node_shapes() -> None:
    def parse(node: dict[str, Any]) -> Model:
        return b.requirement(applicability=node).applicability

    assert isinstance(parse({"const": "unknown", "reason": "nobody resolved it"}), Const)
    assert isinstance(parse({"fact": "ics.x", "op": "in", "value": [1, 2]}), Compare)
    assert isinstance(parse({"all": [b.ALWAYS]}), All)
    assert isinstance(parse({"any": [b.ALWAYS]}), AnyOf)
    negated = parse({"not": b.ALWAYS})
    assert isinstance(negated, Not)
    assert negated.model_dump(mode="json", by_alias=True) == {"not": {"const": "true", "reason": ""}}
    assert Not.model_validate({"operand": b.ALWAYS}) == negated


@pytest.mark.parametrize(
    "node",
    [
        {"eval": "1 + 1"},
        {"python": "__import__('os')"},
        {"const": "maybe"},
        {"const": "true", "fact": "ics.x"},
        {"all": []},
        {"any": []},
        {"all": [b.ALWAYS], "any": [b.ALWAYS]},
        {"not": [b.ALWAYS, b.ALWAYS]},
        {"fact": "ics.x", "op": "matches", "value": ".*"},
        {"fact": "ics.x", "op": "eq"},
        {"fact": "ics.x", "op": "eq", "value": 0.5},
        {"fact": "ics.x", "op": "eq", "value": None},
        {"fact": "ics.x", "op": "eq", "value": {"k": 1}},
        "ics.x == 1",
        True,
        [],
    ],
    ids=str,
)
def test_any_other_shape_of_expression_is_rejected(node: object) -> None:
    with pytest.raises(ValidationError, match="applicability"):
        b.requirement(applicability=node)


@pytest.mark.parametrize(
    "fact",
    [
        "x",
        "ics",
        "ics.",
        ".x",
        "ics..x",
        "ICS.x",
        "ics.X",
        "ics.x-y",
        "ics.x y",
        "ics.x[0]",
        "ics.__class__.x;",
    ],
)
def test_a_fact_path_is_a_dotted_lower_case_name(fact: str) -> None:
    with pytest.raises(ValidationError, match="fact"):
        Compare.model_validate({"fact": fact, "op": "eq", "value": 1})
    assert Compare.model_validate({"fact": "ics.a_b.c1", "op": "eq", "value": 1}).fact == "ics.a_b.c1"


def test_a_comparison_keeps_the_type_of_its_operand() -> None:
    for value in (True, False, 1, 0, "1", "true"):
        kept = Compare.model_validate({"fact": "ics.x", "op": "eq", "value": value}).value
        assert type(kept) is type(value), value
    several = Compare.model_validate({"fact": "ics.x", "op": "in", "value": [True, 1, "1"]}).value
    assert isinstance(several, tuple)
    assert [type(v) for v in several] == [bool, int, str]


@pytest.mark.parametrize(
    "check", ["probe", "Probe.ok", "probe.Ok", "probe..ok", "probe.ok()", "os.system('x')", "probe ok", ""]
)
def test_a_stimulus_names_a_check_by_a_dotted_lower_case_name(check: str) -> None:
    with pytest.raises(ValidationError, match="check"):
        Stimulus(check=check)
    assert Stimulus(check="identifier.parse").params == {}


@pytest.mark.parametrize("identifier", ["", " R-1", "R 1", "-R1", "../R1", "R-1\n", "R#1"])
def test_an_identifier_has_no_space_and_starts_with_a_letter_or_a_digit(identifier: str) -> None:
    with pytest.raises(ValidationError, match="id"):
        b.requirement(identifier)
    with pytest.raises(ValidationError, match="id"):
        b.purpose(identifier)
    assert b.requirement("EU-2023/1542.Art-77_3").id == "EU-2023/1542.Art-77_3"


# --- Declarations --------------------------------------------------------------------------


def test_a_test_purpose_names_a_requirement_a_profile_and_a_mode() -> None:
    for field in ("requirements", "profiles", "permitted_modes"):
        with pytest.raises(ValidationError, match=field):
            b.purpose("T-1", **{field: []})
    with pytest.raises(ValidationError, match="permitted_modes"):
        b.purpose("T-1", permitted_modes=["certified"])
    default = b.purpose("T-1")
    assert (default.manual, default.requires_scope, default.roles) == (False, Scope.READ, ("anonymous",))


AUTHORIZATION: dict[str, Any] = {
    "schema_version": "dppce.authorization/1",
    "authorization_id": "TEST-ONLY-authorization",
    "issuer": "urn:example:owner",
    "subject": "urn:example:test-lab",
    "sut_identifier": "urn:example:sut",
    "endpoints": ["http://127.0.0.1"],
    "methods": ["GET"],
    "roles": ["anonymous"],
    "scopes": ["read"],
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "max_requests": 1,
}


def test_an_authorization_names_at_least_one_endpoint_method_role_and_scope() -> None:
    assert Authorization.model_validate(AUTHORIZATION).scopes == (Scope.READ,)
    for field in ("endpoints", "methods", "roles", "scopes"):
        with pytest.raises(ValidationError, match=field):
            Authorization.model_validate(AUTHORIZATION | {field: []})
    with pytest.raises(ValidationError, match="max_requests"):
        Authorization.model_validate(AUTHORIZATION | {"max_requests": 0})
    with pytest.raises(ValidationError, match="scopes"):
        Authorization.model_validate(AUTHORIZATION | {"scopes": ["everything"]})


def test_an_ixit_holds_a_reference_to_a_secret_and_never_a_bare_value() -> None:
    for reference in ("env:DPPCE_SECRET_AUDITOR", "file:auditor.token"):
        assert RoleIdentity(role="auditor", secret_ref=reference).secret_ref == reference
    for bare in ("hunter2", "Bearer abc", "https://example.invalid/secret", "env:", "file:", ""):
        with pytest.raises(ValidationError, match="secret_ref"):
            RoleIdentity(role="auditor", secret_ref=bare)
    default = IXIT(schema_version="dppce.ixit/1")
    assert [(i.role, i.secret_ref) for i in default.identities] == [("anonymous", None)]
    assert (default.network.allowed_hosts, default.network.allow_private_hosts) == ((), ())


def test_an_ics_may_declare_any_value_as_unknown() -> None:
    blank = b.ics()
    declared = (
        blank.product_category,
        blank.granularity,
        blank.identifier_scheme,
        blank.carriers,
        blank.signature_format,
    )
    assert declared == ("unknown",) * 5
    assert (blank.sut.version, blank.api.version, blank.access.tiers) == ("unknown",) * 3
    assert b.ics(features={"export": "unknown"}).features == {"export": "unknown"}
    with pytest.raises(ValidationError, match="features"):
        b.ics(features={"export": "maybe"})
    with pytest.raises(ValidationError, match="granularity"):
        b.ics(granularity="pallet")


# --- The published schemas -----------------------------------------------------------------


def objects(schema: object) -> list[dict[str, Any]]:
    """Every sub-schema that describes an object with named properties."""
    found: list[dict[str, Any]] = []
    if isinstance(schema, dict):
        if "properties" in schema:
            found.append(schema)
        for value in schema.values():
            found.extend(objects(value))
    elif isinstance(schema, list):
        for value in schema:
            found.extend(objects(value))
    return found


@pytest.mark.parametrize("stem", sorted(SCHEMA_MODELS))
def test_each_published_schema_is_closed_and_has_a_stable_identifier(stem: str) -> None:
    schema = schemas.load(stem)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"urn:dppce:schema:v1:{stem}"
    described = objects(schema)
    assert described
    for node in described:
        assert node.get("additionalProperties") is False, node.get("title")
    assert schemas.generate()[f"{stem}.schema.json"].endswith("\n")


def test_the_generator_publishes_one_schema_for_each_contract() -> None:
    assert sorted(schemas.generate()) == sorted(f"{stem}.schema.json" for stem in SCHEMA_MODELS)
    assert set(SCHEMA_MODELS) >= {
        "pack",
        "ics",
        "ixit",
        "profile",
        "testpack",
        "plan",
        "decision",
        "envelope",
        "trust",
    }


SCHEMA_DOCUMENTS = {
    "pack": INSTANCES["pack"],
    "testpack": INSTANCES["testpack"],
    "profile": INSTANCES["profile"],
    "ics": INSTANCES["ics"],
    "ixit": INSTANCES["ixit"],
    "source": INSTANCES["source"],
    "plan": INSTANCES["plan"],
    "trust": INSTANCES["trust"],
    "authorization": Authorization.model_validate(AUTHORIZATION),
    "runinputs": RunInputsRecord(
        schema_version="dppce.runinputs/2",
        mode=ExecutionMode.ILLUSTRATIVE,
        profile=b.PROFILE_ID,
        evaluation_time="2026-10-13T12:00:00Z",
        ics=cast(ICS, INSTANCES["ics"]),
        ixit=cast(IXIT, INSTANCES["ixit"]),
        import_packs=(),
        extra_packs=(),
        import_testpacks=(),
        extra_testpacks=(),
        trust=None,
        authorization_token=None,
        issuer=IssuerStatement(),
        manual_results=(),
        data_root="/synthetic/data-root",
        input_hashes=InputHashes(
            profile="sha256:" + "0" * 64,
            sources="sha256:" + "1" * 64,
            packs={"pack/a": "sha256:" + "2" * 64},
            testpacks={"tp/a": "sha256:" + "3" * 64},
            bound_files={"rules.yaml": "unavailable"},
        ),
    ),
}


@pytest.mark.parametrize("stem", sorted(SCHEMA_DOCUMENTS))
def test_the_schema_and_the_model_agree_on_a_document(stem: str) -> None:
    validator = jsonschema.Draft202012Validator(schemas.load(stem))
    contract = SCHEMA_MODELS[stem]
    document = SCHEMA_DOCUMENTS[stem].model_dump(mode="json", by_alias=True)
    assert list(validator.iter_errors(document)) == []
    assert contract.model_validate(document) == SCHEMA_DOCUMENTS[stem]
    extra = {**document, "surprise": 1}
    assert list(validator.iter_errors(extra))
    with pytest.raises(ValidationError, match="surprise"):
        contract.model_validate(extra)
    wrong_version = {**document, "schema_version": "dppce.other/9"} if "schema_version" in document else None
    if wrong_version is not None:
        assert list(validator.iter_errors(wrong_version))
        with pytest.raises(ValidationError, match="schema_version"):
            contract.model_validate(wrong_version)


@pytest.mark.parametrize(
    "node",
    [{"eval": "1 + 1"}, {"const": "maybe"}, {"all": []}, {"fact": "ICS.x", "op": "eq", "value": 1}],
    ids=str,
)
def test_the_pack_schema_and_the_model_reject_the_same_expressions(node: dict[str, Any]) -> None:
    validator = jsonschema.Draft202012Validator(schemas.load("pack"))
    document = INSTANCES["pack"].model_dump(mode="json", by_alias=True)
    document["requirements"][0]["applicability"] = node
    assert list(validator.iter_errors(document))
    with pytest.raises(ValidationError, match="applicability"):
        SCHEMA_MODELS["pack"].model_validate(document)


# --- Migrations ----------------------------------------------------------------------------

OLD: dict[str, Any] = {
    "schema_version": "dppce.ics/0",
    "sut": {"name": "Synthetic system", "identifier": "urn:example:sut"},
    "profile": b.PROFILE_ID,
}


def test_a_draft_ics_with_no_legacy_field_gets_the_current_version_only() -> None:
    new = migrate("ics", OLD)
    assert new == {**OLD, "schema_version": "dppce.ics/1", "characteristics": {}}
    assert ICS.model_validate(new).characteristics == {}
    assert migrations.CURRENT["ics"] == "dppce.ics/1"


def test_a_migration_keeps_the_characteristics_that_the_document_had() -> None:
    old = {
        **OLD,
        "characteristics": {"chemistry": "synthetic"},
        "capacity_kwh": 75,
        "features": {"export": True},
    }
    new = migrate("ics", old)
    assert new["characteristics"] == {"chemistry": "synthetic", "capacity_wh": 75000}
    assert new["features"] == {"export": True}
    assert "capacity_kwh" not in new
    only_date = migrate("ics", {**OLD, "placed_on_market": "2027-03-01"})
    assert only_date["characteristics"] == {"placed_on_market_date": "2027-03-01"}
    assert "placed_on_market" not in only_date


def test_a_migration_does_not_change_its_input_at_any_depth() -> None:
    old = {**OLD, "sut": dict(OLD["sut"]), "characteristics": {"chemistry": "synthetic"}, "capacity_kwh": 1}
    snapshot = {**old, "sut": dict(old["sut"]), "characteristics": dict(old["characteristics"])}
    new = migrate("ics", old)
    assert old == snapshot
    new["sut"]["name"] = "changed"
    new["characteristics"]["chemistry"] = "changed"
    assert old == snapshot, "the result shares no part with the input"


@pytest.mark.parametrize(
    ("kilowatt_hours", "watt_hours"),
    [(75, 75000), (2.5, 2500), ("2.5", 2500), (75.123, 75123), (0.001, 1), (0, 0), ("0.057", 57)],
)
def test_kilowatt_hours_become_an_exact_integer_number_of_watt_hours(
    kilowatt_hours: object, watt_hours: int
) -> None:
    new = migrate("ics", {**OLD, "capacity_kwh": kilowatt_hours})
    assert new["characteristics"] == {"capacity_wh": watt_hours}
    assert type(new["characteristics"]["capacity_wh"]) is int
    assert ICS.model_validate(new).characteristics["capacity_wh"] == watt_hours


@pytest.mark.parametrize("capacity", [0.0005, "1.0001", None, True, "", [75], {"value": 75}, float("nan")])
def test_a_capacity_that_is_not_a_whole_number_of_watt_hours_cannot_upgrade(capacity: object) -> None:
    with pytest.raises(MigrationError, match="capacity_kwh"):
        migrate("ics", {**OLD, "capacity_kwh": capacity})


@pytest.mark.parametrize("capacity", [float("inf"), float("-inf"), "Infinity"])
def test_an_infinite_capacity_cannot_upgrade(capacity: object) -> None:
    """A document that cannot be upgraded gives a MigrationError, not an arithmetic error."""
    with pytest.raises(MigrationError, match="capacity_kwh"):
        migrate("ics", {**OLD, "capacity_kwh": capacity})


@pytest.mark.parametrize("version", ["dppce.ics/2", "dppce.ixit/1", "", None, 0, 1, "DPPCE.ICS/1"])
def test_a_document_with_an_unknown_version_is_never_guessed(version: object) -> None:
    with pytest.raises(MigrationError, match="no migration"):
        migrate("ics", {**OLD, "schema_version": version})


@pytest.mark.parametrize("kind", ["ixit", "pack", "ICS", ""])
def test_a_kind_with_no_migration_is_rejected_even_for_a_current_document(kind: str) -> None:
    with pytest.raises(MigrationError, match="unknown document kind"):
        migrate(kind, {"schema_version": f"dppce.{kind}/1"})


def test_a_migration_step_that_does_not_advance_the_version_ends_in_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(migrations._STEPS, ("ics", "dppce.ics/0"), dict)
    with pytest.raises(MigrationError, match="does not reach"):
        migrate("ics", OLD)


# A dppce.runinputs/1 record as the writer at 6a3ea6c wrote it. 0.1.0rc1 left out the last three keys.
RUNINPUTS_1: dict[str, Any] = {
    "schema_version": "dppce.runinputs/1",
    "mode": "illustrative",
    "profile": b.PROFILE_ID,
    "evaluation_time": "2026-10-13T12:00:00Z",
    "ics": INSTANCES["ics"].model_dump(mode="json"),
    "ixit": INSTANCES["ixit"].model_dump(mode="json"),
    "import_packs": [],
    "extra_packs": [],
    "trust": None,
    "authorization_token": None,
    "issuer": IssuerStatement().model_dump(mode="json"),
}


@pytest.mark.parametrize("rc1", [True, False], ids=["rc1", "main"])
def test_a_version_1_record_of_run_inputs_gets_null_hashes_and_empty_lists(rc1: bool) -> None:
    lists = {"import_testpacks": ["/x/tp.yaml"], "extra_testpacks": ["tp/a"], "manual_results": ["T-1"]}
    old = RUNINPUTS_1 if rc1 else {**RUNINPUTS_1, **lists}
    before = copy.deepcopy(old)
    new = migrate("runinputs", old)
    assert old == before, "the input is not changed"
    expected = {key: [] for key in lists} if rc1 else lists
    assert new == {
        **old,
        **expected,
        "schema_version": "dppce.runinputs/2",
        "data_root": None,
        "input_hashes": None,
    }
    record = RunInputsRecord.model_validate(new)
    assert (record.data_root, record.input_hashes) == (None, None)
    assert migrations.CURRENT["runinputs"] == "dppce.runinputs/2"


def test_a_version_1_record_that_holds_a_version_2_field_is_refused() -> None:
    with pytest.raises(MigrationError, match="data_root"):
        migrate("runinputs", {**RUNINPUTS_1, "data_root": "/x"})
    with pytest.raises(MigrationError, match="no migration"):
        migrate("runinputs", {**RUNINPUTS_1, "schema_version": "dppce.runinputs/9"})


def test_a_version_2_record_of_run_inputs_has_no_default() -> None:
    document = SCHEMA_DOCUMENTS["runinputs"].model_dump(mode="json")
    for name in document:
        with pytest.raises(ValidationError, match=name):
            RunInputsRecord.model_validate({k: v for k, v in document.items() if k != name})
