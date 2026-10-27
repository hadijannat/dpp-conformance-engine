"""GS1 resolver checks: resolver.linkset, resolver.well_known, and resolver.conformance (P2-05).

The expected outcome of each seeded fault comes from validation/fault-catalogue.yaml, which was
written before the checks existed. Loopback servers and the local reference system only. A
target of a linkset is never fetched, and no check sends a method other than GET.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.common import schema_errors, validator
from dppce.infrastructure.reference.base import Request
from dppce.infrastructure.reference_server import ReferenceServer, ReferenceSystem
from dppce.models import CheckOutcome, EvidenceEnvelope, ExecutionStatus, Verdict
from tests.test_family_profiles import _cli, _example
from tests.test_resolved_target import ITEM_PATH, RESOLVER_PATH, Origin, moved, resolved_context, served
from tests.test_url_templates import run

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "validation" / "fault-catalogue.yaml"
GS1_SCHEMA = ROOT / "tests" / "vectors" / "gs1-linkset" / "linkset-schema.json"
PROFILE = "family/gs1-resolver"
LINKSET_TYPE = "application/linkset+json"
RELATION = "https://dppce.example.test/rel/passport"
OTHER = "https://dppce.example.test/rel/other"
PURPOSES = {
    "resolver.linkset": "TP-GS1-LINKSET-001",
    "resolver.well_known": "TP-GS1-WELLKNOWN-001",
    "resolver.conformance": "TP-GS1-CONFORMANCE-001",
}
LINKTYPE = RESOLVER_PATH + "?linkType=linkset"
WELL_KNOWN = "/.well-known/gs1resolver"
# The carrier GTIN 09506000134352 with a wrong check digit.
INVALID = "/01/09506000134353/21/EV0001"
OUT_OF_SCOPE = "https://out-of-scope.example.test/x"
# Answers whose body the engine cannot judge: a body coding, and a body over the limit.
Spoil = tuple[dict[str, str], bytes, dict[str, Any] | None]
SPOILS: list[Spoil] = [
    ({"Content-Encoding": "gzip"}, b'{"error": "x"}', None),
    ({}, b'{"error": "' + b"x" * 4096 + b'"}', {"max_body_bytes": 1024}),
]


def _gs1_cases() -> list[dict[str, Any]]:
    document = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    entries = [*document["sut_faults"], *document["boundary_cases"]]
    # Other cases of the family profile (identifier syntax and granularity) are not resolver cases.
    return [e for e in entries if PROFILE in e.get("profiles", ()) and e["test_purpose"] in PURPOSES.values()]


GS1_CASES = _gs1_cases()


def _family_run(tmp_path: Path, faults: frozenset[str] = frozenset()) -> EvidenceEnvelope:
    with ReferenceServer(FIXTURES, faults=faults) as server:
        ics, ixit = _example(tmp_path, "gs1-resolver", server.origin)
        out = tmp_path / "run"
        _cli(
            [
                "run",
                "--profile", PROFILE,
                "--ics", str(ics),
                "--ixit", str(ixit),
                "--trust", str(FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"),
                "--at", "2026-10-13T12:00:00Z",
                "--out", str(out),
                "--keys", str(tmp_path / "keys"),
                "--create-data-key",
                "--allow-private-host", server.origin,
                "--issuer-name", "dppce test rig (synthetic)",
                "--issuer-id", "urn:example:test-lab",
            ]
        )  # fmt: skip
    return EvidenceEnvelope.model_validate_json((out / "envelope.json").read_bytes())


def _step(envelope: EvidenceEnvelope, test_purpose: str) -> tuple[str, str]:
    result = next(t for t in envelope.decision.test_results if t.test_purpose_id == test_purpose)
    return result.verdict.value, result.reason_code


# -- the seeded faults on the family profile -------------------------------------------------------


def test_the_catalogue_names_the_gs1_resolver_cases() -> None:
    assert sorted(e["id"] for e in GS1_CASES) == ["B-14", "F-48", "F-49", "F-50", "F-51", "F-52", "F-76"]
    assert {e["test_purpose"] for e in GS1_CASES} == set(PURPOSES.values())


def test_the_unmodified_reference_resolver_passes_each_resolver_check(tmp_path: Path) -> None:
    envelope = _family_run(tmp_path)
    for test_purpose in PURPOSES.values():
        assert _step(envelope, test_purpose)[0] == "pass", test_purpose
    codes = {_step(envelope, t)[1] for t in PURPOSES.values()}
    assert codes == {"RESOLVER.LINKSET.OK", "RESOLVER.WELLKNOWN.OK", "RESOLVER.CONFORMANCE.OK"}


@pytest.mark.parametrize("case", GS1_CASES, ids=lambda c: str(c["id"]))
def test_each_seeded_resolver_fault_gives_the_catalogue_outcome(case: dict[str, Any], tmp_path: Path) -> None:
    envelope = _family_run(tmp_path, frozenset({case["fault"]}))
    expected = case["expected"]
    assert _step(envelope, case["test_purpose"]) == (expected["verdict"], expected["reason_code"])
    # Each flag changes one behavior: the other resolver steps still pass.
    for test_purpose in set(PURPOSES.values()) - {case["test_purpose"]}:
        assert _step(envelope, test_purpose)[0] == "pass", test_purpose
    if expected["verdict"] == "fail":
        assert envelope.decision.overall is Verdict.FAIL


# -- the reference linkset against the GS1 linkset schema ------------------------------------------


def _reference_linkset(faults: frozenset[str]) -> Any:
    system = ReferenceSystem(FIXTURES, faults)
    status, media, body, _ = system.respond(Request("GET", LINKTYPE, {}))
    assert (status, media) == (200, LINKSET_TYPE)
    return json.loads(body)


@pytest.mark.parametrize(
    ("faults", "valid"),
    [
        (frozenset(), True),
        (frozenset({"resolver_linkset_no_dpp"}), True),
        (frozenset({"resolver_linkset_anchor_mismatch"}), True),
        (frozenset({"resolver_linkset_invalid"}), False),
    ],
)
def test_the_structure_faults_agree_with_the_vendored_gs1_linkset_schema(
    faults: frozenset[str], valid: bool
) -> None:
    """An independent oracle: only the structure fault breaks the GS1 linkset schema."""
    check = validator(json.loads(GS1_SCHEMA.read_text(encoding="utf-8")))
    assert check is not None
    errors = schema_errors(check, _reference_linkset(faults))
    assert (errors == []) is valid, errors


# -- resolver.linkset on loopback shapes -----------------------------------------------------------


def _linkset(origin: str, relation: str = RELATION, **context: Any) -> bytes:
    entry = {"anchor": origin + RESOLVER_PATH, relation: [{"href": origin + ITEM_PATH}]} | context
    return json.dumps({"linkset": [entry]}).encode()


def _routes(body: bytes, media: str = LINKSET_TYPE) -> dict[str, tuple[int, bytes, dict[str, str]]]:
    answer = (200, body, {"Content-Type": media})
    return {RESOLVER_PATH: answer, LINKTYPE: answer}


def _linkset_run(
    tmp_path: Path, loopback: Any, body: bytes | None = None, *, params: dict[str, Any] | None = None
) -> tuple[CheckOutcome, Origin]:
    api = Origin(loopback)
    api.routes.update(
        _routes(_linkset(api.origin) if body is None else body.replace(b"ORIGIN", api.origin.encode()))
    )
    ctx = resolved_context(
        tmp_path, "resolver.linkset", api.origin, params=params or {"relations": [RELATION]}
    )
    return run(ctx), api


def _failed(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, False, code)


def _blocked(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def test_linkset_passes_and_never_fetches_a_target(tmp_path: Path, loopback: Any) -> None:
    outcome, api = _linkset_run(tmp_path, loopback)
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.LINKSET.OK")
    assert sorted(seen["path"] for seen in api.server.seen) == sorted([RESOLVER_PATH, LINKTYPE])
    accepts = [seen.get("Accept") for seen in api.server.seen if seen["path"] == RESOLVER_PATH]
    assert accepts == [LINKSET_TYPE]
    assert api.hits(ITEM_PATH) == 0
    # The summary holds counts and booleans only, never an IRI or an href.
    text = json.dumps([o.summary for o in outcome.observations])
    assert "http" not in text


def test_linkset_accepts_any_one_of_the_declared_relations(tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _linkset_run(tmp_path, loopback, params={"relations": [OTHER, RELATION]})
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.LINKSET.OK")


@pytest.mark.parametrize(
    "body",
    [
        # A linkset media type does not make a linkset: the shape decides, and a wrong shape fails.
        b'{"linkset": {"anchor": "ORIGIN/01/09506000134352/21/EV0001"}}',
        b'{"linkset": []}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001"}], "id": "x"}',
        b'{"id": "ORIGIN/01/09506000134352/21/EV0001"}',
        b"[]",
        b"not json",
        b'{"linkset": [{"anchor": 7}]}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001", "describedby": {"href": "x"}}]}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001", "describedby": ["x"]}]}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001", "describedby": [{"type": "a/b"}]}]}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001", "describedby": [{"href": 7}]}]}',
    ],
)
def test_linkset_with_another_shape_is_a_structure_fail_never_blocked(
    body: bytes, tmp_path: Path, loopback: Any
) -> None:
    outcome, _ = _linkset_run(tmp_path, loopback, body)
    _failed(outcome, "RESOLVER.LINKSET.STRUCTURE")


def test_linkset_with_a_json_media_type_fails_on_the_media_type(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes.update(_routes(_linkset(api.origin), "application/json"))
    _failed(run(resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})),
            "RESOLVER.LINKSET.MEDIA_TYPE")  # fmt: skip


@pytest.mark.parametrize("status", [404, 401, 403, 303, 410])
def test_linkset_status_other_than_200_fails(status: int, tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    answer = (status, b'{"error": "x"}', {"Content-Type": "application/json"})
    api.routes.update({RESOLVER_PATH: answer, LINKTYPE: answer})
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    _failed(run(ctx), "RESOLVER.LINKSET.STATUS")


@pytest.mark.parametrize("spoil", SPOILS, ids=["encoded", "truncated"])
def test_linkset_status_fail_is_not_hidden_by_an_unusable_body(
    spoil: Spoil, tmp_path: Path, loopback: Any
) -> None:
    # The status rule does not read the body, so a body coding or size cannot turn the fail into blocked.
    headers, body, policy = spoil
    api = Origin(loopback)
    answer = (404, body, {"Content-Type": "application/json"} | headers)
    api.routes.update({RESOLVER_PATH: answer, LINKTYPE: answer})
    ctx = resolved_context(
        tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]}, policy=policy
    )
    _failed(run(ctx), "RESOLVER.LINKSET.STATUS")


def test_linkset_body_with_a_coding_is_not_judged(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    answer = (200, _linkset(api.origin), {"Content-Type": LINKSET_TYPE, "Content-Encoding": "gzip"})
    api.routes.update({RESOLVER_PATH: answer, LINKTYPE: answer})
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    _blocked(run(ctx), "TRANSPORT.BODY_ENCODED")


def test_linkset_judges_the_link_type_request_too(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes.update(_routes(_linkset(api.origin)))
    api.routes[LINKTYPE] = (200, _linkset(api.origin, OTHER), {"Content-Type": LINKSET_TYPE})
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    _failed(run(ctx), "RESOLVER.LINKSET.RELATION_MISSING")


@pytest.mark.parametrize(
    "context",
    [
        {"anchor": "ORIGIN/01/09506000134352/21/EV0002"},
        {"anchor": "ORIGIN/01/09506000134352/21/EV0001/"},
        {"anchor": "ORIGIN/01/09506000134352/21/ev0001"},
    ],
)
def test_linkset_anchor_must_equal_the_carrier_as_exact_text(
    context: dict[str, str], tmp_path: Path, loopback: Any
) -> None:
    body = json.dumps({"linkset": [{**context, RELATION: [{"href": "ORIGIN/dpp/x"}]}]}).encode()
    outcome, _ = _linkset_run(tmp_path, loopback, body)
    _failed(outcome, "RESOLVER.LINKSET.ANCHOR")


def test_linkset_without_an_anchor_fails_on_the_anchor(tmp_path: Path, loopback: Any) -> None:
    body = json.dumps({"linkset": [{RELATION: [{"href": "ORIGIN/dpp/x"}]}]}).encode()
    outcome, _ = _linkset_run(tmp_path, loopback, body)
    _failed(outcome, "RESOLVER.LINKSET.ANCHOR")


@pytest.mark.parametrize(
    "body",
    [
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001",'
        b' "describedby": [{"href": "ORIGIN/x"}]}]}',
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001",'
        b' "https://dppce.example.test/rel/passport": []}]}',
        # The relation sits under another anchor, so it is not a link of the carrier.
        b'{"linkset": [{"anchor": "ORIGIN/01/09506000134352/21/EV0001"},'
        b' {"anchor": "ORIGIN/other", "https://dppce.example.test/rel/passport": [{"href": "ORIGIN/x"}]}]}',
    ],
)
def test_linkset_without_a_declared_relation_fails(body: bytes, tmp_path: Path, loopback: Any) -> None:
    outcome, _ = _linkset_run(tmp_path, loopback, body)
    _failed(outcome, "RESOLVER.LINKSET.RELATION_MISSING")


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"relations": []},
        {"relations": "https://dppce.example.test/rel/passport"},
        {"relations": [7]},
        {"relations": ["https://x.example/a\n"]},
        {"relations": ["not a relation"]},
        {"relations": ["https://x.example/a"] * 17},
        # "anchor" names the link context, not a relation: it would match the anchor text.
        {"relations": ["anchor"]},
    ],
)
def test_linkset_with_invalid_parameters_sends_nothing(
    params: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params=params)
    _blocked(run(ctx), "RESOLVER.PARAMS.INVALID")
    assert api.server.seen == []


def test_linkset_server_error_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {RESOLVER_PATH: (503, b"{}", {})})
    outcome = run(
        resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    )
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


@pytest.mark.parametrize("check", sorted(PURPOSES))
def test_a_carrier_that_is_not_a_url_blocks_and_sends_nothing(
    check: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    params = {"relations": [RELATION]} if check == "resolver.linkset" else {}
    ctx = resolved_context(
        tmp_path, check, api.origin, params=params, samples={"identifier": "09506000134352"}
    )
    _blocked(run(ctx), "RESOLVER.NO_TARGET")
    assert api.server.seen == []


# -- resolver.well_known ----------------------------------------------------------------------------


def _description(root: str) -> bytes:
    return json.dumps({"name": "t", "resolverRoot": root, "supportedPrimaryKeys": ["01"]}).encode()


def _well_known(tmp_path: Path, api: Origin) -> CheckOutcome:
    return run(resolved_context(tmp_path, "resolver.well_known", api.origin))


def test_well_known_passes_for_the_carrier_origin_in_any_spelling(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    root = api.origin.replace("http://", "HTTP://") + "/"
    api.routes[WELL_KNOWN] = (200, _description(root), {})
    outcome = _well_known(tmp_path, api)
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.WELLKNOWN.OK")
    assert [seen["path"] for seen in api.server.seen] == [WELL_KNOWN]


def test_well_known_redirect_blocks(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[WELL_KNOWN] = moved(api.origin + "/description.json")
    api.routes["/description.json"] = (200, _description(api.origin), {})
    _blocked(_well_known(tmp_path, api), "RESOLVER.WELLKNOWN.REDIRECTED")


@pytest.mark.parametrize(
    ("route", "code"),
    [
        ((200, _description("https://other.example.test"), {}), "RESOLVER.WELLKNOWN.ROOT"),
        ((404, b'{"error": "x"}', {}), "RESOLVER.WELLKNOWN.STATUS"),
        ((200, b"<html></html>", {"Content-Type": "text/html"}), "RESOLVER.WELLKNOWN.MEDIA_TYPE"),
        ((200, b"[]", {}), "RESOLVER.WELLKNOWN.NOT_JSON"),
    ],
)
def test_well_known_redirect_does_not_hide_a_fail(
    route: tuple[int, bytes, dict[str, str]], code: str, tmp_path: Path, loopback: Any
) -> None:
    # Only a redirected file that would pass is blocked, so a redirect cannot turn a fail into blocked.
    api = Origin(loopback)
    api.routes[WELL_KNOWN] = moved(api.origin + "/description.json")
    api.routes["/description.json"] = route
    _failed(_well_known(tmp_path, api), code)


@pytest.mark.parametrize("spoil", SPOILS, ids=["encoded", "truncated"])
def test_well_known_status_fail_is_not_hidden_by_an_unusable_body(
    spoil: Spoil, tmp_path: Path, loopback: Any
) -> None:
    headers, body, policy = spoil
    api = Origin(loopback, {WELL_KNOWN: (404, body, headers)})
    _failed(run(resolved_context(tmp_path, "resolver.well_known", api.origin, policy=policy)),
            "RESOLVER.WELLKNOWN.STATUS")  # fmt: skip


def test_well_known_body_with_a_coding_is_not_judged(tmp_path: Path, loopback: Any) -> None:
    api = Origin(
        loopback, {WELL_KNOWN: (200, _description("https://other.example.test"), {"Content-Encoding": "br"})}
    )
    _blocked(_well_known(tmp_path, api), "TRANSPORT.BODY_ENCODED")


@pytest.mark.parametrize(
    ("route", "code"),
    [
        ((404, b'{"error": "x"}', {}), "RESOLVER.WELLKNOWN.STATUS"),
        ((403, b'{"error": "x"}', {}), "RESOLVER.WELLKNOWN.STATUS"),
        ((200, b"<html></html>", {"Content-Type": "text/html"}), "RESOLVER.WELLKNOWN.MEDIA_TYPE"),
        ((200, b"[]", {}), "RESOLVER.WELLKNOWN.NOT_JSON"),
        ((200, b'{"resolverRoot": 7}', {}), "RESOLVER.WELLKNOWN.ROOT"),
        ((200, b'{"name": "t"}', {}), "RESOLVER.WELLKNOWN.ROOT"),
        ((200, _description("https://other.example.test"), {}), "RESOLVER.WELLKNOWN.ROOT"),
        ((200, _description("not a url"), {}), "RESOLVER.WELLKNOWN.ROOT"),
    ],
)
def test_well_known_fails(
    route: tuple[int, bytes, dict[str, str]], code: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback, {WELL_KNOWN: route})
    _failed(_well_known(tmp_path, api), code)


# -- resolver.conformance ---------------------------------------------------------------------------


def _resolver(origin: str) -> dict[str, tuple[int, bytes, dict[str, str]]]:
    return {
        RESOLVER_PATH: moved(origin + ITEM_PATH),
        ITEM_PATH: served(),
        LINKTYPE: (200, _linkset(origin), {"Content-Type": LINKSET_TYPE}),
    }


def _conformance(tmp_path: Path, api: Origin) -> CheckOutcome:
    # A small body limit, so that a long body is a truncated one.
    ctx = resolved_context(tmp_path, "resolver.conformance", api.origin, policy={"max_body_bytes": 1024})
    outcome = run(ctx)
    assert {r.method for r in ctx.acquirer.records()} == {"GET"}, "no write method, no HEAD, no OPTIONS"
    return outcome


@pytest.mark.parametrize("invalid", [(404, b"{}", {}), (400, b"{}", {})])
def test_conformance_passes(
    invalid: tuple[int, bytes, dict[str, str]], tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes.update(_resolver(api.origin) | {INVALID: invalid})
    outcome = _conformance(tmp_path, api)
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.CONFORMANCE.OK")
    assert api.hits(INVALID) == 1


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({INVALID: served()}, "RESOLVER.CONFORMANCE.INVALID_ACCEPTED"),
        # A redirect that ends in 200 is a 200 for the invalid identifier too: the final status counts.
        ({INVALID: moved("/elsewhere"), "/elsewhere": served()}, "RESOLVER.CONFORMANCE.INVALID_ACCEPTED"),
        ({INVALID: (410, b"{}", {})}, "RESOLVER.CONFORMANCE.INVALID_STATUS"),
        ({LINKTYPE: (404, b"{}", {})}, "RESOLVER.CONFORMANCE.LINKSET_STATUS"),
        (
            {LINKTYPE: moved("/linkset.json"), "/linkset.json": served()},
            "RESOLVER.CONFORMANCE.LINKSET_REDIRECTED",
        ),
        ({RESOLVER_PATH: served()}, "RESOLVER.CONFORMANCE.NO_REDIRECT"),
        # A redirect that the transport does not follow is still a redirect, so it cannot hide a fail.
        ({INVALID: moved(OUT_OF_SCOPE)}, "RESOLVER.CONFORMANCE.INVALID_STATUS"),
        ({LINKTYPE: moved(OUT_OF_SCOPE)}, "RESOLVER.CONFORMANCE.LINKSET_REDIRECTED"),
        ({INVALID: moved("/a"), "/a": moved("/a")}, "RESOLVER.CONFORMANCE.INVALID_STATUS"),
        # The check never reads a body, so a body coding or size cannot turn a fail into blocked.
        ({INVALID: (200, b"{}", {"Content-Encoding": "gzip"})}, "RESOLVER.CONFORMANCE.INVALID_ACCEPTED"),
        ({INVALID: (200, b"x" * 4096, {})}, "RESOLVER.CONFORMANCE.INVALID_ACCEPTED"),
        ({RESOLVER_PATH: (200, b"{}", {"Content-Encoding": "br"})}, "RESOLVER.CONFORMANCE.NO_REDIRECT"),
    ],
)
def test_conformance_fails(
    changes: dict[str, tuple[int, bytes, dict[str, str]]], code: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes.update(_resolver(api.origin) | changes)
    _failed(_conformance(tmp_path, api), code)


def test_conformance_needs_a_carrier_gtin_with_a_valid_check_digit(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    samples = {"identifier": api.origin + INVALID}
    _blocked(
        run(resolved_context(tmp_path, "resolver.conformance", api.origin, samples=samples)),
        "RESOLVER.NO_TARGET",
    )
    assert api.server.seen == []


def test_conformance_server_error_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes.update(_resolver(api.origin) | {INVALID: (503, b"{}", {})})
    outcome = _conformance(tmp_path, api)
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )
