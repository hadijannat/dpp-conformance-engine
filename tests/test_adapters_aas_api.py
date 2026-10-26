"""AAS API read profiles: the check aas.api_profile (P2-15).

The probes follow the read profiles SSP-002 of the AAS Repository and the Submodel Repository
service specifications of IDTA-01002 Part 2, version 3.0.4 (github.com/admin-shell-io/aas-specs-api
at commit f7bb302f, read on 2026-10-26). The expected outcome of each seeded fault comes from
validation/fault-catalogue.yaml, which was written before the check existed. Loopback servers,
local files, and the local reference system only.
"""

from __future__ import annotations

import base64
import dataclasses
import http.server
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

import pytest
from pydantic import ValidationError
from validation import cases
from validation import run as vrun
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.aas_api import UNKNOWN_SHELL_PROBE as UNKNOWN_SHELL
from dppce.adapters.aas_api import UNKNOWN_SUBMODEL_PROBE, AasApiParams, encoded
from dppce.infrastructure.reference import aas as reference_aas
from dppce.infrastructure.reference.base import Request
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import Authorization, CheckOutcome, ExecutionStatus
from dppce.testdefs.registry import CheckContext
from tests.support import reply
from tests.test_review_findings import transport
from tests.test_url_templates import context, ixit, run, sent

BASE = reference_aas.PREFIX
SHELL = reference_aas.SHELL_IDS[0]
SUBMODEL = reference_aas.SUBMODEL_ID
AAS_PROFILE = (
    "https://admin-shell.io/aas/API/3/0/AssetAdministrationShellRepositoryServiceSpecification/SSP-002"
)


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _authorization(origin: str) -> Authorization:
    return Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-aas-api",
        issuer="urn:example:operator:0001",
        subject="urn:example:test-lab",
        sut_identifier="urn:example:sut:reference-dpp",
        endpoints=(origin,),
        methods=("GET",),
        roles=("anonymous",),
        scopes=("read",),
        not_before="2026-01-01T00:00:00Z",
        not_after="2036-01-01T00:00:00Z",
        max_requests=100,
    )


def _ctx(
    tmp_path: Path,
    origin: str,
    *,
    authorized: str | None = "same",
    samples: dict[str, str] | None = None,
    files: dict[str, Path] | None = None,
    **params: Any,
) -> CheckContext:
    the_ixit = ixit(
        endpoints={"api": origin, "registry": origin, "aas": origin + BASE},
        samples={"aas_shell_id": SHELL, "aas_submodel_id": SUBMODEL} if samples is None else samples,
    )
    engine = transport(samples=files or {})
    ctx = context(tmp_path, "aas.api_profile", params=params, the_ixit=the_ixit, acquirer=engine)
    if authorized is None:
        return ctx
    return dataclasses.replace(
        ctx, authorization=_authorization(origin if authorized == "same" else authorized)
    )


Route = tuple[int, bytes]


def _reference_route(path: str, faults: frozenset[str] = frozenset()) -> Route | None:
    answer = reference_aas.respond(SimpleNamespace(faults=faults), Request("GET", path))  # type: ignore[arg-type]  # a stand-in system with faults only
    return None if answer is None else (answer[0], answer[2])


def _server(loopback: Any, overrides: dict[str, Route] | None = None) -> Any:
    """A loopback AAS server: the reference family, with some answers replaced."""
    table = overrides or {}

    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        route = table.get(request.path) or _reference_route(request.path) or (404, b"{}")
        reply(request, route[0], route[1])

    return loopback(handle)


def _description(*profiles: str) -> Route:
    return 200, json.dumps({"profiles": list(profiles)}).encode()


def _passed(outcome: CheckOutcome) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        "AAS.API.OK",
    ), outcome.message


def _failed(outcome: CheckOutcome, rule: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        "AAS.API.PROFILE",
    ), outcome.message
    assert outcome.observations[-1].summary["rule"] == rule


def _not_done(outcome: CheckOutcome, status: ExecutionStatus, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (status, None, code), outcome.message


def _no_answer(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        code,
    ), outcome.message


# -- the unmodified reference system passes ------------------------------------------------------


def test_the_shell_repository_read_profile_passes_on_the_reference_system(tmp_path: Path) -> None:
    with ReferenceServer(FIXTURES) as server:
        ctx = _ctx(tmp_path, server.origin)
        outcome = run(ctx)
    _passed(outcome)
    paths = [r.url.removeprefix(server.origin) for r in ctx.acquirer.records()]
    cursor = quote(reference_aas.cursor_of(1), safe="")
    assert paths == [
        f"{BASE}/description",
        f"{BASE}/shells?limit=1",
        f"{BASE}/shells?limit=1&cursor={cursor}",
        f"{BASE}/shells/{b64(SHELL)}",
        f"{BASE}/shells/{b64(SHELL)}/submodel-refs",
        f"{BASE}/shells/{b64(UNKNOWN_SHELL)}",
    ]
    assert all("=" not in p.split("/")[-1] for p in paths if "shells/" in p), "base64url without padding"
    summary = outcome.observations[-1].summary
    assert summary["profile"] == "aas-repository-read"
    assert [p["probe"] for p in summary["probes"]] == [
        "description",
        "list",
        "list_cursor",
        "item",
        "submodel_refs",
        "unknown_id",
    ]
    # The pass message names only what ran.
    assert "6 read probes" in outcome.message
    assert "no write" in outcome.message


def test_the_submodel_repository_read_profile_passes_on_the_reference_system(tmp_path: Path) -> None:
    with ReferenceServer(FIXTURES) as server:
        ctx = _ctx(tmp_path, server.origin, profile="submodel-repository-read", id_source="aas_submodel_id")
        outcome = run(ctx)
    _passed(outcome)
    paths = [r.url.removeprefix(server.origin) for r in ctx.acquirer.records()]
    assert paths == [
        f"{BASE}/description",
        f"{BASE}/submodels?limit=1",
        f"{BASE}/submodels/{b64(SUBMODEL)}",
        f"{BASE}/submodels/{b64(UNKNOWN_SUBMODEL_PROBE)}",
    ]
    assert "4 read probes" in outcome.message


def test_the_id_can_come_from_a_pointer_into_an_ixit_sample(tmp_path: Path) -> None:
    sample = Path(__file__).resolve().parent.parent / "fixtures" / "aas" / "TEST-ONLY-dpp-valid.json"
    with ReferenceServer(FIXTURES) as server:
        ctx = _ctx(
            tmp_path,
            server.origin,
            samples={"aas_json": "aas.json"},
            files={"aas_json": sample},
            id_source="aas_json",
            id_pointer="/assetAdministrationShells/0/id",
        )
        outcome = run(ctx)
    _passed(outcome)


# -- engine limits and inputs: nothing is sent -----------------------------------------------------


def test_an_origin_that_the_authorization_does_not_name_is_blocked_before_a_request(
    tmp_path: Path, loopback: Any
) -> None:
    server = _server(loopback)
    ctx = _ctx(tmp_path, server.origin, authorized="http://127.0.0.1:1")
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "AAS.API.NOT_AUTHORIZED")
    assert sent(ctx) == 0
    assert server.seen == []


def test_without_an_authorization_the_transport_policy_decides(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback)
    _passed(run(_ctx(tmp_path, server.origin, authorized=None)))
    # An origin that the operator did not confirm is refused by the transport: no answer, no pass.
    ctx = _ctx(tmp_path, server.origin, authorized=None)
    ctx = dataclasses.replace(ctx, acquirer=transport({"allowed_hosts": ("localhost",)}))
    seen = len(server.seen)
    _no_answer(run(ctx), "TRANSPORT.DENIED")
    assert len(server.seen) == seen


def test_a_missing_endpoint_or_id_is_blocked_before_a_request(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback)
    ctx = _ctx(tmp_path, server.origin, endpoint="nothing")
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "AAS.API.NO_TARGET")
    ctx = _ctx(tmp_path, server.origin, samples={})
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "AAS.API.ID_MISSING")
    ctx = _ctx(tmp_path, server.origin, id_source="aas_json", id_pointer="/assetAdministrationShells/0/id")
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "AAS.API.ID_MISSING")
    assert server.seen == []


def test_an_endpoint_with_a_query_is_not_a_target(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback)
    ctx = _ctx(tmp_path, server.origin)
    endpoints = {"api": server.origin, "registry": server.origin, "aas": server.origin + BASE + "?x=1"}
    the_ixit = ixit(endpoints=endpoints, samples={"aas_shell_id": SHELL})
    ctx = dataclasses.replace(ctx, ixit=the_ixit)
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "AAS.API.NO_TARGET")
    assert server.seen == []


def test_a_declared_version_other_than_3_0_is_unsupported(tmp_path: Path, loopback: Any) -> None:
    newer = AAS_PROFILE.replace("/3/0/", "/3/1/")
    server = _server(loopback, {f"{BASE}/description": _description(newer)})
    outcome = run(_ctx(tmp_path, server.origin))
    _not_done(outcome, ExecutionStatus.UNSUPPORTED, "AAS.API.VERSION_UNSUPPORTED")
    assert [s["path"] for s in server.seen] == [f"{BASE}/description"], "no probe of a 3.0 shape"


def test_the_full_profile_ssp_001_includes_the_read_profile(tmp_path: Path, loopback: Any) -> None:
    full = AAS_PROFILE.replace("SSP-002", "SSP-001")
    server = _server(loopback, {f"{BASE}/description": _description(full)})
    _passed(run(_ctx(tmp_path, server.origin)))


def test_too_small_a_request_budget_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback)
    outcome = run(_ctx(tmp_path, server.origin, max_requests=3))
    _no_answer(outcome, "AAS.API.BUDGET_EXHAUSTED")
    assert len(server.seen) == 3


# -- fails, and fails that a system under test cannot hide ----------------------------------------


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({f"{BASE}/description": (404, b"{}")}, "description_status"),
        ({f"{BASE}/description": (200, b'{"profiles": []}')}, "description_shape"),
        ({f"{BASE}/description": (200, b"[]")}, "description_shape"),
        (
            {
                f"{BASE}/description": _description(
                    AAS_PROFILE.replace("AssetAdministrationShell", "Submodel")
                )
            },
            "profile_not_declared",
        ),
        ({f"{BASE}/shells?limit=1": (400, b"{}")}, "list_status"),
        ({f"{BASE}/shells?limit=1": (200, b'{"result": []}')}, "list_shape"),
        ({f"{BASE}/shells?limit=1": (200, b'{"paging_metadata": {}, "result": {}}')}, "list_shape"),
        (
            {f"{BASE}/shells?limit=1": (200, b'{"paging_metadata": {"cursor": 7}, "result": []}')},
            "list_shape",
        ),
        # An empty list without a cursor, while the declared id answers 200: the list is incomplete.
        ({f"{BASE}/shells?limit=1": (200, b'{"paging_metadata": {}, "result": []}')}, "list_empty"),
        ({f"{BASE}/shells?limit=1": (200, b'{"paging_metadata": {}}')}, "list_empty"),
        ({f"{BASE}/shells/{b64(SHELL)}": (404, b"{}")}, "item_status"),
        (
            {
                f"{BASE}/shells/{b64(SHELL)}": (
                    200,
                    b'{"id": "other", "modelType": "AssetAdministrationShell"}',
                )
            },
            "item_shape",
        ),
        (
            {
                f"{BASE}/shells/{b64(SHELL)}/submodel-refs": (
                    200,
                    b'{"paging_metadata": {}, "result": [{"keys": 1}]}',
                )
            },
            "refs_shape",
        ),
        ({f"{BASE}/shells/{b64(UNKNOWN_SHELL)}": (200, b"{}")}, "unknown_id_status"),
        ({f"{BASE}/shells/{b64(UNKNOWN_SHELL)}": (400, b"{}")}, "unknown_id_status"),
    ],
)
def test_an_answer_that_breaks_the_profile_fails(
    tmp_path: Path, loopback: Any, overrides: dict[str, Route], rule: str
) -> None:
    server = _server(loopback, overrides)
    _failed(run(_ctx(tmp_path, server.origin)), rule)


def test_a_paged_result_without_result_is_an_empty_page(tmp_path: Path, loopback: Any) -> None:
    # Part2-API-Schemas at f7bb302f: PagedResult requires only paging_metadata.
    refs = {f"{BASE}/shells/{b64(SHELL)}/submodel-refs": (200, b'{"paging_metadata": {}}')}
    _passed(run(_ctx(tmp_path, _server(loopback, refs).origin)))


def test_an_empty_submodel_list_with_a_served_submodel_fails(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback, {f"{BASE}/submodels?limit=1": (200, b'{"paging_metadata": {}}')})
    ctx = _ctx(tmp_path, server.origin, profile="submodel-repository-read", id_source="aas_submodel_id")
    _failed(run(ctx), "list_empty")


def test_a_cursor_page_that_repeats_the_first_page_fails(tmp_path: Path, loopback: Any) -> None:
    cursor = quote(reference_aas.cursor_of(1), safe="")
    first = _reference_route(f"{BASE}/shells?limit=1")
    assert first is not None
    server = _server(loopback, {f"{BASE}/shells?limit=1&cursor={cursor}": first})
    _failed(run(_ctx(tmp_path, server.origin)), "paging_cursor")


@pytest.mark.parametrize(
    "limit",
    [
        {f"{BASE}/description": (503, b"{}")},
        {f"{BASE}/description": (401, b"{}")},
        {f"{BASE}/shells/{b64(SHELL)}": (500, b"{}")},
    ],
)
def test_a_fail_of_a_later_probe_beats_an_earlier_missing_answer(
    tmp_path: Path, loopback: Any, limit: dict[str, Route]
) -> None:
    # A system under test must not turn a fail into a step that is not judged.
    unknown = {f"{BASE}/shells/{b64(UNKNOWN_SHELL)}": (200, b"{}")}
    server = _server(loopback, limit | unknown)
    _failed(run(_ctx(tmp_path, server.origin)), "unknown_id_status")


def test_a_server_error_without_a_fail_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback, {f"{BASE}/shells/{b64(SHELL)}": (500, b"{}")})
    _no_answer(run(_ctx(tmp_path, server.origin)), "TRANSPORT.SERVER_ERROR")


def test_an_anonymous_refusal_without_a_fail_is_blocked(tmp_path: Path, loopback: Any) -> None:
    server = _server(loopback, {f"{BASE}/shells?limit=1": (403, b"{}")})
    outcome = run(_ctx(tmp_path, server.origin))
    _not_done(outcome, ExecutionStatus.BLOCKED, "AAS.API.NOT_CONCLUSIVE")


def test_the_cursor_is_percent_encoded_in_the_query(tmp_path: Path, loopback: Any) -> None:
    odd = "wJlC+/6vc=#"
    page = json.dumps({"paging_metadata": {"cursor": odd}, "result": [{"id": SHELL}]}).encode()
    second = f"{BASE}/shells?limit=1&cursor={quote(odd, safe='')}"
    last = json.dumps({"paging_metadata": {}, "result": [{"id": "https://example.test/x"}]}).encode()
    server = _server(loopback, {f"{BASE}/shells?limit=1": (200, page), second: (200, last)})
    _passed(run(_ctx(tmp_path, server.origin)))
    assert second in [s["path"] for s in server.seen]


# -- the parameter model -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"profile": "aas-registry-read"},
        {"max_requests": 0},
        {"max_requests": 17},
        {"id_pointer": "no-slash"},
        {"endpoint": "Not A Key"},
        {"id_source": ""},
        {"suite": "x"},
    ],
)
def test_the_parameter_model_is_closed(params: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AasApiParams.model_validate(params)


def test_an_id_is_base64url_without_padding() -> None:
    assert encoded("a") == "YQ"
    assert encoded("https://example.test/a?b") == "aHR0cHM6Ly9leGFtcGxlLnRlc3QvYT9i"
    assert encoded("ÿþ") == "w7_Dvg"


def test_the_defaults_name_the_shell_repository_read_profile() -> None:
    params = AasApiParams.model_validate({})
    assert (params.endpoint, params.profile, params.id_source, params.id_pointer, params.max_requests) == (
        "aas",
        "aas-repository-read",
        "aas_shell_id",
        None,
        6,
    )


# -- the seeded faults F-74 and F-75 ------------------------------------------------------------


@pytest.mark.parametrize(
    ("flag", "rule"), [("aas_api_wrong_status", "unknown_id_status"), ("aas_api_bad_paging", "paging_limit")]
)
def test_each_flag_of_the_reference_repository_breaks_the_profile(
    tmp_path: Path, flag: str, rule: str
) -> None:
    with ReferenceServer(FIXTURES, faults=frozenset({flag})) as server:
        outcome = run(_ctx(tmp_path, server.origin))
    _failed(outcome, rule)


def test_bad_paging_also_breaks_the_submodel_list_only_when_it_has_two_elements(tmp_path: Path) -> None:
    # The repository holds one submodel, so a list that ignores limit=1 looks the same.
    with ReferenceServer(FIXTURES, faults=frozenset({"aas_api_bad_paging"})) as server:
        ctx = _ctx(tmp_path, server.origin, profile="submodel-repository-read", id_source="aas_submodel_id")
        _passed(run(ctx))


@pytest.mark.parametrize("case_id", ["F-74", "F-75"])
def test_the_catalogue_case_gives_its_expected_outcome(tmp_path: Path, case_id: str) -> None:
    case = next(c for c in cases.sut_faults() if c.id == case_id)
    assert case.expected == {"verdict": "fail", "reason_code": "AAS.API.PROFILE"}
    rows = vrun._sut_cases(tmp_path, [case], "fault", all_profiles=True)
    assert [(r["profile"], r["as_expected"]) for r in rows] == [("family/aas", True)], rows
