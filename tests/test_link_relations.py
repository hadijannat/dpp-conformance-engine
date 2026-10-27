"""Link relations and CORS headers in records, and the Link-header form of resolver.linkset (P2-22).

Loopback servers and the local reference system only. Architecture sections 8 and 10.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.infrastructure.redaction import REMOVED, redact_link, redact_response_headers
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.models import CheckOutcome, ExecutionStatus
from tests.test_adapters_resolver import LINKSET_TYPE, LINKTYPE, OUT_OF_SCOPE, RELATION, _linkset
from tests.test_resolved_target import RESOLVER_PATH, Origin, resolved_context
from tests.test_url_templates import run

JSONLD_CONTEXT = "http://www.w3.org/ns/json-ld#context"
ADVERTISED = "/linksets/EV0001"

# -- Link values in records ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relation",
    [
        "linkset",
        JSONLD_CONTEXT,
        "gs1:pip",
        "gs1:dpp",
        "gs1:activityIdeas",
        "https://ref.gs1.org/voc/pip",
        "https://ref.gs1.org/voc/certificationInfo",
    ],
)
def test_a_link_keeps_linkset_the_json_ld_context_and_gs1_link_types(relation: str) -> None:
    value = f'<https://sut.example/a?token=S1>; rel="{relation}"'
    assert redact_link(value) == f'<https://sut.example/a?token=%3Cremoved%3E>; rel="{relation}"'


def test_several_kept_relations_in_one_value_stay_in_their_order() -> None:
    first = f'<https://sut.example/a>; rel="gs1:pip Next {JSONLD_CONTEXT}"'
    kept = f'<https://sut.example/a>; rel="gs1:pip next {JSONLD_CONTEXT}"'
    assert redact_link(f"{first}, <https://sut.example/b>; rel=linkset") == (
        f'{kept}, <https://sut.example/b>; rel="linkset"'
    )


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        # Free text with ":" and "/" is not a relation of the closed list.
        ('<https://sut.example/a>; rel="https://sut.example/S3CRET"', f"<https://sut.example/a>; {REMOVED}"),
        ('<https://sut.example/a>; rel="gs1:S3CRET"', f"<https://sut.example/a>; {REMOVED}"),
        ('<https://sut.example/a>; rel="urn:S3CRET"', f"<https://sut.example/a>; {REMOVED}"),
        (
            '<https://sut.example/a>; rel="linkset https://sut.example/S3CRET"',
            f'<https://sut.example/a>; rel="linkset"; {REMOVED}',
        ),
        # An extension relation is compared as exact text, so another case is not on the list.
        ('<https://sut.example/a>; rel="gs1:activityideas"', f"<https://sut.example/a>; {REMOVED}"),
        ('<https://sut.example/a>; rel="https://REF.gs1.org/voc/pip"', f"<https://sut.example/a>; {REMOVED}"),
        # The GS1 link types of the list are in the gs1: and the ref.gs1.org form only.
        ('<https://sut.example/a>; rel="https://gs1.org/voc/pip"', f"<https://sut.example/a>; {REMOVED}"),
        # A quoted comma does not split the value, so "gs1:pip," is one word outside the list.
        ('<https://sut.example/a>; rel="gs1:pip, S3CRET"', f"<https://sut.example/a>; {REMOVED}"),
    ],
)
def test_a_relation_outside_the_list_is_dropped_and_its_link_gets_the_marker(value: str, kept: str) -> None:
    assert redact_link(value) == kept
    assert redact_link(kept) == kept


@pytest.mark.parametrize(
    "value",
    [
        # Only the quoted form permits ":" and "/".
        "<https://sut.example/a>; rel=gs1:pip",
        "<https://sut.example/a>; rel=http://www.w3.org/ns/json-ld#context",
        # The rel parameter is given once. A second one is not read, so the value is removed.
        '<https://sut.example/a>; rel="linkset"; REL="next"',
    ],
)
def test_a_link_value_that_is_not_well_formed_is_removed_as_a_whole(value: str) -> None:
    assert redact_link(value) == REMOVED


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        (
            '<https://sut.example/a>; rel="linkset"; type="text/plain"',
            f'<https://sut.example/a>; rel="linkset"; {REMOVED}',
        ),
        (
            '<https://sut.example/a>; title="S3CRET"; REL="gs1:pip"',
            f'<https://sut.example/a>; rel="gs1:pip"; {REMOVED}',
        ),
        ("<https://sut.example/a>; anchor=S3CRET", f"<https://sut.example/a>; {REMOVED}"),
        (
            '<https://sut.example/a>; rel=next; hreflang=de, <https://sut.example/b>; rel="prev"',
            f'<https://sut.example/a>; rel="next"; {REMOVED}, <https://sut.example/b>; rel="prev"',
        ),
    ],
)
def test_a_link_keeps_its_target_and_relations_and_marks_another_parameter(value: str, kept: str) -> None:
    # A title or an anchor is free text, so only a marker shows that the system sent one.
    assert redact_link(value) == kept
    assert redact_link(kept) == kept


def test_the_cors_headers_are_kept_and_an_origin_is_redacted_like_a_url() -> None:
    headers = (
        ("Access-Control-Allow-Origin", "https://user:S3CRET@sut.example"),
        ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"),
        ("Access-Control-Allow-Headers", "Accept, Authorization"),
        ("Access-Control-Expose-Headers", "ETag, Link"),
        ("Access-Control-Max-Age", "600"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Request-Private-Network", "S3CRET"),
        ("X-Other", "S3CRET"),
    )
    assert redact_response_headers(headers) == (
        ("Access-Control-Allow-Origin", "https://sut.example"),
        ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"),
        ("Access-Control-Allow-Headers", "Accept, Authorization"),
        ("Access-Control-Expose-Headers", "ETag, Link"),
        ("Access-Control-Max-Age", "600"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Request-Private-Network", REMOVED),
        ("X-Other", REMOVED),
    )


@pytest.mark.parametrize("value", ["*", "null", "https://sut.example", "http://127.0.0.1:8080"])
def test_an_allowed_origin_without_a_secret_is_kept_unchanged(value: str) -> None:
    assert redact_response_headers((("access-control-allow-origin", value),)) == (
        ("access-control-allow-origin", value),
    )


# -- the Link-header form of resolver.linkset ------------------------------------------------------


def _advertising_run(
    tmp_path: Path,
    loopback: Any,
    advertised: tuple[int, bytes, dict[str, str]] | None,
    link: str = f'<{ADVERTISED}>; rel="linkset"',
    probe: bytes | None = None,
) -> tuple[CheckOutcome, Origin, Any]:
    api = Origin(loopback)
    good = _linkset(api.origin)
    answer = (200, good if probe is None else probe, {"Content-Type": LINKSET_TYPE, "Link": link})
    api.routes.update({RESOLVER_PATH: answer, LINKTYPE: answer})
    if advertised is not None:
        status, body, headers = advertised
        api.routes[ADVERTISED] = (status, body.replace(b"ORIGIN", api.origin.encode()), headers)
    ctx = resolved_context(tmp_path, "resolver.linkset", api.origin, params={"relations": [RELATION]})
    return run(ctx), api, ctx


def _advertised_linkset(origin: str = "ORIGIN", anchor: str = RESOLVER_PATH) -> bytes:
    entry = {"anchor": origin + anchor, RELATION: [{"href": origin + "/dpp/x"}]}
    return json.dumps({"linkset": [entry]}).encode()


def _outcome(outcome: CheckOutcome) -> tuple[ExecutionStatus, bool | None, str]:
    return outcome.status, outcome.passed, outcome.reason_code


def test_an_advertised_linkset_of_the_carrier_passes_and_is_fetched_once(
    tmp_path: Path, loopback: Any
) -> None:
    advertised = (200, _advertised_linkset(), {"Content-Type": LINKSET_TYPE})
    outcome, api, _ = _advertising_run(tmp_path, loopback, advertised)
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert api.hits(ADVERTISED) == 1
    assert [s.get("Accept") for s in api.server.seen if s["path"] == ADVERTISED] == [LINKSET_TYPE]
    assert len(outcome.observations) == 3
    assert outcome.observations[2].summary["request"] == "advertised"
    # The summary holds counts and the media type only, never an IRI or an href.
    assert "http" not in json.dumps([o.summary for o in outcome.observations])


@pytest.mark.parametrize(
    ("advertised", "code"),
    [
        # F-76: the advertised linkset describes another identifier.
        ((200, _advertised_linkset(anchor="/01/09506000134352/21/OTHER0001"), {}), "RESOLVER.LINKSET.ANCHOR"),
        ((404, b'{"error": "x"}', {"Content-Type": "application/json"}), "RESOLVER.LINKSET.STATUS"),
        ((200, _advertised_linkset(), {"Content-Type": "application/json"}), "RESOLVER.LINKSET.MEDIA_TYPE"),
        ((200, b'{"linkset": {}}', {}), "RESOLVER.LINKSET.STRUCTURE"),
    ],
)
def test_an_advertised_linkset_is_judged_by_the_same_rules(
    advertised: tuple[int, bytes, dict[str, str]], code: str, tmp_path: Path, loopback: Any
) -> None:
    status, body, headers = advertised
    outcome, _, _ = _advertising_run(
        tmp_path, loopback, (status, body, {"Content-Type": LINKSET_TYPE} | headers)
    )
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, False, code)
    assert len(outcome.observations) == 3


@pytest.mark.parametrize(
    "link",
    [
        "<ftp://sut.example/l>; rel=linkset",
        "<http://[::1>; rel=linkset",
        f'<{ADVERTISED}>; rel="linkset"; title="x"',
        f'<{ADVERTISED}>; rel="next"',
        # Redaction changed these targets, so the record no longer holds the advertised URL.
        f'<{ADVERTISED}?X-Amz-Signature=abc123>; rel="linkset"',
        f'<{ADVERTISED}?productCode=1>; rel="linkset"',
    ],
)
def test_an_unusable_link_value_is_judged_as_today(link: str, tmp_path: Path, loopback: Any) -> None:
    advertised = (200, _advertised_linkset(anchor="/elsewhere"), {"Content-Type": LINKSET_TYPE})
    outcome, api, _ = _advertising_run(tmp_path, loopback, advertised, link=link)
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert api.hits(ADVERTISED) == 0
    assert not [s for s in api.server.seen if s["path"].startswith(ADVERTISED)]
    assert len(outcome.observations) == 2


def test_an_advertised_linkset_outside_the_policy_is_not_fetched(tmp_path: Path, loopback: Any) -> None:
    # ADR 0011: a Link value of the system does not widen the hosts that the engine contacts.
    outcome, _, ctx = _advertising_run(tmp_path, loopback, None, link=f'<{OUT_OF_SCOPE}>; rel="linkset"')
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert ctx.acquirer.records()[-1].error == "policy_denied"


@pytest.mark.parametrize(
    "advertised",
    [
        (503, b"{}", {}),
        (429, b"", {"Retry-After": "600"}),
        (200, _advertised_linkset(), {"Content-Encoding": "gzip"}),
    ],
)
def test_an_advertised_linkset_without_a_usable_answer_is_judged_as_today(
    advertised: tuple[int, bytes, dict[str, str]], tmp_path: Path, loopback: Any
) -> None:
    status, body, headers = advertised
    outcome, api, _ = _advertising_run(
        tmp_path, loopback, (status, body, {"Content-Type": LINKSET_TYPE} | headers)
    )
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert api.hits(ADVERTISED) == 1


def test_a_broken_link_value_cannot_turn_a_probe_fail_into_blocked(tmp_path: Path, loopback: Any) -> None:
    wrong = _linkset("http://elsewhere.example.test")
    outcome, api, _ = _advertising_run(tmp_path, loopback, (503, b"{}", {}), probe=wrong)
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, False, "RESOLVER.LINKSET.ANCHOR")
    assert api.hits(ADVERTISED) == 0, "the advertised linkset is fetched only after both probes pass"


def test_a_replay_of_the_link_header_form_gives_the_same_outcome(tmp_path: Path, loopback: Any) -> None:
    advertised = (
        200,
        _advertised_linkset(anchor="/01/09506000134352/21/OTHER0001"),
        {"Content-Type": LINKSET_TYPE},
    )
    live, api, ctx = _advertising_run(tmp_path, loopback, advertised)
    replay = ReplayAcquirer(ctx.acquirer.records())
    params = {"relations": [RELATION]}
    again = run(resolved_context(tmp_path, "resolver.linkset", api.origin, params=params, acquirer=replay))
    assert _outcome(again) == _outcome(live) == (ExecutionStatus.COMPLETED, False, "RESOLVER.LINKSET.ANCHOR")
    assert replay.complete()
