"""False-verdict guards for the resolver answer and the signed passport (P2-02, B-10 and B-11).

A linkset (RFC 9264) is not a passport, so no check may pass on one as if it were. A JWS JSON
serialization (RFC 7515, section 7.2) is a valid JWS that this engine does not verify, so it is
blocked, never a malformed token. Both guards go by the exact shape of the body, so that a
system under test cannot use them to turn a fail into a blocked step. Test-local loopback
handlers and the local reference system only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from validation.rig import FIXTURES

from dppce.adapters.common import is_linkset
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import CheckOutcome, ExecutionStatus
from tests import test_review_findings
from tests.test_resolved_target import (
    ITEM_PATH,
    PASSPORT,
    RESOLVER_PATH,
    Origin,
    Route,
    _signed,
    resolved_context,
    served,
    template_mode,
)
from tests.test_review_findings import token
from tests.test_url_templates import run

pki = test_review_findings.pki  # the module fixture of the integrity tests

LINKSET_TYPE = "application/linkset+json"
NATIVE_TYPE = "application/linkset"


def linkset(origin: str) -> bytes:
    """An RFC 9264 linkset whose anchor is the carrier URL and whose one link names the passport."""
    anchor = origin + RESOLVER_PATH
    links = [{"href": origin + ITEM_PATH, "type": "application/json"}]
    return json.dumps({"linkset": [{"anchor": anchor, "describedby": links}]}).encode()


def native_linkset(origin: str) -> bytes:
    """The same linkset in the native format of RFC 9264."""
    return f'<{origin}{ITEM_PATH}>; rel="describedby"; anchor="{origin}{RESOLVER_PATH}"'.encode()


def answer(body: bytes, media: str = LINKSET_TYPE) -> Route:
    return 200, body, {"Content-Type": media}


def with_linkset(origin: str) -> bytes:
    """The passport with a linkset member added. It is still a passport, so every check judges it."""
    return json.dumps(json.loads(PASSPORT) | json.loads(linkset(origin))).encode()


def _blocked(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def _failed(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, False, code)


# -- is_linkset -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"linkset": [{"anchor": "a"}]}, True),
        ({"linkset": [{"anchor": "a"}, {}]}, True),
        # RFC 9264, section 4.2.1: "linkset" is the only member. Any other member makes a passport.
        ({"linkset": [{"anchor": "a"}], "id": "x"}, False),
        ({"id": "x", "linkset": [{"anchor": "a"}]}, False),
        ({"linkset": []}, False),
        ({"linkset": ["a"]}, False),
        ({"linkset": [{"anchor": "a"}, "b"]}, False),
        ({"linkset": {"anchor": "a"}}, False),
        ({"id": "x"}, False),
        ({}, False),
        (None, False),
    ],
)
def test_is_linkset_by_its_shape_only(document: dict[str, Any] | None, expected: bool) -> None:
    assert is_linkset(document) is expected


# -- identifier.resolve ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "media", [LINKSET_TYPE, "application/linkset+json; charset=utf-8", "application/json"]
)
def test_resolve_does_not_call_a_linkset_a_passport(media: str, tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin), media)
    _blocked(run(resolved_context(tmp_path, "identifier.resolve", api.origin)), "IDENTIFIER.RESPONSE.LINKSET")


@pytest.mark.parametrize("media", [LINKSET_TYPE, NATIVE_TYPE])
def test_resolve_judges_a_passport_with_a_linkset_media_type_by_its_body(
    media: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(with_linkset(api.origin), media)
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED")


def test_resolve_judges_a_native_linkset_as_any_body_that_is_not_json(tmp_path: Path, loopback: Any) -> None:
    # The native format has no JSON shape, so the media type and JSON-object rules apply.
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(native_linkset(api.origin), NATIVE_TYPE)
    _failed(run(resolved_context(tmp_path, "identifier.resolve", api.origin)), "IDENTIFIER.RESPONSE.NOT_JSON")
    params = {"accepted_media_types": [NATIVE_TYPE]}
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin, params=params))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED.MEDIA_TYPE")


def test_resolve_with_the_linkset_media_type_accepted_is_a_media_type_pass(
    tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin))
    params = {"accepted_media_types": [LINKSET_TYPE, "application/json"]}
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin, params=params))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED.MEDIA_TYPE")


def test_resolve_with_the_linkset_shape_and_json_accepted_stays_blocked(
    tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin), "application/json")
    params = {"accepted_media_types": ["application/json"]}
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin, params=params))
    _blocked(outcome, "IDENTIFIER.RESPONSE.LINKSET")


def test_resolve_keeps_the_media_type_fail_for_a_type_that_is_not_accepted(
    tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin))
    params = {"accepted_media_types": ["text/html"]}
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin, params=params))
    assert (outcome.passed, outcome.reason_code) == (False, "IDENTIFIER.RESPONSE.MEDIA_TYPE")


def test_control_a_passport_still_resolves(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {RESOLVER_PATH: served(b'{"id": "x", "linkset": "not a list"}')})
    outcome = run(resolved_context(tmp_path, "identifier.resolve", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTIFIER.RESOLVED")


# -- identifier.consistency -----------------------------------------------------------------------


@pytest.mark.parametrize("media", [LINKSET_TYPE, "application/json"])
def test_consistency_has_no_passport_in_a_linkset(media: str, tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin), media)
    ctx = template_mode(resolved_context(tmp_path, "identifier.consistency", api.origin))
    _blocked(run(ctx), "IDENTIFIER.NOT_RESOLVED")


@pytest.mark.parametrize("media", ["application/json", LINKSET_TYPE, NATIVE_TYPE])
def test_consistency_reports_the_mismatch_of_a_passport_with_a_linkset_member(
    media: str, tmp_path: Path, loopback: Any
) -> None:
    # Its id is not the carrier. A linkset member or a linkset media type must not hide that.
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(with_linkset(api.origin), media)
    ctx = template_mode(resolved_context(tmp_path, "identifier.consistency", api.origin))
    _failed(run(ctx), "IDENTIFIER.MISMATCH")


def test_control_a_consistent_passport_still_passes(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = served(json.dumps({"id": api.origin + RESOLVER_PATH}).encode())
    ctx = template_mode(resolved_context(tmp_path, "identifier.consistency", api.origin))
    assert run(ctx).reason_code == "IDENTIFIER.CONSISTENT"


# -- item_target: resolved ------------------------------------------------------------------------


@pytest.mark.parametrize("media", [LINKSET_TYPE, "application/json"])
@pytest.mark.parametrize(
    ("check", "params"),
    [
        ("data.jsonschema", None),
        ("data.context", {"allowed_contexts": ["https://example.test/c"]}),
        ("data.rules", None),
    ],
)
def test_a_resolved_linkset_is_no_item_target(
    check: str, params: dict[str, Any] | None, media: str, tmp_path: Path, loopback: Any
) -> None:
    # The resolver answers 200 with no redirect, so the carrier URL would be the passport URL.
    api = Origin(loopback, {ITEM_PATH: served(PASSPORT)})
    api.routes[RESOLVER_PATH] = answer(linkset(api.origin), media)
    _blocked(run(resolved_context(tmp_path, check, api.origin, params=params)), "DATA.NO_TARGET")
    assert api.hits(ITEM_PATH) == 0


@pytest.mark.parametrize("media", [LINKSET_TYPE, "application/json"])
def test_a_resolved_passport_with_a_linkset_member_is_the_item_target(
    media: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    api.routes[RESOLVER_PATH] = answer(with_linkset(api.origin), media)
    outcome = run(resolved_context(tmp_path, "data.jsonschema", api.origin))
    assert (outcome.passed, outcome.reason_code) == (True, "DATA.SCHEMA.OK")
    assert api.hits(RESOLVER_PATH) == 1, "the check reuses the resolver exchange for the same URL"


# -- integrity.jws: the JSON serialization --------------------------------------------------------


def _json_serialization(pki: dict[str, Any], form: str) -> bytes:
    protected, payload, signature = token(pki["header"], PASSPORT, pki["leaf"][0]).split(".")
    if form == "flattened":
        return json.dumps({"protected": protected, "payload": payload, "signature": signature}).encode()
    signatures = [{"protected": protected, "signature": signature}]
    return json.dumps({"payload": payload, "signatures": signatures}).encode()


def _unsupported_with_the_signed_exchange(outcome: CheckOutcome) -> None:
    _blocked(outcome, "INTEGRITY.FORMAT.UNSUPPORTED")
    (observation,) = outcome.observations
    assert observation.kind == "exchange"
    assert len(observation.record_ids) == 1, "the record of the signed resource, and nothing else"
    assert observation.summary == {"findings": {"status": 200, "structure": "a JWS JSON serialization"}}


@pytest.mark.parametrize("form", ["flattened", "general"])
def test_a_jws_json_serialization_is_unsupported_not_malformed(
    form: str, pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    signed = (200, _json_serialization(pki, form), {"Content-Type": "application/jose+json"})
    api = Origin(loopback, {f"{ITEM_PATH}/signed": signed, ITEM_PATH: served(PASSPORT)})
    ctx = template_mode(resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"]))
    _unsupported_with_the_signed_exchange(run(ctx))


def test_the_reference_flag_signed_jws_json_is_unsupported(pki: dict[str, Any], tmp_path: Path) -> None:
    with ReferenceServer(FIXTURES, faults=frozenset({"signed_jws_json"})) as server:
        ctx = template_mode(resolved_context(tmp_path, "integrity.jws", server.origin, trust=pki["trust"]))
        _unsupported_with_the_signed_exchange(run(ctx))


_HEADER = "eyJhbGciOiJFUzI1NiJ9"  # base64url of {"alg":"ES256"}
_SIGNATURE = "c2ln"


def jose(**members: Any) -> bytes:
    return json.dumps(members).encode()


@pytest.mark.parametrize(
    "body",
    [
        b'{"payload": "e30"}',
        # RFC 7515, section 7.2: the member types make the serialization, not the key names.
        b'{"payload": 1, "signature": 2}',
        b'{"payload": "x", "signatures": "no"}',
        b'{"payload": "x", "signatures": []}',
        b'{"payload": "x", "signatures": [{"signature": 1}]}',
        # The member values must have the shape of RFC 7515, section 7.2, too.
        b'{"payload": "x", "signature": "y"}',
        jose(payload="e30", signature=_SIGNATURE),
        jose(payload="e30", header=None, signature=_SIGNATURE),
        jose(payload="e30", protected=None, header={}, signature=_SIGNATURE),
        jose(payload="e30", header="x", signature=_SIGNATURE),
        jose(payload="e30", header=[], signature=_SIGNATURE),
        jose(payload="", protected=_HEADER, signature=_SIGNATURE),
        jose(payload="e30=", protected=_HEADER, signature=_SIGNATURE),
        jose(payload="e3+/", protected=_HEADER, signature=_SIGNATURE),
        jose(payload="e30", protected=_HEADER, signature=""),
        jose(payload="e30", protected=_HEADER, signature="c2ln=="),
        jose(payload="e30", protected="", signature=_SIGNATURE),
        jose(payload="e30", protected="bm90IGpzb24", signature=_SIGNATURE),  # not JSON
        jose(payload="e30", protected="W10", signature=_SIGNATURE),  # JSON, not an object
        jose(payload="e30", protected="e30=", signature=_SIGNATURE),
        jose(payload="e30", protected="e", signature=_SIGNATURE),  # not decodable
        jose(payload="e30", signatures=[{"signature": _SIGNATURE}]),
        jose(payload="e30", signatures=[{"protected": _HEADER, "signature": _SIGNATURE}, "x"]),
        jose(payload="e30", signatures=[{"protected": "W10", "signature": _SIGNATURE}]),
        # A mixed form: the members of one signature at the top level and a signatures list.
        jose(
            payload="e30",
            protected=_HEADER,
            signature=_SIGNATURE,
            signatures=[{"protected": _HEADER, "signature": _SIGNATURE}],
        ),
        jose(payload="e30", header={}, signatures=[{"protected": _HEADER, "signature": _SIGNATURE}]),
    ],
)
def test_control_a_json_object_that_is_no_jws_stays_malformed(
    body: bytes, pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    signed = (200, body, {"Content-Type": "application/json"})
    api = Origin(loopback, {f"{ITEM_PATH}/signed": signed, ITEM_PATH: served(PASSPORT)})
    ctx = template_mode(resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"]))
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code) == (False, "INTEGRITY.TOKEN.MALFORMED")


# -- integrity.jws: a linkset as the published passport -------------------------------------------


# With item_target: resolved, item_url blocks the linkset first. The integrity guard covers the template.
@pytest.mark.parametrize(
    ("item_target", "code"),
    [("resolved", "INTEGRITY.NO_TARGET"), ("template", "INTEGRITY.PAYLOAD.NOT_COMPARABLE")],
)
def test_integrity_does_not_compare_a_signed_payload_with_a_linkset(
    item_target: str, code: str, pki: dict[str, Any], tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    body = linkset(api.origin)
    # The signer signed the linkset bytes. Equal bytes still do not make the linkset a passport.
    api.routes[f"{ITEM_PATH}/signed"] = _signed(pki, body)
    api.routes[RESOLVER_PATH] = answer(body)
    api.routes[ITEM_PATH] = answer(body)
    ctx = resolved_context(tmp_path, "integrity.jws", api.origin, trust=pki["trust"])
    ctx = ctx if item_target == "resolved" else template_mode(ctx)
    _blocked(run(ctx), code)
