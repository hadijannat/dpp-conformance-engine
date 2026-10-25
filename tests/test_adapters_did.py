"""did:web resolution: the check identity.did (P2-08).

The URL mapping follows the did:web Method Specification, a W3C CCG report (github.com/w3c-ccg/
did-method-web at commit ea423c1, read on 2026-10-25). The DIDs below are synthetic. The expected
outcome of each seeded fault comes from validation/fault-catalogue.yaml, which was written before
the check existed. Loopback servers, local files, and the local reference system only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.did import DidDocument, did_web_url, resolve_did_web
from dppce.evidence.jws import public_jwk_of
from dppce.infrastructure.reference import did as reference_did
from dppce.infrastructure.reference.base import Request
from dppce.infrastructure.reference_server import ReferenceServer, ReferenceSystem
from dppce.models import CheckOutcome, EvidenceEnvelope, ExecutionStatus, Verdict
from dppce.testdefs.registry import CheckContext
from tests.test_family_profiles import _cli, _example
from tests.test_resolved_target import Origin, moved
from tests.test_review_findings import transport
from tests.test_url_templates import context, ixit, run

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "validation" / "fault-catalogue.yaml"
PROFILE = "family/credentials"
PURPOSE = "TP-VC-DID-001"
PUBLIC = "https://id.example.test"
DID = "did:web:id.example.test"
WELL_KNOWN = "/.well-known/did.json"
KEY = {"kty": "EC", "crv": "P-256", "x": "TEST-ONLY-x", "y": "TEST-ONLY-y"}
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k", "oth")


def _method(ident: str = DID + "#key-1", **changes: Any) -> dict[str, Any]:
    method: dict[str, Any] = {"id": ident, "type": "JsonWebKey", "controller": DID, "publicKeyJwk": dict(KEY)}
    return {k: v for k, v in (method | changes).items() if v is not None}


def _document(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "id": DID,
        "verificationMethod": [_method()],
        "assertionMethod": [DID + "#key-1"],
    }
    return {k: v for k, v in (document | changes).items() if v is not None}


def _body(document: Any) -> bytes:
    return json.dumps(document).encode()


def _ctx(
    tmp_path: Path,
    origin: str,
    *,
    did: str = DID,
    source: str | None = None,
    policy: dict[str, Any] | None = None,
    samples: dict[str, Path] | None = None,
) -> CheckContext:
    params: dict[str, Any] = {"did": did} | ({"source": source} if source is not None else {})
    endpoints = {"api": origin, "registry": origin, "public_origin": PUBLIC, "origin_override": origin}
    the_ixit = ixit(endpoints=endpoints)
    engine = transport(policy, samples=samples or {})
    return context(tmp_path, "identity.did", params=params, the_ixit=the_ixit, acquirer=engine)


def _live(tmp_path: Path, loopback: Any, route: tuple[int, bytes, dict[str, str]], **kw: Any) -> CheckOutcome:
    api = Origin(loopback, {WELL_KNOWN: route})
    return run(_ctx(tmp_path, api.origin, **kw))


def _served(document: Any) -> tuple[int, bytes, dict[str, str]]:
    return 200, _body(document), {"Content-Type": "application/did+json"}


def _failed(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, False, code)


def _not_done(outcome: CheckOutcome, status: ExecutionStatus, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (status, None, code)


# -- the did:web to URL mapping --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("did", "url"),
    [
        (DID, "https://id.example.test/.well-known/did.json"),
        ("did:web:id.example.test%3A8443", "https://id.example.test:8443/.well-known/did.json"),
        ("did:web:id.example.test%3a8443", "https://id.example.test:8443/.well-known/did.json"),
        ("did:web:id.example.test:issuers:acme", "https://id.example.test/issuers/acme/did.json"),
        ("did:web:id.example.test%3A8443:a:b_c.d-e", "https://id.example.test:8443/a/b_c.d-e/did.json"),
    ],
)
def test_a_did_web_maps_to_an_https_url(did: str, url: str) -> None:
    assert did_web_url(did) == url


@pytest.mark.parametrize(
    "did",
    [
        "did:web:",
        "did:key:z6MkTEST",
        "did:web:127.0.0.1",
        "did:web:id.example.test%3A0",
        "did:web:id.example.test%3A65536",
        "did:web:id.example.test%3A",
        "did:web:id.example.test%3A1%3A2",
        "did:web:id.example.test%2F",
        "did:web:id.example.test::a",
        "did:web:id.example.test:..",
        "did:web:id.example.test:.",
        "did:web:id.example.test:a%2Fb",
        "did:web:id.example.test/a",
        "did:web:id.example.test#key-1",
        "did:web:id.example.test?service=x",
        "did:web:user@id.example.test",
        "did:web:-id.example.test",
        "did:web:id.example.test\n",
        "did:web:" + "a" * 300,
    ],
)
def test_a_text_that_is_not_a_did_web_maps_to_no_url(did: str) -> None:
    assert did_web_url(did) is None


# -- live resolution on loopback -------------------------------------------------------------------


def test_a_valid_document_passes_and_the_summary_holds_no_value(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {WELL_KNOWN: _served(_document())})
    outcome = run(_ctx(tmp_path, api.origin))
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        "IDENTITY.DID.OK",
    )
    assert [seen["path"] for seen in api.server.seen] == [WELL_KNOWN]
    assert "trust" in outcome.message
    (observation,) = outcome.observations
    assert observation.summary["source"] == "live"
    assert observation.transformations == ("origin_override",)
    text = json.dumps([o.summary for o in outcome.observations])
    for value in ("did:", "http", "TEST-ONLY"):
        assert value not in text


def test_a_did_with_a_path_fetches_the_path(tmp_path: Path, loopback: Any) -> None:
    did = DID + ":issuers:acme"
    document = _document(
        id=did, verificationMethod=[_method(did + "#k", controller=did)], assertionMethod=["#k"]
    )
    api = Origin(loopback, {"/issuers/acme/did.json": _served(document)})
    outcome = run(_ctx(tmp_path, api.origin, did=did))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTITY.DID.OK")


@pytest.mark.parametrize(
    "document",
    [
        _document(verificationMethod=[_method("#key-1")], assertionMethod=["#key-1"]),
        _document(assertionMethod=["#key-1"]),
        _document(verificationMethod=None, assertionMethod=[_method()]),
        _document(verificationMethod=None, assertionMethod=None),
        _document(controller=[DID, "did:web:other.example.test"]),
        _document(service=[{"id": "#s", "type": "x", "serviceEndpoint": "https://elsewhere.example.test"}]),
    ],
    ids=[
        "relative-ids",
        "relative-reference",
        "embedded",
        "no-methods",
        "document-controllers",
        "other-members",
    ],
)
def test_a_valid_document_in_another_shape_passes(document: Any, tmp_path: Path, loopback: Any) -> None:
    outcome = _live(tmp_path, loopback, _served(document))
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTITY.DID.OK"), outcome.message


@pytest.mark.parametrize(
    "document",
    [
        _document(id="did:web:other.example.test"),
        _document(id=DID + ":x"),
        _document(id="DID:web:id.example.test"),
        _document(id=None),
        _document(id=7),
    ],
)
def test_an_id_other_than_the_did_fails(document: Any, tmp_path: Path, loopback: Any) -> None:
    _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.ID_MISMATCH")


@pytest.mark.parametrize("member", PRIVATE_MEMBERS)
def test_a_private_key_member_fails(member: str, tmp_path: Path, loopback: Any) -> None:
    jwk = KEY | {member: "TEST-ONLY-private"}
    document = _document(verificationMethod=[_method(publicKeyJwk=jwk)])
    _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.PRIVATE_KEY")


def test_a_private_key_in_an_embedded_assertion_method_fails(tmp_path: Path, loopback: Any) -> None:
    document = _document(assertionMethod=[_method(DID + "#key-2", publicKeyJwk=KEY | {"d": "TEST-ONLY"})])
    _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.PRIVATE_KEY")


def test_a_private_key_is_not_hidden_by_another_defect(tmp_path: Path, loopback: Any) -> None:
    # A broken method or an unread key format must not turn the private key fail into another outcome.
    leaked = _method(DID + "#key-2", publicKeyJwk=KEY | {"d": "TEST-ONLY"})
    for others in ([_method(DID + "#x", type=None)], [_method(DID + "#m", publicKeyJwk=None)], [7]):
        document = _document(verificationMethod=[*others, leaked], assertionMethod=["#nope"])
        _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.PRIVATE_KEY")


@pytest.mark.parametrize(
    "document",
    [
        _document(verificationMethod={"id": DID + "#key-1"}),
        _document(verificationMethod=[7]),
        _document(verificationMethod=[_method(id=None)]),
        _document(verificationMethod=[_method(id=7)]),
        _document(verificationMethod=[_method(type=None)]),
        _document(verificationMethod=[_method(controller=None)]),
        _document(verificationMethod=[_method(controller=7)]),
        # DID Core 1.0: the controller of a verification method is one DID string.
        _document(verificationMethod=[_method(controller=[DID])]),
        _document(verificationMethod=[_method(publicKeyJwk="TEST-ONLY")]),
        _document(verificationMethod=[{**_method(), "publicKeyJwk": None}]),
        _document(verificationMethod=[_method(publicKeyJwk={"crv": "P-256"})]),
        _document(verificationMethod=[_method(), _method("#key-1")]),
        _document(assertionMethod=[_method(type=None)]),
    ],
)
def test_a_malformed_verification_method_fails(document: Any, tmp_path: Path, loopback: Any) -> None:
    _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.VERIFICATION_METHOD")


@pytest.mark.parametrize(
    "document",
    [
        _document(assertionMethod=["#nope"]),
        _document(assertionMethod=["did:web:other.example.test#key-1"]),
        _document(assertionMethod=[7]),
        _document(assertionMethod=DID + "#key-1"),
        _document(verificationMethod=None),
    ],
)
def test_an_assertion_method_that_does_not_resolve_in_the_document_fails(
    document: Any, tmp_path: Path, loopback: Any
) -> None:
    _failed(_live(tmp_path, loopback, _served(document)), "IDENTITY.DID.ASSERTION_UNRESOLVED")


def test_a_method_without_a_jwk_is_an_engine_limit(tmp_path: Path, loopback: Any) -> None:
    method = _method(publicKeyJwk=None, publicKeyMultibase="zTEST-ONLY")
    outcome = _live(tmp_path, loopback, _served(_document(verificationMethod=[method])))
    _not_done(outcome, ExecutionStatus.UNSUPPORTED, "IDENTITY.DID.KEY_FORMAT")


@pytest.mark.parametrize("status", [404, 410, 401, 403, 400])
def test_a_status_other_than_200_fails(status: int, tmp_path: Path, loopback: Any) -> None:
    _failed(_live(tmp_path, loopback, (status, b'{"error": "x"}', {})), "IDENTITY.DID.STATUS")


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'"did"', b'{"id": "did:web:id.example.test", "id": "x"}', b"\xff\xfe"],
)
def test_a_body_that_is_not_one_json_object_fails(body: bytes, tmp_path: Path, loopback: Any) -> None:
    _failed(_live(tmp_path, loopback, (200, body, {})), "IDENTITY.DID.NOT_JSON")


def test_a_status_fail_is_not_hidden_by_an_unusable_body(tmp_path: Path, loopback: Any) -> None:
    route = (404, b'{"error": "' + b"x" * 4096 + b'"}', {"Content-Encoding": "gzip"})
    _failed(_live(tmp_path, loopback, route, policy={"max_body_bytes": 1024}), "IDENTITY.DID.STATUS")


def test_an_encoded_or_truncated_body_is_not_judged(tmp_path: Path, loopback: Any) -> None:
    encoded = (200, _body(_document(id="x")), {"Content-Encoding": "gzip"})
    _not_done(_live(tmp_path, loopback, encoded), ExecutionStatus.BLOCKED, "TRANSPORT.BODY_ENCODED")
    long = _served(_document(padding="x" * 4096))
    outcome = _live(tmp_path, loopback, long, policy={"max_body_bytes": 1024})
    _not_done(outcome, ExecutionStatus.BLOCKED, "TRANSPORT.BODY_TRUNCATED")


def test_a_document_over_the_size_bound_is_not_judged(tmp_path: Path, loopback: Any) -> None:
    huge = _served(_document(padding="x" * (1024 * 1024)))
    outcome = _live(tmp_path, loopback, huge, policy={"max_body_bytes": 4 * 1024 * 1024})
    _not_done(outcome, ExecutionStatus.BLOCKED, "IDENTITY.DID.TOO_LARGE")


def test_a_redirected_document_that_would_pass_is_blocked(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[WELL_KNOWN] = moved(api.origin + "/moved.json")
    api.routes["/moved.json"] = _served(_document())
    _not_done(run(_ctx(tmp_path, api.origin)), ExecutionStatus.BLOCKED, "IDENTITY.DID.REDIRECTED")


def test_a_redirect_does_not_hide_a_fail(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    api.routes[WELL_KNOWN] = moved(api.origin + "/moved.json")
    api.routes["/moved.json"] = _served(_document(id="did:web:other.example.test"))
    _failed(run(_ctx(tmp_path, api.origin)), "IDENTITY.DID.ID_MISMATCH")


def test_a_server_error_is_no_answer(tmp_path: Path, loopback: Any) -> None:
    outcome = _live(tmp_path, loopback, (503, b"{}", {}))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


def test_a_did_host_outside_the_policy_is_denied_and_nothing_is_sent(tmp_path: Path, loopback: Any) -> None:
    # The DID host is often a third party. Only the engine transport and its policy decide.
    api = Origin(loopback, {WELL_KNOWN: _served(_document())})
    outcome = run(_ctx(tmp_path, api.origin, did="did:web:issuer.example.test"))
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (False, True, "TRANSPORT.DENIED")
    assert api.server.seen == []


@pytest.mark.parametrize(
    "params",
    [{}, {"did": "did:web:127.0.0.1"}, {"did": 7}, {"did": DID, "source": ""}, {"did": DID, "source": 7}],
)
def test_invalid_parameters_send_nothing(params: dict[str, Any], tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {WELL_KNOWN: _served(_document())})
    ctx = _ctx(tmp_path, api.origin)
    ctx = context(tmp_path, "identity.did", params=params, the_ixit=ctx.ixit, acquirer=ctx.acquirer)
    _not_done(run(ctx), ExecutionStatus.BLOCKED, "IDENTITY.DID.PARAMS_INVALID")
    assert api.server.seen == []


# -- the offline copy ------------------------------------------------------------------------------


def test_an_offline_copy_is_judged_without_a_request(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback, {WELL_KNOWN: _served(_document(id="x"))})
    sample = tmp_path / "TEST-ONLY-did.json"
    sample.write_bytes(_body(_document()))
    ctx = _ctx(tmp_path, api.origin, source="did_document", samples={"did_document": sample})
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, "IDENTITY.DID.OK")
    assert api.server.seen == []
    (observation,) = outcome.observations
    assert (observation.kind, observation.summary["source"]) == ("artifact", "sample")


def test_an_offline_copy_gets_the_same_document_rules(tmp_path: Path, loopback: Any) -> None:
    sample = tmp_path / "TEST-ONLY-did.json"
    sample.write_bytes(_body(_document(id="did:web:other.example.test")))
    api = Origin(loopback)
    ctx = _ctx(tmp_path, api.origin, source="did_document", samples={"did_document": sample})
    _failed(run(ctx), "IDENTITY.DID.ID_MISMATCH")
    sample.write_bytes(b"not json")
    _failed(run(_ctx(tmp_path, api.origin, source="did_document", samples={"did_document": sample})),
            "IDENTITY.DID.NOT_JSON")  # fmt: skip


def test_a_missing_offline_copy_is_blocked(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    outcome = run(_ctx(tmp_path, api.origin, source="did_document"))
    _not_done(outcome, ExecutionStatus.BLOCKED, "IDENTITY.DID.SAMPLE_MISSING")
    assert api.server.seen == []


# -- the function that later checks reuse -----------------------------------------------------------


def test_resolve_did_web_gives_the_public_keys_by_absolute_method_id(tmp_path: Path, loopback: Any) -> None:
    other = {"kty": "OKP", "crv": "Ed25519", "x": "TEST-ONLY-x"}
    document = _document(
        verificationMethod=[_method("#key-1"), _method(DID + "#key-2", publicKeyJwk=other)],
        assertionMethod=["#key-1", DID + "#key-2"],
    )
    api = Origin(loopback, {WELL_KNOWN: _served(document)})
    resolved = resolve_did_web(_ctx(tmp_path, api.origin), DID)
    assert isinstance(resolved, DidDocument)
    assert resolved.keys == {DID + "#key-1": KEY, DID + "#key-2": other}
    assert resolved.assertion_methods == (DID + "#key-1", DID + "#key-2")
    assert resolved.source == "live"


# -- the reference DID family and the seeded faults --------------------------------------------------


def _did_cases() -> list[dict[str, Any]]:
    document = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    # Some boundary cases name a requirement, not a test purpose.
    entries = (*document["sut_faults"], *document["boundary_cases"])
    return [e for e in entries if e.get("test_purpose") == PURPOSE]


DID_CASES = _did_cases()


def _family_run(tmp_path: Path, faults: frozenset[str] = frozenset()) -> EvidenceEnvelope:
    with ReferenceServer(FIXTURES, faults=faults) as server:
        ics, the_ixit = _example(tmp_path, "credentials", server.origin)
        out = tmp_path / "run"
        _cli(
            [
                "run",
                "--profile", PROFILE,
                "--ics", str(ics),
                "--ixit", str(the_ixit),
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


def _steps(envelope: EvidenceEnvelope) -> dict[str, tuple[str, str]]:
    return {t.test_purpose_id: (t.verdict.value, t.reason_code) for t in envelope.decision.test_results}


def test_the_catalogue_names_the_did_cases() -> None:
    assert sorted(e["id"] for e in DID_CASES) == ["B-15", "F-61", "F-62"]
    assert all(e["profiles"] == [PROFILE] for e in DID_CASES)


def test_the_unmodified_reference_system_passes_every_credential_step(tmp_path: Path) -> None:
    steps = {k: v for k, v in _steps(_family_run(tmp_path)).items() if k.startswith("TP-VC-")}
    assert steps[PURPOSE] == ("pass", "IDENTITY.DID.OK")
    assert all(verdict == "pass" for verdict, _ in steps.values()), steps


@pytest.mark.parametrize("case", DID_CASES, ids=lambda c: str(c["id"]))
def test_each_seeded_did_fault_gives_the_catalogue_outcome(case: dict[str, Any], tmp_path: Path) -> None:
    envelope = _family_run(tmp_path, frozenset({case["fault"]}))
    steps = _steps(envelope)
    expected = case["expected"]
    assert steps[PURPOSE] == (expected["verdict"], expected["reason_code"])
    # Each flag changes the DID document only: the other credential steps still pass.
    others = {k: v for k, v in steps.items() if k.startswith("TP-VC-") and k != PURPOSE}
    assert all(verdict == "pass" for verdict, _ in others.values()), others
    if expected["verdict"] == "fail":
        assert envelope.decision.overall is Verdict.FAIL


def test_the_reference_did_key_is_the_public_key_of_the_test_leaf() -> None:
    leaf = x509.load_pem_x509_certificate((FIXTURES / "pki" / "TEST-ONLY-leaf.cert.pem").read_bytes())
    public = leaf.public_key()
    assert isinstance(public, ec.EllipticCurvePublicKey)
    assert public_jwk_of(public) == reference_did.PUBLIC_JWK


def test_the_did_family_serves_only_the_did_document_path() -> None:
    system = ReferenceSystem(FIXTURES)
    status, media, body, _ = system.respond(Request("GET", WELL_KNOWN, {}))
    assert (status, media) == (200, "application/did+json")
    assert json.loads(body)["id"] == DID
    assert reference_did.respond(system, Request("GET", "/.well-known/gs1resolver", {})) is None
    assert reference_did.respond(system, Request("GET", "/dpp/x/did.json", {})) is None
