"""The check integrity.jose and its JOSE profiles (package P2-07).

Oracles: RFC 7515, RFC 7517, RFC 7518, RFC 8037, and RFC 8725 (IETF), the W3C Recommendation
"Securing Verifiable Credentials using JOSE and COSE" (source record w3c-vc-jose-cose), and the
vendored Wycheproof JWS vectors. The expected outcome of each seeded fault comes from
validation/fault-catalogue.yaml, which was written before the check existed.

Every key here is a TEST-ONLY key, made at run time or published as a test vector. Loopback
servers and local files only. The report signing profile of dppce.evidence.jws is not tested
here and does not change.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.evidence.jose_profiles import MAX_BODY_BYTES, MAX_SIGNATURES, JoseError, parse
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import CheckOutcome, EvidenceEnvelope, ExecutionStatus, TrustBundle, Verdict
from tests.support import make_artifact, make_record
from tests.test_family_profiles import _cli, _example
from tests.test_review_findings import transport
from tests.test_url_templates import context, ixit, run

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "validation" / "fault-catalogue.yaml"
WYCHEPROOF = ROOT / "tests" / "vectors" / "wycheproof" / "TEST-ONLY-json_web_signature_test.json"
TRUST_FILE = FIXTURES / "trust" / "TEST-ONLY-trust-bundle.json"
NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)  # 1791892800, the evaluation time of the rig
PROFILE = "family/credentials"
PURPOSE = "TP-VC-JOSE-001"
ISSUER = "urn:example:operator:0001"
KID = "TEST-ONLY-kid-1"
SUBJECT = "https://id.example.test/01/09506000134352/21/EV0001"
VC_HEADER: dict[str, Any] = {"alg": "ES256", "kid": KID, "typ": "vc+jwt"}

Private = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json(document: Any) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


def p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def sign(private: Private, signing_input: bytes) -> bytes:
    if isinstance(private, ed25519.Ed25519PrivateKey):
        return private.sign(signing_input)
    size = 48 if isinstance(private.curve, ec.SECP384R1) else 32
    digest = hashes.SHA384() if size == 48 else hashes.SHA256()
    r, s = decode_dss_signature(private.sign(signing_input, ec.ECDSA(digest)))
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def jwk(private: Private) -> dict[str, str]:
    public = private.public_key()
    if isinstance(public, ed25519.Ed25519PublicKey):
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
    size = 48 if isinstance(public.curve, ec.SECP384R1) else 32
    numbers = public.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-384" if size == 48 else "P-256",
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
    }


def compact(header: dict[str, Any], payload: bytes, private: Private | None = None) -> str:
    signing_input = f"{b64u(_json(header))}.{b64u(payload)}"
    signature = sign(private, signing_input.encode()) if private is not None else b""
    return f"{signing_input}.{b64u(signature)}"


def flattened(token: str, header: dict[str, Any] | None = None) -> bytes:
    protected, payload, signature = token.split(".")
    member: dict[str, Any] = {"protected": protected, "payload": payload, "signature": signature}
    return _json(member | ({"header": header} if header else {}))


def general(*tokens: str) -> bytes:
    payloads = {t.split(".")[1] for t in tokens}
    assert len(payloads) == 1
    signatures = [{"protected": t.split(".")[0], "signature": t.split(".")[2]} for t in tokens]
    return _json({"payload": payloads.pop(), "signatures": signatures})


def vc(**changes: Any) -> bytes:
    document: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": ISSUER,
        "validFrom": "2026-01-01T00:00:00Z",
        "validUntil": "2036-01-01T00:00:00Z",
        "credentialSubject": {"id": SUBJECT},
    }
    document |= changes
    return _json({k: v for k, v in document.items() if v is not None})


def bundle(
    keys: dict[str, dict[str, str]],
    *,
    issuer: str = ISSUER,
    purposes: tuple[str, ...] = ("passport",),
    window: tuple[str, str] = ("2026-01-01T00:00:00Z", "2036-01-01T00:00:00Z"),
    revoked: tuple[str, ...] = (),
) -> TrustBundle:
    entries = [
        {"kid": kid, "issuer": issuer, "purposes": list(purposes), "public_jwk": public,
         "not_before": window[0], "not_after": window[1]}
        for kid, public in keys.items()
    ]  # fmt: skip
    return TrustBundle.model_validate(
        {
            "schema_version": "dppce.trust/2",
            "policy_version": "TEST-ONLY-jose-1",
            "keys": entries,
            "revoked_keys": [{"kid": kid, "revoked_at": None} for kid in revoked],
        }
    )


class Served:
    """An acquirer that answers every fetch with one body and holds named local artifacts."""

    def __init__(
        self, body: bytes | str = b"", status: int = 200, artifacts: dict[str, bytes] | None = None
    ) -> None:
        self._body = body.encode() if isinstance(body, str) else body
        self._status, self._artifacts = status, artifacts or {}
        self._records: list[Record] = []
        self.requests: list[Request] = []

    def fetch(self, request: Request) -> Record:
        self.requests.append(request)
        base = make_record(len(self._records) + 1, self._body, request.url)
        record = Record(**{**base.__dict__, "status": self._status})
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        if name not in self._artifacts:
            record = make_artifact(name, error="artifact_unavailable", index=len(self._records) + 1)
        else:
            record = make_artifact(name, self._artifacts[name], index=len(self._records) + 1)
        self._records.append(record)
        return record

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)


def jose(tmp_path: Path, served: Served, trust: TrustBundle | None, **params: Any) -> CheckOutcome:
    ctx = context(tmp_path, "integrity.jose", params=params, acquirer=served, trust=trust)  # type: ignore[arg-type]
    return run(replace(ctx, evaluation_time=NOW))


def failed(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.COMPLETED, False, code)
    assert not outcome.unreachable


def is_blocked(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.BLOCKED, None, code)


def passed(outcome: CheckOutcome) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        "INTEGRITY.JOSE.OK",
    ), outcome.message


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return p256()


@pytest.fixture
def trust(key: ec.EllipticCurvePrivateKey) -> TrustBundle:
    return bundle({KID: jwk(key)})


# -- the vc-jose profile with a pinned key ---------------------------------------------------------


@pytest.mark.parametrize(
    ("alg", "make"),
    [
        ("ES256", p256),
        ("ES384", lambda: ec.generate_private_key(ec.SECP384R1())),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate),
    ],
)
def test_a_vc_jose_credential_signed_with_a_pinned_key_passes(tmp_path: Path, alg: str, make: Any) -> None:
    private = make()
    served = Served(compact({**VC_HEADER, "alg": alg}, vc(), private))
    outcome = jose(tmp_path, served, bundle({KID: jwk(private)}), accept="application/vc+jwt")
    passed(outcome)
    assert served.requests[0].headers == {"Accept": "application/vc+jwt"}
    summary = outcome.observations[0].summary["findings"]
    assert summary["serialization"] == "compact"
    assert "valid" in str(summary["signature"])


def test_each_serialization_verifies_and_every_signature_must_verify(tmp_path: Path) -> None:
    first, second = p256(), ed25519.Ed25519PrivateKey.generate()
    trust = bundle({"TEST-ONLY-a": jwk(first), "TEST-ONLY-b": jwk(second)})
    one = compact({**VC_HEADER, "kid": "TEST-ONLY-a"}, vc(), first)
    two = compact({"alg": "EdDSA", "kid": "TEST-ONLY-b", "typ": "vc+jwt"}, vc(), second)
    for body in (one.encode(), flattened(one), general(one, two)):
        passed(jose(tmp_path, Served(body), trust))
    # The general form passes only if each signature verifies, not if one of them does.
    broken = two[:-4] + ("AAAA" if not two.endswith("AAAA") else "BBBB")
    failed(jose(tmp_path, Served(general(one, broken)), trust), "INTEGRITY.JOSE.SIGNATURE")
    unknown = compact({**VC_HEADER, "kid": "TEST-ONLY-unknown"}, vc(), first)
    failed(jose(tmp_path, Served(general(one, unknown)), trust), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")


def test_a_tampered_payload_fails_in_each_serialization(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    good = compact(VC_HEADER, vc(), key)
    protected, _, signature = good.split(".")
    tampered = f"{protected}.{b64u(vc(credentialSubject={'id': 'urn:example:other'}))}.{signature}"
    # A JSON serialization of the same bytes is no way out of the fail (lesson of waves 1 and 2).
    for body in (tampered.encode(), flattened(tampered), general(tampered)):
        failed(jose(tmp_path, Served(body), trust), "INTEGRITY.JOSE.SIGNATURE")


def test_a_wrong_signature_length_is_an_invalid_signature(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    good = compact(VC_HEADER, vc(), key)
    for signature in (b64u(b"\x00" * 63), b64u(b"\x01" * 2048), ""):
        token = good.rsplit(".", 1)[0] + "." + signature
        failed(jose(tmp_path, Served(token), trust), "INTEGRITY.JOSE.SIGNATURE")


# -- RFC 8725: the algorithm comes from the profile and the key, never from the header ------------


def _mac(header: dict[str, Any], payload: bytes, secret: bytes, digest: Any) -> str:
    signing_input = f"{b64u(_json(header))}.{b64u(payload)}"
    return f"{signing_input}.{b64u(hmac.new(secret, signing_input.encode(), digest).digest())}"


@pytest.mark.parametrize("kid", [KID, "TEST-ONLY-unknown"])
def test_none_and_hmac_algorithms_fail_before_any_key_is_looked_up(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, kid: str
) -> None:
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    tokens = [compact({**VC_HEADER, "alg": "none", "kid": kid}, vc())]
    for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
        tokens.append(_mac({**VC_HEADER, "alg": alg, "kid": kid}, vc(), spki, digest))
    for token in tokens:
        failed(jose(tmp_path, Served(token), trust), "INTEGRITY.JOSE.ALGORITHM")


@pytest.mark.parametrize("alg", ["ES384", "EdDSA", "ES512", "RS256", "PS256", "ES256K", "none ", "es256"])
def test_a_header_algorithm_that_the_key_does_not_dictate_fails(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, alg: str
) -> None:
    token = compact({**VC_HEADER, "alg": alg}, vc(), key)
    failed(jose(tmp_path, Served(token), trust), "INTEGRITY.JOSE.ALGORITHM")


def test_the_allowlist_parameter_narrows_the_profile(tmp_path: Path) -> None:
    private = ed25519.Ed25519PrivateKey.generate()
    token = compact({**VC_HEADER, "alg": "EdDSA"}, vc(), private)
    trust = bundle({KID: jwk(private)})
    passed(jose(tmp_path, Served(token), trust, algorithms=["EdDSA"]))
    failed(jose(tmp_path, Served(token), trust, algorithms=["ES256"]), "INTEGRITY.JOSE.ALGORITHM")


def test_a_trusted_key_of_a_type_that_this_engine_does_not_verify_is_blocked(tmp_path: Path) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    public = {"kty": "RSA", "n": b64u(numbers.n.to_bytes(256, "big")), "e": b64u(b"\x01\x00\x01")}
    token = compact({**VC_HEADER, "alg": "PS256"}, vc(), p256())
    is_blocked(jose(tmp_path, Served(token), bundle({KID: public})), "INTEGRITY.JOSE.UNSUPPORTED")
    p521 = ec.generate_private_key(ec.SECP521R1()).public_key().public_numbers()
    curve = {
        "kty": "EC",
        "crv": "P-521",
        "x": b64u(p521.x.to_bytes(66, "big")),
        "y": b64u(p521.y.to_bytes(66, "big")),
    }
    is_blocked(jose(tmp_path, Served(token), bundle({KID: curve})), "INTEGRITY.JOSE.UNSUPPORTED")


# -- header rules: crit, b64, typ -------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["vc-jose", "jws"])
def test_an_extension_in_crit_fails_and_a_malformed_crit_is_malformed(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, profile: str
) -> None:
    extension = compact({**VC_HEADER, "crit": ["urn:example:ext"], "urn:example:ext": 1}, vc(), key)
    failed(jose(tmp_path, Served(extension), trust, profile=profile), "INTEGRITY.JOSE.HEADER")
    for crit in ([], ["urn:example:absent"], "b64", [7]):
        token = compact({**VC_HEADER, "crit": crit}, vc(), key)
        failed(jose(tmp_path, Served(token), trust, profile=profile), "INTEGRITY.JOSE.MALFORMED")
    good = compact(VC_HEADER, vc(), key)
    # RFC 7515, section 4.1.11: crit must be integrity protected.
    unprotected = flattened(good, {"crit": ["x"], "x": 1})
    failed(jose(tmp_path, Served(unprotected), trust, profile=profile), "INTEGRITY.JOSE.MALFORMED")
    # RFC 7515, section 7.2.1: the protected and the unprotected header are disjoint.
    repeated = flattened(good, {"kid": KID})
    failed(jose(tmp_path, Served(repeated), trust, profile=profile), "INTEGRITY.JOSE.MALFORMED")


def test_an_unencoded_payload_is_outside_vc_jose_and_an_unsupported_form_of_jws(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    token = compact({**VC_HEADER, "b64": False, "crit": ["b64"]}, vc(), key)
    failed(jose(tmp_path, Served(token), trust), "INTEGRITY.JOSE.HEADER")
    is_blocked(jose(tmp_path, Served(token), trust, profile="jws"), "INTEGRITY.JOSE.UNSUPPORTED")
    not_boolean = compact({**VC_HEADER, "b64": "false", "crit": ["b64"]}, vc(), key)
    failed(jose(tmp_path, Served(not_boolean), trust, profile="jws"), "INTEGRITY.JOSE.MALFORMED")
    # RFC 7797, section 6: b64 is protected and crit names it. Any other b64 is not that form, so a
    # system under test cannot turn a bad signature into a blocked step with one more member.
    zeroed = f"{b64u(_json(VC_HEADER))}.{b64u(vc())}.{b64u(bytes(64))}"
    for profile in ("vc-jose", "jws"):
        unprotected = jose(tmp_path, Served(flattened(zeroed, {"b64": False})), trust, profile=profile)
        failed(unprotected, "INTEGRITY.JOSE.MALFORMED")
        no_crit = compact({**VC_HEADER, "b64": False}, vc(), key)
        failed(jose(tmp_path, Served(no_crit), trust, profile=profile), "INTEGRITY.JOSE.MALFORMED")
    # b64 true is the default form (RFC 7797, section 3).
    passed(jose(tmp_path, Served(compact({**VC_HEADER, "b64": True, "crit": ["b64"]}, vc(), key)), trust))


@pytest.mark.parametrize(
    ("typ", "ok"),
    [(None, True), ("vc+jwt", True), ("application/vc+jwt", True), ("VC+JWT", True),
     ("JWT", False), ("dpp+jws", False), ("vc+ld+json+jwt", False), (7, False)],
)  # fmt: skip
def test_a_present_typ_must_name_vc_jwt(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, typ: Any, ok: bool
) -> None:
    header = {k: v for k, v in VC_HEADER.items() if k != "typ"} | ({} if typ is None else {"typ": typ})
    outcome = jose(tmp_path, Served(compact(header, vc(), key)), trust)
    if ok:
        passed(outcome)
    else:
        failed(outcome, "INTEGRITY.JOSE.TYPE")


def test_the_jws_profile_reads_no_typ_and_no_claims(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    token = compact({"alg": "ES256", "kid": KID, "typ": "dpp+jws"}, b"\x00 not JSON", key)
    passed(jose(tmp_path, Served(token), trust, profile="jws"))


# -- the trusted key ----------------------------------------------------------------------------------


def test_the_kid_must_name_a_valid_passport_key_of_the_trust_bundle(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    public = {KID: jwk(key)}
    token = compact(VC_HEADER, vc(), key)
    no_kid = compact({k: v for k, v in VC_HEADER.items() if k != "kid"}, vc(), key)
    failed(jose(tmp_path, Served(no_kid), bundle(public)), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    report_key = bundle(public, purposes=("report",))
    failed(jose(tmp_path, Served(token), report_key), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    failed(jose(tmp_path, Served(token), bundle(public, revoked=(KID,))), "INTEGRITY.JOSE.KEY_NOT_VALID")
    late = bundle(public, window=("2026-11-01T00:00:00Z", "2036-01-01T00:00:00Z"))
    failed(jose(tmp_path, Served(token), late), "INTEGRITY.JOSE.KEY_NOT_VALID")
    # The trust bundle binds the key to one issuer. A credential of another issuer is not trusted.
    other = bundle(public, issuer="urn:example:operator:0002")
    failed(jose(tmp_path, Served(token), other), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")


def test_no_trust_bundle_is_blocked_and_nothing_is_fetched(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    served = Served(compact(VC_HEADER, vc(), key))
    is_blocked(jose(tmp_path, served, None), "INTEGRITY.TRUST.MISSING")
    assert served.requests == []


# -- credential claims --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"validUntil": "2026-10-13T11:59:59Z"}, "INTEGRITY.JOSE.EXPIRED"),
        ({"exp": 1791892799}, "INTEGRITY.JOSE.EXPIRED"),  # 2026-10-13T11:59:59Z
        ({"exp": 1791892800}, "INTEGRITY.JOSE.EXPIRED"),  # exactly the evaluation time (RFC 7519, 4.1.4)
        ({"validFrom": "2026-10-13T12:00:01Z"}, "INTEGRITY.JOSE.NOT_YET_VALID"),
        ({"nbf": 1791892801}, "INTEGRITY.JOSE.NOT_YET_VALID"),
        # Moments at the edge of the date range are judged, never an error of the engine.
        ({"validFrom": "9999-12-31T23:59:59-01:00"}, "INTEGRITY.JOSE.NOT_YET_VALID"),
        ({"validUntil": "0001-01-01T00:00:00+01:00"}, "INTEGRITY.JOSE.EXPIRED"),
        ({"iss": "urn:example:operator:0002"}, "INTEGRITY.JOSE.ISSUER_MISMATCH"),
        ({"issuer": None}, "INTEGRITY.JOSE.CLAIMS"),
        ({"issuer": {"name": "no id"}}, "INTEGRITY.JOSE.CLAIMS"),
        ({"validUntil": "2036-01-01"}, "INTEGRITY.JOSE.CLAIMS"),
        ({"validFrom": "2026-01-01T00:00:00"}, "INTEGRITY.JOSE.CLAIMS"),
        ({"exp": True}, "INTEGRITY.JOSE.CLAIMS"),
        ({"exp": "1791892799"}, "INTEGRITY.JOSE.CLAIMS"),
    ],
)
def test_credential_claims_are_judged_at_the_evaluation_time(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, changes: dict[str, Any], code: str
) -> None:
    outcome = jose(tmp_path, Served(compact(VC_HEADER, vc(**changes), key)), trust)
    failed(outcome, code)


@pytest.mark.parametrize(
    "changes",
    [
        {"issuer": {"id": ISSUER, "name": "Example Battery Works (synthetic)"}},
        {"iss": ISSUER, "exp": 2082758400, "nbf": 1767225600.5},
        {"validFrom": "2026-01-01t00:00:00.250+01:00", "validUntil": "2036-12-31T23:59:60Z"},
        {"validFrom": None, "validUntil": None},
        {"validFrom": "0001-01-01T00:00:00+01:00", "validUntil": "9999-12-31T23:59:59-01:00"},
    ],
)
def test_valid_claims_pass(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, changes: dict[str, Any]
) -> None:
    passed(jose(tmp_path, Served(compact(VC_HEADER, vc(**changes), key)), trust))


@pytest.mark.parametrize("payload", [b"not json", b"[1]", b'{"issuer": "a", "issuer": "b"}'])
def test_a_payload_that_is_not_one_json_object_is_a_claims_fail(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, payload: bytes
) -> None:
    failed(jose(tmp_path, Served(compact(VC_HEADER, payload, key)), trust), "INTEGRITY.JOSE.CLAIMS")


# -- shapes and sizes: a system under test cannot reshape a fail into a blocked step -------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not a token",
        b"a.b",
        b"a.b.c.d",
        b"eyJhbGciOiJFUzI1NiJ9.e30.!!!",
        b64u(b"not json").encode() + b".e30.AAAA",
        b64u(b"[1]").encode() + b".e30.AAAA",
        b"\xff\xfe",
        b'{"payload": "e30"}',
        b'{"payload": "e30", "signatures": []}',
        b'{"payload": "e30", "signature": "AAAA", "signatures": [{"protected": "e30", "signature": "AAAA"}]}',
        b'{"payload": "e30", "protected": "e30", "signature": "AAAA", "payload": "e30"}',
        b'{"linkset": [{"anchor": "x"}]}',
        b"[]",
    ],
)
def test_a_body_that_is_no_jws_is_malformed_not_blocked(
    tmp_path: Path, trust: TrustBundle, body: bytes
) -> None:
    failed(jose(tmp_path, Served(body), trust), "INTEGRITY.JOSE.MALFORMED")


def test_an_alg_that_is_not_a_string_is_malformed(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    for header in ({"kid": KID}, {**VC_HEADER, "alg": 256}):
        failed(jose(tmp_path, Served(compact(header, vc(), key)), trust), "INTEGRITY.JOSE.MALFORMED")


def test_size_limits_are_engine_limits(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    token = compact(VC_HEADER, vc(), key)
    is_blocked(jose(tmp_path, Served(token + " " * MAX_BODY_BYTES), trust), "INTEGRITY.JOSE.TOO_LARGE")
    is_blocked(
        jose(tmp_path, Served(general(*[token] * (MAX_SIGNATURES + 1))), trust), "INTEGRITY.JOSE.TOO_LARGE"
    )
    passed(jose(tmp_path, Served(general(*[token] * MAX_SIGNATURES)), trust))


def test_parse_names_the_serialization() -> None:
    token = compact(VC_HEADER, b"{}", p256())
    assert parse(token.encode()).serialization == "compact"
    assert parse(flattened(token)).serialization == "flattened"
    assert parse(general(token, token)).serialization == "general"
    with pytest.raises(JoseError) as caught:
        parse(b"x")
    assert caught.value.code == "INTEGRITY.JOSE.MALFORMED"


# -- the sources ------------------------------------------------------------------------------------


def test_an_offline_credential_sample_is_read_and_nothing_is_fetched(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    served = Served(b"unused", artifacts={"credential": compact(VC_HEADER, vc(), key).encode() + b"\n"})
    outcome = jose(tmp_path, served, trust, source="sample")
    passed(outcome)
    assert served.requests == []
    assert outcome.observations[0].kind == "artifact"
    is_blocked(
        jose(tmp_path, served, trust, source="sample", sample="other"), "INTEGRITY.JOSE.SAMPLE_MISSING"
    )


def test_the_signed_resource_must_answer_200(tmp_path: Path, trust: TrustBundle) -> None:
    failed(jose(tmp_path, Served(b"{}", status=404), trust), "INTEGRITY.JOSE.NOT_AVAILABLE")
    outcome = jose(tmp_path, Served(b"{}", status=503), trust)
    assert (outcome.passed, outcome.unreachable, outcome.reason_code) == (
        False,
        True,
        "TRANSPORT.SERVER_ERROR",
    )


@pytest.mark.parametrize(
    "params",
    [
        {"profile": "jwt"},
        {"key_source": "did"},
        {"source": "resource"},
        {"algorithms": []},
        {"algorithms": ["HS256"]},
        {"algorithms": ["ES256", "ES256"]},
        {"accept": "\n"},
        {"sample": ""},
        {"other": 1},
        # No rule binds the credential issuer to a certificate yet, so vc-jose needs trust_kid.
        {"key_source": "x5c"},
        {"profile": "vc-jose", "key_source": "x5c"},
    ],
)
def test_invalid_parameters_are_blocked_and_nothing_is_read(
    tmp_path: Path, trust: TrustBundle, params: dict[str, Any]
) -> None:
    served = Served(b"x")
    is_blocked(jose(tmp_path, served, trust, **params), "INTEGRITY.JOSE.PARAMS")
    assert served.records() == ()


# -- oracles ---------------------------------------------------------------------------------------

# RFC 8037, Appendix A.1 and A.4: the published Ed25519 test key and its JWS.
RFC8037_PUBLIC = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
RFC8037_JWS = (
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)


def test_the_rfc_8037_ed25519_vector_verifies_and_a_changed_byte_does_not(tmp_path: Path) -> None:
    trust = bundle({"TEST-ONLY-rfc8037": RFC8037_PUBLIC})
    with_kid = Served(RFC8037_JWS)
    # The vector has no kid. Its JSON form adds the kid in the unprotected header.
    protected, payload, signature = RFC8037_JWS.split(".")
    body = _json({"protected": protected, "payload": payload, "signature": signature,
                  "header": {"kid": "TEST-ONLY-rfc8037"}})  # fmt: skip
    passed(jose(tmp_path, Served(body), trust, profile="jws"))
    failed(jose(tmp_path, with_kid, trust, profile="jws"), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    changed = _json({"protected": protected, "payload": payload[:-1] + "Z", "signature": signature,
                     "header": {"kid": "TEST-ONLY-rfc8037"}})  # fmt: skip
    failed(jose(tmp_path, Served(changed), trust, profile="jws"), "INTEGRITY.JOSE.SIGNATURE")


def test_the_wycheproof_es256_vectors_agree(tmp_path: Path) -> None:
    document = json.loads(WYCHEPROOF.read_bytes())
    checked = valid = 0
    not_a_fail: dict[int, tuple[ExecutionStatus, str | None]] = {}
    for group in document["testGroups"]:
        public = group.get("public") or {}
        if (public.get("kty"), public.get("crv")) != ("EC", "P-256"):
            continue
        # The vectors name the kid of the published test key. The use and alg members stay. A
        # trusted key holds string members only, so a key_ops list cannot be pinned.
        trust = bundle({public["kid"]: {k: v for k, v in public.items() if isinstance(v, str)}})
        for test in group["tests"]:
            outcome = jose(tmp_path, Served(test["jws"]), trust, profile="jws")
            checked += 1
            if test["result"] == "valid":
                valid += 1
                passed(outcome)
            elif (outcome.status, outcome.passed) != (ExecutionStatus.COMPLETED, False):
                not_a_fail[test["tcId"]] = (outcome.status, outcome.reason_code)
    assert (checked, valid) == (41, 2)
    # Every other invalid vector is a completed fail: not blocked, not an error. Two vectors change
    # the trusted key, not the token. tcId 354 pins a key with use "enc": the engine does not use
    # that operator key, so the step is blocked. tcId 356 expects a refusal for key_ops ["encrypt"].
    # The trust bundle cannot express key_ops: the operator pins a key for the purpose passport only.
    assert not_a_fail == {
        354: (ExecutionStatus.BLOCKED, "INTEGRITY.JOSE.UNSUPPORTED"),
        356: (ExecutionStatus.COMPLETED, "INTEGRITY.JOSE.OK"),
    }


# -- the reference system: control C-FAMILY-VC and faults F-56 to F-60 --------------------------------


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
                "--trust", str(TRUST_FILE),
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


def _vc_cases() -> list[dict[str, Any]]:
    document = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    return [e for e in document["sut_faults"] if e["test_purpose"] == PURPOSE]


def test_the_catalogue_names_the_credential_faults() -> None:
    cases = _vc_cases()
    assert [c["id"] for c in cases] == ["F-56", "F-57", "F-58", "F-59", "F-60"]
    assert all(c["profiles"] == [PROFILE] for c in cases)


def test_control_c_family_vc_the_unmodified_reference_system_passes(tmp_path: Path) -> None:
    envelope = _family_run(tmp_path)
    steps = _steps(envelope)
    assert steps[PURPOSE] == ("pass", "INTEGRITY.JOSE.OK")
    assert steps["TP-VC-INTEGRITY-001"] == ("pass", "INTEGRITY.OK"), "integrity.jws keeps its answer"
    assert all(v[0] == "pass" for k, v in steps.items() if k.startswith("TP-VC-")), steps
    assert envelope.decision.overall is Verdict.PASS


@pytest.mark.parametrize("case", _vc_cases(), ids=lambda c: str(c["id"]))
def test_each_seeded_credential_fault_gives_the_catalogue_outcome(
    case: dict[str, Any], tmp_path: Path
) -> None:
    envelope = _family_run(tmp_path, frozenset({case["fault"]}))
    steps = _steps(envelope)
    assert steps[PURPOSE] == (case["expected"]["verdict"], case["expected"]["reason_code"])
    # Each flag changes the credential only: the signed passport of integrity.jws still passes.
    assert steps["TP-VC-INTEGRITY-001"] == ("pass", "INTEGRITY.OK")
    assert envelope.decision.overall is Verdict.FAIL


def _reference_context(tmp_path: Path, origin: str, **params: Any) -> Any:
    the_ixit = ixit(endpoints={"api": origin, "registry": origin})
    trust = TrustBundle.model_validate_json(TRUST_FILE.read_bytes())
    return context(
        tmp_path, "integrity.jose", params=params, the_ixit=the_ixit, acquirer=transport(), trust=trust
    )  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("faults", "code"),
    [
        (frozenset(), "INTEGRITY.JOSE.OK"),
        (frozenset({"sig_invalid"}), "INTEGRITY.JOSE.SIGNATURE"),
        (frozenset({"sig_untrusted_issuer"}), "INTEGRITY.JOSE.ISSUER_UNTRUSTED"),
        (frozenset({"cert_expired"}), "INTEGRITY.CERT.EXPIRED"),
        (frozenset({"signed_jws_json"}), "INTEGRITY.JOSE.OK"),
    ],
)
def test_the_jws_profile_verifies_the_signed_passport_through_its_x5c_chain(
    tmp_path: Path, faults: frozenset[str], code: str
) -> None:
    with ReferenceServer(FIXTURES, faults=faults) as server:
        outcome = run(_reference_context(tmp_path, server.origin, profile="jws", key_source="x5c"))
    assert outcome.reason_code == code, outcome.message
    assert outcome.passed is (code == "INTEGRITY.JOSE.OK")


def test_a_long_x5c_chain_is_blocked_only_if_every_entry_is_a_certificate(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    pem = (FIXTURES / "pki" / "TEST-ONLY-leaf.cert.pem").read_text()
    der = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    for chain, junk in ((["AAAA"] * 6, True), ([der] * 5 + ["AAAA"], True), ([der] * 6, False)):
        token = compact({"alg": "ES256", "x5c": chain}, b"{}", key)
        outcome = jose(tmp_path, Served(token), trust, profile="jws", key_source="x5c")
        if junk:
            failed(outcome, "INTEGRITY.JOSE.MALFORMED")
        else:
            is_blocked(outcome, "INTEGRITY.JOSE.TOO_LARGE")


def test_the_reference_credential_is_served_for_its_media_type_only(tmp_path: Path) -> None:
    with ReferenceServer(FIXTURES) as server:
        outcome = run(_reference_context(tmp_path, server.origin, accept="application/vc+jwt"))
        # Without the Accept value, the signed route gives the dpp+jws token of version 1.
        default = run(_reference_context(tmp_path, server.origin))
    passed(outcome)
    failed(default, "INTEGRITY.JOSE.TYPE")
