"""RFC 3161 trusted timestamps over report signatures (gaps D6-01 and D6-02; ADR 0015).

Expected values come from docs/explanation/architecture.md, sections 11.3 and 11.4. Every TSA
key and certificate is generated for the test run (TEST-ONLY). No test contacts a TSA.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

from dppce.adapters.capabilities import manifest
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.timestamp import MAX_TOKEN_BYTES, MAX_TOKEN_TEXT, MAX_TOKENS
from dppce.models import (
    CapabilityState,
    EvidenceEnvelope,
    IssuerStatement,
    RevokedCertificate,
    RevokedKey,
    TrustAnchor,
    TrustBundle,
    VerificationReport,
)
from dppce.verifier import verify
from tests.support import AT, ISSUER, KID, make_envelope
from tests.tsa_support import (
    Pair,
    b64,
    bad_version,
    break_time,
    make_token,
    pem,
    repeat_extension,
    tsa_ca,
    tsa_cert,
)

GEN = datetime(2026, 10, 13, 12, 6, tzinfo=UTC)
LATE = datetime(2027, 6, 1, tzinfo=UTC)  # after the report key expires (2027-01-01)
SIGNED_AT = "2026-10-13T12:05:00Z"


def imprint(token: str) -> bytes:
    """SHA-256 over the base64url-decoded third part of a compact JWS (section 11.3)."""
    part = token.split(".")[2]
    return hashlib.sha256(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).digest()


@dataclass(frozen=True)
class Tsa:
    ca: Pair
    cert: Pair


@pytest.fixture(scope="module")
def tsa() -> Tsa:
    ca = tsa_ca()
    return Tsa(ca, tsa_cert(ca))


def anchor(pair: Pair) -> TrustAnchor:
    return TrustAnchor(name="TEST-ONLY TSA anchor", certificate_pem=pem(pair[1]))


def stamped(trust: TrustBundle, *anchors: Pair, require: bool = False, **more: Any) -> TrustBundle:
    return trust.model_copy(
        update={"timestamp_anchors": tuple(anchor(a) for a in anchors), "require_timestamp": require, **more}
    )


def with_tokens(envelope: EvidenceEnvelope, *tokens: bytes | str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(envelope.model_dump_json(by_alias=True))
    document["timestamp_evidence"] = [t if isinstance(t, str) else b64(t) for t in tokens]
    return document


def check(document: dict[str, Any], trust: TrustBundle, at: datetime = AT) -> VerificationReport:
    return verify(document, trust, at)


def dim(report: VerificationReport, name: str) -> tuple[str, str]:
    found = next(d for d in report.dimensions if d.name == name)
    return found.outcome, found.detail


def good(envelope: EvidenceEnvelope, tsa: Tsa, gen: datetime = GEN, **options: Any) -> bytes:
    return make_token(imprint(envelope.signatures[0]), gen, tsa.cert, **options)


# -- D6-01: the timestamp dimension -------------------------------------------------------------


def test_a_good_token_passes_and_names_gen_time(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    report = check(with_tokens(signed, good(signed, tsa)), stamped(trust, tsa.ca))
    outcome, detail = dim(report, "timestamp")
    assert outcome == "pass"
    assert detail.startswith("TIMESTAMP.OK")
    assert "2026-10-13T12:06:00Z" in detail
    assert KID in detail


def test_require_timestamp_with_a_good_token_is_complete(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    bundle = stamped(trust, tsa.ca, require=True)
    assert not check(with_tokens(signed), bundle).complete, "missing evidence is not complete"
    report = check(with_tokens(signed, good(signed, tsa)), bundle)
    assert report.complete
    # D6-03: a report that states no status entry and no valid_until leaves both not checked.
    optional = {d.name: d.outcome for d in report.dimensions if d.name in ("status", "validity")}
    assert optional == {"status": "not_checked", "validity": "not_checked"}
    assert all(d.outcome == "pass" for d in report.dimensions if d.name not in optional)


Case = Callable[[EvidenceEnvelope, TrustBundle, Tsa], tuple[list[bytes | str], TrustBundle, datetime]]


def _eku(eku: Any = (ExtendedKeyUsageOID.SERVER_AUTH,), critical: bool = True) -> Case:
    def case(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
        signer = tsa_cert(tsa.ca, eku=eku, eku_critical=critical)
        return [make_token(imprint(env.signatures[0]), GEN, signer)], stamped(trust, tsa.ca), AT

    return case


def _expired(gen: datetime, not_after: datetime) -> Case:
    def case(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
        signer = tsa_cert(tsa.ca, not_after=not_after)
        return [make_token(imprint(env.signatures[0]), gen, signer)], stamped(trust, tsa.ca), AT

    return case


def _revoked(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
    entry = RevokedCertificate(
        serial=f"{tsa.cert[1].serial_number:x}",
        issuer_name=tsa.ca[1].subject.rfc4514_string(),
        revoked_at="2026-10-01T00:00:00Z",
    )
    return [good(env, tsa)], stamped(trust, tsa.ca, revoked_certificates=(entry,)), AT


def _ed25519(declared: str | None) -> Case:
    def case(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
        signer = tsa_cert(tsa.ca, key="ed25519")
        token = make_token(imprint(env.signatures[0]), GEN, signer, signature_algorithm=declared)
        return [token], stamped(trust, tsa.ca), AT

    return case


def _unloadable(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
    unique = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
    extra = tsa_ca("TEST-ONLY extra certificate", not_before=unique)
    token = break_time(good(env, tsa, certs=[tsa.cert[1], extra[1]]), unique)
    return [token], stamped(trust, tsa.ca), AT


def _bad_version(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
    return [bad_version(good(env, tsa), tsa.cert[1])], stamped(trust, tsa.ca), AT


def _repeated_extension(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
    signer = (tsa.cert[0], repeat_extension(tsa.ca[0], tsa.cert[1]))
    return [make_token(imprint(env.signatures[0]), GEN, signer)], stamped(trust, tsa.ca), AT


def _sha512(env: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> Any:
    digest = hashlib.sha512(imprint(env.signatures[0])).digest()
    return [make_token(digest, GEN, tsa.cert, imprint_alg="sha512")], stamped(trust, tsa.ca), AT


FAULTS: dict[str, tuple[Case, str]] = {
    "wrong imprint": (
        lambda env, trust, tsa: (
            [make_token(hashlib.sha256(b"other").digest(), GEN, tsa.cert)],
            stamped(trust, tsa.ca),
            AT,
        ),
        "TIMESTAMP.IMPRINT.MISMATCH",
    ),
    "no timestamp anchor": (
        lambda env, trust, tsa: ([good(env, tsa)], stamped(trust), AT),
        "TIMESTAMP.TSA.UNTRUSTED",
    ),
    "the CA only in the passport anchors": (
        lambda env, trust, tsa: ([good(env, tsa)], stamped(trust, anchors=(anchor(tsa.ca),)), AT),
        "TIMESTAMP.TSA.UNTRUSTED",
    ),
    "EKU serverAuth": (_eku(), "TIMESTAMP.TSA.EKU"),
    "no EKU": (_eku(None), "TIMESTAMP.TSA.EKU"),
    "non-critical EKU": (_eku((ExtendedKeyUsageOID.TIME_STAMPING,), critical=False), "TIMESTAMP.TSA.EKU"),
    "two purposes": (
        _eku((ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH)),
        "TIMESTAMP.TSA.EKU",
    ),
    "no digital signature usage": (
        lambda env, trust, tsa: (
            [make_token(imprint(env.signatures[0]), GEN, tsa_cert(tsa.ca, digital_signature=False))],
            stamped(trust, tsa.ca),
            AT,
        ),
        "TIMESTAMP.TSA.KEY_USAGE",
    ),
    "flipped signature byte": (
        lambda env, trust, tsa: ([good(env, tsa, tamper="signature")], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.CMS.SIGNATURE_INVALID",
    ),
    "TSTInfo changed after signing": (
        lambda env, trust, tsa: ([good(env, tsa, tamper="tstinfo")], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.CMS.SIGNATURE_INVALID",
    ),
    "genTime after the evaluation time": (
        lambda env, trust, tsa: ([good(env, tsa, AT + timedelta(days=1))], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TIME.FUTURE",
    ),
    "genTime half a second after the evaluation time": (
        lambda env, trust, tsa: (
            [good(env, tsa, AT + timedelta(milliseconds=500))],
            stamped(trust, tsa.ca),
            AT,
        ),
        "TIMESTAMP.TIME.FUTURE",
    ),
    "sha512 imprint": (_sha512, "TIMESTAMP.IMPRINT.ALGORITHM"),
    "not base64": (
        lambda env, trust, tsa: (["not base64!"], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.MALFORMED",
    ),
    "random DER": (
        lambda env, trust, tsa: ([b"\x30\x03\x02\x01\x01"], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.MALFORMED",
    ),
    "a certificate that does not load": (_unloadable, "TIMESTAMP.TOKEN.MALFORMED"),
    "a signer certificate with an invalid X.509 version": (_bad_version, "TIMESTAMP.TOKEN.MALFORMED"),
    "a TSA certificate with a repeated extension": (_repeated_extension, "TIMESTAMP.TSA.EKU"),
    "six certificates": (
        lambda env, trust, tsa: ([good(env, tsa, certs=[tsa.cert[1]] * 6)], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.TOO_LARGE",
    ),
    "a critical TSTInfo extension": (
        lambda env, trust, tsa: ([good(env, tsa, critical_ext=True)], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION",
    ),
    "no ESS attribute": (
        lambda env, trust, tsa: ([good(env, tsa, ess=None)], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.CMS.SIGNING_CERT",
    ),
    "the signer certificate is absent": (
        lambda env, trust, tsa: ([good(env, tsa, certs=[])], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TSA.UNKNOWN",
    ),
    "expired at genTime": (
        _expired(GEN, datetime(2026, 10, 1, tzinfo=UTC)),
        "TIMESTAMP.TSA.EXPIRED",
    ),
    "genTime 0.9 s after not_after": (
        _expired(GEN + timedelta(milliseconds=900), GEN),
        "TIMESTAMP.TSA.EXPIRED",
    ),
    "revoked under its issuer": (_revoked, "TIMESTAMP.TSA.REVOKED"),
    "Ed25519 key": (_ed25519(None), "TIMESTAMP.CMS.UNSUPPORTED"),
    "Ed25519 key declared as ECDSA": (_ed25519("sha256_ecdsa"), "TIMESTAMP.CMS.UNSUPPORTED"),
    "a combined signature OID that names another hash": (
        lambda env, trust, tsa: (
            [good(env, tsa, digest="sha512", signature_algorithm="sha256_ecdsa")],
            stamped(trust, tsa.ca),
            AT,
        ),
        "TIMESTAMP.CMS.UNSUPPORTED",
    ),
    "17 tokens": (
        lambda env, trust, tsa: ([good(env, tsa)] * (MAX_TOKENS + 1), stamped(trust, tsa.ca), AT),
        "TIMESTAMP.EVIDENCE.TOO_MANY",
    ),
    "a token of MAX_TOKEN_BYTES + 1 bytes": (
        lambda env, trust, tsa: ([good(env, tsa, pad_to=MAX_TOKEN_BYTES + 1)], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.TOO_LARGE",
    ),
    "text of MAX_TOKEN_TEXT + 1 characters": (
        lambda env, trust, tsa: (["A" * (MAX_TOKEN_TEXT + 1)], stamped(trust, tsa.ca), AT),
        "TIMESTAMP.TOKEN.TOO_LARGE",
    ),
}


@pytest.mark.parametrize("name", list(FAULTS))
def test_a_single_fault_fails_with_its_code(
    name: str, signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    build, code = FAULTS[name]
    tokens, bundle, at = build(signed, trust, tsa)
    report = check(with_tokens(signed, *tokens), bundle.model_copy(update={"require_timestamp": True}), at)
    outcome, detail = dim(report, "timestamp")
    assert (outcome, detail.split(":")[0]) == ("fail", code), detail
    assert not report.complete


def test_the_size_limits_are_consistent() -> None:
    assert MAX_TOKEN_TEXT == 87384 == len(base64.b64encode(b"\x00" * MAX_TOKEN_BYTES))
    assert len(base64.b64encode(b"\x00" * (MAX_TOKEN_BYTES + 1))) == MAX_TOKEN_TEXT, (
        "one byte more still fits the text limit, so the byte limit is checked after decoding"
    )


def test_a_token_of_exactly_max_token_bytes_gets_past_the_size_step(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    token = good(signed, tsa, pad_to=MAX_TOKEN_BYTES)
    assert len(b64(token)) == MAX_TOKEN_TEXT
    outcome, detail = dim(check(with_tokens(signed, token), stamped(trust, tsa.ca)), "timestamp")
    assert not detail.startswith("TIMESTAMP.TOKEN.TOO_LARGE")
    assert outcome == "pass", detail


@pytest.mark.parametrize("sid", ["issuer_serial", "key_id"])
def test_a_pinned_tsa_certificate_passes(
    sid: Any, signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    report = check(with_tokens(signed, good(signed, tsa, sid=sid)), stamped(trust, tsa.cert))
    assert dim(report, "timestamp")[0] == "pass"


def test_a_pinned_self_signed_tsa_certificate_passes(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    alone = tsa_cert(None)
    token = make_token(imprint(signed.signatures[0]), GEN, alone)
    assert dim(check(with_tokens(signed, token), stamped(trust, alone)), "timestamp")[0] == "pass"


def test_a_tsa_certificate_expired_at_the_evaluation_time_but_valid_at_gen_time_passes(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    short = tsa_cert(tsa.ca, not_after=datetime(2026, 12, 1, tzinfo=UTC))
    token = make_token(imprint(signed.signatures[0]), GEN, short)
    assert dim(check(with_tokens(signed, token), stamped(trust, tsa.ca), LATE), "timestamp")[0] == "pass"


def test_an_rsa_tsa_with_rsa_encryption_and_ess_v1_passes(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    rsa_tsa = tsa_cert(tsa.ca, key="rsa")
    token = make_token(imprint(signed.signatures[0]), GEN, rsa_tsa, ess="v1")
    assert dim(check(with_tokens(signed, token), stamped(trust, tsa.ca)), "timestamp")[0] == "pass"
    sha384 = make_token(
        imprint(signed.signatures[0]), GEN, rsa_tsa, digest="sha384", signature_algorithm="sha384_rsa"
    )
    assert dim(check(with_tokens(signed, sha384), stamped(trust, tsa.ca)), "timestamp")[0] == "pass"


def test_one_bad_and_one_good_token_pass(signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> None:
    report = check(with_tokens(signed, "garbage", good(signed, tsa)), stamped(trust, tsa.ca))
    outcome, detail = dim(report, "timestamp")
    assert outcome == "pass"
    assert detail.startswith("TIMESTAMP.OK")


def test_two_bad_tokens_fail_with_the_code_of_the_first(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    report = check(with_tokens(signed, good(signed, tsa, ess=None), "garbage"), stamped(trust, tsa.ca))
    outcome, detail = dim(report, "timestamp")
    assert outcome == "fail"
    assert detail.startswith("TIMESTAMP.CMS.SIGNING_CERT: token 0:")


def test_an_unsigned_envelope_with_a_token_is_not_checked(trust: TrustBundle, tsa: Tsa) -> None:
    unsigned = make_envelope()
    token = make_token(hashlib.sha256(b"x").digest(), GEN, tsa.cert)
    outcome, detail = dim(check(with_tokens(unsigned, token), stamped(trust, tsa.ca)), "timestamp")
    assert outcome == "not_checked"
    assert detail.startswith("TIMESTAMP.SIGNATURE.NONE")


def test_a_token_over_the_signature_of_an_untrusted_key_does_not_match(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    stranger = LocalSigner.generate("TEST-ONLY-stranger-key")
    both = sign_envelope(signed, stranger, issuer=ISSUER, signed_at=SIGNED_AT)
    token = make_token(imprint(both.signatures[1]), GEN, tsa.cert)
    outcome, detail = dim(check(with_tokens(both, token), stamped(trust, tsa.ca)), "timestamp")
    assert (outcome, detail.split(":")[0]) == ("fail", "TIMESTAMP.IMPRINT.MISMATCH")


def test_the_detail_quotes_the_tsa_subject_through_repr(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    ca = tsa_ca()
    odd = tsa_cert(ca, name="TEST-ONLY TSA \x1b[31m")
    token = make_token(imprint(signed.signatures[0]), GEN, odd)
    outcome, detail = dim(check(with_tokens(signed, token), stamped(trust, ca)), "timestamp")
    assert outcome == "pass"
    assert "\x1b" not in detail


# -- D6-02: key validity at the signing time -----------------------------------------------------

STAMPED = "2026-10-13T12:06:00Z, the genTime of a trusted timestamp over its signature"


def test_a_trusted_timestamp_keeps_a_report_valid_after_its_key_expires(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    bundle = stamped(trust, tsa.ca)
    report = check(with_tokens(signed, good(signed, tsa)), bundle, LATE)
    outcome, detail = dim(report, "issuer_trust")
    assert outcome == "pass"
    assert STAMPED in detail
    outcome, detail = dim(check(with_tokens(signed), bundle, LATE), "issuer_trust")
    assert outcome == "fail"
    assert detail == f"Key '{KID}' is outside its validity period at the evaluation time."


@pytest.mark.parametrize(
    ("revoked_at", "expected"),
    [("2026-10-01T00:00:00Z", "fail"), ("2026-12-01T00:00:00Z", "pass"), (None, "fail")],
)
def test_a_revocation_is_judged_at_gen_time(
    revoked_at: str | None, expected: str, signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    bundle = stamped(trust, tsa.ca, revoked_keys=(RevokedKey(kid=KID, revoked_at=revoked_at),))
    outcome, detail = dim(check(with_tokens(signed, good(signed, tsa)), bundle, LATE), "issuer_trust")
    assert outcome == expected, detail
    if expected == "fail":
        assert detail == f"Key '{KID}' is revoked at {STAMPED}."


def test_a_gen_time_before_the_key_validity_fails(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    ca = tsa_ca(not_before=datetime(2025, 1, 1, tzinfo=UTC))
    early = tsa_cert(ca, not_before=datetime(2025, 1, 1, tzinfo=UTC))
    gen = datetime(2025, 12, 1, tzinfo=UTC)
    token = make_token(imprint(signed.signatures[0]), gen, early)
    report = check(with_tokens(signed, token), stamped(trust, ca), LATE)
    assert dim(report, "timestamp")[0] == "pass"
    outcome, detail = dim(report, "issuer_trust")
    assert outcome == "fail"
    assert detail == (
        f"Key '{KID}' is outside its validity period at 2025-12-01T00:00:00Z, the genTime of a trusted "
        "timestamp over its signature."
    )


def test_a_bad_token_leaves_the_key_time_at_the_evaluation_time(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    report = check(with_tokens(signed, good(signed, tsa, ess=None)), stamped(trust, tsa.ca), LATE)
    outcome, detail = dim(report, "issuer_trust")
    assert outcome == "fail"
    assert "at the evaluation time" in detail


def test_the_earliest_good_gen_time_is_used(signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa) -> None:
    later = good(signed, tsa, datetime(2026, 12, 15, tzinfo=UTC))
    report = check(with_tokens(signed, later, good(signed, tsa)), stamped(trust, tsa.ca), LATE)
    assert STAMPED in dim(report, "issuer_trust")[1]


def test_a_fraction_of_a_second_is_kept_in_the_detail(
    signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    token = good(signed, tsa, GEN + timedelta(microseconds=250_000))
    detail = dim(check(with_tokens(signed, token), stamped(trust, tsa.ca), LATE), "issuer_trust")[1]
    assert "2026-10-13T12:06:00.250000Z, the genTime" in detail


LAB = IssuerStatement(name="TEST-ONLY lab", identifier=ISSUER)
_STATEMENTS = {
    "pass": LAB,
    "ISSUER.STATEMENT.MISMATCH": IssuerStatement(name="TEST-ONLY other", identifier="urn:example:other-lab"),
    "ISSUER.STATEMENT.UNSPECIFIED": IssuerStatement(),
    "ISSUER.ACCREDITATION.NO_REFERENCE": LAB.model_copy(update={"accreditation_status": "TEST-ONLY status"}),
    "outside validity": LAB,
    "revoked": LAB,
}
EARLY_GEN = datetime(2025, 12, 1, tzinfo=UTC)


@pytest.mark.parametrize("name", list(_STATEMENTS))
@pytest.mark.parametrize("stamp", [True, False], ids=["stamped", "unstamped"])
def test_every_issuer_trust_detail_names_the_time_used(
    name: str, stamp: bool, signer: LocalSigner, trust: TrustBundle
) -> None:
    envelope = sign_envelope(
        make_envelope(issuer=_STATEMENTS[name]), signer, issuer=ISSUER, signed_at=SIGNED_AT
    )
    ca = tsa_ca(not_before=datetime(2025, 1, 1, tzinfo=UTC))
    tsa_pair = tsa_cert(ca, not_before=datetime(2025, 1, 1, tzinfo=UTC))
    # Outside validity, stamped: a genTime before the validity of the report key.
    gen = EARLY_GEN if name == "outside validity" else GEN
    at = LATE if name == "outside validity" and not stamp else AT
    revoked = (RevokedKey(kid=KID, revoked_at=None),) if name == "revoked" else ()
    bundle = stamped(trust, ca, revoked_keys=revoked)
    tokens = [make_token(imprint(envelope.signatures[0]), gen, tsa_pair)] if stamp else []
    outcome, detail = dim(check(with_tokens(envelope, *tokens), bundle, at), "issuer_trust")
    stamp_text = gen.strftime("%Y-%m-%dT%H:%M:%SZ")
    when = (
        f"{stamp_text}, the genTime of a trusted timestamp over its signature"
        if stamp
        else "the evaluation time"
    )
    if name == "pass":
        assert outcome == "pass"
        assert detail.startswith(
            f"Key '{KID}' of issuer '{ISSUER}' is trusted at {when}, and the report states"
        )
    elif name == "outside validity":
        assert (outcome, detail) == ("fail", f"Key '{KID}' is outside its validity period at {when}.")
    elif name == "revoked":
        assert (outcome, detail) == ("fail", f"Key '{KID}' is revoked at {when}.")
    else:
        assert outcome == "fail"
        assert detail.startswith(name)
        assert detail.endswith(f" Key validity was checked at {when}."), detail


def test_without_a_token_the_pass_detail_is_unchanged(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    detail = dim(check(with_tokens(signed), trust), "issuer_trust")[1]
    assert detail.startswith(
        f"Key '{KID}' of issuer 'urn:example:test-lab' is trusted at the evaluation time, "
    )


# -- the signature outcome (finding 2) -------------------------------------------------------------


def _broken(token: str) -> str:
    """The same header and payload with a signature that does not verify."""
    head, payload, _ = token.split(".")
    return f"{head}.{payload}.{base64.urlsafe_b64encode(b'x' * 64).rstrip(b'=').decode()}"


def test_a_good_signature_then_a_broken_one_passes_the_signature(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    document = with_tokens(signed)
    document["signatures"] = [signed.signatures[0], _broken(signed.signatures[0])]
    report = check(document, trust)
    assert dim(report, "signature") == (
        "pass",
        f"Signature by key '{KID}' verifies and binds the decision digest.",
    )
    assert dim(report, "issuer_trust")[0] == "pass"


def test_a_good_signature_with_an_expired_key_then_a_broken_one_passes_the_signature_only(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    document = with_tokens(signed)
    document["signatures"] = [signed.signatures[0], _broken(signed.signatures[0])]
    report = check(document, trust, LATE)
    assert dim(report, "signature")[0] == "pass"
    assert dim(report, "issuer_trust")[0] == "fail"
    assert not report.complete


# -- capability -------------------------------------------------------------------------------------


def test_the_capability_manifest_lists_rfc3161_supported() -> None:
    entry = next(c for c in manifest().capabilities if c.id == "evidence.rfc3161")
    assert (entry.state, entry.available, entry.acceptance_criteria) == (CapabilityState.SUPPORTED, True, "")
    assert "contacts no timestamp authority" in entry.description
