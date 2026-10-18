"""Property tests of the timestamp verifier (ADR 0015, finding 1 of the design review).

``verify_token`` raises only ``TimestampError``, and ``verify`` never raises on a token. A
mutated token passes only with the stamp of the original token.

A single-byte mutation can pass. CMS has framing bytes that no signature covers: the version
of SignedData and of SignerInfo, the outer digestAlgorithms set, and unsigned attributes. The
verifier does not read them. The property is therefore that a pass reports the genTime, the
imprint, and the TSA of the original token, which the signature and the ESS attribute bind.

Generation is derandomized. The TEST-ONLY keys are still generated for each run.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from hypothesis import example, given
from hypothesis import strategies as st

from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.timestamp import Stamp, TimestampError, verify_token
from dppce.models import TrustAnchor, TrustBundle, TrustedKey
from dppce.verifier import verify
from tests.support import AT, ISSUER, make_envelope
from tests.test_properties import SETTINGS
from tests.tsa_support import b64, make_token, pem, tsa_ca, tsa_cert, version_offset

GEN = datetime(2026, 10, 13, 12, 6, tzinfo=UTC)
SIGNER = LocalSigner.generate("TEST-ONLY-property-report-key")
ENVELOPE = sign_envelope(make_envelope(), SIGNER, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
_PART = ENVELOPE.signatures[0].split(".")[2]
IMPRINT = hashlib.sha256(base64.urlsafe_b64decode(_PART + "=" * (-len(_PART) % 4))).digest()
CA = tsa_ca()
TSA = tsa_cert(CA)
GOOD = make_token(IMPRINT, GEN, TSA)
TRUST = TrustBundle(
    schema_version="dppce.trust/2",
    policy_version="test-1",
    keys=(
        TrustedKey(
            kid=SIGNER.key_id,
            issuer=ISSUER,
            purposes=("report",),
            public_jwk=SIGNER.public_jwk(),
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        ),
    ),
    timestamp_anchors=(TrustAnchor(name="TEST-ONLY TSA root", certificate_pem=pem(CA[1])),),
)
ORIGINAL = verify_token(b64(GOOD), {IMPRINT}, TRUST, AT)


def _mutate(raw: bytes, kind: str, position: int, value: int) -> bytes:
    position %= len(raw)
    if kind == "flip":
        return raw[:position] + bytes([raw[position] ^ (value or 1)]) + raw[position + 1 :]
    if kind == "delete":
        return raw[:position] + raw[position + 1 :]
    return raw[:position] + bytes([value]) + raw[position:]


MUTATIONS = st.tuples(
    st.sampled_from(["flip", "delete", "insert"]), st.integers(0, len(GOOD) - 1), st.integers(0, 255)
)
# The derandomized run never reaches this byte. The flip sets the version value of the TSA
# certificate to 3, which no X.509 version uses. cryptography raises InvalidVersion, no ValueError.
VERSION_FLIP = ("flip", version_offset(GOOD, TSA[1]), 1)


def _only_timestamp_error(text: str) -> Stamp | None:
    try:
        return verify_token(text, {IMPRINT}, TRUST, AT)
    except TimestampError:
        return None


def test_the_original_token_verifies() -> None:
    assert Stamp(gen_time=GEN, imprint=IMPRINT, tsa_subject=TSA[1].subject.rfc4514_string()) == ORIGINAL


@SETTINGS
@given(st.binary(max_size=2048))
@example(b"")
@example(b"\x30\x80\x00\x00")
@example(b"\x30" + b"\x84\xff\xff\xff\xff")
def test_random_bytes_raise_only_timestamp_error(raw: bytes) -> None:
    assert _only_timestamp_error(b64(raw)) is None


@SETTINGS
@given(st.text(max_size=300))
def test_random_text_raises_only_timestamp_error(text: str) -> None:
    _only_timestamp_error(text)


@SETTINGS
@given(MUTATIONS)
@example(VERSION_FLIP)
def test_a_mutated_token_passes_only_with_the_original_stamp(mutation: tuple[str, int, int]) -> None:
    stamp = _only_timestamp_error(b64(_mutate(GOOD, *mutation)))
    assert stamp is None or stamp == ORIGINAL


def _verify(token: bytes) -> tuple[str, str]:
    document: dict[str, Any] = json.loads(ENVELOPE.model_dump_json(by_alias=True))
    document["timestamp_evidence"] = [b64(token)]
    report = verify(document, TRUST, AT)
    found = next(d for d in report.dimensions if d.name == "timestamp")
    return found.outcome, found.detail


GOOD_DETAIL = _verify(GOOD)


@SETTINGS
@given(MUTATIONS)
@example(VERSION_FLIP)
def test_verify_never_raises_and_passes_a_mutated_token_only_with_the_original_detail(
    mutation: tuple[str, int, int],
) -> None:
    assert GOOD_DETAIL[0] == "pass"
    outcome, detail = _verify(_mutate(GOOD, *mutation))
    assert outcome in ("pass", "fail")
    if outcome == "pass":
        assert detail == GOOD_DETAIL[1]
