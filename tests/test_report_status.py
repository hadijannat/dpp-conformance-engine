"""Report status lists, the validity period, and supersession (gap D6-03; ADR 0016).

Expected values come from docs/explanation/architecture.md, section 11.4 ("Report status
lists" and "Validity and supersession"). Every key, list, and issuer is TEST-ONLY. No test
contacts a status service: the operator supplies the list as a file.
"""

from __future__ import annotations

import base64
import gzip
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from validation.evidence_cases import SETUP

from dppce import cli
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.envelope import ATTESTATION_TYP, decision_digest, sign_envelope
from dppce.evidence.jws import LocalSigner, sign_compact
from dppce.evidence.status import (
    MAX_TOKEN_BYTES,
    MIN_BITS,
    STATUS_LIST_TYP,
    StatusError,
    bit_is_set,
    decode_list,
    encode_list,
    sign_status_list,
)
from dppce.models import (
    Attestation,
    EvidenceEnvelope,
    RevokedKey,
    StatusList,
    StatusReference,
    TrustBundle,
    TrustedKey,
    VerificationReport,
)
from dppce.report import render
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from tests.support import AT, ISSUER, make_envelope

STATUS_SIGNER = LocalSigner.generate("TEST-ONLY-status-key-1")
LIST_ID = "urn:example:TEST-ONLY-status-list-1"
INDEX = 42
SIGNED_AT = "2026-10-13T12:05:00Z"
ISSUED_AT = "2026-10-13T00:00:00Z"
AT_TEXT = "2026-10-14T00:00:00Z"
ENTRY = StatusReference(list_id=LIST_ID, index=INDEX)
V1_KEYS = {"schema_version", "decision_digest", "results_root", "records_root", "issuer", "signed_at"}


def _key(signer: LocalSigner, purposes: tuple[Any, ...], issuer: str = ISSUER, **changes: Any) -> TrustedKey:
    fields: dict[str, Any] = {
        "kid": signer.key_id,
        "issuer": issuer,
        "purposes": purposes,
        "public_jwk": signer.public_jwk(),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }
    return TrustedKey(**(fields | changes))


def _with(trust: TrustBundle, *keys: TrustedKey, **changes: Any) -> TrustBundle:
    return trust.model_copy(update={"keys": (*trust.keys, *keys), **changes})


@pytest.fixture
def bundle(trust: TrustBundle) -> TrustBundle:
    """The report key of the fixture plus a TEST-ONLY status key of the same issuer."""
    return _with(trust, _key(STATUS_SIGNER, ("status",)))


def _sign(envelope: EvidenceEnvelope, signer: LocalSigner, **options: Any) -> EvidenceEnvelope:
    return sign_envelope(envelope, signer, issuer=ISSUER, signed_at=SIGNED_AT, **options)


def _report(signer: LocalSigner, **options: Any) -> EvidenceEnvelope:
    """A report whose issuer signature names the status entry ENTRY, unless ``status`` says otherwise."""
    return _sign(make_envelope(), signer, **({"status": ENTRY} | options))


def _list(
    *bits: int,
    purpose: str = "revocation",
    issued_at: str = ISSUED_AT,
    list_id: str = LIST_ID,
    signer: LocalSigner = STATUS_SIGNER,
    size: int = MIN_BITS,
) -> bytes:
    payload = StatusList(
        schema_version="dppce.statuslist/1",
        id=list_id,
        status_purpose=purpose,  # type: ignore[arg-type] - a test passes each allowed value as text
        issued_at=issued_at,
        encoded_list=encode_list(set(bits), size),
    )
    return sign_status_list(payload, signer).encode("ascii")


def _document(envelope: EvidenceEnvelope) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(envelope.model_dump_json(by_alias=True))
    return document


def _verify(
    subject: EvidenceEnvelope | dict[str, Any],
    trust: TrustBundle,
    status_list: bytes | None = None,
    at: datetime = AT,
) -> VerificationReport:
    document = _document(subject) if isinstance(subject, EvidenceEnvelope) else subject
    return verify(document, trust, at, status_list=status_list)


def _dim(report: VerificationReport, name: str) -> tuple[str, str]:
    found = next(d for d in report.dimensions if d.name == name)
    return found.outcome, found.detail


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _bitstring(encoded: str) -> bytes:
    """Decode with gzip and base64 only, apart from the code under test."""
    body = encoded.removeprefix("u")
    return gzip.decompress(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


# -- bitstring encoding -----------------------------------------------------------------------------


def test_encode_list_puts_index_0_in_the_most_significant_bit() -> None:
    encoded = encode_list({0, 9})
    assert encoded.startswith("u")
    assert "=" not in encoded
    bits = _bitstring(encoded)
    assert len(bits) == MIN_BITS // 8 == 16384
    assert (bits[0], bits[1]) == (0x80, 0x40)
    assert not any(bits[2:])
    assert decode_list(encoded) == bits
    assert [bit_is_set(bits, i) for i in (0, 1, 7, 8, 9, 10)] == [True, False, False, False, True, False]


def test_a_hand_built_vector_decodes_to_the_same_bits() -> None:
    raw = bytes([0x80, 0x40]) + bytes(MIN_BITS // 8 - 2)
    assert decode_list("u" + _b64(gzip.compress(raw))) == raw


def test_decode_refuses_a_gzip_bomb() -> None:
    with pytest.raises(StatusError) as caught:
        decode_list("u" + _b64(gzip.compress(bytes(32 * 1024 * 1024))))
    assert caught.value.code == "STATUSLIST.FILE.TOO_LARGE"


_GOOD = gzip.compress(bytes(MIN_BITS // 8))


@pytest.mark.parametrize(
    "encoded",
    [
        "u" + _b64(_GOOD + b"trailing data"),
        "u" + _b64(_GOOD + _GOOD),  # a second gzip member is trailing data too
        "u" + _b64(_GOOD[:-10]),  # a truncated stream
        "u" + _b64(gzip.compress(b"")),  # no bits
        "u" + _b64(b"not gzip at all"),
        _b64(_GOOD),  # no multibase prefix
        "u***",
        "uA",  # base64url of one character cannot be decoded
        "u",
        "",
    ],
)
def test_decode_refuses_trailing_data_a_truncated_stream_and_bad_base64(encoded: str) -> None:
    with pytest.raises(StatusError) as caught:
        decode_list(encoded)
    assert caught.value.code == "STATUSLIST.FILE.MALFORMED"


def test_encode_refuses_fewer_than_131072_bits() -> None:
    with pytest.raises(ValueError, match="131072"):
        encode_list({1}, MIN_BITS - 8)
    with pytest.raises(ValueError, match="multiple of 8"):
        encode_list({1}, MIN_BITS + 1)
    with pytest.raises(ValueError, match="index"):
        encode_list({MIN_BITS})
    with pytest.raises(ValueError, match="index"):
        encode_list({-1})
    assert len(_bitstring(encode_list(set(), MIN_BITS * 2))) == MIN_BITS * 2 // 8


def test_bit_is_set_refuses_an_index_beyond_the_list() -> None:
    with pytest.raises(StatusError) as caught:
        bit_is_set(bytes(2), 16)
    assert caught.value.code == "STATUSLIST.INDEX.OUT_OF_RANGE"


# -- the dimension status -----------------------------------------------------------------------------


@pytest.mark.parametrize(("purpose", "word"), [("revocation", "revoked"), ("suspension", "suspended")])
def test_a_set_bit_fails_status_with_revoked_or_suspended(
    purpose: str, word: str, signer: LocalSigner, bundle: TrustBundle, tmp_path: Path
) -> None:
    envelope = _report(signer)
    status_list = _list(INDEX, purpose=purpose)
    report = _verify(envelope, bundle, status_list)
    outcome, detail = _dim(report, "status")
    assert outcome == "fail"
    assert detail.startswith(f"STATUSLIST.REPORT.{word.upper()}")
    assert word in detail
    assert not bundle.require_status
    assert report.complete is False
    assert cli.main(["verify", *_cli_files(tmp_path, envelope, bundle, status_list)]) == 4


def test_a_clear_bit_passes_and_verification_is_complete(
    signer: LocalSigner, bundle: TrustBundle, tmp_path: Path
) -> None:
    envelope = _report(signer)
    status_list = _list(INDEX - 1, INDEX + 1)
    report = _verify(envelope, bundle, status_list)
    outcome, detail = _dim(report, "status")
    assert outcome == "pass"
    assert detail.startswith("STATUSLIST.REPORT.ACTIVE")
    for named in (LIST_ID, "revocation", ISSUED_AT, str(INDEX)):
        assert named in detail
    assert report.complete is True
    assert cli.main(["verify", *_cli_files(tmp_path, envelope, bundle, status_list)]) == 0


def test_a_list_file_with_a_trailing_newline_is_accepted(signer: LocalSigner, bundle: TrustBundle) -> None:
    report = _verify(_report(signer), bundle, _list() + b"\n")
    assert _dim(report, "status")[1].startswith("STATUSLIST.REPORT.ACTIVE")
    report = _verify(_report(signer), bundle, b" \r\n" + _list() + b"\r\n\t")
    assert _dim(report, "status")[1].startswith("STATUSLIST.REPORT.ACTIVE")


def _status_code(report: VerificationReport) -> tuple[str, str]:
    outcome, detail = _dim(report, "status")
    return outcome, detail.split(":")[0]


def test_a_list_signed_by_a_key_without_the_status_purpose_fails(
    signer: LocalSigner, bundle: TrustBundle
) -> None:
    report = _verify(_report(signer), bundle, _list(signer=signer))
    assert _status_code(report) == ("fail", "STATUSLIST.KEY.PURPOSE")
    assert not report.complete


def test_a_list_key_outside_the_bundle_or_revoked_fails(
    signer: LocalSigner, trust: TrustBundle, bundle: TrustBundle
) -> None:
    envelope = _report(signer)
    assert _status_code(_verify(envelope, trust, _list())) == ("fail", "STATUSLIST.KEY.UNKNOWN")
    revoked = bundle.model_copy(
        update={"revoked_keys": (RevokedKey(kid=STATUS_SIGNER.key_id, revoked_at="2026-10-01T00:00:00Z"),)}
    )
    assert _status_code(_verify(envelope, revoked, _list())) == ("fail", "STATUSLIST.KEY.NOT_TRUSTED")
    expired = _with(trust, _key(STATUS_SIGNER, ("status",), not_after="2026-10-01T00:00:00Z"))
    assert _status_code(_verify(envelope, expired, _list())) == ("fail", "STATUSLIST.KEY.NOT_TRUSTED")


@pytest.mark.parametrize("issued_at", ["2026-10-06T00:00:00Z", "2026-10-14T00:00:01Z"], ids=["old", "future"])
def test_a_stale_or_future_list_fails(issued_at: str, signer: LocalSigner, bundle: TrustBundle) -> None:
    assert bundle.status_max_age_days == 7
    report = _verify(_report(signer), bundle, _list(issued_at=issued_at))
    assert _status_code(report) == ("fail", "STATUSLIST.TIME.STALE")
    assert not report.complete
    # Exactly the maximum age is still fresh.
    fresh = _verify(_report(signer), bundle, _list(issued_at="2026-10-07T00:00:00Z"))
    assert _status_code(fresh) == ("pass", "STATUSLIST.REPORT.ACTIVE")


def test_a_list_with_another_id_fails(signer: LocalSigner, bundle: TrustBundle) -> None:
    report = _verify(_report(signer), bundle, _list(list_id="urn:example:TEST-ONLY-status-list-2"))
    assert _status_code(report) == ("fail", "STATUSLIST.ID.MISMATCH")


def test_a_list_of_another_issuer_fails(signer: LocalSigner, trust: TrustBundle) -> None:
    other = _with(trust, _key(STATUS_SIGNER, ("status",), issuer="urn:example:other-lab"))
    report = _verify(_report(signer), other, _list(INDEX))
    assert _status_code(report) == ("fail", "STATUSLIST.ISSUER.MISMATCH")


def test_an_index_beyond_the_list_fails(signer: LocalSigner, bundle: TrustBundle) -> None:
    envelope = _report(signer, status=StatusReference(list_id=LIST_ID, index=MIN_BITS))
    report = _verify(envelope, bundle, _list())
    assert _status_code(report) == ("fail", "STATUSLIST.INDEX.OUT_OF_RANGE")
    larger = _verify(envelope, bundle, _list(size=MIN_BITS * 2))
    assert _status_code(larger) == ("pass", "STATUSLIST.REPORT.ACTIVE")


def _non_canonical() -> bytes:
    payload = {
        "schema_version": "dppce.statuslist/1",
        "id": LIST_ID,
        "status_purpose": "revocation",
        "issued_at": ISSUED_AT,
        "encoded_list": encode_list(set()),
    }
    # Valid JSON, but not RFC 8785: a space and the keys out of order.
    text = json.dumps(payload, separators=(", ", ":")).encode()
    return sign_compact(text, STATUS_SIGNER, typ=STATUS_LIST_TYP).encode("ascii")


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"not a compact jws", "STATUSLIST.FILE.MALFORMED"),
        (b"\xff\xfe", "STATUSLIST.FILE.MALFORMED"),
        ("ü".encode(), "STATUSLIST.FILE.MALFORMED"),
        (b"", "STATUSLIST.FILE.MALFORMED"),
        (b"a" * (MAX_TOKEN_BYTES + 1), "STATUSLIST.FILE.TOO_LARGE"),
    ],
)
def test_a_non_canonical_or_non_ascii_or_oversized_file_fails(
    raw: bytes, code: str, signer: LocalSigner, bundle: TrustBundle
) -> None:
    assert _status_code(_verify(_report(signer), bundle, raw)) == ("fail", code)


def test_a_non_canonical_payload_fails(signer: LocalSigner, bundle: TrustBundle) -> None:
    report = _verify(_report(signer), bundle, _non_canonical())
    assert _status_code(report) == ("fail", "STATUSLIST.FILE.MALFORMED")


def test_a_list_issued_at_a_time_that_does_not_exist_fails(signer: LocalSigner, bundle: TrustBundle) -> None:
    payload = {
        "schema_version": "dppce.statuslist/1",
        "id": LIST_ID,
        "status_purpose": "revocation",
        "issued_at": "2026-10-32T00:00:00Z",
        "encoded_list": encode_list(set()),
    }
    token = sign_compact(canonical_bytes(payload), STATUS_SIGNER, typ=STATUS_LIST_TYP).encode("ascii")
    assert _status_code(_verify(_report(signer), bundle, token)) == ("fail", "STATUSLIST.FILE.MALFORMED")


def test_a_report_attestation_cannot_pass_as_a_status_list(signer: LocalSigner, bundle: TrustBundle) -> None:
    token = sign_compact(b"{}", STATUS_SIGNER, typ=ATTESTATION_TYP).encode("ascii")
    assert _status_code(_verify(_report(signer), bundle, token)) == ("fail", "STATUSLIST.SIGNATURE.INVALID")


def test_a_tampered_list_signature_fails(signer: LocalSigner, bundle: TrustBundle) -> None:
    head, payload, _ = _list().decode("ascii").split(".")
    forged = f"{head}.{payload}.{_b64(b'x' * 64)}".encode("ascii")
    report = _verify(_report(signer), bundle, forged)
    assert _status_code(report) == ("fail", "STATUSLIST.SIGNATURE.INVALID")


# -- when the dimension status is mandatory -------------------------------------------------------


def test_require_status_without_a_list_is_not_complete(signer: LocalSigner, bundle: TrustBundle) -> None:
    needs = bundle.model_copy(update={"require_status": True})
    report = _verify(_report(signer), needs)
    assert _status_code(report) == ("missing", "STATUSLIST.FILE.MISSING")
    assert not report.complete


def test_status_as_of_alone_no_longer_gives_pass(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    fresh = trust.model_copy(update={"require_status": True, "status_as_of": "2026-10-13T00:00:00Z"})
    report = _verify(signed, fresh)
    assert _status_code(report) == ("missing", "STATUSLIST.REFERENCE.NONE")
    assert report.complete is False


def test_a_stale_status_as_of_fails_first(signer: LocalSigner, bundle: TrustBundle) -> None:
    stale = bundle.model_copy(update={"status_as_of": "2026-09-01T00:00:00Z"})
    report = _verify(_report(signer), stale, _list())
    assert _status_code(report) == ("fail", "TRUST.SNAPSHOT.STALE")


def test_a_supplied_list_makes_status_mandatory(signed: EvidenceEnvelope, bundle: TrustBundle) -> None:
    report = _verify(signed, bundle, _list())
    assert _status_code(report) == ("missing", "STATUSLIST.REFERENCE.NONE")
    assert report.complete is False


def test_a_list_without_a_passing_issuer_signature_is_not_checked(trust: TrustBundle) -> None:
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    report = _verify(_report(stranger), _with(trust, _key(STATUS_SIGNER, ("status",))), _list())
    assert _status_code(report) == ("not_checked", "STATUSLIST.REPORT.UNSIGNED")
    assert not report.complete


def test_a_stated_status_entry_without_a_list_is_not_complete(
    signer: LocalSigner, bundle: TrustBundle, tmp_path: Path
) -> None:
    envelope = _report(signer)
    report = _verify(envelope, bundle)
    assert _status_code(report) == ("missing", "STATUSLIST.FILE.MISSING")
    assert report.complete is False
    assert cli.main(["verify", *_cli_files(tmp_path, envelope, bundle)]) == 4


def test_a_v1_report_without_a_list_or_require_status_keeps_status_not_checked(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    report = _verify(signed, trust)
    assert _status_code(report) == ("not_checked", "STATUSLIST.REFERENCE.NONE")
    assert report.complete is True


# -- validity and supersession ----------------------------------------------------------------------


def test_valid_until_before_the_evaluation_time_fails_validity_only(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    report = _verify(_report(signer, status=None, valid_until="2026-10-13T23:59:59Z"), trust)
    outcome, detail = _dim(report, "validity")
    assert (outcome, detail.split(":")[0]) == ("fail", "VALIDITY.PERIOD.EXPIRED")
    assert "2026-10-13T23:59:59Z" in detail
    assert _dim(report, "status")[0] == "not_checked"
    assert _dim(report, "signers")[0] == "pass"
    assert report.complete is False


def test_valid_until_equal_to_the_evaluation_time_passes(signer: LocalSigner, trust: TrustBundle) -> None:
    report = _verify(_report(signer, status=None, valid_until=AT_TEXT), trust)
    assert _dim(report, "validity")[1].startswith("VALIDITY.PERIOD.OK")
    assert _dim(report, "validity")[0] == "pass"
    assert report.complete is True


def test_without_valid_until_validity_is_not_checked_and_not_mandatory(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    report = _verify(signed, trust)
    outcome, detail = _dim(report, "validity")
    assert (outcome, detail.split(":")[0]) == ("not_checked", "VALIDITY.PERIOD.NOT_STATED")
    assert report.complete is True


def test_validity_without_a_passing_issuer_signature_is_not_checked(trust: TrustBundle) -> None:
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    report = _verify(_report(stranger, status=None, valid_until="2026-10-01T00:00:00Z"), trust)
    assert _dim(report, "validity")[0] == "not_checked"
    assert _dim(report, "validity")[1].startswith("VALIDITY.REPORT.UNSIGNED")


def test_a_superseding_report_shows_the_earlier_digest_in_signers_and_html(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    earlier = "sha256:" + "a" * 64
    envelope = _report(signer, status=None, supersedes=earlier)
    report = _verify(envelope, trust)
    outcome, detail = _dim(report, "signers")
    assert outcome == "pass"
    assert earlier in detail
    assert report.complete is True
    page = render(envelope, report)
    assert "Signatures as declared" in page
    assert page.count(earlier) >= 2, "the declared table and the verification section show it"
    assert earlier in render(envelope)


def test_the_order_of_issuer_signatures_does_not_hide_the_lifecycle(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    base = make_envelope()
    plain = _sign(base, signer).signatures[0]
    stated = _sign(base, signer, status=ENTRY, valid_until="2026-10-13T00:00:00Z").signatures[0]
    for order in ([plain, stated], [stated, plain]):
        document = _document(base) | {"signatures": order}
        report = _verify(document, trust)
        outcome, detail = _dim(report, "signers")
        assert (outcome, detail.split(":")[0]) == ("fail", "SIGNER.LIFECYCLE.CONFLICT"), order
        assert _dim(report, "validity")[0] == "fail"
        assert _dim(report, "validity")[1].startswith("VALIDITY.PERIOD.EXPIRED")
        assert _status_code(report) == ("missing", "STATUSLIST.FILE.MISSING")
        assert (_dim(report, "signature")[0], _dim(report, "issuer_trust")[0]) == ("pass", "pass")
        assert report.complete is False


def test_two_issuer_signatures_with_equal_lifecycles_do_not_conflict(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    base = make_envelope()
    first = _sign(base, signer, valid_until="2026-12-01T00:00:00Z")
    both = sign_envelope(
        first, signer, issuer=ISSUER, signed_at="2026-10-13T12:06:00Z", valid_until="2026-12-01T00:00:00Z"
    )
    report = _verify(both, trust)
    assert _dim(report, "signers")[0] == "pass"
    assert _dim(report, "validity")[0] == "pass"
    assert report.complete is True


# -- attestation versions ------------------------------------------------------------------------------

_BASE: dict[str, Any] = {
    "decision_digest": "sha256:" + "0" * 64,
    "results_root": "0" * 64,
    "records_root": "0" * 64,
    "issuer": ISSUER,
    "signed_at": SIGNED_AT,
}


@pytest.mark.parametrize(
    "fields",
    [
        {"schema_version": "dppce.attestation/1", "role": "issuer"},
        {"schema_version": "dppce.attestation/1", "valid_until": "2026-12-01T00:00:00Z"},
        {"schema_version": "dppce.attestation/2"},
        {"schema_version": "dppce.attestation/2", "role": "reviewer", "valid_until": "2026-12-01T00:00:00Z"},
        {"schema_version": "dppce.attestation/2", "role": "reviewer", "status": {"list_id": "x", "index": 1}},
        {"schema_version": "dppce.attestation/2", "role": "reviewer", "supersedes": "sha256:" + "1" * 64},
        {"schema_version": "dppce.attestation/2", "role": "issuer", "supersedes": _BASE["decision_digest"]},
        {"schema_version": "dppce.attestation/2", "role": "issuer", "valid_until": "2026-12-01"},
        # The pattern admits month 13. The verifier compares the time, so it must exist.
        {"schema_version": "dppce.attestation/2", "role": "issuer", "valid_until": "2026-13-01T00:00:00Z"},
        {"schema_version": "dppce.attestation/2", "role": "issuer", "supersedes": "sha256:short"},
        {"schema_version": "dppce.attestation/2", "role": "issuer", "status": {"list_id": "x", "index": -1}},
        {"schema_version": "dppce.attestation/2", "role": "admin"},
    ],
)
def test_attestation_versions_pair_with_their_fields(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Attestation.model_validate(_BASE | fields)


def test_a_v2_attestation_writes_every_field() -> None:
    attestation = Attestation.model_validate(
        _BASE | {"schema_version": "dppce.attestation/2", "role": "reviewer"}
    )
    assert attestation.signer_role == "reviewer"
    written = json.loads(canonical_bytes(attestation))
    assert written == _BASE | {
        "schema_version": "dppce.attestation/2",
        "role": "reviewer",
        "status": None,
        "valid_until": None,
        "supersedes": None,
    }


def test_a_default_signature_is_still_attestation_1_byte_for_byte(signed: EvidenceEnvelope) -> None:
    part = signed.signatures[0].split(".")[1]
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    payload = json.loads(raw)
    assert set(payload) == V1_KEYS
    assert payload["schema_version"] == "dppce.attestation/1"
    attestation = Attestation.model_validate(payload)
    assert attestation.signer_role == "issuer"
    assert canonical_bytes(attestation) == raw


def test_a_v2_payload_that_omits_a_null_field_is_not_canonical(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    envelope = make_envelope()
    payload = {
        "schema_version": "dppce.attestation/2",
        "decision_digest": decision_digest(envelope.decision),
        "results_root": envelope.decision.results_root,
        "records_root": envelope.decision.records_root,
        "issuer": ISSUER,
        "signed_at": SIGNED_AT,
        "role": "issuer",
        "status": None,
        "valid_until": None,
    }
    token = sign_compact(canonical_bytes(payload), signer, typ=ATTESTATION_TYP)
    report = _verify(_document(envelope) | {"signatures": [token]}, trust)
    assert _dim(report, "signature")[0] == "fail"
    outcome, detail = _dim(report, "signers")
    assert outcome == "fail"
    assert "SIGNER.SIGNATURE.INVALID" in detail
    assert not report.complete


# -- command line ----------------------------------------------------------------------------------------


def _cli_files(
    tmp_path: Path, envelope: EvidenceEnvelope, trust: TrustBundle, status_list: bytes | None = None
) -> list[str]:
    envelope_path, trust_path = tmp_path / "envelope.json", tmp_path / "trust.json"
    envelope_path.write_text(envelope.model_dump_json(by_alias=True), encoding="utf-8")
    trust_path.write_text(trust.model_dump_json(), encoding="utf-8")
    arguments = ["--envelope", str(envelope_path), "--trust", str(trust_path), "--at", AT_TEXT]
    if status_list is not None:
        list_path = tmp_path / "status-list.jws"
        list_path.write_bytes(status_list)
        arguments += ["--status-list", str(list_path)]
    return arguments


def _verifier_arguments(arguments: list[str]) -> list[str]:
    """The same files for ``python -m dppce.verifier``, which takes the envelope as a position."""
    return [arguments[1], *arguments[2:]]


def test_cli_verify_and_python_m_verifier_take_status_list(
    signer: LocalSigner, bundle: TrustBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope = _report(signer)
    clear = _cli_files(tmp_path, envelope, bundle, _list())
    assert cli.main(["verify", *clear]) == 0
    assert "STATUSLIST.REPORT.ACTIVE" in capsys.readouterr().out
    assert verifier_main(_verifier_arguments(clear)) == 0
    assert "STATUSLIST.REPORT.ACTIVE" in capsys.readouterr().out
    revoked = _cli_files(tmp_path, envelope, bundle, _list(INDEX))
    assert cli.main(["verify", *revoked]) == 4
    assert verifier_main(_verifier_arguments(revoked)) == 4
    capsys.readouterr()
    # An oversized file reaches the verifier, which reports it. It is not read in full.
    oversized = _cli_files(tmp_path, envelope, bundle, b"a" * (MAX_TOKEN_BYTES + 100))
    assert cli.main(["verify", "--json", *oversized]) == 4
    report = VerificationReport.model_validate_json(capsys.readouterr().out)
    assert _status_code(report) == ("fail", "STATUSLIST.FILE.TOO_LARGE")
    missing = [*clear[:-1], str(tmp_path / "no-such-file")]
    assert cli.main(["verify", *missing]) == 2
    assert verifier_main(_verifier_arguments(missing)) == 2


def test_report_status_list_without_trust_is_a_usage_error(
    signer: LocalSigner, bundle: TrustBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = _cli_files(tmp_path, _report(signer), bundle, _list())
    envelope, status_list = arguments[:2], arguments[-2:]
    assert cli.main(["report", *envelope, *status_list]) == 2
    assert "STATUSLIST.FILE.OPTION" in capsys.readouterr().err
    out = tmp_path / "report.html"
    assert cli.main(["report", *arguments, "--out", str(out)]) == 0
    page = out.read_text(encoding="utf-8")
    assert "STATUSLIST.REPORT.ACTIVE" in page
    assert "Signatures as declared" in page


# -- validation setup (fault E-14) -----------------------------------------------------------------------


def test_validation_setup_revoked_bit(
    signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle
) -> None:
    subject = SETUP["revoked_bit"](signed, signer, trust, AT)
    assert subject.status_list is not None
    report = verify(subject.document, subject.trust, AT, status_list=subject.status_list)
    assert _status_code(report) == ("fail", "STATUSLIST.REPORT.REVOKED")
    assert (_dim(report, "signature")[0], _dim(report, "issuer_trust")[0]) == ("pass", "pass")
    assert report.complete is False
