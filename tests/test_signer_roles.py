"""A second signature with a declared role (gap D8-14, report part; ADR 0016).

Expected values come from docs/explanation/architecture.md, section 11.4 ("Signer roles").
Every key is TEST-ONLY. An attestation names a key and a role, never a person.
"""

from __future__ import annotations

import base64
import hashlib
import json
import string
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from validation.evidence_cases import SETUP

from dppce import cli
from dppce.evidence.envelope import declared_attestation, sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import (
    EvidenceEnvelope,
    RevokedKey,
    TrustAnchor,
    TrustBundle,
    TrustedKey,
    VerificationReport,
)
from dppce.report import render
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from tests.support import AT, ISSUER, KID, make_envelope
from tests.tsa_support import b64, make_token, pem, tsa_ca, tsa_cert

REVIEW_SIGNER = LocalSigner.generate("TEST-ONLY-review-key-1")
STRANGER = LocalSigner.generate("TEST-ONLY-unknown-review-key")
REVIEW_KID = REVIEW_SIGNER.key_id
SIGNED_AT = "2026-10-13T12:05:00Z"
REVIEWED_AT = "2026-10-13T12:10:00Z"
AT_TEXT = "2026-10-14T00:00:00Z"


def _key(signer: LocalSigner, purposes: tuple[Any, ...], **changes: Any) -> TrustedKey:
    fields: dict[str, Any] = {
        "kid": signer.key_id,
        "issuer": ISSUER,
        "purposes": purposes,
        "public_jwk": signer.public_jwk(),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
    }
    return TrustedKey(**(fields | changes))


def _with(trust: TrustBundle, *keys: TrustedKey, **changes: Any) -> TrustBundle:
    return TrustBundle.model_validate(trust.model_dump() | {"keys": [*trust.keys, *keys], **changes})


@pytest.fixture
def bundle(trust: TrustBundle) -> TrustBundle:
    """The report key of the fixture plus a TEST-ONLY review key of the same issuer."""
    return _with(trust, _key(REVIEW_SIGNER, ("review",)))


def _review(
    envelope: EvidenceEnvelope, signer: LocalSigner = REVIEW_SIGNER, issuer: str = ISSUER
) -> EvidenceEnvelope:
    return sign_envelope(envelope, signer, issuer=issuer, signed_at=REVIEWED_AT, role="reviewer")


def _check(
    subject: EvidenceEnvelope | dict[str, Any], trust: TrustBundle, at: datetime = AT
) -> tuple[VerificationReport, dict[str, str]]:
    document = (
        json.loads(subject.model_dump_json(by_alias=True))
        if isinstance(subject, EvidenceEnvelope)
        else subject
    )
    report = verify(document, trust, at)
    return report, {d.name: d.outcome for d in report.dimensions}


def _detail(report: VerificationReport, name: str) -> str:
    return next(d.detail for d in report.dimensions if d.name == name)


def _row(position: int, kid: str, role: str, code: str) -> str:
    return f"signature {position}: key {kid!r} of issuer {ISSUER!r} as {role}: {code}"


def _broken(token: str) -> str:
    """The same header and payload with a signature that does not verify."""
    head, payload, _ = token.split(".")
    return f"{head}.{payload}.{base64.urlsafe_b64encode(b'x' * 64).rstrip(b'=').decode()}"


# -- roles ---------------------------------------------------------------------------------------------


def test_a_reviewer_signature_with_the_review_purpose_passes_and_lists_each_signer(
    signed: EvidenceEnvelope, bundle: TrustBundle
) -> None:
    alone, _ = _check(signed, bundle)
    report, outcomes = _check(_review(signed), bundle)
    assert outcomes["signers"] == "pass"
    detail = _detail(report, "signers")
    assert _row(1, KID, "issuer", "SIGNER.ROLE.OK") in detail
    assert _row(2, REVIEW_KID, "reviewer", "SIGNER.ROLE.OK") in detail
    for name in ("signature", "issuer_trust"):
        assert _detail(report, name) == _detail(alone, name)
    assert report.complete is True


def test_the_report_key_cannot_sign_as_reviewer(
    signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle
) -> None:
    report, outcomes = _check(_review(signed, signer), trust)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "pass")
    assert outcomes["signers"] == "fail"
    assert _row(2, KID, "reviewer", "SIGNER.ROLE.NOT_GRANTED") in _detail(report, "signers")
    assert report.complete is False


def test_a_review_key_cannot_sign_as_issuer(signed: EvidenceEnvelope, bundle: TrustBundle) -> None:
    alone = sign_envelope(make_envelope(), REVIEW_SIGNER, issuer=ISSUER, signed_at=SIGNED_AT)
    report, outcomes = _check(alone, bundle)
    assert outcomes["signature"] == "pass", "the dimension keeps its meaning"
    assert outcomes["issuer_trust"] == "fail"
    assert _detail(report, "issuer_trust") == f"Key '{REVIEW_KID}' is not trusted for reports."
    assert outcomes["signers"] == "fail"
    assert _row(1, REVIEW_KID, "issuer", "SIGNER.ROLE.NOT_GRANTED") in _detail(report, "signers")
    assert report.complete is False

    after_a_good_one = sign_envelope(signed, REVIEW_SIGNER, issuer=ISSUER, signed_at=SIGNED_AT)
    report, outcomes = _check(after_a_good_one, bundle)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "pass")
    assert outcomes["signers"] == "fail"
    assert _row(2, REVIEW_KID, "issuer", "SIGNER.ROLE.NOT_GRANTED") in _detail(report, "signers")
    assert report.complete is False


def test_a_reviewer_only_envelope_has_no_issuer_signature(bundle: TrustBundle) -> None:
    report, outcomes = _check(_review(make_envelope()), bundle)
    assert (outcomes["signature"], _detail(report, "signature")) == (
        "missing",
        "SIGNATURE.ISSUER.NONE: no signature that verifies declares the role issuer.",
    )
    assert outcomes["issuer_trust"] == "fail"
    assert _detail(report, "issuer_trust").startswith("SIGNATURE.ISSUER.NONE")
    assert outcomes["signers"] == "pass"
    assert report.complete is False


def test_a_broken_reviewer_signature_keeps_signature_pass_but_is_incomplete(
    signed: EvidenceEnvelope, bundle: TrustBundle
) -> None:
    document = json.loads(_review(signed).model_dump_json(by_alias=True))
    document["signatures"][1] = _broken(document["signatures"][1])
    report, outcomes = _check(document, bundle)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "pass")
    assert outcomes["signers"] == "fail"
    detail = _detail(report, "signers")
    assert f"signature 2: key {REVIEW_KID!r}" in detail
    assert "SIGNER.SIGNATURE.INVALID" in detail
    assert report.complete is False


def test_an_unreadable_signature_is_invalid_not_a_crash(signed: EvidenceEnvelope, trust: TrustBundle) -> None:
    document = json.loads(signed.model_dump_json(by_alias=True))
    document["signatures"].append("not a compact jws")
    report, outcomes = _check(document, trust)
    assert outcomes["signers"] == "fail"
    assert "signature 2: SIGNER.SIGNATURE.INVALID" in _detail(report, "signers")
    assert report.complete is False


@pytest.mark.parametrize("problem", ["expired", "revoked"])
def test_an_expired_or_revoked_review_key_is_not_trusted(
    problem: str, signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    if problem == "expired":
        bad = _with(trust, _key(REVIEW_SIGNER, ("review",), not_after="2026-10-13T13:00:00Z"))
    else:
        bad = _with(
            trust,
            _key(REVIEW_SIGNER, ("review",)),
            revoked_keys=[RevokedKey(kid=REVIEW_KID, revoked_at="2026-10-13T13:00:00Z")],
        )
    reviewed = _review(signed)
    report, outcomes = _check(reviewed, bad)
    assert (outcomes["signature"], outcomes["issuer_trust"]) == ("pass", "pass")
    assert outcomes["signers"] == "fail"
    assert _row(2, REVIEW_KID, "reviewer", "SIGNER.KEY.NOT_TRUSTED") in _detail(report, "signers")
    assert report.complete is False

    # A trusted timestamp over the reviewer signature checks the key at its genTime.
    ca = tsa_ca()
    gen = datetime(2026, 10, 13, 12, 11, tzinfo=UTC)
    part = reviewed.signatures[1].split(".")[2]
    signature_value = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    token = make_token(hashlib.sha256(signature_value).digest(), gen, tsa_cert(ca))
    document = json.loads(reviewed.model_dump_json(by_alias=True)) | {"timestamp_evidence": [b64(token)]}
    anchored = bad.model_copy(
        update={"timestamp_anchors": (TrustAnchor(name="TEST-ONLY TSA anchor", certificate_pem=pem(ca[1])),)}
    )
    report, outcomes = _check(document, anchored)
    assert outcomes["timestamp"] == "pass"
    assert outcomes["signers"] == "pass"
    assert _row(2, REVIEW_KID, "reviewer", "SIGNER.ROLE.OK") in _detail(report, "signers")
    assert report.complete is True


def test_a_reviewer_attestation_with_another_issuer_fails(
    signed: EvidenceEnvelope, bundle: TrustBundle
) -> None:
    report, outcomes = _check(_review(signed, issuer="urn:example:other-lab"), bundle)
    assert outcomes["signers"] == "fail"
    assert _row(2, REVIEW_KID, "reviewer", "SIGNER.ISSUER.MISMATCH") in _detail(report, "signers")
    assert report.complete is False


def test_a_signature_with_an_unknown_key_is_listed_and_not_checked(
    signed: EvidenceEnvelope, bundle: TrustBundle
) -> None:
    report, outcomes = _check(_review(signed, STRANGER), bundle)
    assert outcomes["signers"] == "pass"
    assert f"signature 2: key {STRANGER.key_id!r}: SIGNER.KEY.UNKNOWN, not checked" in _detail(
        report, "signers"
    )
    assert report.complete is True


def test_signers_without_a_trusted_key_is_not_checked_and_without_signatures_missing(
    trust: TrustBundle,
) -> None:
    _, outcomes = _check(_review(make_envelope(), STRANGER), trust)
    assert outcomes["signers"] == "not_checked"
    _, outcomes = _check(make_envelope(), trust)
    assert outcomes["signers"] == "missing"


def test_existing_envelope_compatibility_of_signers(
    signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle
) -> None:
    # (a) An extra token that names the trusted report key but does not verify.
    document = json.loads(signed.model_dump_json(by_alias=True))
    document["signatures"].append(_broken(signed.signatures[0]))
    report, outcomes = _check(document, trust)
    assert (outcomes["signature"], outcomes["issuer_trust"], outcomes["signers"]) == ("pass", "pass", "fail")
    assert "SIGNER.SIGNATURE.INVALID" in _detail(report, "signers")
    assert report.complete is False

    # (b) An extra version 1 signature by a trusted key with only the purpose manual.
    manual = LocalSigner.generate("TEST-ONLY-manual-key-1")
    with_manual = _with(trust, _key(manual, ("manual",)))
    extra = sign_envelope(signed, manual, issuer=ISSUER, signed_at=SIGNED_AT)
    report, outcomes = _check(extra, with_manual)
    assert (outcomes["issuer_trust"], outcomes["signers"]) == ("pass", "fail")
    assert _row(2, manual.key_id, "issuer", "SIGNER.ROLE.NOT_GRANTED") in _detail(report, "signers")
    assert report.complete is False

    # (c) An earlier issuer signature by an expired key K1, then a good one by K2: unchanged.
    old = LocalSigner.generate("TEST-ONLY-report-key-old")
    with_old = _with(trust, _key(old, ("report",), not_after="2026-10-01T00:00:00Z"))
    first = sign_envelope(make_envelope(), old, issuer=ISSUER, signed_at=SIGNED_AT)
    both = sign_envelope(first, signer, issuer=ISSUER, signed_at=SIGNED_AT)
    report, outcomes = _check(both, with_old)
    assert (outcomes["issuer_trust"], outcomes["signers"]) == ("pass", "pass")
    assert _row(1, old.key_id, "issuer", "SIGNER.KEY.NOT_TRUSTED") in _detail(report, "signers")
    assert _row(2, KID, "issuer", "SIGNER.ROLE.OK") in _detail(report, "signers")
    assert report.complete is True


# -- the trust bundle refuses one key with review and report ----------------------------------------


def _bundle(*keys: TrustedKey) -> TrustBundle:
    return TrustBundle(schema_version="dppce.trust/2", policy_version="test-1", keys=keys)


def test_a_key_with_review_and_report_is_refused(signer: LocalSigner) -> None:
    with pytest.raises(ValidationError, match=r"TRUST\.KEY\.ROLE_CONFLICT"):
        _bundle(_key(signer, ("report", "review")))
    _bundle(_key(signer, ("report", "authorization")), _key(REVIEW_SIGNER, ("review",)))


def _respelled(text: str) -> str:
    """The same 32 bytes in base64url with a different value in the two unused low bits."""
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    return text[:-1] + alphabet[alphabet.index(text[-1]) ^ 1]


def test_one_public_key_under_two_kids_with_review_and_report_is_refused(signer: LocalSigner) -> None:
    report_key = _key(signer, ("report",), kid="lab-1")
    with pytest.raises(ValidationError, match=r"TRUST\.KEY\.ROLE_CONFLICT"):
        _bundle(report_key, _key(signer, ("review",), kid="lab-1-review"))
    jwk = signer.public_jwk()
    respelled = {**jwk, "x": _respelled(jwk["x"])}
    assert respelled["x"] != jwk["x"]
    assert base64.urlsafe_b64decode(respelled["x"] + "=") == base64.urlsafe_b64decode(jwk["x"] + "=")
    with pytest.raises(ValidationError, match=r"TRUST\.KEY\.ROLE_CONFLICT"):
        _bundle(report_key, _key(signer, ("review",), kid="lab-1-review", public_jwk=respelled))


def test_trust_bundle_role_conflict_is_reported_with_its_code(
    signed: EvidenceEnvelope, signer: LocalSigner, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conflict = json.loads(_key(signer, ("report",)).model_dump_json())
    conflict["purposes"] = ["report", "review"]
    trust_path, envelope_path = tmp_path / "bundle.json", tmp_path / "envelope.json"
    trust_path.write_text(
        json.dumps({"schema_version": "dppce.trust/2", "policy_version": "test-1", "keys": [conflict]}),
        encoding="utf-8",
    )
    envelope_path.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    files = ["--envelope", str(envelope_path), "--trust", str(trust_path), "--at", AT_TEXT]
    for run in (
        lambda: cli.main(["verify", *files]),
        lambda: cli.main(["report", *files]),
        lambda: verifier_main([str(envelope_path), *files[2:]]),
    ):
        assert run() == 2
        error = capsys.readouterr().err
        assert error.startswith("error: TRUST.KEY.ROLE_CONFLICT"), error


# -- command line and HTML -------------------------------------------------------------------------------


def test_cli_sign_role_reviewer_and_option_errors(
    signed: EvidenceEnvelope, bundle: TrustBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key_path, envelope_path = tmp_path / "TEST-ONLY-review.key.pem", tmp_path / "envelope.json"
    key_path.write_bytes(REVIEW_SIGNER.to_pem())
    envelope_path.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    common = ["sign", "--envelope", str(envelope_path), "--key", str(key_path), "--kid", REVIEW_KID]
    common += ["--issuer", ISSUER, "--allow-unencrypted-key"]

    out = tmp_path / "reviewed.json"
    assert cli.main([*common, "--role", "reviewer", "--out", str(out), "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert (summary["role"], summary["signatures"]) == ("reviewer", 2)
    reviewed = EvidenceEnvelope.model_validate_json(out.read_text(encoding="utf-8"))
    kid, attestation = declared_attestation(reviewed.signatures[1])
    assert kid == REVIEW_KID
    assert attestation is not None
    assert (attestation.schema_version, attestation.signer_role) == ("dppce.attestation/2", "reviewer")
    assert _check(reviewed, bundle)[0].complete is True

    for wrong in (
        ["--role", "reviewer", "--valid-until", "2026-12-01T00:00:00Z"],
        ["--status-index", "3"],
        ["--status-list-id", "urn:example:TEST-ONLY-status-list-1"],
        ["--valid-until", "tomorrow"],
        ["--supersedes", "sha256:short"],
    ):
        assert cli.main([*common, *wrong, "--out", str(tmp_path / "x.json")]) == 2, wrong
        assert "SIGN.OPTION.INVALID" in capsys.readouterr().err
    assert not (tmp_path / "x.json").exists()

    stated = tmp_path / "stated.json"
    issuer_options = ["--status-list-id", "urn:example:TEST-ONLY-status-list-1", "--status-index", "3"]
    issuer_options += ["--valid-until", "2026-12-01T00:00:00Z", "--supersedes", "sha256:" + "b" * 64]
    assert cli.main([*common, *issuer_options, "--out", str(stated)]) == 0
    capsys.readouterr()
    _, attestation = declared_attestation(
        EvidenceEnvelope.model_validate_json(stated.read_text()).signatures[1]
    )
    assert attestation is not None
    assert attestation.signer_role == "issuer"
    assert attestation.status is not None
    assert (attestation.status.index, attestation.valid_until) == (3, "2026-12-01T00:00:00Z")


def test_html_lists_each_declared_signature_escaped(signed: EvidenceEnvelope) -> None:
    odd = LocalSigner.generate("TEST-ONLY-<b>-key")
    envelope = _review(signed, odd)
    envelope = envelope.model_copy(update={"signatures": (*envelope.signatures, "not a compact jws")})
    page = render(envelope)
    assert "Signatures as declared" in page
    assert "TEST-ONLY-&lt;b&gt;-key" in page
    assert "<b>-key" not in page
    assert "reviewer" in page
    assert "cannot be read" in page
    assert "Only the verification section shows whether a signature verifies." in page


# -- validation setup (fault E-15) -----------------------------------------------------------------------


def test_validation_setup_role_swap(
    signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle
) -> None:
    subject = SETUP["role_swap"](signed, signer, trust, AT)
    report = verify(subject.document, subject.trust, AT, status_list=subject.status_list)
    outcomes = {d.name: d.outcome for d in report.dimensions}
    assert (outcomes["signature"], outcomes["issuer_trust"], outcomes["signers"]) == ("pass", "pass", "fail")
    assert "SIGNER.ROLE.NOT_GRANTED" in _detail(report, "signers")
    assert report.complete is False
