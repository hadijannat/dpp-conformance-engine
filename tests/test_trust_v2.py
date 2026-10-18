"""Trust bundle version 2: issuer-scoped, dated revocation (gap D8-10) and its migration.

Expected values come from docs/explanation/architecture.md, section 11.4 ("Trust bundle
version 2"). Every key and certificate here is generated for the test run and is TEST-ONLY.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from dppce import cli
from dppce.evidence.x509path import revoked
from dppce.migrations import CURRENT, MigrationError, migrate
from dppce.models import (
    EvidenceEnvelope,
    RevokedCertificate,
    RevokedKey,
    RunInputsRecord,
    TrustAnchor,
    TrustBundle,
)
from dppce.verifier.__main__ import main as verifier_main

START, END = datetime(2026, 1, 1, tzinfo=UTC), datetime(2036, 1, 1, tzinfo=UTC)
AT = datetime(2026, 10, 14, tzinfo=UTC)
SERIAL = 0x1F2E3D
Pair = tuple[ec.EllipticCurvePrivateKey, x509.Certificate]


def _authority(name: str) -> Pair:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEST-ONLY authorities"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(START)
        .not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _leaf(authority: Pair, *, serial: int = SERIAL, aki: bool = True) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST-ONLY leaf")]))
        .issuer_name(authority[1].subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(START)
        .not_valid_after(END)
    )
    if aki:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority[0].public_key()), critical=False
        )
    return builder.sign(authority[0], hashes.SHA256())


def _key_id(authority: Pair) -> str:
    return x509.SubjectKeyIdentifier.from_public_key(authority[0].public_key()).digest.hex()


def _by_name(authority: Pair, revoked_at: str | None = None, serial: int = SERIAL) -> RevokedCertificate:
    return RevokedCertificate(
        serial=f"{serial:x}", issuer_name=authority[1].subject.rfc4514_string(), revoked_at=revoked_at
    )


# -- model validators -------------------------------------------------------------------------


def test_a_revoked_certificate_names_exactly_one_issuer() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        RevokedCertificate(serial="01", revoked_at=None)
    with pytest.raises(ValidationError, match="exactly one"):
        RevokedCertificate(serial="01", issuer_name="CN=TEST-ONLY A", issuer_key_id="0a0b", revoked_at=None)
    assert (
        RevokedCertificate(serial="01", issuer_name="CN=TEST-ONLY A", revoked_at=None).issuer_key_id is None
    )
    assert RevokedCertificate(serial="01", issuer_key_id="0A0b", revoked_at=None).issuer_name is None


def test_an_issuer_name_that_is_not_rfc_4514_is_refused() -> None:
    with pytest.raises(ValidationError, match="RFC 4514"):
        RevokedCertificate(serial="01", issuer_name="not a name", revoked_at=None)
    with pytest.raises(ValidationError):
        RevokedCertificate(serial="01", issuer_key_id="abc", revoked_at=None)  # odd number of digits


@pytest.mark.parametrize("serial", ["not-hex", "", "12 34", "0x1f", "12::34"])
def test_a_serial_that_cannot_be_parsed_is_refused(serial: str) -> None:
    with pytest.raises(ValidationError):
        RevokedCertificate(serial=serial, issuer_name="CN=TEST-ONLY A", revoked_at=None)


def test_revoked_at_is_a_time_or_null_and_has_no_default() -> None:
    with pytest.raises(ValidationError, match="revoked_at"):
        RevokedCertificate.model_validate({"serial": "01", "issuer_name": "CN=TEST-ONLY A"})
    with pytest.raises(ValidationError, match="revoked_at"):
        RevokedKey.model_validate({"kid": "k"})
    with pytest.raises(ValidationError):
        RevokedKey(kid="k", revoked_at="2026-10-13")
    with pytest.raises(ValidationError):
        RevokedKey(kid="", revoked_at=None)
    assert RevokedKey(kid="k", revoked_at="2026-10-13T12:00:00Z").revoked_at == "2026-10-13T12:00:00Z"


def test_an_anchor_with_a_pem_that_does_not_load_is_refused() -> None:
    with pytest.raises(ValidationError, match="PEM"):
        TrustAnchor(name="TEST-ONLY garbage", certificate_pem="-----BEGIN CERTIFICATE-----\nAAAA\n")
    with pytest.raises(ValidationError, match="PEM"):
        TrustAnchor(name="TEST-ONLY not ascii", certificate_pem="é")


# -- issuer-scoped revocation (D8-10) -------------------------------------------------------------


def test_a_serial_revoked_under_authority_a_does_not_revoke_a_certificate_of_authority_b() -> None:
    a, b = _authority("TEST-ONLY authority A"), _authority("TEST-ONLY authority B")
    leaf_a, leaf_b = _leaf(a), _leaf(b)
    assert leaf_a.serial_number == leaf_b.serial_number
    by_name = (_by_name(a),)
    assert revoked([leaf_a, a[1]], by_name, AT)
    assert not revoked([leaf_b, b[1]], by_name, AT), "the issuer of B differs"
    by_key_id = (RevokedCertificate(serial=f"{SERIAL:X}", issuer_key_id=_key_id(a), revoked_at=None),)
    assert revoked([leaf_a, a[1]], by_key_id, AT)
    assert not revoked([leaf_b, b[1]], by_key_id, AT)


def test_the_issuer_name_round_trips_through_rfc_4514() -> None:
    a = _authority("TEST-ONLY authority A")
    assert x509.Name.from_rfc4514_string(a[1].subject.rfc4514_string()) == a[1].subject


def test_a_certificate_without_an_authority_key_identifier_never_matches_a_key_id() -> None:
    a = _authority("TEST-ONLY authority A")
    bare = _leaf(a, aki=False)
    entry = RevokedCertificate(serial=f"{SERIAL:x}", issuer_key_id=_key_id(a), revoked_at=None)
    assert not revoked([bare], (entry,), AT)
    assert revoked([bare], (_by_name(a),), AT), "the name still matches"


def test_the_serial_must_match_too() -> None:
    a = _authority("TEST-ONLY authority A")
    assert not revoked([_leaf(a)], (_by_name(a, serial=SERIAL + 1),), AT)
    assert not revoked([_leaf(a)], (), AT)


def test_a_revocation_applies_from_revoked_at() -> None:
    a = _authority("TEST-ONLY authority A")
    leaf = _leaf(a)
    assert revoked([leaf], (_by_name(a, None),), AT), "null: revoked at every time"
    assert revoked([leaf], (_by_name(a, "2026-10-14T00:00:00Z"),), AT), "equal counts"
    assert revoked([leaf], (_by_name(a, "2026-10-13T23:59:59Z"),), AT)
    assert not revoked([leaf], (_by_name(a, "2026-10-14T00:00:01Z"),), AT)
    later = AT + timedelta(microseconds=500_000)
    assert not revoked([leaf], (_by_name(a, "2026-10-14T00:00:01Z"),), later), "exact instants"


def test_key_revoked_follows_the_same_rules() -> None:
    def bundle(*entries: RevokedKey) -> TrustBundle:
        return TrustBundle(schema_version="dppce.trust/2", policy_version="test", revoked_keys=entries)

    at = datetime(2026, 10, 13, 12, 6, tzinfo=UTC)
    assert bundle(RevokedKey(kid="k", revoked_at=None)).key_revoked("k", at)
    assert not bundle(RevokedKey(kid="k", revoked_at=None)).key_revoked("other", at)
    assert bundle(RevokedKey(kid="k", revoked_at="2026-10-13T12:06:00Z")).key_revoked("k", at)
    assert not bundle(RevokedKey(kid="k", revoked_at="2026-10-13T12:06:01Z")).key_revoked("k", at)
    half = at + timedelta(microseconds=500_000)
    assert bundle(RevokedKey(kid="k", revoked_at="2026-10-13T12:06:00Z")).key_revoked("k", half)
    assert not bundle(RevokedKey(kid="k", revoked_at="2026-10-13T12:06:01Z")).key_revoked("k", half)


# -- migration ----------------------------------------------------------------------------------

V1: dict[str, Any] = {"schema_version": "dppce.trust/1", "policy_version": "test-1"}


def test_current_versions() -> None:
    assert CURRENT["trust"] == "dppce.trust/2"
    assert CURRENT["runinputs"] == "dppce.runinputs/3"


def test_a_version_1_bundle_with_revoked_kids_migrates_without_a_change_of_effect() -> None:
    old = {**V1, "revoked_kids": ["k", "k"], "revoked_serials": []}
    before = copy.deepcopy(old)
    new = migrate("trust", old)
    assert old == before, "the input is not changed"
    assert new == {
        "schema_version": "dppce.trust/2",
        "policy_version": "test-1",
        "revoked_keys": [{"kid": "k", "revoked_at": None}],
        "revoked_certificates": [],
        "timestamp_anchors": [],
    }
    bundle = TrustBundle.model_validate(new)
    assert bundle.key_revoked("k", AT)


def test_a_version_1_bundle_without_revocations_migrates() -> None:
    bundle = TrustBundle.model_validate(migrate("trust", dict(V1)))
    assert (bundle.revoked_keys, bundle.revoked_certificates, bundle.timestamp_anchors) == ((), (), ())


def test_a_version_1_bundle_with_revoked_serials_is_refused() -> None:
    old = {**V1, "revoked_serials": ["01"]}
    before = copy.deepcopy(old)
    with pytest.raises(MigrationError, match=r"TRUST\.MIGRATION\.UNSCOPED_SERIAL"):
        migrate("trust", old)
    assert old == before


@pytest.mark.parametrize(
    "fields",
    [
        {"revoked_kids": None},
        {"revoked_kids": "abc"},
        {"revoked_kids": [[1]]},
        {"revoked_kids": [""]},
        {"revoked_serials": False},
        {"revoked_serials": 0},
        {"revoked_serials": None},
        {"revoked_keys": []},
        {"revoked_certificates": []},
        {"timestamp_anchors": []},
    ],
)
def test_a_version_1_bundle_of_the_wrong_shape_is_refused(fields: dict[str, Any]) -> None:
    old = {**V1, **fields}
    before = copy.deepcopy(old)
    with pytest.raises(MigrationError, match=r"TRUST\.MIGRATION\.MALFORMED"):
        migrate("trust", old)
    assert old == before


def _runinputs_2(trust: Any) -> dict[str, Any]:
    from tests.core.test_models_and_migrations import RUNINPUTS_1  # noqa: PLC0415 - one shared layout

    record = migrate("runinputs", {**RUNINPUTS_1, "trust": None})
    return {**record, "schema_version": "dppce.runinputs/2", "trust": trust}


def test_a_version_2_record_of_run_inputs_migrates_its_trust_bundle() -> None:
    old = _runinputs_2({**V1, "revoked_kids": ["k"]})
    before = copy.deepcopy(old)
    new = migrate("runinputs", old)
    assert old == before
    assert new["schema_version"] == "dppce.runinputs/3"
    assert new["trust"]["schema_version"] == "dppce.trust/2"
    assert new["trust"]["revoked_keys"] == [{"kid": "k", "revoked_at": None}]
    assert RunInputsRecord.model_validate(new).trust is not None
    assert migrate("runinputs", _runinputs_2(None))["trust"] is None


@pytest.mark.parametrize("trust", ["x", [], {**V1, "schema_version": "dppce.trust/9"}])
def test_a_version_2_record_with_a_wrong_trust_value_is_refused(trust: Any) -> None:
    with pytest.raises(MigrationError, match=r"TRUST\.MIGRATION\.MALFORMED"):
        migrate("runinputs", _runinputs_2(trust))


def test_a_version_2_record_with_unscoped_serials_is_refused() -> None:
    with pytest.raises(MigrationError, match=r"TRUST\.MIGRATION\.UNSCOPED_SERIAL"):
        migrate("runinputs", _runinputs_2({**V1, "revoked_serials": ["01"]}))


def test_a_version_1_record_of_run_inputs_chains_to_version_3() -> None:
    from tests.core.test_models_and_migrations import RUNINPUTS_1  # noqa: PLC0415

    new = migrate("runinputs", {**RUNINPUTS_1, "trust": {**V1, "revoked_kids": []}})
    assert new["schema_version"] == "dppce.runinputs/3"
    assert new["trust"]["schema_version"] == "dppce.trust/2"


# -- loaders --------------------------------------------------------------------------------------


def _as_v1(bundle: TrustBundle, **more: Any) -> dict[str, Any]:
    document = json.loads(bundle.model_dump_json())
    for name in ("revoked_certificates", "revoked_keys", "timestamp_anchors"):
        del document[name]
    return {**document, "schema_version": "dppce.trust/1", "revoked_serials": [], "revoked_kids": [], **more}


def _files(tmp_path: Path, signed: EvidenceEnvelope, trust: dict[str, Any]) -> tuple[Path, Path]:
    envelope, bundle = tmp_path / "envelope.json", tmp_path / "trust.json"
    envelope.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    bundle.write_text(json.dumps(trust), encoding="utf-8")
    return envelope, bundle


@pytest.mark.parametrize("entry", ["cli", "module"])
def test_a_version_1_bundle_file_is_migrated_when_it_loads(
    entry: str,
    tmp_path: Path,
    signed: EvidenceEnvelope,
    trust: TrustBundle,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def run(document: dict[str, Any]) -> int:
        envelope, bundle = _files(tmp_path, signed, document)
        at = "2026-10-14T00:00:00Z"
        if entry == "cli":
            return cli.main(["verify", "--envelope", str(envelope), "--trust", str(bundle), "--at", at])
        return verifier_main([str(envelope), "--trust", str(bundle), "--at", at])

    assert run(_as_v1(trust)) == 0
    capsys.readouterr()
    assert run(_as_v1(trust, revoked_serials=["01"])) == 2
    err = capsys.readouterr().err
    assert "TRUST.MIGRATION.UNSCOPED_SERIAL" in err
    assert "Traceback" not in err
    assert run(_as_v1(trust, revoked_kids="abc")) == 2
    err = capsys.readouterr().err
    assert "TRUST.MIGRATION.MALFORMED" in err
    assert "Traceback" not in err


def test_a_bundle_file_that_is_not_an_object_is_an_input_error(
    tmp_path: Path, signed: EvidenceEnvelope, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope, bundle = tmp_path / "envelope.json", tmp_path / "trust.json"
    envelope.write_text(signed.model_dump_json(by_alias=True), encoding="utf-8")
    bundle.write_text("[1]", encoding="utf-8")
    at = "2026-10-14T00:00:00Z"
    assert cli.main(["verify", "--envelope", str(envelope), "--trust", str(bundle), "--at", at]) == 2
    assert "TRUST.BUNDLE.NOT_OBJECT" in capsys.readouterr().err
    assert verifier_main([str(envelope), "--trust", str(bundle), "--at", at]) == 2
    assert "TRUST.BUNDLE.NOT_OBJECT" in capsys.readouterr().err
