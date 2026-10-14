"""Edge cases of the evidence layer: malformed tokens, damaged recordings, retention, and the
standalone verifier command.

Each case here is a way that input can be wrong. None of them may be reported as a valid result.
"""

from __future__ import annotations

import base64
import json
from datetime import date
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.jws import (
    MAX_HEADER_BYTES,
    LocalSigner,
    SignatureError,
    header_of,
    sign_compact,
    verify_compact,
)
from dppce.evidence.recording import (
    RecordingError,
    commit,
    purge_expired,
    read_index,
    read_recording,
    record_commitments,
    record_from_json,
    record_to_json,
    write_recording,
)
from dppce.infrastructure.authorization import AUTHORIZATION_TYP, AuthorizationError, validate_authorization
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.resources import data_root
from dppce.models import EvidenceEnvelope, TrustBundle
from dppce.verifier.__main__ import main as verifier_main
from tests.support import AT, make_record

TYP = "dppce-attestation+jws"


class _Keys:
    def __init__(self, key: bytes = bytes(range(32))) -> None:
        self._key = key

    def data_key(self, key_id: str) -> bytes:
        return self._key

    def default_key_id(self) -> str:
        return "TEST-ONLY-data-key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# -- tokens -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    ["only.two", "a.b.c.d", "!!!.e30.sig", f"{_b64(b'not json')}.e30.sig", f"{_b64(b'[1, 2]')}.e30.sig"],
)
def test_a_malformed_token_has_no_header(token: str) -> None:
    with pytest.raises(SignatureError) as caught:
        header_of(token)
    assert caught.value.code == "MALFORMED"


def _token(header: dict[str, object], signer: LocalSigner, payload: bytes = b"payload") -> str:
    signing_input = f"{_b64(canonical_bytes(header))}.{_b64(payload)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64(signer.sign(signing_input))}"


def test_each_reason_a_token_is_refused_has_its_own_code(signer: LocalSigner) -> None:
    good = {"alg": "ES256", "kid": signer.key_id, "typ": TYP}
    jwk = signer.public_jwk()
    assert verify_compact(_token(good, signer), jwk, typ=TYP) == b"payload"
    refused = {
        "an algorithm outside the allowlist": (_token(good | {"alg": "ES384"}, signer), jwk, "ALGORITHM"),
        "a different type": (_token(good | {"typ": "other+jws"}, signer), jwk, "TYPE"),
        "an unknown header parameter": (_token(good | {"crit": ["x"]}, signer), jwk, "HEADER"),
        "a key on a different curve": (_token(good, signer), jwk | {"crv": "P-384"}, "KEY"),
        "a key of a different type": (_token(good, signer), jwk | {"kty": "oct"}, "KEY"),
        "a different key": (
            _token(good, signer),
            LocalSigner.generate("other").public_jwk(),
            "BAD_SIGNATURE",
        ),
        "a changed payload": (
            _token(good, signer).replace(_b64(b"payload"), _b64(b"changed")),
            jwk,
            "BAD_SIGNATURE",
        ),
    }
    for reason, (token, key, code) in refused.items():
        with pytest.raises(SignatureError) as caught:
            verify_compact(token, key, typ=TYP)
        assert caught.value.code == code, reason


def test_a_token_above_the_size_limit_is_too_large_and_not_invalid(signer: LocalSigner) -> None:
    """A limit of the engine must never read as a failed signature."""
    padded = {"alg": "ES256", "kid": "k" * (MAX_HEADER_BYTES + 1), "typ": TYP}
    with pytest.raises(SignatureError) as caught:
        verify_compact(_token(padded, signer), signer.public_jwk(), typ=TYP)
    assert caught.value.code == "TOO_LARGE"
    with pytest.raises(SignatureError) as caught:
        verify_compact("a" * 3_000_000, signer.public_jwk(), typ=TYP)
    assert caught.value.code == "TOO_LARGE"


def test_a_header_with_a_certificate_fits_inside_the_limit(signer: LocalSigner) -> None:
    """The library default of 512 bytes is smaller than one certificate. See the limits in jws.py."""
    with_certificate = {"alg": "ES256", "kid": signer.key_id, "typ": TYP, "x5c": ["A" * 2000]}
    assert verify_compact(_token(with_certificate, signer), signer.public_jwk(), typ=TYP) == b"payload"


def test_a_local_signer_accepts_only_a_p256_key(tmp_path: Path) -> None:
    signer = LocalSigner.generate("TEST-ONLY-k")
    path = tmp_path / "TEST-ONLY-k.pem"
    path.write_bytes(signer.to_pem())
    assert LocalSigner.from_pem(path, "TEST-ONLY-k").public_jwk() == signer.public_jwk()
    with pytest.raises(SignatureError, match="P-256"):
        LocalSigner("k", ec.generate_private_key(ec.SECP384R1()))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    with pytest.raises(SignatureError, match="elliptic-curve"):
        LocalSigner.from_pem(path, "k")


def test_a_signer_with_a_disallowed_algorithm_cannot_sign() -> None:
    class Other:
        key_id, algorithm = "k", "HS256"

        def sign(self, signing_input: bytes) -> bytes:
            return b""

    with pytest.raises(SignatureError) as caught:
        sign_compact(b"x", Other(), typ=TYP)
    assert caught.value.code == "ALGORITHM"


# -- authorization ----------------------------------------------------------------------------


def test_a_malformed_or_non_canonical_authorization_is_refused(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization("not-a-token", trust, AT, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"
    not_an_authorization = sign_compact(b'{"hello": "world"}', signer, typ=AUTHORIZATION_TYP)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(not_an_authorization, trust, AT, "urn:example:sut")
    assert caught.value.code == "AUTHZ.MALFORMED"


# -- recording --------------------------------------------------------------------------------


def test_record_identifiers_are_checked_before_anything_is_written(tmp_path: Path) -> None:
    with pytest.raises(RecordingError, match="repeated"):
        record_commitments([make_record(1), make_record(1)])
    escape = Record(**{**make_record(1).__dict__, "record_id": "../escape"})
    with pytest.raises(RecordingError, match="not valid"):
        record_commitments([escape])
    with pytest.raises(RecordingError, match="not valid"):
        write_recording(tmp_path / "r", [escape], _Keys(), created=date(2026, 10, 13), retention_days=1)
    short_salt = Record(**{**make_record(1).__dict__, "salt": b"short"})
    with pytest.raises(RecordingError, match="salt"):
        commit(short_salt)


def test_a_record_round_trips_through_its_json_form() -> None:
    record = make_record(7, b"\x00\xff binary")
    assert record_from_json(record_to_json(record, with_salt=True)) == record
    assert "salt" not in record_to_json(record, with_salt=False)
    with pytest.raises(RecordingError, match="malformed"):
        record_from_json({"record_id": "r0001"})


def test_a_damaged_recording_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RecordingError, match="index"):
        read_index(tmp_path)
    directory = tmp_path / "recording"
    write_recording(
        directory, [make_record(1), make_record(2)], _Keys(), created=date(2026, 10, 13), retention_days=1
    )
    with pytest.raises(RecordingError, match="does not authenticate"):
        read_recording(directory, _Keys(bytes(32))), "a different key reads nothing"
    (directory / "records" / "r0002.enc").unlink()
    with pytest.raises(RecordingError, match="missing"):
        read_recording(directory, _Keys())
    index = json.loads((directory / "recording.json").read_text())
    index["records"][0]["record_id"] = "../../etc/passwd"
    (directory / "recording.json").write_text(json.dumps(index))
    with pytest.raises(RecordingError):
        read_recording(directory, _Keys())


def test_an_empty_recording_is_valid(tmp_path: Path) -> None:
    index = write_recording(tmp_path / "r", [], _Keys(), created=date(2026, 10, 13), retention_days=0)
    assert index.records == ()
    assert read_recording(tmp_path / "r", _Keys()) == ()


def test_purge_deletes_only_recordings_past_their_retention_date(tmp_path: Path) -> None:
    runs = tmp_path / "run"
    write_recording(runs / "old", [make_record(1)], _Keys(), created=date(2026, 1, 1), retention_days=30)
    write_recording(runs / "new", [make_record(1)], _Keys(), created=date(2026, 10, 1), retention_days=30)
    (runs / "not-a-recording").mkdir()
    (runs / "not-a-recording" / "keep.txt").write_text("keep")
    (runs / "damaged").mkdir()
    (runs / "damaged" / "recording.json").write_text("{not json")
    keys, today = _Keys(), date(2026, 10, 13)
    assert purge_expired(runs, date(2026, 1, 31), keys, delete=True).expired == (), "the last day is kept"
    assert purge_expired(runs, today, keys).expired == (runs / "old",)
    assert (runs / "old").is_dir(), "a purge without the delete option removes nothing"
    assert purge_expired(runs, today, keys, delete=True).expired == (runs / "old",)
    assert sorted(p.name for p in runs.iterdir()) == ["damaged", "new", "not-a-recording"]
    assert purge_expired(tmp_path / "absent", today, keys, delete=True).expired == ()


# -- standalone verifier command ----------------------------------------------------------------


def test_the_verifier_runs_alone_and_reports_through_its_exit_status(
    signed: EvidenceEnvelope, trust: TrustBundle, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    envelope, bundle = tmp_path / "envelope.json", tmp_path / "trust.json"
    envelope.write_text(signed.model_dump_json(by_alias=True))
    bundle.write_text(trust.model_dump_json())
    arguments = [str(envelope), "--trust", str(bundle), "--at", "2026-10-14T00:00:00Z"]
    assert verifier_main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["complete"] is True
    envelope.write_text(signed.model_dump_json(by_alias=True).replace('"overall":"fail"', '"overall":"pass"'))
    assert verifier_main(arguments) == 4
    assert json.loads(capsys.readouterr().out)["complete"] is False
    assert verifier_main([str(envelope), "--trust", str(bundle), "--at", "yesterday"]) == 2
    assert (
        verifier_main([str(tmp_path / "absent.json"), "--trust", str(bundle), "--at", "2026-10-14T00:00:00Z"])
        == 2
    )
    bundle.write_text(
        '{"schema_version": "dppce.trust/1", "schema_version": "dppce.trust/1", "policy_version": "x"}'
    )
    assert verifier_main(arguments) == 2, "a trust bundle with a repeated key is not read"
    assert "error:" in capsys.readouterr().err


def test_the_verifier_does_not_import_the_orchestrator_or_the_adapters() -> None:
    """The verifier must run without the orchestrator and without the system under test."""
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    code = (
        "import sys, dppce.verifier, dppce.verifier.__main__\n"
        "bad = [m for m in sys.modules if m.startswith(('dppce.orchestrator', 'dppce.adapters', "
        "'dppce.infrastructure.transport', 'dppce.testdefs', 'dppce.cli'))]\n"
        "print(bad); sys.exit(1 if bad else 0)"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)  # noqa: S603 - fixed code
    assert done.returncode == 0, done.stdout


# -- resources --------------------------------------------------------------------------------


def test_the_data_root_is_the_override_or_the_checkout(tmp_path: Path) -> None:
    assert data_root(tmp_path) == tmp_path
    assert (data_root() / "catalogue" / "sources.yaml").is_file()
