"""Operator key tooling: keys generate, sign, authorize, trust-bundle add-key, and run data keys (gap D6-08).

Expected values come from docs/explanation/architecture.md, sections 10 and 11.3 ("Signing keys").
Every key is generated in a temporary directory and is TEST-ONLY. Each passphrase is generated for
the test run and is set through a ``DPPCE_SECRET_`` variable. Nothing reaches another host.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from asn1crypto import keys as asn1_keys
from asn1crypto import pem as asn1_pem
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from validation.rig import ReferenceRig

from dppce import cli, schemas
from dppce.evidence.jws import LocalSigner, _b64, public_jwk_of
from dppce.infrastructure.authorization import validate_authorization
from dppce.models import Authorization, TrustBundle
from tests.support import ISSUER, make_envelope
from tests.test_review_round2 import FIXTURES, _run_arguments

PASSPHRASE_ENV = "DPPCE_SECRET_TEST_ONLY_PASSPHRASE"
PASSPHRASE_REF = f"env:{PASSPHRASE_ENV}"
WRONG_ENV = "DPPCE_SECRET_TEST_ONLY_WRONG_PASSPHRASE"
AT_TEXT = "2026-10-14T00:00:00Z"
OWNER = "urn:example:operator:0001"
SUT = "urn:example:sut"
PERIOD = ["--not-before", "2026-01-01T00:00:00Z", "--not-after", "2027-01-01T00:00:00Z"]
PURPOSES = ("report", "authorization", "passport", "manual", "review", "status")

Run = Callable[..., tuple[int, str, str]]


@pytest.fixture
def passphrase(monkeypatch: pytest.MonkeyPatch) -> str:
    value = "TEST-ONLY-" + secrets.token_urlsafe(24)
    monkeypatch.setenv(PASSPHRASE_ENV, value)
    return value


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Run:
    """Run the command line. An argparse refusal gives its exit status, as from the shell."""

    def call(*arguments: str) -> tuple[int, str, str]:
        capsys.readouterr()
        try:
            code = cli.main(list(arguments))
        except SystemExit as exc:
            code = int(exc.code or 0)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return call


def _generate(run: Run, path: Path) -> dict[str, str]:
    code, out, err = run("keys", "generate", "--out", str(path), "--passphrase-ref", PASSPHRASE_REF)
    assert code == 0, err
    jwk: dict[str, str] = json.loads(out)
    return jwk


def _write_jwk(path: Path, jwk: dict[str, Any]) -> Path:
    path.write_text(json.dumps(jwk), encoding="utf-8")
    return path


def _add_key(
    run: Run,
    out: Path,
    jwk: Path,
    *,
    kid: str,
    purposes: tuple[str, ...],
    source: list[str],
    issuer: str = ISSUER,
) -> tuple[int, str, str]:
    arguments = ["trust-bundle", "add-key", "--out", str(out), *source, "--kid", kid, "--issuer", issuer]
    for purpose in purposes:
        arguments += ["--purpose", purpose]
    return run(*arguments, "--public-key", str(jwk), *PERIOD)


def _envelope(path: Path) -> Path:
    path.write_text(make_envelope().model_dump_json(by_alias=True) + "\n", encoding="utf-8")
    return path


def limited(limit: int, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the command line in a child whose files cannot grow past ``limit`` bytes.

    A write past the limit fails with EFBIG, as a write to a full disk fails. Python ignores SIGXFSZ.
    """
    code = (
        "import resource, sys\n"
        "from dppce.cli import main\n"
        f"resource.setrlimit(resource.RLIMIT_FSIZE, ({limit}, {limit}))\n"
        "sys.exit(main(sys.argv[1:]))\n"
    )
    environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(  # noqa: S603 - fixed code; the arguments are test paths
        [sys.executable, "-c", code, *arguments], capture_output=True, text=True, check=False, env=environment
    )


# -- keys generate ------------------------------------------------------------------------------------


def test_keys_generate_writes_an_encrypted_pkcs8_pem_and_prints_the_public_jwk(
    run: Run, passphrase: str, tmp_path: Path
) -> None:
    path = tmp_path / "TEST-ONLY-report.key.pem"
    code, out, err = run("keys", "generate", "--out", str(path), "--passphrase-ref", PASSPHRASE_REF)
    assert code == 0, err
    data = path.read_bytes()
    assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(data, password=None)
    loaded = serialization.load_pem_private_key(data, password=passphrase.encode())
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)
    # The stated parameters (architecture section 11.3). A library change must fail here.
    _, _, der = asn1_pem.unarmor(data)
    algorithm = asn1_keys.EncryptedPrivateKeyInfo.load(der)["encryption_algorithm"]
    assert algorithm["algorithm"].native == "pbes2"
    kdf = algorithm["parameters"]["key_derivation_func"]
    assert kdf["algorithm"].native == "pbkdf2"
    assert kdf["parameters"]["prf"]["algorithm"].native == "sha256"
    assert kdf["parameters"]["iteration_count"].native == 2048
    assert algorithm["parameters"]["encryption_scheme"]["algorithm"].native == "aes256_cbc"
    assert json.loads(out) == public_jwk_of(loaded.public_key())
    body = "".join(data.decode("ascii").splitlines()[1:-1])
    for secret in (passphrase, body, body[:40]):
        assert secret not in out
        assert secret not in err


def test_keys_generate_json_names_the_file_and_the_public_jwk(
    run: Run, passphrase: str, tmp_path: Path
) -> None:
    path = tmp_path / "TEST-ONLY-report.key.pem"
    code, out, _ = run("keys", "generate", "--out", str(path), "--passphrase-ref", PASSPHRASE_REF, "--json")
    assert code == 0
    document = json.loads(out)
    assert document["written"] == str(path)
    assert set(document["public_jwk"]) == {"kty", "crv", "x", "y"}


def test_keys_generate_refusals(
    run: Run, passphrase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = tmp_path / "TEST-ONLY-existing.key.pem"
    existing.write_bytes(b"TEST-ONLY placeholder")
    code, _, err = run("keys", "generate", "--out", str(existing), "--passphrase-ref", PASSPHRASE_REF)
    assert (code, existing.read_bytes()) == (2, b"TEST-ONLY placeholder")
    assert "KEYS.FILE.EXISTS" in err

    for size, expected in ((31, 2), (32, 0), (1023, 0), (1024, 2)):
        value = ("TEST-ONLY-" + "x" * size)[:size]
        monkeypatch.setenv(PASSPHRASE_ENV, value)
        path = tmp_path / f"TEST-ONLY-{size}.key.pem"
        code, _, err = run("keys", "generate", "--out", str(path), "--passphrase-ref", PASSPHRASE_REF)
        assert code == expected, (size, err)
        assert path.exists() is (expected == 0)
        if expected:
            assert "KEYS.PASSPHRASE.LENGTH" in err
            assert value not in err

    literal = "TEST-ONLY-" + secrets.token_urlsafe(24)
    for reference in ("env:HOME", literal, "env:DPPCE_SECRET_TEST_ONLY_UNSET"):
        path = tmp_path / "TEST-ONLY-refused.key.pem"
        code, _, err = run("keys", "generate", "--out", str(path), "--passphrase-ref", reference)
        assert code == 2, reference
        assert not path.exists()
        assert literal not in err


def test_a_failed_write_leaves_no_file_and_a_retry_succeeds(
    run: Run, passphrase: str, tmp_path: Path
) -> None:
    path = tmp_path / "TEST-ONLY-report.key.pem"
    arguments = ("keys", "generate", "--out", str(path), "--passphrase-ref", PASSPHRASE_REF)
    done = limited(100, *arguments)
    assert done.returncode == 2, done.stderr
    assert not path.exists(), path.stat().st_size
    assert passphrase not in done.stderr
    code, _, err = run(*arguments)
    assert code == 0, err


def test_a_secret_that_is_not_utf8_is_refused_without_its_bytes(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Section 11.3: no command prints a passphrase. A decoder message would print one byte and its position.
    directory = tmp_path / "secrets"
    directory.mkdir()
    (directory / "TEST-ONLY-passphrase").write_bytes(b"TEST-ONLY-" + b"x" * 12 + b"\xfe" + b"y" * 20)
    monkeypatch.setenv(PASSPHRASE_ENV, "TEST-ONLY-" + "x" * 12 + "\udcfe" + "y" * 20)
    path = tmp_path / "TEST-ONLY-refused.key.pem"
    for reference in ("file:TEST-ONLY-passphrase", PASSPHRASE_REF):
        code, out, err = run(
            "keys", "generate", "--out", str(path), "--passphrase-ref", reference, "--secrets", str(directory)
        )
        assert code == 2, (reference, err)
        for leak in ("0xfe", "\\udcfe", "\udcfe", "position", "x" * 12):
            assert leak not in err, (reference, err)
            assert leak not in out, (reference, out)
        assert not path.exists()


# -- sign ---------------------------------------------------------------------------------------------


def test_sign_reads_an_encrypted_key_with_a_passphrase_reference(
    run: Run, passphrase: str, tmp_path: Path
) -> None:
    key = tmp_path / "TEST-ONLY-report.key.pem"
    jwk = _write_jwk(tmp_path / "TEST-ONLY-report.jwk.json", _generate(run, key))
    bundle = tmp_path / "bundle.json"
    code, _, err = _add_key(
        run, bundle, jwk, kid="TEST-ONLY-lab-key", purposes=("report",), source=["--policy-version", "test-1"]
    )
    assert code == 0, err
    envelope, signed = _envelope(tmp_path / "envelope.json"), tmp_path / "signed.json"
    code, _, err = run(
        "sign", "--envelope", str(envelope), "--key", str(key), "--kid", "TEST-ONLY-lab-key",
        "--issuer", ISSUER, "--passphrase-ref", PASSPHRASE_REF, "--out", str(signed),
    )  # fmt: skip
    assert code == 0, err
    assert passphrase not in err
    code, out, _ = run("verify", "--envelope", str(signed), "--trust", str(bundle), "--at", AT_TEXT, "--json")
    assert code == 0
    assert json.loads(out)["complete"] is True


def _plain_key(tmp_path: Path) -> Path:
    path = tmp_path / "TEST-ONLY-plain.key.pem"
    path.write_bytes(LocalSigner.generate("TEST-ONLY-plain").to_pem())
    return path


def _sign(run: Run, envelope: Path, key: Path, *more: str) -> tuple[int, str, str]:
    return run(
        "sign",
        "--envelope",
        str(envelope),
        "--key",
        str(key),
        "--kid",
        "TEST-ONLY-plain",
        "--issuer",
        ISSUER,
        *more,
    )


def test_sign_refuses_an_unencrypted_key_without_the_flag(run: Run, tmp_path: Path) -> None:
    envelope, out, key = _envelope(tmp_path / "envelope.json"), tmp_path / "signed.json", _plain_key(tmp_path)
    code, _, err = _sign(run, envelope, key, "--out", str(out))
    assert code == 2
    assert "KEYS.KEY.UNENCRYPTED" in err
    assert not out.exists()
    code, _, err = _sign(run, envelope, key, "--out", str(out), "--allow-unencrypted-key")
    assert code == 0, err
    assert out.exists()


def test_sign_refuses_a_missing_or_wrong_passphrase(
    run: Run, passphrase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "TEST-ONLY-report.key.pem"
    _generate(run, key)
    wrong = "TEST-ONLY-" + secrets.token_urlsafe(24)
    monkeypatch.setenv(WRONG_ENV, wrong)
    envelope, out = _envelope(tmp_path / "envelope.json"), tmp_path / "signed.json"
    common = ["sign", "--envelope", str(envelope), "--key", str(key), "--kid", "k", "--issuer", ISSUER]
    for more, code_text in (
        ([], "KEYS.PASSPHRASE.MISSING"),
        (["--passphrase-ref", f"env:{WRONG_ENV}"], "KEYS.KEY.UNREADABLE"),
    ):
        code, stdout, err = run(*common, *more, "--out", str(out))
        assert code == 2
        assert code_text in err
        for secret in (passphrase, wrong):
            assert secret not in err
            assert secret not in stdout
        assert not out.exists()
    not_a_key = tmp_path / "TEST-ONLY-not-a-key.pem"
    not_a_key.write_text("TEST-ONLY not a key\n", encoding="ascii")
    code, _, err = _sign(run, envelope, not_a_key, "--out", str(out), "--allow-unencrypted-key")
    assert code == 2
    assert "KEYS.KEY.UNREADABLE" in err
    p384 = tmp_path / "TEST-ONLY-p384.key.pem"
    p384.write_bytes(
        ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    code, _, err = _sign(run, envelope, p384, "--out", str(out), "--allow-unencrypted-key")
    assert code == 2
    assert "KEYS.KEY.NOT_P256" in err
    for unreadable in (tmp_path / "TEST-ONLY-missing.key.pem", tmp_path):
        code, _, err = _sign(run, envelope, unreadable, "--out", str(out), "--allow-unencrypted-key")
        assert (code, err.startswith(f"error: KEYS.KEY.UNREADABLE: {unreadable} ")) == (2, True), err
        assert not out.exists()


def test_sign_never_overwrites_its_input(run: Run, tmp_path: Path) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    before = envelope.read_bytes()
    assert _sign(run, envelope, key, "--allow-unencrypted-key")[0] == 2
    assert envelope.read_bytes() == before
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--out", str(envelope))
    assert (code, envelope.read_bytes()) == (2, before)
    assert "SIGN.OUTPUT.IS_INPUT" in err
    other = tmp_path / "existing.json"
    other.write_text("{}\n", encoding="utf-8")
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--out", str(other))
    assert (code, other.read_text(encoding="utf-8")) == (2, "{}\n")
    assert "SIGN.OUTPUT.EXISTS" in err
    both = ["--allow-unencrypted-key", "--out", str(tmp_path / "new.json"), "--in-place"]
    assert _sign(run, envelope, key, *both)[0] == 2
    assert not (tmp_path / "new.json").exists()
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--in-place")
    assert code == 0, err
    assert len(json.loads(envelope.read_text(encoding="utf-8"))["signatures"]) == 1


def test_a_new_output_file_is_readable_only_by_its_owner(run: Run, tmp_path: Path) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    out = tmp_path / "signed.json"
    previous = os.umask(0)
    try:
        code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--out", str(out))
    finally:
        os.umask(previous)
    assert code == 0, err
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_sign_in_place_keeps_the_mode_and_refuses_a_link(run: Run, tmp_path: Path) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    # Not the 0600 of mkstemp, so a kept mode is seen.
    os.chmod(envelope, 0o700)
    assert _sign(run, envelope, key, "--allow-unencrypted-key", "--in-place")[0] == 0
    assert stat.S_IMODE(envelope.stat().st_mode) == 0o700
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".dppce-sign-")]

    target = _envelope(tmp_path / "target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    before = target.read_bytes()
    code, _, err = _sign(run, link, key, "--allow-unencrypted-key", "--in-place")
    assert code == 2
    assert "SIGN.INPUT.LINK" in err
    assert link.is_symlink()
    assert target.read_bytes() == before
    assert _sign(run, link, key, "--allow-unencrypted-key", "--out", str(tmp_path / "new.json"))[0] == 0


def _edit_ordering(document: dict[str, Any]) -> None:
    results = document["decision"]["requirement_results"]
    results[0], results[1] = results[1], results[0]


def _edit_results_root(document: dict[str, Any]) -> None:
    document["decision"]["results_root"] = "0" * 64


def _edit_records_root(document: dict[str, Any]) -> None:
    document["decision"]["record_commitments"][0]["commitment"] = "f" * 64


def _edit_counts(document: dict[str, Any]) -> None:
    document["decision"]["verdict_counts"]["pass"] += 1


def _edit_structure(document: dict[str, Any]) -> None:
    document["surprise"] = 1


@pytest.mark.parametrize(
    ("dimension", "edit"),
    [
        ("ordering", _edit_ordering),
        ("results_root", _edit_results_root),
        ("records_root", _edit_records_root),
        ("counts", _edit_counts),
        ("structure", _edit_structure),
    ],
)
def test_sign_refuses_an_envelope_whose_body_fails(
    run: Run, tmp_path: Path, dimension: str, edit: Callable[[dict[str, Any]], None]
) -> None:
    key = _plain_key(tmp_path)
    document = json.loads(make_envelope().model_dump_json(by_alias=True))
    edit(document)
    envelope, out = tmp_path / "envelope.json", tmp_path / "signed.json"
    envelope.write_text(json.dumps(document), encoding="utf-8")
    before = envelope.read_bytes()
    for target in (["--out", str(out)], ["--in-place"]):
        code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", *target)
        assert code == 2
        assert "ENVELOPE.BODY.INVALID" in err
        assert dimension in err
    assert not out.exists()
    assert envelope.read_bytes() == before


def test_sign_refuses_an_envelope_that_is_not_strict_json(run: Run, tmp_path: Path) -> None:
    key = _plain_key(tmp_path)
    valid = make_envelope().model_dump_json(by_alias=True)
    envelope, out = tmp_path / "envelope.json", tmp_path / "signed.json"
    for text in ('{"schema_version": "dppce.envelope/1", ' + valid[1:], valid[:-1], ""):
        envelope.write_text(text, encoding="utf-8")
        for target in (["--out", str(out)], ["--in-place"]):
            code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", *target)
            assert (code, "ENVELOPE.BODY.INVALID: the envelope fails these checks: structure" in err) == (
                2,
                True,
            ), err
        assert not out.exists()
        assert envelope.read_text(encoding="utf-8") == text


# -- authorize ----------------------------------------------------------------------------------------


def _authorization(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "dppce.authorization/1",
        "authorization_id": "TEST-ONLY-authorization-1",
        "issuer": OWNER,
        "subject": ISSUER,
        "sut_identifier": SUT,
        "endpoints": ["http://127.0.0.1:8765"],
        "methods": ["GET"],
        "roles": ["anonymous"],
        "scopes": ["read"],
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "max_requests": 10,
    }
    return document | changes


def test_authorize_signs_an_authorization_that_validate_authorization_accepts(
    run: Run, passphrase: str, tmp_path: Path
) -> None:
    key = tmp_path / "TEST-ONLY-owner.key.pem"
    jwk = _write_jwk(tmp_path / "TEST-ONLY-owner.jwk.json", _generate(run, key))
    bundle = tmp_path / "bundle.json"
    code, _, err = _add_key(
        run,
        bundle,
        jwk,
        kid="TEST-ONLY-owner-key",
        purposes=("authorization",),
        source=["--policy-version", "test-1"],
        issuer=OWNER,
    )
    assert code == 0, err
    document = tmp_path / "authorization.json"
    document.write_text(json.dumps(_authorization()), encoding="utf-8")
    token_path = tmp_path / "authorization.jws"
    code, out, err = run(
        "authorize", "--document", str(document), "--key", str(key), "--kid", "TEST-ONLY-owner-key",
        "--passphrase-ref", PASSPHRASE_REF, "--out", str(token_path), "--json",
    )  # fmt: skip
    assert code == 0, err
    assert json.loads(out) == {
        "written": str(token_path),
        "authorization_id": "TEST-ONLY-authorization-1",
        "kid": "TEST-ONLY-owner-key",
        "issuer": OWNER,
    }
    trust = TrustBundle.model_validate_json(bundle.read_bytes())
    token = token_path.read_text(encoding="ascii").strip()
    at = datetime(2026, 10, 14, tzinfo=UTC)
    assert validate_authorization(token, trust, at, SUT) == Authorization.model_validate(_authorization())


def test_authorize_refusals(run: Run, passphrase: str, tmp_path: Path) -> None:
    key = _plain_key(tmp_path)
    out = tmp_path / "authorization.jws"

    def authorize(document: dict[str, Any] | str) -> tuple[int, str]:
        path = tmp_path / "authorization.json"
        path.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
        code, _, err = run(
            "authorize", "--document", str(path), "--key", str(key), "--kid", "TEST-ONLY-plain",
            "--out", str(out), "--allow-unencrypted-key",
        )  # fmt: skip
        return code, err

    for document in (
        _authorization(surprise=1),
        _authorization(schema_version="dppce.authorization/9"),
        _authorization(max_requests="10"),
        "[]",
        "{not json",
    ):
        code, err = authorize(document)
        assert code == 2, document
        assert "AUTHORIZE.DOCUMENT.INVALID" in err, err
        assert not out.exists()
    for document in (
        _authorization(not_before="2027-01-02T00:00:00Z"),
        _authorization(not_after="2026-02-30T00:00:00Z"),
        _authorization(not_before="tomorrow"),
        _authorization(not_before="2026-1-1T0:0:0Z"),
    ):
        code, err = authorize(document)
        assert (code, "AUTHORIZE.PERIOD.INVALID" in err) == (2, True), err
        assert not out.exists()
    for endpoint in (
        "https://h.example/path",
        "ftp://h.example",
        "h.example",
        "http://TEST-ONLY-user:TEST-ONLY-password@127.0.0.1:8765",
        "http://@127.0.0.1:8765",
        "http://127.0.0.1:8765?a=1",
        "http://127.0.0.1:8765/?",
        "http://127.0.0.1:8765#f",
        "http://127.0.0.1:8765/#",
        # urlsplit drops tab, CR, and LF and strips edge spaces: the signed text would not be the origin.
        "http://127.0.0.1:87\t65",
        "https://dpp.example\n.evil.example",
        " http://127.0.0.1:8765",
        "\x01http://127.0.0.1:8765",
        "http://127.0.0.1:0",
    ):
        code, err = authorize(_authorization(endpoints=[endpoint]))
        assert (code, "AUTHORIZE.ENDPOINT.INVALID" in err) == (2, True), err
        assert "TEST-ONLY-password" not in err
        assert not out.exists()
    # The key rules of section 11.3 apply to the owner key too, not only to the report key.
    encrypted = tmp_path / "TEST-ONLY-owner.key.pem"
    _generate(run, encrypted)
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(_authorization()), encoding="utf-8")
    common = ["authorize", "--document", str(valid), "--kid", "k", "--out", str(out)]
    for owner_key, code_text in ((key, "KEYS.KEY.UNENCRYPTED"), (encrypted, "KEYS.PASSPHRASE.MISSING")):
        code, _, err = run(*common, "--key", str(owner_key))
        assert (code, code_text in err) == (2, True), err
        assert not out.exists()
    assert authorize(_authorization()) == (0, "")
    out_bytes = out.read_bytes()
    code, err = authorize(_authorization())
    assert (code, out.read_bytes()) == (2, out_bytes)
    assert "AUTHORIZE.OUTPUT.EXISTS" in err


# -- trust-bundle add-key -----------------------------------------------------------------------------


def _jwk(tmp_path: Path, name: str, curve: ec.EllipticCurve | None = None, **changes: Any) -> Path:
    key = ec.generate_private_key(curve or ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    size = (key.curve.key_size + 7) // 8
    jwk: dict[str, Any] = {
        "kty": "EC",
        "crv": {256: "P-256", 384: "P-384"}[key.curve.key_size],
        "x": _b64(numbers.x.to_bytes(size, "big")),
        "y": _b64(numbers.y.to_bytes(size, "big")),
    }
    return _write_jwk(tmp_path / f"TEST-ONLY-{name}.jwk.json", jwk | changes)


def test_trust_bundle_add_key_writes_a_bundle_that_validates_against_the_trust_schema(
    run: Run, tmp_path: Path
) -> None:
    validator = jsonschema.Draft202012Validator(schemas.load("trust"))
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    issuer_jwk = _jwk(tmp_path, "issuer", kid="ignored", use="sig", alg="ES256")
    code, out, err = _add_key(
        run, first, issuer_jwk, kid="TEST-ONLY-issuer", purposes=PURPOSES[:4] + PURPOSES[5:],
        source=["--policy-version", "test-1"],
    )  # fmt: skip
    assert code == 0, err
    review_jwk = _jwk(tmp_path, "review")
    code, out, err = run(
        "trust-bundle", "add-key", "--out", str(second), "--bundle", str(first), "--kid", "TEST-ONLY-review",
        "--issuer", ISSUER, "--purpose", "review", "--public-key", str(review_jwk), *PERIOD, "--json",
    )  # fmt: skip
    assert code == 0, err
    assert json.loads(out) == {
        "written": str(second),
        "kid": "TEST-ONLY-review",
        "purposes": ["review"],
        "keys": 2,
    }
    for path in (first, second):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert list(validator.iter_errors(document)) == []
        TrustBundle.model_validate(document)
    bundle = TrustBundle.model_validate_json(second.read_bytes())
    assert {p for k in bundle.keys for p in k.purposes} == set(PURPOSES)
    assert set(bundle.keys[0].public_jwk) == {"kty", "crv", "x", "y"}
    assert bundle.policy_version == "test-1"

    v1 = tmp_path / "v1.json"
    v1.write_text(
        json.dumps({"schema_version": "dppce.trust/1", "policy_version": "old-1"}), encoding="utf-8"
    )
    upgraded = tmp_path / "upgraded.json"
    code, _, err = _add_key(
        run, upgraded, _jwk(tmp_path, "v1"), kid="k", purposes=("report",), source=["--bundle", str(v1)]
    )
    assert code == 0, err
    document = json.loads(upgraded.read_text(encoding="utf-8"))
    assert document["schema_version"] == "dppce.trust/2"
    assert list(validator.iter_errors(document)) == []


def test_trust_bundle_add_key_refusals(run: Run, tmp_path: Path) -> None:
    jwk = _jwk(tmp_path, "report")
    base = tmp_path / "base.json"
    assert (
        _add_key(
            run, base, jwk, kid="TEST-ONLY-report", purposes=("report",), source=["--policy-version", "t"]
        )[0]
        == 0
    )
    out = tmp_path / "out.json"

    def refused(
        code_text: str,
        *,
        jwk_path: Path = jwk,
        kid: str = "new",
        purposes: tuple[str, ...] = ("report",),
        source: list[str] | None = None,
        period: list[str] = PERIOD,
        target: Path = out,
    ) -> None:
        arguments = [
            "trust-bundle",
            "add-key",
            "--out",
            str(target),
            *(["--bundle", str(base)] if source is None else source),
        ]
        arguments += ["--kid", kid, "--issuer", ISSUER, "--public-key", str(jwk_path), *period]
        for purpose in purposes:
            arguments += ["--purpose", purpose]
        before = target.read_bytes() if target.exists() else None
        code, _, err = run(*arguments)
        assert code == 2, (code_text, err)
        assert code_text in err, err
        assert (target.read_bytes() if target.exists() else None) == before

    refused("TRUST.KEY.PRIVATE", jwk_path=_jwk(tmp_path, "private", d="TEST-ONLY-not-a-real-scalar"))
    # A WebCrypto or jose export of a private key holds members that are not strings.
    refused(
        "TRUST.KEY.PRIVATE",
        jwk_path=_jwk(tmp_path, "webcrypto", d="TEST-ONLY-not-a-real-scalar", ext=True, key_ops=["sign"]),
    )
    refused("TRUST.KEY.NOT_P256", jwk_path=_jwk(tmp_path, "p384", ec.SECP384R1()))
    document = json.loads(jwk.read_text(encoding="utf-8"))
    refused(
        "TRUST.KEY.NOT_P256",
        jwk_path=_write_jwk(tmp_path / "off.jwk.json", {**document, "x": _b64(b"\x01" * 32)}),
    )
    refused(
        "TRUST.KEY.NOT_P256",
        jwk_path=_write_jwk(tmp_path / "short.jwk.json", {**document, "x": _b64(b"\x01")}),
    )
    refused("TRUST.KEY.NOT_P256", jwk_path=_write_jwk(tmp_path / "enc.jwk.json", {**document, "use": "enc"}))
    not_an_object = tmp_path / "list.jwk.json"
    not_an_object.write_text('["EC"]', encoding="utf-8")
    refused("TRUST.KEY.NOT_P256", jwk_path=not_an_object)
    refused("TRUST.KEY.DUPLICATE_KID", jwk_path=_jwk(tmp_path, "other"), kid="TEST-ONLY-report")
    refused("TRUST.KEY.ROLE_CONFLICT", purposes=("review",))
    refused(
        "TRUST.KEY.PERIOD_INVALID",
        period=["--not-before", "2027-01-01T00:00:00Z", "--not-after", "2026-01-01T00:00:00Z"],
    )
    refused(
        "TRUST.KEY.PERIOD_INVALID",
        period=["--not-before", "2026-02-30T00:00:00Z", "--not-after", "2027-01-01T00:00:00Z"],
    )
    refused(
        "TRUST.KEY.PERIOD_INVALID",
        period=["--not-before", "2026-1-1T0:0:0Z", "--not-after", "2027-01-01T00:00:00Z"],
    )
    out.write_text("{}\n", encoding="utf-8")
    refused("TRUST.OUTPUT.EXISTS", jwk_path=_jwk(tmp_path, "third"))
    refused("TRUST.OUTPUT.EXISTS", jwk_path=_jwk(tmp_path, "fourth"), target=base)
    out.unlink()
    refused("TRUST.BUNDLE.OPTION", source=[])
    refused("TRUST.BUNDLE.OPTION", source=["--bundle", str(base), "--policy-version", "t"])
    v1 = tmp_path / "v1.json"
    v1.write_text(
        json.dumps({"schema_version": "dppce.trust/1", "policy_version": "old", "revoked_serials": ["01"]}),
        encoding="utf-8",
    )
    refused("TRUST.MIGRATION.UNSCOPED_SERIAL", source=["--bundle", str(v1)])


# -- run: the data key --------------------------------------------------------------------------------


@pytest.mark.qr
def test_run_creates_a_missing_data_key_only_with_the_flag(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ReferenceRig(tmp_path) as rig:
        built: list[object] = []
        real = cli.PolicyTransport

        def refuse(*args: Any, **kwargs: Any) -> Any:
            built.append(args)
            raise AssertionError("no transport may be built before the data key check")

        monkeypatch.setattr(cli, "PolicyTransport", refuse)
        out = tmp_path / "refused"
        code, _, err = run(*rig.run_arguments(out))
        assert code == 2
        assert "KEYS.DATA_KEY.UNAVAILABLE" in err
        assert not out.exists()
        assert built == []
        for bad in ("../x", "bad id"):
            code, _, err = run(
                *rig.run_arguments(tmp_path / "bad-id"), "--data-key-id", bad, "--create-data-key"
            )
            assert (code, "KEYS.DATA_KEY.UNAVAILABLE" in err) == (2, True), err
            assert not (tmp_path / "bad-id").exists()
        # An unusable key: 31 bytes, not 32. Without --create-data-key it is never replaced.
        unusable = tmp_path / "keys" / "local-data-key-1.key"
        unusable.parent.mkdir(exist_ok=True)
        unusable.write_bytes(bytes(31))
        code, _, err = run(*rig.run_arguments(tmp_path / "unusable"))
        assert (code, "KEYS.DATA_KEY.UNAVAILABLE" in err) == (2, True), err
        assert not (tmp_path / "unusable").exists()
        assert built == []
        assert unusable.read_bytes() == bytes(31)
        unusable.unlink()
        # A failed write leaves no partial key, and a retry gets past the key check to the transport.
        done = limited(16, *rig.run_arguments(tmp_path / "limited"), "--create-data-key")
        assert (done.returncode, "KEYS.DATA_KEY.UNAVAILABLE" in done.stderr) == (2, True), done.stderr
        assert not unusable.exists(), unusable.stat().st_size
        assert "create it with --create-data-key" not in done.stderr
        assert not (tmp_path / "limited").exists()
        code, _, err = run(*rig.run_arguments(tmp_path / "retry"), "--create-data-key")
        assert (code, len(built), len(unusable.read_bytes())) == (3, 1, 32), err
        unusable.unlink()
        monkeypatch.setattr(cli, "PolicyTransport", real)

        first = rig.run(extra=["--data-key-id", "TEST-ONLY-data-key-7"])
        key = tmp_path / "keys" / "TEST-ONLY-data-key-7.key"
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        assert not (tmp_path / "keys" / "local-data-key-1.key").exists()
        index = json.loads((first.run_dir / "recording" / "recording.json").read_text(encoding="utf-8"))
        assert index["key_id"] == "TEST-ONLY-data-key-7"
        code, summary = rig.replay(first)
        assert summary["match"] is True, summary
        before = key.read_bytes()
        second = rig.run(create_data_key=False, extra=["--data-key-id", "TEST-ONLY-data-key-7"])
        assert second.exit_code == first.exit_code
        assert key.read_bytes() == before


@pytest.mark.parametrize("flag", ["--allow-private-host", "--allow-remote-host"])
def test_run_refuses_a_confirmed_origin_with_userinfo_a_query_or_a_fragment(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no transport may be built for an origin that is not valid")

    monkeypatch.setattr(cli, "PolicyTransport", refuse)
    for value in (
        "http://TEST-ONLY-user:TEST-ONLY-password@127.0.0.1:8765",
        "http://127.0.0.1:8765?",
        "http://127.0.0.1:8765/#f",
        "http://127.0.0.1:87\t65",
        "http://127.0.0.1:8765\n",
        " http://127.0.0.1:8765",
        # No service listens on port 0, so no operator confirms it.
        "http://127.0.0.1:0",
    ):
        code, _, err = run(*_run_arguments(FIXTURES, tmp_path, extra=(flag, value, "--create-data-key")))
        assert (code, f"{flag} takes an origin" in err) == (2, True), err
        assert "TEST-ONLY-password" not in err
        assert not (tmp_path / "run").exists()
