"""Open items of the key tooling review: SR-N2, SR-N6, SR-N7, and tokens issued before a2352dc.

The items are in validation/records/review-key-tooling-2026-10-18.md. Expected values come from
docs/explanation/architecture.md, sections 9.1, 10.2, and 11.3. Every key is TEST-ONLY and is made
in the test run. Nothing reaches another host.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from dppce import cli
from dppce.evidence import disclosure
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.envelope import records_root
from dppce.evidence.jws import LocalSigner, _b64
from dppce.evidence.recording import record_commitments
from dppce.infrastructure.authorization import issue_authorization, validate_authorization
from dppce.infrastructure.transport import _origins
from dppce.models import Authorization, TrustBundle
from tests.support import AT, ISSUER, KID, make_envelope, make_record
from tests.test_cli_keys import (
    PASSPHRASE_ENV,
    PASSPHRASE_REF,
    Run,
    _add_key,
    _authorization,
    _envelope,
    _generate,
    _plain_key,
    _sign,
    _write_jwk,
)
from tests.test_disclosure import _dimensions


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Run:
    def call(*arguments: str) -> tuple[int, str, str]:
        capsys.readouterr()
        try:
            code = cli.main(list(arguments))
        except SystemExit as exc:
            code = int(exc.code or 0)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return call


@pytest.fixture
def passphrase(monkeypatch: pytest.MonkeyPatch) -> str:
    value = "TEST-ONLY-" + secrets.token_urlsafe(24)
    monkeypatch.setenv(PASSPHRASE_ENV, value)
    return value


# The prime of P-256 and the constant b of its curve equation y^2 = x^3 - 3x + b.
P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _jwk_document(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _small_point() -> tuple[int, int]:
    """A point of P-256 whose x is small, so that x + p still has 32 bytes."""
    for x in range(1, 1000):
        rhs = (x**3 - 3 * x + P256_B) % P256_P
        y = pow(rhs, (P256_P + 1) // 4, P256_P)  # p is 3 mod 4
        if y * y % P256_P == rhs:
            return x, y
    raise AssertionError("no small point found")


def _flip_unused_bits(text: str) -> str:
    """Set the unused low bits of the last character. The decoded bytes stay the same."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    alphabet += "-_" if "=" not in text else "+/"
    body = text.rstrip("=")
    last = alphabet.index(body[-1])
    unused = 0b11 if len(body) % 4 == 3 else 0b1111  # 43 of 44 characters: 2 unused bits
    assert last & unused == 0, "the input is canonical"
    return body[:-1] + alphabet[last | 1] + text[len(body) :]


# -- SR-N2: add-key accepts each coordinate in one spelling only -------------------------------------


def test_add_key_refuses_a_coordinate_that_is_not_canonical_base64url(run: Run, tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    while not {"-", "_"} & set(_jwk_document(key)["x"] + _jwk_document(key)["y"]):
        key = ec.generate_private_key(ec.SECP256R1())
    good = _jwk_document(key)
    name = "x" if {"-", "_"} & set(good["x"]) else "y"
    x, y = _small_point()
    spellings: dict[str, dict[str, Any]] = {
        "padded": {**good, "x": good["x"] + "="},
        "standard-alphabet": {**good, name: good[name].replace("-", "+").replace("_", "/")},
        "junk": {**good, "x": good["x"][:10] + "!" + good["x"][10:]},
        "space": {**good, "x": good["x"][:10] + " " + good["x"][10:]},
        "unused-bits": {**good, "x": _flip_unused_bits(good["x"])},
        # The decoder reduces x modulo p, so x + p names the same point.
        "unreduced": {
            **good,
            "x": _b64((x + P256_P).to_bytes(32, "big")),
            "y": _b64(y.to_bytes(32, "big")),
        },
    }
    for label, document in spellings.items():
        jwk = _write_jwk(tmp_path / f"TEST-ONLY-{label}.jwk.json", document)
        out = tmp_path / f"{label}.json"
        code, _, err = _add_key(
            run, out, jwk, kid="TEST-ONLY-k", purposes=("report",), source=["--policy-version", "t"]
        )
        assert code == 2, (label, err)
        assert "TRUST.KEY.NOT_P256" in err, (label, err)
        assert not out.exists(), label
    # The canonical spelling of the same points is still accepted.
    small = {**good, "x": _b64(x.to_bytes(32, "big")), "y": _b64(y.to_bytes(32, "big"))}
    for label, document in (("good", good), ("small", small)):
        jwk = _write_jwk(tmp_path / f"TEST-ONLY-{label}.jwk.json", document)
        out = tmp_path / f"{label}.json"
        code, _, err = _add_key(
            run, out, jwk, kid="TEST-ONLY-k", purposes=("report",), source=["--policy-version", "t"]
        )
        assert code == 0, (label, err)
        assert TrustBundle.model_validate_json(out.read_bytes()).keys[0].public_jwk == document


# -- SR-N6: a link swapped in while sign --in-place runs ----------------------------------------------


def test_sign_in_place_refuses_a_link_swapped_in_while_it_signs(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    target = _envelope(tmp_path / "target.json")
    before = target.read_bytes()
    original = cli.sign_envelope

    def swap_then_sign(*arguments: Any, **options: Any) -> Any:
        # Another local user with write access to the directory puts a link in place of the input.
        envelope.unlink()
        envelope.symlink_to(target)
        return original(*arguments, **options)

    monkeypatch.setattr(cli, "sign_envelope", swap_then_sign)
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--in-place")
    assert code == 2, err
    assert "SIGN.INPUT.LINK" in err
    assert envelope.is_symlink()
    assert target.read_bytes() == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".dppce-sign-")]


def test_sign_in_place_holds_the_input_open_until_the_rename(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    pinned = os.stat(envelope)
    original = cli.sign_envelope
    held: list[bool] = []

    def unlink_then_sign(*arguments: Any, **options: Any) -> Any:
        # A file system can give a freed inode number to the next file. Only an open descriptor
        # keeps the number of the unlinked input, so a swapped-in entry cannot match it.
        envelope.unlink()
        held.append(any(_names(fd, pinned) for fd in range(3, 1024)))
        _envelope(envelope)
        return original(*arguments, **options)

    monkeypatch.setattr(cli, "sign_envelope", unlink_then_sign)
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--in-place")
    assert held == [True]
    assert code == 2, err
    assert "SIGN.INPUT.LINK" in err


def _names(fd: int, pinned: os.stat_result) -> bool:
    try:
        now = os.fstat(fd)
    except OSError:
        return False
    return (now.st_dev, now.st_ino) == (pinned.st_dev, pinned.st_ino)


def test_sign_in_place_refuses_another_file_swapped_in_while_it_signs(
    run: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _plain_key(tmp_path)
    envelope = _envelope(tmp_path / "envelope.json")
    original = cli.sign_envelope

    def swap_then_sign(*arguments: Any, **options: Any) -> Any:
        _envelope(tmp_path / "other.json").replace(envelope)
        return original(*arguments, **options)

    monkeypatch.setattr(cli, "sign_envelope", swap_then_sign)
    code, _, err = _sign(run, envelope, key, "--allow-unencrypted-key", "--in-place")
    swapped_in = json.loads(envelope.read_text(encoding="utf-8"))
    assert code == 2, err
    assert "SIGN.INPUT.LINK" in err
    # The signature of the first file never lands on the second one.
    assert swapped_in["signatures"] == []


# -- SR-N7: an opening has one salt string -----------------------------------------------------------


def test_an_opening_whose_salt_is_not_canonical_base64_fails(trust: TrustBundle) -> None:
    first, second = make_record(1), make_record(2)
    commitments = record_commitments([first, second])
    decision = make_envelope().decision.model_copy(
        update={"record_commitments": commitments, "records_root": records_root(commitments)}
    )
    opening = disclosure.open_record(decision, first)
    assert _dimensions(decision, trust, opening=canonical_bytes(opening))["opening"][0] == "pass"
    malleated = opening.model_copy(update={"salt": _flip_unused_bits(opening.salt)})
    assert base64.b64decode(malleated.salt) == base64.b64decode(opening.salt)
    dims = _dimensions(decision, trust, opening=canonical_bytes(malleated))
    assert dims["opening"][0] == "fail", dims["opening"]
    assert dims["opening"][1].startswith("OPENING.FILE.MALFORMED"), dims["opening"]
    # A file that is not well formed fails before the root rule gives not_checked.
    broken = decision.model_copy(update={"records_root": "0" * 64})
    dims = _dimensions(broken, trust, opening=canonical_bytes(malleated))
    assert dims["opening"][0] == "fail", dims["opening"]


# -- Tokens issued before a2352dc ---------------------------------------------------------------------


def test_a_token_from_before_a2352dc_with_userinfo_authorizes_only_the_reduced_origin(
    run: Run, passphrase: str, signer: LocalSigner, trust: TrustBundle, tmp_path: Path
) -> None:
    """Pin the current behavior. Since a2352dc, authorize refuses such a document.

    A token signed before a2352dc can still name an endpoint with userinfo. run validates it, and
    the transport compares origins only. The endpoint then authorizes its origin without the
    userinfo. The engine uses the endpoints of a token only to compare origins.
    """
    endpoint = "http://TEST-ONLY-user:TEST-ONLY-password@127.0.0.1:8765"
    document = _authorization(issuer=ISSUER, endpoints=[endpoint])
    token = issue_authorization(Authorization.model_validate(document), signer)
    authorization = validate_authorization(token, trust, AT, "urn:example:sut")
    assert authorization.endpoints == (endpoint,)
    assert _origins(authorization.endpoints) == {"http://127.0.0.1:8765"}

    # authorize no longer signs it.
    key = tmp_path / "TEST-ONLY-owner.key.pem"
    _generate(run, key)
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    out = tmp_path / "authorization.jws"
    code, _, err = run(
        "authorize", "--document", str(path), "--key", str(key), "--kid", KID,
        "--passphrase-ref", PASSPHRASE_REF, "--out", str(out),
    )  # fmt: skip
    assert code == 2, err
    assert "AUTHORIZE.ENDPOINT.INVALID" in err
    assert "TEST-ONLY-password" not in err
    assert not out.exists()
