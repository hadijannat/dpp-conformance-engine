"""The commands ``dppce timestamp imprint`` and ``dppce timestamp attach`` (ADR 0015).

Neither command contacts a timestamp authority. The responses here are built in-process with
TEST-ONLY keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dppce import cli
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import EvidenceEnvelope, TrustAnchor, TrustBundle
from tests.support import ISSUER, KID, make_envelope
from tests.tsa_support import make_response, make_token, pem, tsa_ca, tsa_cert

GEN = datetime(2026, 10, 13, 12, 6, tzinfo=UTC)
AT = "2026-10-14T00:00:00Z"


def _imprint(token: str) -> bytes:
    part = token.split(".")[2]
    return hashlib.sha256(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).digest()


class Files:
    def __init__(self, tmp_path: Path, signed: EvidenceEnvelope, trust: TrustBundle) -> None:
        self.ca = tsa_ca()
        self.tsa = tsa_cert(self.ca)
        self.signed = signed
        self.envelope = tmp_path / "envelope.json"
        self.envelope.write_text(signed.model_dump_json(by_alias=True) + "\n", encoding="utf-8")
        self.response = tmp_path / "response.tsr"
        self.out = tmp_path / "stamped.json"
        self.trust = tmp_path / "trust.json"
        anchor = TrustAnchor(name="TEST-ONLY TSA root", certificate_pem=pem(self.ca[1]))
        bundle = trust.model_copy(update={"timestamp_anchors": (anchor,), "require_timestamp": True})
        self.trust.write_text(bundle.model_dump_json(), encoding="utf-8")

    def token(self, imprint: bytes | None = None) -> bytes:
        return make_token(imprint or _imprint(self.signed.signatures[0]), GEN, self.tsa)

    def attach(self, response: bytes, *extra: str, envelope: Path | None = None) -> int:
        self.response.write_bytes(response)
        return cli.main(
            [
                "timestamp", "attach", "--envelope", str(envelope or self.envelope),
                "--response", str(self.response), "--out", str(self.out), *extra,
            ]
        )  # fmt: skip


@pytest.fixture
def files(tmp_path: Path, signed: EvidenceEnvelope, trust: TrustBundle) -> Files:
    return Files(tmp_path, signed, trust)


def test_imprint_prints_one_line_per_signature(
    files: Files, signer: LocalSigner, capsys: pytest.CaptureFixture[str]
) -> None:
    other = LocalSigner.generate("TEST-ONLY-second-key")
    both = sign_envelope(files.signed, other, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    files.envelope.write_text(both.model_dump_json(by_alias=True), encoding="utf-8")
    assert cli.main(["timestamp", "imprint", "--envelope", str(files.envelope)]) == 0
    expected = [f"sha256:{_imprint(token).hex()}" for token in both.signatures]
    assert capsys.readouterr().out.splitlines() == [
        f"{signer.key_id!r} {expected[0]}",
        f"{other.key_id!r} {expected[1]}",
    ]
    assert cli.main(["timestamp", "imprint", "--envelope", str(files.envelope), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "imprints": [
            {"kid": signer.key_id, "imprint": expected[0]},
            {"kid": other.key_id, "imprint": expected[1]},
        ]
    }


def test_imprint_of_an_unsigned_envelope_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "unsigned.json"
    path.write_text(make_envelope().model_dump_json(by_alias=True), encoding="utf-8")
    assert cli.main(["timestamp", "imprint", "--envelope", str(path)]) == 2
    assert "TIMESTAMP.SIGNATURE.NONE" in capsys.readouterr().err


def test_attach_writes_a_token_that_verify_accepts(files: Files, capsys: pytest.CaptureFixture[str]) -> None:
    before = files.envelope.read_bytes()
    assert files.attach(make_response(files.token())) == 0
    out = capsys.readouterr().out
    assert "not verified: run dppce verify" in out
    assert files.envelope.read_bytes() == before, "the input envelope is unchanged"
    stamped = EvidenceEnvelope.model_validate_json(files.out.read_bytes())
    assert len(stamped.timestamp_evidence) == len(files.signed.timestamp_evidence) + 1
    code = cli.main(
        ["verify", "--envelope", str(files.out), "--trust", str(files.trust), "--at", AT, "--json"]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert {d["name"]: d["outcome"] for d in report["dimensions"]}["timestamp"] == "pass"
    assert report["complete"] is True


def test_attach_with_granted_with_mods_and_json(files: Files, capsys: pytest.CaptureFixture[str]) -> None:
    assert files.attach(make_response(files.token(), status=1), "--json") == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["written"] == str(files.out)
    assert summary["kid"] == KID
    assert summary["gen_time"] == "2026-10-13T12:06:00Z"
    assert summary["timestamps"] == 1


@pytest.mark.parametrize(
    ("build", "code"),
    [
        (lambda f: make_response(None, status=2), "TIMESTAMP.RESPONSE.REJECTED"),
        (lambda f: make_response(f.token(), status=2), "TIMESTAMP.RESPONSE.REJECTED"),
        (lambda f: b"garbage", "TIMESTAMP.RESPONSE.MALFORMED"),
        (lambda f: make_response(None, status=0), "TIMESTAMP.RESPONSE.MALFORMED"),
        (lambda f: b"\x00" * (64 * 1024 + 1), "TIMESTAMP.RESPONSE.TOO_LARGE"),
        (lambda f: make_response(f.token(hashlib.sha256(b"other").digest())), "TIMESTAMP.IMPRINT.MISMATCH"),
    ],
    ids=[
        "rejection",
        "rejection with a token",
        "garbage",
        "granted without a token",
        "too large",
        "other signature",
    ],
)
def test_attach_refuses_a_response_that_cannot_be_used(
    build: Callable[[Files], bytes], code: str, files: Files, capsys: pytest.CaptureFixture[str]
) -> None:
    assert files.attach(build(files)) == 2
    assert code in capsys.readouterr().err
    assert not files.out.exists()


def test_attach_refuses_the_same_token_twice(files: Files, capsys: pytest.CaptureFixture[str]) -> None:
    response = make_response(files.token())
    assert files.attach(response) == 0
    first = files.out.with_name("first.json")
    files.out.rename(first)
    capsys.readouterr()
    assert files.attach(response, envelope=first) == 2
    assert "TIMESTAMP.TOKEN.DUPLICATE" in capsys.readouterr().err


def test_attach_needs_out(files: Files) -> None:
    files.response.write_bytes(make_response(files.token()))
    with pytest.raises(SystemExit) as caught:
        cli.main(
            ["timestamp", "attach", "--envelope", str(files.envelope), "--response", str(files.response)]
        )
    assert caught.value.code == 2
