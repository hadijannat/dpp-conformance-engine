"""Differential checks: the engine against a second, independent implementation.

Each check compares two code paths that share no logic. Agreement is evidence, not proof:
a majority of implementations is not a normative truth. Where two implementations are known
to disagree, the test records the disagreement and says which one the engine follows and why.

1. JWS ES256: the JOSE library path of the engine against a direct check with the
   cryptography library.
2. Canonical JSON: the RFC 8785 library against the standard-library JSON encoder, on the
   domain where the two must agree, and one documented case where they must differ.
3. Merkle root: the recursive implementation of the engine against an iterative one that is
   written from the definition in the architecture contract, section 11.2.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from hypothesis import given, settings
from hypothesis import strategies as st

from dppce.evidence import merkle
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.jws import LocalSigner, SignatureError, sign_compact, verify_compact

SETTINGS = settings(max_examples=200, deadline=None, derandomize=True)
TYP = "dppce-attestation+jws"

# -- 1. JWS ES256 -------------------------------------------------------------------------------


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_with_cryptography_only(token: str, jwk: dict[str, str]) -> bool:
    """Check an ES256 compact JWS without any JOSE library."""
    header, payload, signature = token.split(".")
    raw = _unb64(signature)
    if len(raw) != 64:
        return False
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_unb64(jwk["x"]), "big"), int.from_bytes(_unb64(jwk["y"]), "big"), ec.SECP256R1()
    )
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        numbers.public_key().verify(der, f"{header}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _engine_accepts(token: str, jwk: dict[str, str]) -> bool:
    try:
        verify_compact(token, jwk, typ=TYP)
    except SignatureError:
        return False
    return True


@SETTINGS
@given(payload=st.binary(max_size=300))
def test_both_implementations_accept_a_signature_from_the_engine(payload: bytes) -> None:
    signer = LocalSigner.generate("TEST-ONLY-differential")
    token = sign_compact(payload, signer, typ=TYP)
    assert _engine_accepts(token, signer.public_jwk())
    assert verify_with_cryptography_only(token, signer.public_jwk())


@SETTINGS
@given(payload=st.binary(min_size=1, max_size=120), position=st.integers(min_value=0), bit=st.integers(0, 7))
def test_both_implementations_reject_a_changed_token(payload: bytes, position: int, bit: int) -> None:
    signer = LocalSigner.generate("TEST-ONLY-differential")
    header, body, signature = sign_compact(payload, signer, typ=TYP).split(".")
    changed = bytearray(_unb64(body))
    changed[position % len(changed)] ^= 1 << bit
    forged = f"{header}.{base64.urlsafe_b64encode(bytes(changed)).rstrip(b'=').decode()}.{signature}"
    assert not _engine_accepts(forged, signer.public_jwk())
    assert not verify_with_cryptography_only(forged, signer.public_jwk())
    stranger = LocalSigner.generate("other").public_jwk()
    original = f"{header}.{body}.{signature}"
    assert not _engine_accepts(original, stranger)
    assert not verify_with_cryptography_only(original, stranger)


# -- 2. canonical JSON --------------------------------------------------------------------------

_BMP_TEXT = st.text(
    st.characters(min_codepoint=0x20, max_codepoint=0xFFFF, exclude_categories=("Cs",)), max_size=12
)
_SCALARS = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1), _BMP_TEXT
)
_VALUES = st.recursive(
    _SCALARS,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(_BMP_TEXT, inner, max_size=4)),
    max_leaves=12,
)


def standard_library_form(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@SETTINGS
@given(value=_VALUES)
def test_the_two_canonical_forms_agree_on_the_domain_of_the_engine(value: Any) -> None:
    """Integers, strings, booleans, and null, with keys in the Basic Multilingual Plane."""
    assert canonical_bytes(value) == standard_library_form(value)
    assert json.loads(canonical_bytes(value)) == value, "the canonical form loses nothing"


def test_the_two_forms_differ_on_key_order_outside_the_basic_plane_and_the_engine_follows_rfc_8785() -> None:
    """A recorded disagreement, expected by the specification.

    RFC 8785 sorts keys by UTF-16 code units. Python sorts by code point. A key above U+FFFF is
    two surrogates in UTF-16 (0xD83D ...), so it sorts BEFORE U+FF5E there and AFTER it in Python.
    The engine follows RFC 8785, because that is the form that other implementations reproduce.
    """
    value = {"\U0001f600": 1, "\uff5e": 2}
    assert canonical_bytes(value) != standard_library_form(value)
    assert canonical_bytes(value) == '{"\U0001f600":1,"\uff5e":2}'.encode()
    assert standard_library_form(value) == '{"\uff5e":2,"\U0001f600":1}'.encode()


# -- 3. Merkle root -----------------------------------------------------------------------------


def iterative_root(label: str, leaves: list[bytes]) -> bytes:
    """An independent implementation, written from the contract: a stack of perfect subtrees.

    Push each leaf hash. While the two top subtrees have the same size, merge them. At the
    end, fold the stack from the right. That gives the tree whose left part is the largest
    power of two, which is the RFC 6962 shape, with no padding of an odd level.
    """
    prefix = b"dppce.merkle.v1\x00" + label.encode("ascii") + b"\x00"
    if not leaves:
        return hashlib.sha256(prefix + b"\x02").digest()
    stack: list[tuple[int, bytes]] = []
    for leaf in leaves:
        stack.append((1, hashlib.sha256(prefix + b"\x00" + leaf).digest()))
        while len(stack) > 1 and stack[-1][0] == stack[-2][0]:
            (size, right), (_, left) = stack.pop(), stack.pop()
            stack.append((2 * size, hashlib.sha256(prefix + b"\x01" + left + right).digest()))
    root = stack.pop()[1]
    while stack:
        root = hashlib.sha256(prefix + b"\x01" + stack.pop()[1] + root).digest()
    return root


@SETTINGS
@given(leaves=st.lists(st.binary(max_size=40), max_size=70), label=st.sampled_from(["results", "records"]))
def test_the_recursive_and_the_iterative_merkle_root_agree(leaves: list[bytes], label: str) -> None:
    assert merkle.root(label, leaves) == iterative_root(label, leaves)


@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 100])
def test_the_two_merkle_implementations_agree_at_every_shape_boundary(size: int) -> None:
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    assert merkle.root("results", leaves) == iterative_root("results", leaves)


@SETTINGS
@given(leaves=st.lists(st.binary(max_size=20), min_size=1, max_size=40, unique=True), data=st.data())
def test_any_change_to_the_leaves_changes_the_root(leaves: list[bytes], data: st.DataObject) -> None:
    """Omit, repeat, replace, or move a leaf: the root must differ."""
    root = merkle.root("results", leaves)
    index = data.draw(st.integers(0, len(leaves) - 1))
    assert merkle.root("results", leaves[:index] + leaves[index + 1 :]) != root, "omitted"
    assert merkle.root("results", [*leaves[: index + 1], leaves[index], *leaves[index + 1 :]]) != root, (
        "repeated"
    )
    assert merkle.root("results", [*leaves[:index], leaves[index] + b"x", *leaves[index + 1 :]]) != root, (
        "replaced"
    )
    if len(leaves) > 1:
        other = (index + 1) % len(leaves)
        moved = list(leaves)
        moved[index], moved[other] = moved[other], moved[index]
        assert merkle.root("results", moved) != root, "moved"
