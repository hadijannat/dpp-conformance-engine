"""Report status lists: a signed bitstring in which the issuer withdraws a report (ADR 0016).

The list is a compact JWS over ``dppce.statuslist/1``. The bitstring uses the encoding of the
W3C Bitstring Status List v1.0 only: GZIP, then base64url without padding after the multibase
prefix ``u``. Index 0 is the most significant bit of the first byte. A list is not a W3C
verifiable credential.

The operator supplies the list as a file. Nothing here fetches anything.
Implements docs/explanation/architecture.md, section 11.4, "Report status lists", steps 5 to 16.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Final

from dppce.evidence.canonical import canonical_bytes, parse_strict
from dppce.evidence.jws import SignatureError, header_of, sign_compact, verify_compact
from dppce.infrastructure.interfaces import Signer
from dppce.models import StatusList, TrustBundle, TrustedKey

STATUS_LIST_TYP: Final = "dppce-status-list+jws"
MIN_BITS: Final = 131072
MAX_BITSTRING_BYTES: Final = 16 * 1024 * 1024
MAX_TOKEN_BYTES: Final = 2 * 1024 * 1024
_ENCODED: Final = re.compile(r"u[A-Za-z0-9_-]+")
_STAMP: Final = "%Y-%m-%dT%H:%M:%SZ"
# The signature checks that a token fails as a file problem, not as a bad signature.
_FILE_CODES: Final = {"MALFORMED": "STATUSLIST.FILE.MALFORMED", "TOO_LARGE": "STATUSLIST.FILE.TOO_LARGE"}


class StatusError(ValueError):
    """A status list cannot be used. ``code`` is a reason code of section 11.4."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def encode_list(indices: Iterable[int], size_bits: int = MIN_BITS) -> str:
    """Return ``encoded_list`` with a 1 at each of ``indices``."""
    if size_bits < MIN_BITS:
        raise ValueError(f"a status list has at least {MIN_BITS} bits")
    if size_bits % 8:
        raise ValueError("the number of bits of a status list is a multiple of 8")
    bits = bytearray(size_bits // 8)
    for index in indices:
        if not 0 <= index < size_bits:
            raise ValueError(f"index {index} is outside a list of {size_bits} bits")
        bits[index // 8] |= 0x80 >> (index % 8)
    packer = zlib.compressobj(wbits=31)  # 31: a GZIP container
    data = packer.compress(bytes(bits)) + packer.flush()
    return "u" + base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_list(encoded: str) -> bytes:
    """Return the bitstring of ``encoded_list``. The output is capped against a GZIP bomb."""
    if not _ENCODED.fullmatch(encoded):
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the list is not base64url after the prefix 'u'")
    body = encoded[1:]
    try:
        data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the list is not base64url") from exc
    unpacker = zlib.decompressobj(wbits=31)
    try:
        bits = unpacker.decompress(data, MAX_BITSTRING_BYTES + 1)
    except zlib.error as exc:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the list is not GZIP data") from exc
    if len(bits) > MAX_BITSTRING_BYTES or unpacker.unconsumed_tail:
        raise StatusError(
            "STATUSLIST.FILE.TOO_LARGE", f"the list expands to more than {MAX_BITSTRING_BYTES} bytes"
        )
    if not unpacker.eof or unpacker.unused_data or not bits:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the list is not one complete GZIP stream of bits")
    return bits


def bit_is_set(bits: bytes, index: int) -> bool:
    if not 0 <= index < len(bits) * 8:
        raise StatusError(
            "STATUSLIST.INDEX.OUT_OF_RANGE", f"index {index} is outside a list of {len(bits) * 8} bits"
        )
    return bool(bits[index // 8] & (0x80 >> (index % 8)))


def sign_status_list(status_list: StatusList, signer: Signer) -> str:
    return sign_compact(canonical_bytes(status_list), signer, typ=STATUS_LIST_TYP)


def read_status_list(raw: bytes, trust: TrustBundle, at: datetime) -> tuple[StatusList, TrustedKey]:
    """Check steps 5 to 10 and return the list and its key. Every failure is a ``StatusError``."""
    if len(raw) > MAX_TOKEN_BYTES:
        raise StatusError("STATUSLIST.FILE.TOO_LARGE", f"the file is larger than {MAX_TOKEN_BYTES} bytes")
    try:
        # Most tools end a file with a newline.
        token = raw.decode("ascii").strip()
        header = header_of(token)
    except (UnicodeDecodeError, SignatureError) as exc:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the file is not one compact JWS in ASCII") from exc
    kid = str(header.get("kid"))
    key = {k.kid: k for k in trust.keys}.get(kid)
    if key is None:
        raise StatusError("STATUSLIST.KEY.UNKNOWN", f"key {kid!r} of the list is not in the trust bundle")
    if "status" not in key.purposes:
        raise StatusError("STATUSLIST.KEY.PURPOSE", f"key {kid!r} does not have the purpose 'status'")
    not_before, not_after = (
        datetime.strptime(t, _STAMP).replace(tzinfo=UTC) for t in (key.not_before, key.not_after)
    )
    if not not_before <= at <= not_after or trust.key_revoked(key.kid, at):
        raise StatusError(
            "STATUSLIST.KEY.NOT_TRUSTED",
            f"key {kid!r} is outside its validity or revoked at the evaluation time",
        )
    try:
        payload = verify_compact(token, key.public_jwk, typ=STATUS_LIST_TYP)
    except SignatureError as exc:
        code = _FILE_CODES.get(exc.code, "STATUSLIST.SIGNATURE.INVALID")
        raise StatusError(code, f"the signature of the list does not verify: {exc}") from exc
    try:
        status_list = StatusList.model_validate(parse_strict(payload))
        canonical = canonical_bytes(status_list) == payload
    except (ValueError, RecursionError) as exc:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the payload is not dppce.statuslist/1") from exc
    if not canonical:
        raise StatusError("STATUSLIST.FILE.MALFORMED", "the payload is not in its canonical form")
    return status_list, key
