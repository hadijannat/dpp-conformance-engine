"""Local key and secret providers for development and tests.

A production deployment implements ``DataKeyProvider`` and ``Signer`` for a KMS or a PKCS#11
device. Those integrations are interfaces only in this version.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dppce.evidence.jws import LocalSigner, public_jwk_of

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_KEY_BYTES = 32
# PKCS#8 encryption in the installed cryptography package uses PBKDF2 with 2048 iterations, and
# the count cannot be raised. The passphrase must therefore carry the entropy (section 11.3).
MIN_PASSPHRASE_BYTES: Final = 32
MAX_PASSPHRASE_BYTES: Final = 1023
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NEW_FILE: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW


class KeyError_(ValueError):  # noqa: N801, N818 - "KeyError" is a builtin with a different meaning
    """A key or a secret reference cannot be used."""


class FileDataKeyProvider:
    """Reads 256-bit data keys from a directory. Keep that directory apart from the recordings."""

    def __init__(self, directory: Path, key_id: str = "local-data-key-1") -> None:
        if not _KEY_ID.match(key_id):
            raise KeyError_(f"key id {key_id!r} is not valid")
        self._directory = directory
        self._key_id = key_id

    def default_key_id(self) -> str:
        return self._key_id

    def _path(self, key_id: str) -> Path:
        if not _KEY_ID.match(key_id):
            raise KeyError_(f"key id {key_id!r} is not valid")
        return self._directory / f"{key_id}.key"

    def create(self) -> Path:
        """Create the default key from operating-system randomness if it does not exist."""
        path = self._path(self._key_id)
        if not path.exists():
            self._directory.mkdir(parents=True, exist_ok=True)
            write_new_file(path, secrets.token_bytes(_KEY_BYTES), 0o600)
        return path

    def data_key(self, key_id: str) -> bytes:
        try:
            key = self._path(key_id).read_bytes()
        except OSError as exc:
            raise KeyError_(f"data key '{key_id}' is not available") from exc
        if len(key) != _KEY_BYTES:
            raise KeyError_(f"data key '{key_id}' is not {_KEY_BYTES} bytes")
        return key


def write_new_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create ``path`` with ``data``. Never replaces a file and never follows a link.

    A failed write removes the file again: a partial key or opening never stays, and a retry works.
    The default mode makes a report, a proof, or a token readable only by its owner, also under umask 0.
    The operator changes the mode to share the file.
    """
    handle = os.open(path, _NEW_FILE, mode)  # outside the try: a file that exists is not ours to remove
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        raise


def generate_signing_key(path: Path, passphrase: str) -> dict[str, str]:
    """Write a new P-256 key as PKCS#8 PEM encrypted with ``passphrase``. Return its public JWK."""
    secret = passphrase.encode("utf-8")
    if not MIN_PASSPHRASE_BYTES <= len(secret) <= MAX_PASSPHRASE_BYTES:
        raise KeyError_(
            f"KEYS.PASSPHRASE.LENGTH: a passphrase has {MIN_PASSPHRASE_BYTES} to {MAX_PASSPHRASE_BYTES} "
            "bytes in UTF-8; generate it, for example with secrets.token_urlsafe(32)"
        )
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(secret),
    )
    try:
        write_new_file(path, pem, 0o600)
    except FileExistsError as exc:
        raise KeyError_(f"KEYS.FILE.EXISTS: {path} exists; a key file is never replaced") from exc
    return public_jwk_of(key.public_key())


def load_signing_key(
    path: Path, key_id: str, passphrase: str | None, *, allow_unencrypted: bool = False
) -> LocalSigner:
    """Load a P-256 signing key. An unencrypted key needs ``allow_unencrypted`` (TEST-ONLY keys).

    No message holds the passphrase or text of the cryptography library.
    """
    try:
        data = path.read_bytes()
    except OSError:
        raise KeyError_(f"KEYS.KEY.UNREADABLE: {path} cannot be read") from None
    unreadable = f"KEYS.KEY.UNREADABLE: {path} is not a private key that this passphrase decrypts"
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        if passphrase is None:
            raise KeyError_(f"KEYS.PASSPHRASE.MISSING: {path} is encrypted; give --passphrase-ref") from None
        try:
            key = serialization.load_pem_private_key(data, password=passphrase.encode("utf-8"))
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise KeyError_(unreadable) from None
    except (ValueError, UnsupportedAlgorithm):
        raise KeyError_(unreadable) from None
    else:
        if not allow_unencrypted:
            raise KeyError_(
                f"KEYS.KEY.UNENCRYPTED: {path} is not encrypted; encrypt it with dppce keys generate, "
                "or give --allow-unencrypted-key for a TEST-ONLY key"
            )
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise KeyError_(f"KEYS.KEY.NOT_P256: {path} is not a P-256 private key")
    return LocalSigner(key_id, key)


SECRET_ENV_PREFIX = "DPPCE_SECRET_"  # noqa: S105 - the name prefix of a variable, not a secret


def resolve_secret(
    reference: str, *, secrets_dir: Path | None = None, environ: Mapping[str, str] | None = None
) -> str:
    """Resolve ``env:NAME`` or ``file:NAME``. The IXIT holds the reference, never the secret.

    The IXIT can come from the supplier of the system under test, so a reference cannot name an
    arbitrary secret. An environment name must start with ``DPPCE_SECRET_``. A file must lie
    inside the secrets directory that the operator supplies.
    """
    kind, _, target = reference.partition(":")
    if kind == "env":
        if not target.startswith(SECRET_ENV_PREFIX):
            raise KeyError_(f"an environment secret must have a name that starts with {SECRET_ENV_PREFIX}")
        try:
            value = (os.environ if environ is None else environ)[target]
        except KeyError as exc:
            raise KeyError_(f"the environment secret '{target}' is not set") from exc
    elif kind == "file":
        if secrets_dir is None:
            raise KeyError_("a file secret needs a secrets directory from the operator")
        root = secrets_dir.resolve()
        path = (root / target).resolve()
        if not path.is_relative_to(root):
            raise KeyError_("a file secret must lie inside the secrets directory")
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            # A decoder message names a byte of the secret and its position (section 11.3).
            raise KeyError_("a file secret cannot be read as UTF-8 text") from None
    else:
        raise KeyError_("a secret reference starts with 'env:' or 'file:'")
    try:
        # An environment value with a byte that is not UTF-8 arrives as a lone surrogate.
        value.encode("utf-8")
    except UnicodeError:
        raise KeyError_("a secret is not valid UTF-8") from None
    return value
