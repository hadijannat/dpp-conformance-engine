"""Local key and secret providers for development and tests.

A production deployment implements ``DataKeyProvider`` and ``Signer`` for a KMS or a PKCS#11
device. Those integrations are interfaces only in this version.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Mapping
from pathlib import Path

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_KEY_BYTES = 32


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
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(handle, "wb") as out:
                out.write(secrets.token_bytes(_KEY_BYTES))
        return path

    def data_key(self, key_id: str) -> bytes:
        try:
            key = self._path(key_id).read_bytes()
        except OSError as exc:
            raise KeyError_(f"data key '{key_id}' is not available") from exc
        if len(key) != _KEY_BYTES:
            raise KeyError_(f"data key '{key_id}' is not {_KEY_BYTES} bytes")
        return key


def resolve_secret(reference: str, environ: Mapping[str, str] | None = None) -> str:
    """Resolve ``env:NAME`` or ``file:PATH``. The IXIT holds the reference, never the secret."""
    kind, _, target = reference.partition(":")
    try:
        if kind == "env":
            return (os.environ if environ is None else environ)[target]
        if kind == "file":
            return Path(target).read_text(encoding="utf-8").strip()
    except (KeyError, OSError) as exc:
        raise KeyError_(f"secret reference '{kind}:...' cannot be resolved") from exc
    raise KeyError_("a secret reference starts with 'env:' or 'file:'")
