"""Encrypted recordings and salted commitments to raw records.

Format: docs/explanation/architecture.md, section 10.

A published commitment is ``HMAC-SHA256(salt, tag || plaintext)``. The salt is 32 random bytes
and stays inside the encrypted record. A bare hash of a predictable value would let anyone
confirm a guess; this construction does not. Opening a commitment means disclosing the salt
and the plaintext to an authorized party.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import shutil
from collections.abc import Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from dppce.evidence.canonical import canonical_bytes
from dppce.infrastructure.interfaces import DataKeyProvider, Record
from dppce.models import Model, RecordCommitment

SCHEMA = "dppce.recording/1"
_COMMIT_TAG = b"dppce.record.v1\x00"
_RECORD_ID = re.compile(r"^r\d{4,6}$")
_SALT_BYTES = 32
_NONCE_BYTES = 12


class RecordingError(ValueError):
    """A recording is missing, damaged, or does not match its index."""


class RecordingIndex(Model):
    """The clear-text index. It holds no URL, no header, and no payload."""

    schema_version: Literal["dppce.recording/1"]
    key_id: str
    created: str
    delete_after: str
    records: tuple[RecordCommitment, ...]


def new_salt() -> bytes:
    return secrets.token_bytes(_SALT_BYTES)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def record_to_json(record: Record, *, with_salt: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "record_id": record.record_id,
        "kind": record.kind,
        "acquired_at": record.acquired_at,
        "method": record.method,
        "url": record.url,
        "role": record.role,
        "request_headers": [list(h) for h in record.request_headers],
        "status": record.status,
        "headers": [list(h) for h in record.headers],
        "body": _b64(record.body),
        "truncated": record.truncated,
        "error": record.error,
        "redirects": list(record.redirects),
        "attempts": record.attempts,
    }
    if with_salt:
        data["salt"] = _b64(record.salt)
    return data


def record_from_json(data: dict[str, Any]) -> Record:
    try:
        return Record(
            record_id=data["record_id"],
            kind=data["kind"],
            acquired_at=data["acquired_at"],
            method=data["method"],
            url=data["url"],
            role=data["role"],
            request_headers=tuple((k, v) for k, v in data["request_headers"]),
            status=data["status"],
            headers=tuple((k, v) for k, v in data["headers"]),
            body=base64.b64decode(data["body"], validate=True),
            truncated=data["truncated"],
            error=data["error"],
            redirects=tuple(data["redirects"]),
            attempts=data["attempts"],
            salt=base64.b64decode(data["salt"], validate=True),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RecordingError(f"a record is malformed: {exc}") from exc


def commit(record: Record) -> str:
    """Salted commitment to everything in the record except the salt."""
    if len(record.salt) != _SALT_BYTES:
        raise RecordingError(f"{record.record_id}: the salt must be {_SALT_BYTES} random bytes")
    plaintext = canonical_bytes(record_to_json(record, with_salt=False))
    return hmac.new(record.salt, _COMMIT_TAG + plaintext, hashlib.sha256).hexdigest()


def record_commitments(records: Sequence[Record]) -> tuple[RecordCommitment, ...]:
    """Commitments sorted by record identifier. A repeated or malformed identifier is an error."""
    ids = [r.record_id for r in records]
    if len(set(ids)) != len(ids):
        raise RecordingError("a record identifier is repeated")
    for record_id in ids:
        if not _RECORD_ID.match(record_id):
            raise RecordingError(f"record identifier {record_id!r} is not valid")
    ordered = sorted(records, key=lambda r: r.record_id)
    return tuple(RecordCommitment(record_id=r.record_id, commitment=commit(r)) for r in ordered)


def _aad(record_id: str) -> bytes:
    return f"{SCHEMA}:{record_id}".encode("ascii")


def write_recording(
    directory: Path, records: Sequence[Record], keys: DataKeyProvider, *, created: date, retention_days: int
) -> RecordingIndex:
    """Encrypt each record with AES-256-GCM and write the index. Never overwrites a recording."""
    if directory.exists() and any(directory.iterdir()):
        raise RecordingError(f"{directory}: is not empty; a recording is never overwritten")
    index = RecordingIndex(
        schema_version=SCHEMA,
        key_id=keys.default_key_id(),
        created=created.isoformat(),
        delete_after=(created + timedelta(days=retention_days)).isoformat(),
        records=record_commitments(records),
    )
    cipher = AESGCM(keys.data_key(index.key_id))
    (directory / "records").mkdir(parents=True, exist_ok=True)
    for record in records:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        plaintext = canonical_bytes(record_to_json(record, with_salt=True))
        sealed = nonce + cipher.encrypt(nonce, plaintext, _aad(record.record_id))
        (directory / "records" / f"{record.record_id}.enc").write_bytes(sealed)
    (directory / "recording.json").write_bytes(canonical_bytes(index) + b"\n")
    return index


def read_index(directory: Path) -> RecordingIndex:
    try:
        return RecordingIndex.model_validate(json.loads((directory / "recording.json").read_bytes()))
    except (OSError, ValueError, ValidationError) as exc:
        raise RecordingError(f"{directory}: the recording index is missing or not valid") from exc


def read_recording(directory: Path, keys: DataKeyProvider) -> tuple[Record, ...]:
    """Decrypt and return the records in acquisition order.

    Fails if a record does not authenticate, is not the record that the index names, or does
    not match its commitment.
    """
    index = read_index(directory)
    cipher = AESGCM(keys.data_key(index.key_id))
    records: list[Record] = []
    for entry in index.records:
        if not _RECORD_ID.match(entry.record_id):
            raise RecordingError(f"record identifier {entry.record_id!r} is not valid")
        try:
            sealed = (directory / "records" / f"{entry.record_id}.enc").read_bytes()
            plaintext = cipher.decrypt(sealed[:_NONCE_BYTES], sealed[_NONCE_BYTES:], _aad(entry.record_id))
        except (OSError, InvalidTag) as exc:
            raise RecordingError(f"{entry.record_id}: missing or does not authenticate") from exc
        record = record_from_json(json.loads(plaintext))
        if record.record_id != entry.record_id or not hmac.compare_digest(commit(record), entry.commitment):
            raise RecordingError(f"{entry.record_id}: does not match the commitment in the index")
        records.append(record)
    return tuple(records)


def purge_expired(root: Path, today: date) -> list[Path]:
    """Delete every recording under ``root`` whose ``delete_after`` date has passed.

    Only a directory with a valid recording index is deleted.
    """
    removed: list[Path] = []
    if not root.is_dir():
        return removed
    for directory in sorted(p for p in root.iterdir() if (p / "recording.json").is_file()):
        try:
            expired = date.fromisoformat(read_index(directory).delete_after) < today
        except (RecordingError, ValueError):
            continue
        if expired:
            shutil.rmtree(directory)
            removed.append(directory)
    return removed
