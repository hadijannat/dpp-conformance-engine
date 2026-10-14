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
import os
import re
import secrets
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.infrastructure.interfaces import DataKeyProvider, Record
from dppce.models import Model, RecordCommitment

SCHEMA = "dppce.recording/1"
_COMMIT_TAG = b"dppce.record.v1\x00"
_RECORD_ID = re.compile(r"^r\d{4,6}$")
_SALT_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
_INDEX_AAD = f"{SCHEMA}:index".encode("ascii")
_INDEX_FILE, _SEAL_FILE, _RECORDS_DIR = "recording.json", "recording.sealed", "records"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW


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
        if not _RECORD_ID.fullmatch(record_id):
            raise RecordingError(f"record identifier {record_id!r} is not valid")
    ordered = sorted(records, key=lambda r: r.record_id)
    return tuple(RecordCommitment(record_id=r.record_id, commitment=commit(r)) for r in ordered)


def _aad(record_id: str) -> bytes:
    return f"{SCHEMA}:{record_id}".encode("ascii")


def write_recording(
    directory: Path, records: Sequence[Record], keys: DataKeyProvider, *, created: date, retention_days: int
) -> RecordingIndex:
    """Encrypt each record with AES-256-GCM and write the index. Never overwrites a recording."""
    if retention_days < 0:
        raise RecordingError("the retention period cannot be negative")
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
    (directory / _INDEX_FILE).write_bytes(canonical_bytes(index) + b"\n")
    # The index is clear text, so that a tool can list a recording with no key. This sealed copy
    # authenticates it: the retention date and the record list cannot change without the key.
    nonce = secrets.token_bytes(_NONCE_BYTES)
    (directory / _SEAL_FILE).write_bytes(nonce + cipher.encrypt(nonce, canonical_bytes(index), _INDEX_AAD))
    return index


def _open(cipher: AESGCM, sealed: bytes, aad: bytes, what: str) -> bytes:
    """Decrypt one sealed file. Every way that it can be damaged gives ``RecordingError``."""
    if len(sealed) < _NONCE_BYTES + _TAG_BYTES:
        raise RecordingError(f"{what}: too short to be a sealed file")
    try:
        return cipher.decrypt(sealed[:_NONCE_BYTES], sealed[_NONCE_BYTES:], aad)
    except (InvalidTag, ValueError) as exc:
        raise RecordingError(f"{what}: missing or does not authenticate") from exc


# A reader returns the bytes of one file of a recording, by a name such as "records/r0001.enc".
Reader = Callable[[str], bytes]


def _path_reader(directory: Path) -> Reader:
    return lambda name: (directory / name).read_bytes()


def _descriptor_reader(directory_fd: int) -> Reader:
    """Read through an open directory: no name is looked up again from the top, no link is followed."""

    def read(name: str) -> bytes:
        *parents, leaf = name.split("/")
        opened: list[int] = []
        parent = directory_fd
        try:
            for part in parents:
                parent = os.open(part, _DIRECTORY_FLAGS, dir_fd=parent)
                opened.append(parent)
            handle = os.open(leaf, os.O_RDONLY | _NOFOLLOW | _NONBLOCK, dir_fd=parent)
            with os.fdopen(handle, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise OSError(f"{name} is not a regular file")
                return source.read()
        finally:
            for descriptor in opened:
                os.close(descriptor)

    return read


def _index_from(read: Reader, where: object) -> RecordingIndex:
    try:
        return RecordingIndex.model_validate(parse_strict(read(_INDEX_FILE)))
    except (OSError, CanonicalizationError, ValidationError) as exc:
        raise RecordingError(f"{where}: the recording index is missing or not valid") from exc


def _verified_index_from(read: Reader, keys: DataKeyProvider, where: object) -> RecordingIndex:
    index = _index_from(read, where)
    try:
        sealed = read(_SEAL_FILE)
    except OSError as exc:
        raise RecordingError(f"{where}: the sealed index is missing") from exc
    stated = _open(AESGCM(keys.data_key(index.key_id)), sealed, _INDEX_AAD, "the sealed index")
    if not hmac.compare_digest(stated, canonical_bytes(index)):
        raise RecordingError(f"{where}: the index differs from its sealed copy")
    return index


def _records_from(read: Reader, index: RecordingIndex, keys: DataKeyProvider) -> tuple[Record, ...]:
    cipher = AESGCM(keys.data_key(index.key_id))
    records: list[Record] = []
    for entry in index.records:
        if not _RECORD_ID.fullmatch(entry.record_id):
            raise RecordingError(f"record identifier {entry.record_id!r} is not valid")
        try:
            sealed = read(f"{_RECORDS_DIR}/{entry.record_id}.enc")
        except OSError as exc:
            raise RecordingError(f"{entry.record_id}: missing or does not authenticate") from exc
        plaintext = _open(cipher, sealed, _aad(entry.record_id), entry.record_id)
        try:
            record = record_from_json(parse_strict(plaintext))
        except CanonicalizationError as exc:
            raise RecordingError(f"{entry.record_id}: a record is malformed") from exc
        if record.record_id != entry.record_id or not hmac.compare_digest(commit(record), entry.commitment):
            raise RecordingError(f"{entry.record_id}: does not match the commitment in the index")
        records.append(record)
    # Identifiers are numbered in acquisition order. Text order breaks from r10000 on.
    return tuple(sorted(records, key=lambda r: int(r.record_id[1:])))


def read_index(directory: Path) -> RecordingIndex:
    """Read the clear-text index. It is NOT authenticated: see ``read_verified_index``."""
    return _index_from(_path_reader(directory), directory)


def read_verified_index(directory: Path, keys: DataKeyProvider) -> RecordingIndex:
    """Read the index and check it against its sealed copy. Needs the data key."""
    return _verified_index_from(_path_reader(directory), keys, directory)


def read_recording(directory: Path, keys: DataKeyProvider) -> tuple[Record, ...]:
    """Decrypt and return the records in acquisition order.

    Fails if the index does not authenticate, if a record does not authenticate, if a record is
    not the one that the index names, or if a record does not match its commitment.
    """
    read = _path_reader(directory)
    return _records_from(read, _verified_index_from(read, keys, directory), keys)


@dataclass(frozen=True)
class PurgeResult:
    """What a purge removed, or would remove, and what it left alone and why."""

    expired: tuple[Path, ...] = ()
    kept: tuple[tuple[Path, str], ...] = field(default=())
    deleted: bool = False


def _is_only_a_recording(directory_fd: int, index: RecordingIndex) -> bool:
    """True if the open directory holds the files of this recording and nothing else."""
    if set(os.listdir(directory_fd)) - {_INDEX_FILE, _SEAL_FILE, _RECORDS_DIR}:
        return False
    expected = {f"{entry.record_id}.enc" for entry in index.records}
    try:
        records_fd = os.open(_RECORDS_DIR, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return not expected
    except OSError:
        return False  # a link or a file in place of the records directory
    try:
        names = os.listdir(records_fd)
        regular = all(
            stat.S_ISREG(os.stat(name, dir_fd=records_fd, follow_symlinks=False).st_mode) for name in names
        )
        return regular and set(names) <= expected
    finally:
        os.close(records_fd)


def _identity(found: os.stat_result) -> tuple[int, int]:
    return found.st_dev, found.st_ino


def _purge_one(
    root_fd: int, name: str, directory_fd: int, today: date, keys: DataKeyProvider, *, delete: bool
) -> str | None:
    """Return "expired", a reason to keep the directory, or None if it is no expired recording.

    Every step works through ``directory_fd``. A directory that is renamed or replaced after the
    check is never the one that is emptied.
    """
    if _INDEX_FILE not in os.listdir(directory_fd):
        return None
    read = _descriptor_reader(directory_fd)
    try:
        index = _verified_index_from(read, keys, name)
        if date.fromisoformat(index.delete_after) >= today:
            return None
        # Each record must belong to this index. An authentic index copied from a different,
        # expired recording does not match the records of this one.
        _records_from(read, index, keys)
    except (RecordingError, ValueError, LookupError) as exc:
        return f"not an authentic recording: {exc}"
    if not _is_only_a_recording(directory_fd, index):
        return "holds files that are not part of the recording"
    if delete:
        try:
            _delete_recording(root_fd, name, directory_fd, index)
        except OSError as exc:
            return f"not deleted completely: {exc}"
    return "expired"


def purge_expired(root: Path, today: date, keys: DataKeyProvider, *, delete: bool = False) -> PurgeResult:
    """Find the recordings under ``root`` whose retention date has passed, and delete them if asked.

    A directory is deleted only if its index authenticates with the data key of the operator,
    every record matches that index, and the directory holds the files of that recording and
    nothing else. A directory that only looks like a recording is left alone. Without
    ``delete`` this is a dry run.
    """
    expired: list[Path] = []
    kept: list[tuple[Path, str]] = []
    try:
        root_fd = os.open(root, _DIRECTORY_FLAGS & ~_NOFOLLOW)
    except OSError:
        return PurgeResult()
    try:
        for name in sorted(os.listdir(root_fd)):
            try:
                directory_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root_fd)
            except OSError:
                continue  # not a directory, or a link: never followed
            try:
                outcome = _purge_one(root_fd, name, directory_fd, today, keys, delete=delete)
            finally:
                os.close(directory_fd)
            if outcome == "expired":
                expired.append(root / name)
            elif outcome is not None:
                kept.append((root / name, outcome))
    finally:
        os.close(root_fd)
    return PurgeResult(expired=tuple(expired), kept=tuple(kept), deleted=delete)


def _delete_recording(root_fd: int, name: str, directory_fd: int, index: RecordingIndex) -> None:
    """Delete the files of the recording by name inside the open directory, then the directories.

    No recursive delete: a file that appeared after the check makes ``rmdir`` fail, and the
    directory stays with that file in it. The last step removes the name only if it still
    leads to the directory that was checked and emptied.
    """
    try:
        records_fd = os.open(_RECORDS_DIR, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        records_fd = None
    if records_fd is not None:
        try:
            for entry in index.records:
                os.unlink(f"{entry.record_id}.enc", dir_fd=records_fd)
        finally:
            os.close(records_fd)
        os.rmdir(_RECORDS_DIR, dir_fd=directory_fd)
    for file_name in (_INDEX_FILE, _SEAL_FILE):
        os.unlink(file_name, dir_fd=directory_fd)
    if _identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) != _identity(os.fstat(directory_fd)):
        raise OSError(f"{name} was replaced during the purge; it is not removed")
    os.rmdir(name, dir_fd=root_fd)
