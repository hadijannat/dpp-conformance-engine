"""Domain-separated Merkle tree.

Construction: docs/explanation/architecture.md, section 11.2. The tree shape follows RFC 6962.
A node is never duplicated to pad an odd level, so two different leaf lists cannot share a root.
This module is a hash-tree library. It is not a transparency log.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

_DOMAIN = b"dppce.merkle.v1\x00"
_LEAF, _NODE, _EMPTY = b"\x00", b"\x01", b"\x02"


def _prefix(label: str) -> bytes:
    if not label.isascii() or not label.isalnum():
        raise ValueError("a tree label is ASCII letters and digits")
    return _DOMAIN + label.encode("ascii") + b"\x00"


def leaf_hash(label: str, leaf: bytes) -> bytes:
    return hashlib.sha256(_prefix(label) + _LEAF + leaf).digest()


def _node(label: str, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_prefix(label) + _NODE + left + right).digest()


def _split(count: int) -> int:
    """Largest power of two that is smaller than ``count`` (``count`` >= 2)."""
    return 1 << ((count - 1).bit_length() - 1)


def _subtree(label: str, hashes: Sequence[bytes]) -> bytes:
    if len(hashes) == 1:
        return hashes[0]
    k = _split(len(hashes))
    return _node(label, _subtree(label, hashes[:k]), _subtree(label, hashes[k:]))


def root(label: str, leaves: Sequence[bytes]) -> bytes:
    """Root of the tree over ``leaves`` in the given order. The empty tree has its own value."""
    if not leaves:
        return hashlib.sha256(_prefix(label) + _EMPTY).digest()
    return _subtree(label, [leaf_hash(label, leaf) for leaf in leaves])


def inclusion_proof(label: str, leaves: Sequence[bytes], index: int) -> tuple[bytes, ...]:
    """Audit path for the leaf at ``index``."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index is outside the tree")

    def path(position: int, hashes: Sequence[bytes]) -> list[bytes]:
        if len(hashes) == 1:
            return []
        k = _split(len(hashes))
        if position < k:
            return [*path(position, hashes[:k]), _subtree(label, hashes[k:])]
        return [*path(position - k, hashes[k:]), _subtree(label, hashes[:k])]

    return tuple(path(index, [leaf_hash(label, leaf) for leaf in leaves]))


def verify_inclusion(
    label: str, leaf: bytes, *, index: int, size: int, proof: Sequence[bytes], expected_root: bytes
) -> bool:
    """Check an audit path. The algorithm is the one in RFC 9162, section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    position, last = index, size - 1
    current = leaf_hash(label, leaf)
    for sibling in proof:
        if last == 0:
            return False
        if position & 1 or position == last:
            current = _node(label, sibling, current)
            if not position & 1:
                while position and not position & 1:
                    position >>= 1
                    last >>= 1
        else:
            current = _node(label, current, sibling)
        position >>= 1
        last >>= 1
    return last == 0 and hmac.compare_digest(current, expected_root)
