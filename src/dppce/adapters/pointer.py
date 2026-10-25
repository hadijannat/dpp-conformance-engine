"""JSON Pointer (RFC 6901) with the standard library only.

A pointer comes from a test pack or an IXIT, so it is untrusted input. It is parsed once, in the
parameter model, and a malformed pointer is refused there. A pointer that does not resolve gives
``MISSING``, which the checks treat as a missing field.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from dppce.adapters.common import MISSING

MAX_POINTER_LENGTH: Final = 512
# RFC 6901, section 4: no leading zero, and "-" names a position past the end, which never resolves.
_INDEX: Final = re.compile(r"0|[1-9][0-9]*")
_BAD_ESCAPE: Final = re.compile(r"~(?![01])")


def parse_pointer(pointer: str) -> tuple[str, ...]:
    """Split a pointer into its unescaped reference tokens. Raise ValueError if it is malformed."""
    if len(pointer) > MAX_POINTER_LENGTH:
        raise ValueError(f"a JSON pointer has at most {MAX_POINTER_LENGTH} characters")
    if pointer == "":
        return ()
    if not pointer.startswith("/") or _BAD_ESCAPE.search(pointer):
        raise ValueError("not a JSON pointer of RFC 6901")
    # The order is fixed by RFC 6901, section 4: ~1 first, then ~0.
    return tuple(t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/"))


def resolve_pointer(document: Any, tokens: tuple[str, ...]) -> Any:
    """The value at the tokens, or ``MISSING``."""
    node = document
    for token in tokens:
        if isinstance(node, Mapping):
            if token not in node:
                return MISSING
            node = node[token]
        elif isinstance(node, list) and _INDEX.fullmatch(token) and int(token) < len(node):
            node = node[int(token)]
        else:
            return MISSING
    return node
