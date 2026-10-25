"""The uncompressed GS1 Digital Link URI grammar, with AI data from the GS1 Barcode Syntax Dictionary.

The dictionary is vendored unchanged in ``testpacks/data/gs1-syntax-engine``. It gives the AI
formats, the primary keys, the key qualifiers in their order, and the data attribute flag. The
parse steps follow ``gs1_parseDLuri`` of gs1-syntax-engine (Apache-2.0) at the commit of the
vendored ``tests/vectors/gs1-syntax-engine/dl.c``, with its default options. That file is the
oracle of this module. Pairing rules of the dictionary (``req``, ``ex``) are not applied.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from itertools import combinations
from typing import Final, Literal

from dppce.infrastructure.resources import data_root

DICTIONARY: Final = ("testpacks", "data", "gs1-syntax-engine", "gs1-syntax-dictionary.txt")
Rule = Literal["URI", "KEY", "QUALIFIER_ORDER", "AI_VALUE", "CHECK_DIGIT", "PERCENT", "ATTRIBUTE"]
# The closed set of summary.rule values. COMPRESSED is an engine limit, not one of them.
RULES: Final[tuple[Rule, ...]] = (
    "URI", "KEY", "QUALIFIER_ORDER", "AI_VALUE", "CHECK_DIGIT", "PERCENT", "ATTRIBUTE",
)  # fmt: skip

_URI = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
_BAD_DOMAIN = frozenset("_~?#@!$&'()*+,;=%")
_SCHEMES = ("https://", "HTTPS://", "http://", "HTTP://")
_CSET82 = "!\"%&'()*+,-./0123456789:;<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
_CSETS: Final = {
    "N": frozenset("0123456789"),
    "X": frozenset(_CSET82),
    "Y": frozenset("#-/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
}
_FLAGS = frozenset("*!?\"$%&'()+,-./:;<=>@[\\]^_`{|}~")
_COMPONENT = re.compile(r"(\[)?([NXYZ])(?:(\d+)|\.\.(\d+))((?:,[a-z0-9]+)*)(\])?")
# ponytail: a heuristic. A compressed URI ends in one base64url segment and has no primary key in
# the path. A long base64url last segment of a URL that is no GS1 URI also gives COMPRESSED, which
# is unsupported, never a pass. Decode the binary form to tell them apart (TDS) if it matters.
_COMPRESSED = re.compile(r"[A-Za-z0-9_-]{10,}")
_HEX = re.compile(r"[0-9A-Fa-f]{2}")


@dataclass(frozen=True)
class Component:
    cset: str
    min: int
    max: int
    optional: bool
    linters: tuple[str, ...]


@dataclass(frozen=True)
class Entry:
    ai: str
    fixed: bool  # flag "*": a predefined length, no FNC1 after the value
    attribute: bool  # flag "?": a permitted GS1 Digital Link data attribute
    components: tuple[Component, ...]

    @property
    def min_length(self) -> int:
        return sum(c.min for c in self.components if not c.optional)

    @property
    def max_length(self) -> int:
        return sum(c.max for c in self.components)


@dataclass(frozen=True)
class Dictionary:
    entries: dict[str, Entry]
    # Every valid AI sequence of the path: a primary key and an ordered subset of one qualifier list.
    sequences: frozenset[tuple[str, ...]]


@dataclass(frozen=True)
class DigitalLink:
    key: str
    qualifiers: tuple[str, ...]
    attributes: tuple[str, ...]
    # (AI, decoded value) in URI order. Values are payload: never put them in a summary.
    elements: tuple[tuple[str, str], ...]
    # Linters of query data attributes that this version does not implement, sorted.
    unchecked: tuple[str, ...]


@dataclass(frozen=True)
class Problem:
    rule: Rule | Literal["COMPRESSED"]
    reason: str


def _expand(ais: str) -> list[str]:
    first, _, last = ais.partition("-")
    width = len(first)
    return [str(n).zfill(width) for n in range(int(first), int(last or first) + 1)]


def _sequences(key: str, value: str) -> set[tuple[str, ...]]:
    out = set()
    for alternative in value.split("|"):
        qualifiers = tuple(q for q in alternative.split(",") if q)
        for size in range(len(qualifiers) + 1):
            out |= {(key, *subset) for subset in combinations(qualifiers, size)}
    return out


@cache
def dictionary() -> Dictionary:
    """Read the vendored dictionary once. Each line: AIs [flags] components [attributes] [# title]."""
    entries: dict[str, Entry] = {}
    sequences: set[tuple[str, ...]] = set()
    text = data_root().joinpath(*DICTIONARY).read_text(encoding="utf-8")
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        ais, rest = _expand(tokens[0]), tokens[1:]
        flags = rest.pop(0) if rest and set(rest[0]) <= _FLAGS else ""
        components = []
        while rest and (match := _COMPONENT.fullmatch(rest[0])):
            rest.pop(0)
            fixed, high = match[3], match[4]
            components.append(
                Component(
                    cset=match[2],
                    min=int(fixed) if fixed else 1,
                    max=int(fixed or high),
                    optional=match[1] is not None,
                    linters=tuple(match[5].split(",")[1:]),
                )
            )
        for ai in ais:
            entries[ai] = Entry(ai, "*" in flags, "?" in flags, tuple(components))
            for attribute in rest:
                if attribute == "dlpkey" or attribute.startswith("dlpkey="):
                    sequences |= _sequences(ai, attribute.partition("=")[2])
    return Dictionary(entries, frozenset(sequences))


# -- Linters: ports of gs1-syntax-engine src/c-lib/syntax/lint_*.c -----------------------------


def _csum(data: str) -> Rule | None:
    weights = (3, 1) if len(data) % 2 == 0 else (1, 3)
    total = sum(int(d) * weights[i % 2] for i, d in enumerate(data[:-1]))
    return None if (10 - total % 10) % 10 == int(data[-1]) else "CHECK_DIGIT"


_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)
_CSET32 = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def _csumalpha(data: str) -> Rule | None:
    # A GMN is at most 25 characters, so 23 weights suffice. The C table goes on to 509.
    if len(data) < 2 or len(data) - 2 > len(_PRIMES):
        return "CHECK_DIGIT"
    body = data[:-2]
    total = sum(_CSET82.index(c) * _PRIMES[len(body) - 1 - i] for i, c in enumerate(body)) % 1021
    return None if data[-2:] == _CSET32[total >> 5] + _CSET32[total & 31] else "CHECK_DIGIT"


def _gcppos1(data: str) -> Rule | None:
    # Without a GS1 Company Prefix lookup the C linter checks the minimum prefix only.
    return None if len(data) >= 4 and data[:4].isascii() and data[:4].isdigit() else "AI_VALUE"


def _gcppos2(data: str) -> Rule | None:
    return _gcppos1(data[1:]) if len(data) >= 2 else "AI_VALUE"


def _zero(data: str) -> Rule | None:
    return None if data and set(data) == {"0"} else "AI_VALUE"


def _pieceoftotal(data: str) -> Rule | None:
    half = len(data) // 2
    piece, total = data[:half], data[half:]
    valid = data.isdigit() and len(data) % 2 == 0 and int(piece) > 0 and int(total) > 0 and piece <= total
    return None if valid else "AI_VALUE"


def _importeridx(data: str) -> Rule | None:
    return None if len(data) == 1 and (data in "-_" or (data.isascii() and data.isalnum())) else "AI_VALUE"


def _nozeroprefix(data: str) -> Rule | None:
    return None if not data.startswith("0") and data.isdigit() else "AI_VALUE"


LINTERS: Final[dict[str, Callable[[str], Rule | None]]] = {
    "csum": _csum,
    "csumalpha": _csumalpha,
    "gcppos1": _gcppos1,
    "gcppos2": _gcppos2,
    "importeridx": _importeridx,
    "nozeroprefix": _nozeroprefix,
    "pieceoftotal": _pieceoftotal,
    "zero": _zero,
}


def _validate(entry: Entry, value: str, unchecked: set[str]) -> Problem | None:
    """Apply each component in turn, as validate_ai_val of gs1-syntax-engine does."""
    rest = value
    for component in entry.components:
        part, rest = rest[: component.max], rest[component.max :]
        if component.optional and not part:
            continue
        if len(part) < component.min:
            return Problem("AI_VALUE", f"the value of AI ({entry.ai}) has a wrong length")
        cset = _CSETS.get(component.cset)
        if cset is None:
            unchecked.add("cset64")  # ponytail: base64url values occur in data attributes only
        elif not set(part) <= cset:
            return Problem("AI_VALUE", f"the value of AI ({entry.ai}) has a character outside its set")
        for name in component.linters:
            linter = LINTERS.get(name)
            if linter is None:
                unchecked.add(name)
            elif (rule := linter(part)) is not None:
                return Problem(rule, f"the value of AI ({entry.ai}) fails the GS1 check '{name}'")
    return None


def _unescape(raw: str, query: bool) -> str | None:
    """Percent-decode as URIunescape of dl.c: a bad escape stays literal; None for a decoded NUL."""
    out, i = [], 0
    while i < len(raw):
        char = raw[i]
        if char == "%" and _HEX.fullmatch(raw[i + 1 : i + 3]):
            decoded = chr(int(raw[i + 1 : i + 3], 16))
            if decoded == "\0":
                return None
            out.append(decoded)
            i += 3
            continue
        out.append(" " if query and char == "+" else char)
        i += 1
    return "".join(out)


def _element(ai: str, raw: str, query: bool) -> tuple[str, str] | Problem:
    where = "query" if query else "path"
    if not raw:
        return Problem("AI_VALUE", f"the value of AI ({ai}) in the {where} is empty")
    value = _unescape(raw, query)
    if value is None:
        return Problem("PERCENT", f"the decoded value of AI ({ai}) in the {where} holds a NUL character")
    entry = dictionary().entries[ai]
    if not entry.min_length <= len(value) <= entry.max_length or "^" in value:
        return Problem("AI_VALUE", f"the value of AI ({ai}) has a wrong length")
    return ai, value


def _split(text: str) -> tuple[list[str], str | None] | Problem:
    """The path segments after the host and the query (None if absent). The fragment is dropped."""
    if not set(text) <= _URI:
        return Problem("URI", "the URI has a character that a URI does not permit")
    scheme = next((s for s in _SCHEMES if text.startswith(s)), None)
    if scheme is None:
        return Problem("URI", "it is not an HTTP or HTTPS URI")
    domain, slash, rest = text[len(scheme) :].partition("/")
    if set(domain) & _BAD_DOMAIN:
        return Problem("URI", "the host has a character that GS1 Digital Link does not permit")
    if not domain or not slash:
        return Problem("URI", "the URI has no host or no path")
    path, has_query, query = rest.partition("#")[0].partition("?")
    return path.split("/"), query if has_query else None


def _path_elements(segments: list[str]) -> list[tuple[str, str]] | Problem:
    """Walk back over /AI/value pairs from the end of the path to the first primary key."""
    entries, keys = dictionary().entries, {sequence[0] for sequence in dictionary().sequences}
    start, index = None, len(segments) - 1
    while index >= 1 and segments[index - 1] in entries:
        if segments[index - 1] in keys:
            start = index - 1
            break
        index -= 2
    if start is None:
        if _COMPRESSED.fullmatch(segments[-1]) and not segments[-1].isdigit():
            return Problem("COMPRESSED", "the URI looks like a compressed GS1 Digital Link URI")
        return Problem("KEY", "the path has no GS1 Digital Link primary key")
    elements = []
    for at in range(start, len(segments), 2):
        element = _element(segments[at], segments[at + 1], query=False)
        if isinstance(element, Problem):
            return element
        elements.append(element)
    return elements


def _query_elements(query: str | None) -> list[tuple[str, str]] | Problem:
    elements = []
    for parameter in query.split("&") if query is not None else ():
        name, equals, raw = parameter.partition("=")
        # An empty name counts as numeric, so "=x" is an unknown AI: the stricter reading.
        numeric = not name or (name.isascii() and name.isdigit())
        if not equals or not numeric:
            continue  # a singleton or a parameter that is not an AI: ignored
        if name not in dictionary().entries:
            return Problem("ATTRIBUTE", f"the query has the unknown AI ({name})")
        element = _element(name, raw, query=True)
        if isinstance(element, Problem):
            return element
        elements.append(element)
    return elements


def _attribute_problem(path_ais: tuple[str, ...], attributes: tuple[str, ...]) -> Problem | None:
    for ai in attributes:
        if not dictionary().entries[ai].attribute:
            return Problem("ATTRIBUTE", f"the AI ({ai}) is not a permitted data attribute")
        trials = ((*path_ais[:j], ai, *path_ais[j:]) for j in range(1, len(path_ais) + 1))
        if any(trial in dictionary().sequences for trial in trials):
            return Problem("ATTRIBUTE", f"the AI ({ai}) is a key qualifier and belongs in the path")
    return None


def parse(text: str) -> DigitalLink | Problem:
    """Parse an uncompressed GS1 Digital Link URI. A Problem names the rule that failed."""
    entries = dictionary().entries
    split = _split(text)
    if isinstance(split, Problem):
        return split
    segments, query = split
    path_elements = _path_elements(segments)
    if isinstance(path_elements, Problem):
        return path_elements
    query_elements = _query_elements(query)
    if isinstance(query_elements, Problem):
        return query_elements
    elements = path_elements + query_elements
    path_ais = tuple(ai for ai, _ in path_elements)
    if path_ais not in dictionary().sequences:
        return Problem("QUALIFIER_ORDER", "the key qualifiers of the path are not a valid sequence in order")
    all_ais = [ai for ai, _ in elements]
    if len(set(all_ais)) != len(all_ais):
        return Problem("ATTRIBUTE", "an AI occurs more than once")
    attributes = tuple(all_ais[len(path_ais) :])
    if (problem := _attribute_problem(path_ais, attributes)) is not None:
        return problem
    unchecked: set[str] = set()
    for ai, value in elements:
        if (problem := _validate(entries[ai], value, unchecked)) is not None:
            return problem
    return DigitalLink(path_ais[0], path_ais[1:], attributes, tuple(elements), tuple(sorted(unchecked)))
