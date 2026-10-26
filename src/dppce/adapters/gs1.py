"""The uncompressed GS1 Digital Link URI grammar, with AI data from the GS1 Barcode Syntax Dictionary.

The dictionary is vendored unchanged in ``testpacks/data/gs1-syntax-engine``. It gives the AI
formats, the primary keys, the key qualifiers in their order, and the data attribute flag. The
parse steps follow ``gs1_parseDLuri`` of gs1-syntax-engine (Apache-2.0) at the commit of the
vendored ``tests/vectors/gs1-syntax-engine/dl.c``, with its default options. That file is the
oracle of this module. Pairing rules of the dictionary (``req``, ``ex``) are not applied.

The module also holds the declared identity sources of ``identifier.consistency`` and the check
``identifier.equivalence``. They are here because ``identifier`` imports this module.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from itertools import combinations
from typing import Any, Final, Literal, cast, get_args
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, field_validator, model_validator

from dppce.adapters.common import (
    MISSING,
    blocked,
    carrier_identifier,
    completed,
    fetch_once,
    is_http_url,
    is_linkset,
    json_object,
    not_done,
    resource_url,
    unusable,
)
from dppce.adapters.pointer import MAX_POINTER_LENGTH, parse_pointer, resolve_pointer
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.resources import data_root
from dppce.models import CheckOutcome, ExecutionStatus, Model, ResourceName
from dppce.testdefs.registry import CheckContext, register

DICTIONARY: Final = ("testpacks", "data", "gs1-syntax-engine", "gs1-syntax-dictionary.txt")
Rule = Literal["URI", "KEY", "QUALIFIER_ORDER", "AI_VALUE", "CHECK_DIGIT", "PERCENT", "ATTRIBUTE"]
# The closed set of summary.rule values. COMPRESSED is an engine limit, not one of them.
RULES: Final[tuple[Rule, ...]] = (
    "URI", "KEY", "QUALIFIER_ORDER", "AI_VALUE", "CHECK_DIGIT", "PERCENT", "ATTRIBUTE",
)  # fmt: skip

_URI = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
_BAD_DOMAIN = frozenset("_~?#@!$&'()*+,;=%")
HOST: Final = re.compile(r"[A-Za-z0-9.:\[\]-]+")  # the netloc that both forms accept
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


def _element(ai: str, raw: str, query: bool, zero_suppressed: bool = False) -> tuple[str, str] | Problem:
    where = "query" if query else "path"
    if not raw:
        return Problem("AI_VALUE", f"the value of AI ({ai}) in the {where} is empty")
    value = _unescape(raw, query)
    if value is None:
        return Problem("PERCENT", f"the decoded value of AI ({ai}) in the {where} holds a NUL character")
    if zero_suppressed and ai == "01" and len(value) in (8, 12, 13):
        # dl.c with permitZeroSuppressedGTINinDLuris: a GTIN-8, -12, or -13 is left-padded to 14.
        value = value.zfill(14)
    if "^" in value:
        return Problem("AI_VALUE", f"the value of AI ({ai}) holds the FNC1 character")
    entry = dictionary().entries[ai]
    if not entry.min_length <= len(value) <= entry.max_length:
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
    # Stricter than dl.c, which checks only the characters of the host: the authority must also
    # be one that RFC 3986 permits, as in the form dppce-item.
    try:
        parts = urlsplit(text)
        _ = parts.port
    except ValueError:
        return Problem("URI", "the host or the port is not a valid URI authority")
    if not parts.hostname or not HOST.fullmatch(parts.netloc):
        return Problem("URI", "the host or the port is not a valid URI authority")
    path, has_query, query = rest.partition("#")[0].partition("?")
    return path.split("/"), query if has_query else None


def _path_elements(segments: list[str], zero_suppressed: bool) -> list[tuple[str, str]] | Problem:
    """Walk back over /AI/value pairs from the end of the path to the first primary key."""
    entries, keys = dictionary().entries, {sequence[0] for sequence in dictionary().sequences}
    start, index = None, len(segments) - 1
    while index >= 1 and segments[index - 1] in entries:
        if segments[index - 1] in keys:
            start = index - 1
            break
        index -= 2
    if start is None:
        if (
            not keys.intersection(segments)
            and _COMPRESSED.fullmatch(segments[-1])
            and not segments[-1].isdigit()
        ):
            return Problem("COMPRESSED", "the URI looks like a compressed GS1 Digital Link URI")
        return Problem("KEY", "the path has no GS1 Digital Link primary key")
    elements = []
    for at in range(start, len(segments), 2):
        element = _element(segments[at], segments[at + 1], query=False, zero_suppressed=zero_suppressed)
        if isinstance(element, Problem):
            return element
        elements.append(element)
    return elements


def _query_elements(query: str | None, zero_suppressed: bool) -> list[tuple[str, str]] | Problem:
    elements = []
    for parameter in query.split("&") if query is not None else ():
        name, equals, raw = parameter.partition("=")
        # An empty name counts as numeric, so "=x" is an unknown AI: the stricter reading.
        numeric = not name or (name.isascii() and name.isdigit())
        if not equals or not numeric:
            continue  # a singleton or a parameter that is not an AI: ignored
        if name not in dictionary().entries:
            return Problem("ATTRIBUTE", f"the query has the unknown AI ({name})")
        element = _element(name, raw, query=True, zero_suppressed=zero_suppressed)
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


def parse(text: str, *, zero_suppressed: bool = False) -> DigitalLink | Problem:
    """Parse an uncompressed GS1 Digital Link URI. A Problem names the rule that failed.

    ``zero_suppressed`` pads a GTIN-8, GTIN-12, or GTIN-13 in AI (01) to 14 digits, as the dl.c
    option permitZeroSuppressedGTINinDLuris does. The default is the default of dl.c: no padding.
    """
    entries = dictionary().entries
    split = _split(text)
    if isinstance(split, Problem):
        return split
    segments, query = split
    path_elements = _path_elements(segments, zero_suppressed)
    if isinstance(path_elements, Problem):
        return path_elements
    query_elements = _query_elements(query, zero_suppressed)
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


# -- Declared identity sources ------------------------------------------------------------------

SourceKind = Literal["resolved", "resource", "sample"]
MAX_SOURCES: Final = 8
_RESOURCES: Final = frozenset(get_args(ResourceName))


class Source(Model):
    label: str = Field(
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
        description=(
            "Name of the source in the summary. For the kind resource, the IXIT resource name. "
            "For the kind sample, the IXIT sample name."
        ),
    )
    kind: SourceKind = Field(
        description=(
            "resolved: the passport that the carrier resolves to. resource: the document at the IXIT "
            "resource template that the label names. sample: the JSON file of the IXIT sample that "
            "the label names."
        ),
    )
    pointer: str = Field(
        max_length=MAX_POINTER_LENGTH,
        description="JSON Pointer (RFC 6901) to the identifier in the source document.",
    )

    @field_validator("pointer")
    @classmethod
    def _pointer(cls, value: str) -> str:
        parse_pointer(value)
        return value

    @model_validator(mode="after")
    def _resource(self) -> Source:
        if self.kind == "resource" and self.label not in _RESOURCES:
            raise ValueError(f"the label of a resource source is one of {', '.join(sorted(_RESOURCES))}")
        return self


def source_value(ctx: CheckContext, source: Source, carrier: str) -> tuple[Any, Record | None]:
    """The JSON value at the pointer of the source and the record that was read.

    The value is ``MISSING`` if the pointer does not resolve, and a ``CheckOutcome`` if the source
    gives no JSON object. A resolved source follows the rules 1 and 2 of ``identifier.consistency``.
    """
    if source.kind == "sample":
        record = ctx.acquirer.artifact(source.label)
        document = json_object(record) if record.error is None else None
        if document is None:
            message = f"The sample '{source.label}' is not available as a JSON object. Nothing is compared."
            return blocked("IDENTIFIER.CROSS.SOURCE_MISSING", message), record
    else:
        if source.kind == "resolved" and not is_http_url(carrier):
            message = "The carrier identifier is not a URL. There is no passport to compare."
            return blocked("IDENTIFIER.NOT_RESOLVABLE", message), None
        # The model admits a resource name only for the kind resource.
        url = (
            carrier
            if source.kind == "resolved"
            else resource_url(ctx, cast(ResourceName, source.label), "IDENTIFIER")
        )
        if isinstance(url, CheckOutcome):
            return url, None
        record = fetch_once(ctx, url)
        if (problem := unusable(ctx, record)) is not None:
            return problem, record
        document = json_object(record) if record.status == 200 else None
        if source.kind == "resolved" and (document is None or is_linkset(document)):
            found = (
                "resolves to a linkset, not to a passport" if document else "did not resolve to a passport"
            )
            message = f"The identifier {found}. There is nothing to compare."
            return blocked("IDENTIFIER.NOT_RESOLVED", message), record
        if document is None:
            message = (
                f"The resource '{source.label}' is not a JSON object with status 200. Nothing is compared."
            )
            return blocked("IDENTIFIER.CROSS.SOURCE_MISSING", message), record
    return resolve_pointer(document, parse_pointer(source.pointer)), record


# -- identifier.equivalence ---------------------------------------------------------------------


class EquivalenceParams(Model):
    source: Source = Field(
        description="The declared identifier that is compared with the carrier identifier."
    )


def canonical(text: str) -> tuple[str, str, tuple[tuple[str, str], ...]] | Problem:
    """The scheme, the authority, and the key with its qualifiers, each as GS1 compares them.

    Case does not count in the scheme and the host. Percent-decoding, the path prefix, and a
    zero-suppressed GTIN do not count. Query data attributes are not part of the identity.
    """
    result = parse(text, zero_suppressed=True)
    if isinstance(result, Problem):
        return result
    parts = urlsplit(text)
    return parts.scheme.lower(), parts.netloc.lower(), result.elements[: 1 + len(result.qualifiers)]


_PARTS: Final = ("scheme", "authority", "key")


def _not_parsed(side: str, problem: Problem) -> CheckOutcome:
    message = (
        f"The {side} is not a valid uncompressed GS1 Digital Link URI (rule {problem.rule}), "
        "so it has no canonical form. Nothing is compared."
    )
    return blocked("IDENTIFIER.EQUIVALENCE.NOT_PARSED", message)


@register("identifier.equivalence", capability="identifier.equivalence", params=EquivalenceParams)
def equivalence(ctx: CheckContext) -> CheckOutcome:
    """Compare the carrier with a declared GS1 Digital Link URI in canonical form."""
    try:
        params = EquivalenceParams.model_validate(ctx.params)
    except ValidationError:
        # The lint refuses such a test pack. This guard covers a plan that skipped the lint.
        return blocked("IDENTIFIER.PARAMS.INVALID", "The parameter 'source' is not valid. Nothing is read.")
    carrier, records, transformations, problem = carrier_identifier(ctx)
    if problem is not None or carrier is None:
        return problem or blocked("CARRIER.SAMPLE.MISSING", "No identifier is available.")
    value, record = source_value(ctx, params.source, carrier)
    if isinstance(value, CheckOutcome):
        return value
    observed = [*records, *([record] if record is not None else [])]
    label = params.source.label
    if value is MISSING:
        message = f"The source '{label}' has no value at its pointer. Nothing is compared."
        return blocked("IDENTIFIER.CROSS.SOURCE_MISSING", message)
    kind: Literal["exchange", "artifact"] = (
        "exchange" if any(r.kind == "http" for r in observed) else "artifact"
    )

    def observation(summary: dict[str, object]) -> list[Any]:
        summary = {"source": label, "kind": params.source.kind, **summary}
        return [
            ctx.observation(0, kind=kind, records=observed, summary=summary, transformations=transformations)
        ]

    # A present value that is not text differs: a system must not turn a difference into blocked.
    if not isinstance(value, str):
        message = (
            f"The source '{label}' holds no text at its pointer, so it differs from the carrier identifier."
        )
        return completed(
            False, "IDENTIFIER.EQUIVALENCE.DIFFERENT", message, observation({"different": ["type"]})
        )
    left, right = canonical(carrier), canonical(value)
    if isinstance(left, Problem) and left.rule == "COMPRESSED":
        message = (
            "The carrier identifier looks like a compressed GS1 Digital Link URI. "
            "This version does not decompress it."
        )
        return not_done(ExecutionStatus.UNSUPPORTED, "IDENTIFIER.SYNTAX.COMPRESSED", message)
    if isinstance(left, Problem):
        return _not_parsed("carrier identifier", left)
    if isinstance(right, Problem):
        return _not_parsed(f"source '{label}'", right)
    different = [part for part, a, b in zip(_PARTS, left, right, strict=True) if a != b]
    if different:
        message = f"The carrier identifier and the source '{label}' differ in: {', '.join(different)}."
        return completed(
            False, "IDENTIFIER.EQUIVALENCE.DIFFERENT", message, observation({"different": different})
        )
    message = (
        f"The carrier identifier and the source '{label}' have the same GS1 canonical form. "
        "Digital consistency does not prove physical authenticity."
    )
    return completed(True, "IDENTIFIER.EQUIVALENCE.OK", message, observation({"different": []}))
