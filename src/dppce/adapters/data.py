"""Data adapter: JSON Schema, context allowlist, and versioned rule packs.

Rule pack format: docs/reference/reference-system.md, section 5.1. Every rule states its basis.
A normative threshold must cite its source. An engineering threshold is a project choice and is
reported as such. SHACL validation is an interface only in this version.

The parameter ``source`` selects where the judged document comes from (architecture section 8):
the resource that ``document`` names (the default), an IXIT sample, the payload of a credential
that verifies first, or the JSON-LD scripts of an HTML page. Each embedded document is judged, so
a system under test cannot hide a failing document behind a second one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final, Literal, Self
from urllib.parse import unquote, urljoin

from jsonschema import SchemaError
from jsonschema.protocols import Validator
from pydantic import Field, ValidationError, field_validator, model_validator

from dppce.adapters.common import (
    MISSING,
    DialectError,
    blocked,
    completed,
    dig,
    fetch_once,
    item_url,
    json_object,
    media_type,
    not_200,
    resource_url,
    schema_errors,
    unassertable_formats,
    unusable,
    validator,
)
from dppce.adapters.jose import JoseParams, _Finding, _judge, finding_of
from dppce.adapters.pointer import parse_pointer, resolve_pointer
from dppce.applicability import ApplicabilityError, evaluate, facts_from
from dppce.catalogue import CatalogueError, load_data, load_model
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.jose_profiles import JoseError
from dppce.evidence.manual import SAMPLE_PREFIX
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
from dppce.infrastructure.redaction import JSONLD_CONTEXT, REMOVED, parse_link, redact_url
from dppce.models import CheckOutcome, ExecutionStatus, Expr, JsonValue, Model, Tri
from dppce.testdefs.registry import CheckContext, register

DocumentKind = Literal["item", "model"]
CREDENTIAL: Final = "credential_payload"
EMBEDDED: Final = "embedded_jsonld"
# Engine limit of the source embedded_jsonld: a larger page is not judged. Every script of a page
# within the limit is judged, so a script count limit would let a page hide a failing script.
MAX_PAGE_BYTES: Final = 2 * 1024 * 1024
# One path segment of a parameter file: no empty, "." or ".." segment, no backslash.
_SEGMENT: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
# The parameter of each check that names a file under the data root (architecture section 9.2).
FILE_PARAMS: Final = {"data.jsonschema": "schema", "data.rules": "rule_pack", "data.context": "context_files"}
# When more than one rule fails, the first kind in this order names the reason code. The kinds of
# version 2 come after the kinds of version 1, so a pack of version 1 keeps its reason codes.
_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("required_fields", "DATA.COMPLETENESS.MISSING"),
    ("unit", "DATA.UNIT.INVALID"),
    ("range", "DATA.RANGE.VIOLATED"),
    ("relationship", "DATA.RELATIONSHIP.VIOLATED"),
    ("freshness", "DATA.FRESHNESS.STALE"),
    ("forbidden", "DATA.FIELD.FORBIDDEN"),
    ("pattern", "DATA.PATTERN.MISMATCH"),
    ("equals", "DATA.EQUALITY.VIOLATED"),
)
V1: Final = "dppce.rulepack/1"
V2: Final = "dppce.rulepack/2"
_V2_KINDS: Final = frozenset({"pattern", "forbidden", "equals", "each"})
_V2_KEYS: Final = frozenset({"path", "pattern", "max_length", "value", "other", "rule"})
# The accepted subset of a pattern (reference-system.md, section 5.1). Python's re backtracks, so
# a quantifier applies to one character, class, or escape only, never to a group. That refuses
# nested quantifiers and quantified alternations, the constructs with exponential time.
# Each "|" is a choice like a variable quantifier, so both share one budget of three.
# ponytail: with k such choices the worst case is O(n^k); k <= 3 and n <= 512 bound it.
MAX_PATTERN: Final = 256
MAX_SUBJECT: Final = 512
# The pattern work of one rule on one answer: each match costs len(value) ** 2 units. The system
# under test supplies the values, and ``each`` applies a rule to every element of an array, so one
# bounded subject does not bound an answer. A rule that would exceed its budget is not judged. Each
# rule has its own budget, so an array for one rule cannot use up the budget of another rule.
# ponytail: 2**24 units is 64 values of 512 characters, about 10 s per rule at the worst pattern;
# the pinned rule pack, not the system, sets the number of rules.
MAX_PATTERN_WORK: Final = 2**24
_MAX_VARIABLE: Final = 3
_MAX_REPEAT: Final = 1000
_CLASS_ESCAPES: Final = frozenset("dDwWsS")
_REPEAT: Final = re.compile(r"\{([0-9]{1,4})(?:(,)([0-9]{0,4}))?\}")


def _escape(pattern: str, i: int) -> int:
    """The index after the escape at ``i``. Only a class escape or an escaped symbol is accepted."""
    if i + 1 >= len(pattern):
        raise ValueError("a pattern ends with a backslash")
    char = pattern[i + 1]
    if char.isalnum() and char not in _CLASS_ESCAPES:
        # A digit is a backreference, and a letter is an anchor, a code, or a named reference.
        raise ValueError(f"the escape \\{char} is not in the accepted subset")
    return i + 2


def _class_end(pattern: str, i: int) -> int:
    """The index after the character class that starts at ``i``."""
    j = i + 1
    if j < len(pattern) and pattern[j] == "^":
        j += 1
    if j < len(pattern) and pattern[j] == "]":
        j += 1  # a "]" right after "[" or "[^" is a literal
    while j < len(pattern):
        char = pattern[j]
        if char == "]":
            return j + 1
        if char == "[":
            raise ValueError("a nested set in a character class is not in the accepted subset")
        j = _escape(pattern, j) if char == "\\" else j + 1
    raise ValueError("a character class is not closed")


def check_pattern(pattern: str) -> str:  # noqa: PLR0912, PLR0915 - one branch per token of the accepted subset
    """Return the pattern if it is in the accepted subset, or raise ValueError."""
    if not 1 <= len(pattern) <= MAX_PATTERN:
        raise ValueError(f"a pattern has 1 to {MAX_PATTERN} characters")
    depth = variable = 0
    repeatable = False  # whether the item before can take a quantifier
    i = 0
    while i < len(pattern):
        char = pattern[i]
        quantifier = _REPEAT.match(pattern, i) if char == "{" else None
        if char in "*+?" or quantifier:
            if not repeatable:
                raise ValueError("a quantifier applies to one character, class, or escape only")
            fixed = False  # "*", "+", and "?" are variable
            if quantifier:
                low, comma, high = quantifier.groups()
                top = int(high) if high else _MAX_REPEAT if comma else int(low)
                if int(low) > top or top > _MAX_REPEAT:
                    raise ValueError(f"a counted repeat has bounds of at most {_MAX_REPEAT}, in order")
                fixed = top == int(low) and not (comma and not high)
            variable += 0 if fixed else 1
            if variable > _MAX_VARIABLE:
                raise ValueError(
                    f"a pattern has at most {_MAX_VARIABLE} variable quantifiers and '|' together"
                )
            repeatable = False  # so a lazy "?" or a possessive "+" is refused
            i = quantifier.end() if quantifier else i + 1
            continue
        if char == "{":
            raise ValueError("a literal { is written as \\{")
        if char == "(":
            if pattern.startswith("(?", i) and not pattern.startswith("(?:", i):
                raise ValueError("a group is (...) or (?:...); lookaround, flags, and names are refused")
            depth += 1
            i += 3 if pattern.startswith("(?:", i) else 1
            repeatable = False
            continue
        if char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("a pattern closes a group that is not open")
            repeatable = False  # a group never takes a quantifier
        elif char in "|^$":
            # A chain of unquantified alternations backtracks like a chain of "?", so "|" counts too.
            variable += char == "|"
            if variable > _MAX_VARIABLE:
                raise ValueError(
                    f"a pattern has at most {_MAX_VARIABLE} variable quantifiers and '|' together"
                )
            repeatable = False
        elif char == "[":
            i = _class_end(pattern, i)
            repeatable = True
            continue
        elif char == "\\":
            i = _escape(pattern, i)
            repeatable = True
            continue
        else:
            repeatable = True
        i += 1
    if depth:
        raise ValueError("a pattern leaves a group open")
    try:
        re.compile(pattern, re.ASCII)
    except re.error as exc:
        raise ValueError(f"not a regular expression: {exc}") from exc
    return pattern


def _pointer(value: str) -> str:
    parse_pointer(value)  # raises ValueError for a malformed pointer
    return value


class Basis(Model):
    """Why a rule exists. A normative rule cites its source; an engineering rule is a project choice."""

    basis_class: Literal["normative", "engineering", "illustrative"] = Field(alias="class")
    source_id: str = ""
    citation: str = ""
    note: str = ""

    @model_validator(mode="after")
    def _normative_cites_a_source(self) -> Self:
        if self.basis_class == "normative" and not (self.source_id and self.citation):
            raise ValueError("a normative rule cites a source and a provision")
        return self


def _subset(value: str) -> str:
    return value and check_pattern(value)


class _Judgment(Model):
    """The judgment of one rule. ``each`` applies one to every element of an array.

    The kinds of version 1 read dotted ``field`` paths. The kinds of version 2 read the JSON
    Pointer ``path``. Inside ``each``, both are relative to the element, and the path ``""`` is
    the element itself.
    """

    kind: str
    fields: tuple[str, ...] = ()
    field: str = ""
    allowed: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    left: str = ""
    op: Literal["lt", "le", "eq", "ge", "gt"] = "le"
    right: str = ""
    max_age_days: int | None = Field(default=None, ge=0)
    path: str = ""
    pattern: str = ""
    max_length: int = Field(default=256, ge=1, le=MAX_SUBJECT)
    value: str | None = None
    other: str | None = None

    _path = field_validator("path")(_pointer)
    _pattern = field_validator("pattern")(_subset)

    @field_validator("other")
    @classmethod
    def _other(cls, value: str | None) -> str | None:
        return None if value is None else _pointer(value)

    @model_validator(mode="after")
    def _judges_something(self) -> Self:
        # A rule without the fields of its kind always holds. It would count as applied and pass.
        needed: dict[str, bool] = {
            "required_fields": bool(self.fields) and all(self.fields),
            "unit": bool(self.field and self.allowed),
            "range": bool(self.field) and (self.min is not None or self.max is not None),
            "relationship": bool(self.left and self.right),
            "freshness": bool(self.field) and self.max_age_days is not None,
            "pattern": bool(self.pattern),
            # The root is never absent, so a forbidden root would always fail.
            "forbidden": bool(self.path),
            "equals": (self.value is None) != (self.other is None),
            "each": True,  # Rule checks its own fields
        }
        if not needed[self.kind]:
            raise ValueError(f"a {self.kind} rule needs the fields of its kind")
        return self


class ElementRule(_Judgment):
    """The rule of an ``each`` rule. It cannot be an ``each`` rule itself, so the work is bounded."""

    kind: Literal[
        "required_fields", "unit", "range", "relationship", "freshness", "pattern", "forbidden", "equals"
    ]


class Rule(_Judgment):
    id: str
    kind: Literal[
        "required_fields",
        "unit",
        "range",
        "relationship",
        "freshness",
        "pattern",
        "forbidden",
        "equals",
        "each",
    ]
    document: DocumentKind
    basis: Basis
    when: Expr | None = None
    rule: ElementRule | None = None

    @model_validator(mode="after")
    def _each_judges_something(self) -> Self:
        if (self.kind == "each") != (self.rule is not None):
            raise ValueError("an each rule, and only an each rule, has a rule")
        # The root of a document is an object, so a rule on it would break for every document.
        # Only the rule of an each rule names its element with the root pointer.
        if self.kind in ("pattern", "equals", "each") and not self.path:
            raise ValueError(f"a {self.kind} rule names a field by a pointer other than the root")
        return self


class RulePack(Model):
    schema_version: Literal["dppce.rulepack/1", "dppce.rulepack/2"]
    rulepack_id: str
    version: str
    rules: tuple[Rule, ...]

    @model_validator(mode="after")
    def _version_1_is_unchanged(self) -> Self:
        # An engine of version 1 refuses these packs, so a pack of version 1 must not use them. A
        # key of version 2 at its default value changes nothing, as in a dumped rule of version 1.
        if self.schema_version == V1 and any(
            r.kind in _V2_KINDS or any(getattr(r, k) != Rule.model_fields[k].default for k in _V2_KEYS)
            for r in self.rules
        ):
            raise ValueError(f"a kind or a key of version 2 needs schema_version {V2}")
        return self


def _relative_file(value: str | None) -> str | None:
    if value is not None and (len(value) > 256 or not all(_SEGMENT.fullmatch(p) for p in value.split("/"))):
        raise ValueError(
            "must be a relative path under the data root, with segments of A-Z, a-z, 0-9, '_', '.', "
            "and '-', and no '.' or '..' segment"
        )
    return value


def param_files(check: str, params: Mapping[str, Any]) -> tuple[str, ...]:
    """The files under the data root that the parameters of a test purpose name (section 9.2)."""
    value = params.get(FILE_PARAMS.get(check, ""))
    values = list(value.values()) if isinstance(value, Mapping) else [value]
    try:
        return tuple(v for v in values if isinstance(v, str) and _relative_file(v))
    except ValueError:
        return ()  # the planner refuses these parameters, and no check reads the file


class DocumentParams(Model):
    document: DocumentKind = Field(
        default="item",
        description="Item-level or model-level document. It selects the profile schema and the rules.",
    )
    source: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "Experimental. Where the document comes from. Default: the resource that document names. "
            "item or model: that resource. credential_payload: the payload of a JWS credential that "
            "verifies first under 'credential'. embedded_jsonld: each <script type=\"application/ld+json\"> "
            "of an HTML page. Any other value names an IXIT sample, which is read and not fetched."
        ),
    )
    sample: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "For embedded_jsonld: the IXIT sample that holds the HTML page. Default: the page at the "
            "resource that document names, fetched with Accept: text/html. A name never starts with manual/."
        ),
    )
    credential: JoseParams | None = Field(
        default=None,
        description=(
            "For credential_payload: the parameters of integrity.jose that verify the credential. "
            "Default: the profile vc-jose, the key source trust_kid, and the resource 'signed'."
        ),
    )

    @model_validator(mode="after")
    def _source_fields(self) -> Self:
        # The manual results of other test purposes are in the same artifact namespace.
        jose = self.credential
        names = (self.source, self.sample, jose and jose.sample, jose and jose.did_sample)
        if any(name and name.startswith(SAMPLE_PREFIX) for name in names):
            raise ValueError(f"a sample name never starts with {SAMPLE_PREFIX}")
        if self.credential is not None and self.source != CREDENTIAL:
            raise ValueError(f"credential needs the source {CREDENTIAL}")
        if self.sample is not None and self.source != EMBEDDED:
            raise ValueError(f"sample needs the source {EMBEDDED}")
        return self


class SchemaParams(DocumentParams):
    schema_file: str | None = Field(
        default=None,
        alias="schema",
        description=(
            "A JSON Schema file under the data root, in place of the profile schema. The run binds it."
        ),
    )

    _schema_file = field_validator("schema_file")(_relative_file)


class RulesParams(DocumentParams):
    rule_pack: str | None = Field(
        default=None,
        description=(
            "A rule pack file under the data root, in place of the rule packs of the profile. "
            "The run binds it."
        ),
    )

    _rule_pack = field_validator("rule_pack")(_relative_file)


class ContextParams(DocumentParams):
    allowed_contexts: tuple[str, ...] = Field(
        min_length=1, description="Exact context URLs that are allowed. No context is fetched."
    )
    context_files: dict[str, str] = Field(
        default_factory=dict,
        max_length=32,
        description=(
            "Experimental. A pinned copy of an allowed context: the context URL and a JSON file under "
            "the data root. The check reads the @import and @context references of each pinned "
            "context. It follows a reference only into another pinned context. The run binds each file."
        ),
    )

    @field_validator("context_files")
    @classmethod
    def _files(cls, value: dict[str, str]) -> dict[str, str]:
        for path in value.values():
            _relative_file(path)
        return value

    @model_validator(mode="after")
    def _files_are_allowed(self) -> Self:
        if not set(self.context_files) <= set(self.allowed_contexts):
            raise ValueError("each key of context_files is an allowed context")
        return self


@dataclass(frozen=True)
class _Documents:
    """The documents of one source. ``summary`` holds the summary keys of a source that is not the default."""

    documents: list[dict[str, Any]]
    record: Record
    summary: dict[str, JsonValue] = field(default_factory=dict)

    def observation(self, ctx: CheckContext, summary: dict[str, JsonValue]) -> Any:
        kind: Literal["artifact", "exchange"] = "artifact" if self.record.kind == "artifact" else "exchange"
        return ctx.observation(0, kind=kind, records=[self.record], summary=summary | self.summary)


def _params[P: DocumentParams](ctx: CheckContext, model: type[P]) -> P | CheckOutcome:
    try:
        return model.model_validate(ctx.params)
    except ValidationError:
        return blocked("DATA.PARAMS.INVALID", "The parameters are not valid. Nothing is read.")


def _not_json(ctx: CheckContext, record: Record, message: str, source: str) -> CheckOutcome:
    kind: Literal["artifact", "exchange"] = "artifact" if record.kind == "artifact" else "exchange"
    summary: dict[str, JsonValue] = {"status": record.status, "source": source}
    observation = ctx.observation(0, kind=kind, records=[record], summary=summary)
    return completed(False, "DATA.RESPONSE.NOT_JSON", message, [observation])


def _sample(ctx: CheckContext, name: str) -> Record | CheckOutcome:
    record = ctx.acquirer.artifact(name)
    if record.error is not None:
        return blocked("DATA.SAMPLE.MISSING", f"The sample '{name}' is not available.")
    return record


def _answer(
    ctx: CheckContext, resource: Literal["item", "model", "signed"], accept: str | None = None
) -> Record | CheckOutcome:
    """The answer of a resource with the status 200 and a usable body, or the outcome."""
    url = item_url(ctx, "DATA") if resource == "item" else resource_url(ctx, resource, "DATA")
    if isinstance(url, CheckOutcome):
        return url
    record = fetch_once(ctx, url, accept=accept)
    return unusable(ctx, record) or not_200(ctx, "DATA", record, [record]) or record


def _credential(ctx: CheckContext, jose: JoseParams, decimals: bool) -> _Documents | CheckOutcome:
    """The payload of a credential that verifies. An unverified payload is never judged."""
    if ctx.trust is None:
        message = "No trust bundle is configured, so the credential cannot verify. Its payload is not judged."
        return blocked("DATA.CREDENTIAL.UNVERIFIED", message)
    acquired = _sample(ctx, jose.sample) if jose.source == "sample" else _answer(ctx, "signed", jose.accept)
    if isinstance(acquired, CheckOutcome):
        return acquired
    record = acquired
    try:
        token = _judge(ctx, ctx.trust, jose, record.body, findings={}, dids={})
    except (JoseError, _Finding) as exc:
        _, code, _ = finding_of(exc, {})
        kind: Literal["artifact", "exchange"] = "artifact" if record.kind == "artifact" else "exchange"
        summary: dict[str, JsonValue] = {"source": CREDENTIAL, "verification": code}
        observation = ctx.observation(0, kind=kind, records=[record], summary=summary)
        message = (
            f"The credential does not verify ({code}), so its payload is not judged. "
            "integrity.jose reports the signature itself."
        )
        return CheckOutcome(
            status=ExecutionStatus.BLOCKED,
            reason_code="DATA.CREDENTIAL.UNVERIFIED",
            message=message,
            observations=(observation,),
        )
    try:
        document = parse_strict(token.payload, decimals=decimals)
    except CanonicalizationError:
        document = None
    if not isinstance(document, dict):
        return _not_json(ctx, record, "The verified credential payload is not a JSON object.", CREDENTIAL)
    return _Documents([document], record, {"source": CREDENTIAL})


class _JsonLdScripts(HTMLParser):
    """The text of each <script type="application/ld+json"> of a page.

    The parser never renders or executes the page. Script text is raw: HTML does not decode
    character references in a script.
    """

    def __init__(self) -> None:
        super().__init__()
        self.found: list[str] = []
        self._open: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        kind = next((v for k, v in attrs if k == "type"), None) or ""
        if tag == "script" and kind.split(";")[0].strip().lower() == "application/ld+json":
            self._open = []

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._open.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._open is not None:
            self.found.append("".join(self._open))
            self._open = None

    def close(self) -> None:
        super().close()
        if self._open is not None:  # an unclosed script ends with the page
            self.found.append("".join(self._open))
            self._open = None


def _embedded(ctx: CheckContext, params: DocumentParams, decimals: bool) -> _Documents | CheckOutcome:
    """Each JSON-LD document of an HTML page. A script that is not one JSON object is a fail."""
    # A resolver with content negotiation can answer */* with JSON, so the engine asks for the page.
    acquired = _sample(ctx, params.sample) if params.sample else _answer(ctx, params.document, "text/html")
    if isinstance(acquired, CheckOutcome):
        return acquired
    record = acquired
    if len(record.body) > MAX_PAGE_BYTES:
        return blocked("DATA.EMBEDDED.TOO_LARGE", f"The page is larger than {MAX_PAGE_BYTES} bytes.")
    try:
        text = record.body.decode("utf-8")
    except UnicodeDecodeError:
        # JSON text between systems is UTF-8 (RFC 8259, section 8.1), so the scripts are not JSON.
        return _not_json(ctx, record, "The page is not UTF-8 text, so its scripts are not JSON.", EMBEDDED)
    # ponytail: html.parser reads the whole page; MAX_PAGE_BYTES bounds its work and every script.
    parser = _JsonLdScripts()
    parser.feed(text)
    parser.close()
    if not parser.found:
        kind: Literal["artifact", "exchange"] = "artifact" if record.kind == "artifact" else "exchange"
        summary: dict[str, JsonValue] = {"source": EMBEDDED, "documents": 0}
        observation = ctx.observation(0, kind=kind, records=[record], summary=summary)
        message = 'The page holds no <script type="application/ld+json"> element.'
        return completed(False, "DATA.EMBEDDED.MISSING", message, [observation])
    documents: list[dict[str, Any]] = []
    for script in parser.found:
        try:
            document = parse_strict(script, decimals=decimals)
        except CanonicalizationError:
            document = None
        if not isinstance(document, dict):
            message = "An embedded JSON-LD script is not one JSON object."
            return _not_json(ctx, record, message, EMBEDDED)
        documents.append(document)
    summary = {"source": EMBEDDED, "documents": len(documents)}
    return _Documents(documents, record, summary)


def _documents(
    ctx: CheckContext, params: DocumentParams, *, decimals: bool = False
) -> _Documents | CheckOutcome:
    """The documents that ``source`` selects, or the outcome if none can be judged."""
    source = params.source
    if source == CREDENTIAL:
        return _credential(ctx, params.credential or JoseParams(), decimals)
    if source == EMBEDDED:
        return _embedded(ctx, params, decimals)
    if source is not None and source not in ("item", "model"):
        acquired = _sample(ctx, source)
        if isinstance(acquired, CheckOutcome):
            return acquired
        document = json_object(acquired, decimals=decimals)
        if document is None:
            return _not_json(ctx, acquired, f"The sample '{source}' is not a JSON object.", source)
        return _Documents([document], acquired, {"source": source})
    document, record, problem = _fetch_document(ctx, source or params.document, decimals=decimals)
    if problem is not None or document is None or record is None:
        return problem or blocked("DATA.NO_TARGET", "No document is available.")
    return _Documents([document], record, {} if source is None else {"source": source})


def _fetch_document(
    ctx: CheckContext, kind: str, *, decimals: bool = False
) -> tuple[dict[str, Any] | None, Record | None, CheckOutcome | None]:
    """Fetch the item-level passport or the model-level data: (document, record, outcome if not usable)."""
    record = _answer(ctx, "model" if kind == "model" else "item")
    if isinstance(record, CheckOutcome):
        return None, None, record
    document = json_object(record, decimals=decimals)
    if document is None:
        observation = ctx.observation(0, kind="exchange", records=[record], summary={"status": record.status})
        message = f"The {kind}-level document is not a JSON object (status {record.status})."
        return None, record, completed(False, "DATA.RESPONSE.NOT_JSON", message, [observation])
    return document, record, None


_MALFORMED: Final = blocked(
    "DATA.SCHEMA.MALFORMED",
    "The pinned schema is not a valid JSON Schema, or a local reference does not resolve.",
)


def _pinned_path(ctx: CheckContext, path: str, *, parameter: bool) -> Path:
    """The file of a pinned path. A parameter file that a link takes out of the data root is not read."""
    file = ctx.data_root / path
    if parameter and not file.resolve().is_relative_to(ctx.data_root.resolve()):
        raise CatalogueError("the file is not inside the data root")
    return file


def _compiled(schema: Any) -> Validator | CheckOutcome:
    """The validator of a pinned schema, or the blocked outcome of a schema that the engine cannot use."""
    if not isinstance(schema, Mapping):
        return _MALFORMED
    try:
        check = validator(schema)
    except DialectError:
        message = "The pinned schema names a dialect other than JSON Schema 2020-12 or draft-07."
        return blocked("DATA.SCHEMA.DIALECT", message)
    except SchemaError:
        return _MALFORMED
    if check is None:
        return blocked(
            "DATA.SCHEMA.NOT_LOCAL", "The schema uses a reference that is not local. Nothing is fetched."
        )
    if formats := unassertable_formats(schema):
        message = f"The schema uses formats that the engine cannot assert: {', '.join(formats)}."
        return blocked("DATA.SCHEMA.UNSUPPORTED_FORMAT", message)
    return check


@register("data.jsonschema", capability="data.jsonschema", params=SchemaParams)
def jsonschema_check(ctx: CheckContext) -> CheckOutcome:
    params = _params(ctx, SchemaParams)
    if isinstance(params, CheckOutcome):
        return params
    kind = params.document
    path = params.schema_file or (ctx.profile.model_schema if kind == "model" else ctx.profile.item_schema)
    if path is None:
        return blocked("DATA.SCHEMA.MISSING", f"The profile names no {kind}-level schema.")
    try:
        schema = load_data(_pinned_path(ctx, path, parameter=params.schema_file is not None))
    except CatalogueError:
        return blocked("DATA.SCHEMA.MISSING", f"The pinned {kind}-level schema cannot be read.")
    check = _compiled(schema)
    if isinstance(check, CheckOutcome):
        return check
    # Exact decimals, like data.rules: a binary float can round a value onto a schema bound.
    got = _documents(ctx, params, decimals=True)
    if isinstance(got, CheckOutcome):
        return got
    judged: list[list[JsonValue] | None] = []
    for document in got.documents:
        try:
            judged.append(schema_errors(check, document))
        except SchemaError:
            return _MALFORMED
    errors = [e for found in judged if found for e in found]
    summary: dict[str, JsonValue] = {"document": kind, "schema": path, "schema_errors": errors}
    observation = got.observation(ctx, summary)
    if errors:
        what = f"The {kind}-level document has" if len(judged) == 1 else f"{len(judged)} documents have"
        return completed(False, "DATA.SCHEMA.INVALID", f"{what} {len(errors)} schema errors.", [observation])
    # A document that is too deep is judged only after every other document: a fail comes first.
    if any(found is None for found in judged):
        return blocked(
            "DATA.RESPONSE.TOO_DEEP", "The document is nested too deeply to validate. It is not judged."
        )
    what = f"The {kind}-level document matches" if len(judged) == 1 else f"All {len(judged)} documents match"
    return completed(True, "DATA.SCHEMA.OK", f"{what} the pinned schema.", [observation])


def _references(node: Any) -> tuple[list[Any], list[Any]]:
    """(every @context entry, every @import value) in a JSON value.

    A JSON-LD processor also reads a scoped @context in any nested node, so each one counts.
    A work list, not recursion: a deeply nested document must not stop the check.
    """
    every: list[Any] = []
    imports: list[Any] = []
    pending: list[Any] = [node]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            value = node.get("@context")
            if value is not None:
                every.extend(value if isinstance(value, list) else [value])
            if "@import" in node:
                imports.append(node["@import"])
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return every, imports


def _contexts(document: dict[str, Any], allowed: list[Any]) -> tuple[int, set[str]]:
    """(top-level context entries, context references outside the allowlist) of one document."""
    declared = document.get("@context")
    entries = declared if isinstance(declared, list) else [declared] if declared is not None else []
    # An inline context object is not a pinned reference, so it is never in the allowlist.
    return len(entries), {
        str(e) if isinstance(e, str) else "<inline context>"
        for e in _references(document)[0]
        if e not in allowed
    }


def _pinned_contexts(ctx: CheckContext, params: ContextParams) -> dict[str, list[str]] | CheckOutcome:
    """The context references of each pinned context, by context URL. Read before any request."""
    pinned: dict[str, list[str]] = {}
    for url, path in params.context_files.items():
        try:
            document = load_data(_pinned_path(ctx, path, parameter=True))
        except (CatalogueError, CanonicalizationError):
            document = None
        every, imports = _references(document)
        # An @import value is one URL (JSON-LD 1.1), so any other value makes the pinned copy invalid.
        if not isinstance(document, dict) or not all(isinstance(i, str) for i in imports):
            return blocked(
                "DATA.CONTEXT.FILE_INVALID", f"The pinned context file of {url} is not a valid context."
            )
        # An inline object is a part of the pinned context itself, not a reference.
        pinned[url] = [r for r in every if isinstance(r, str)] + imports
    return pinned


def _link_contexts(record: Record, allowed: list[Any]) -> tuple[list[str], int]:
    """The targets of the links with the JSON-LD context relation, and how many cannot be compared.

    JSON-LD 1.1 API, section 9.4.1: a processor reads the href of such a link and ignores the
    header for application/ld+json. The record holds the form that redaction keeps. A link with
    the relation names its target, whatever its other parameters are. Redaction keeps the links
    that RFC 8288, appendix B, reads before a malformed part; the rest names no context. A target
    that redaction changed holds the marker and is compared in that form. It cannot be compared
    only if it equals the redacted form of an allowed URL that redaction changes too.
    """
    if record.kind != "http" or media_type(record) == "application/ld+json":
        return [], 0
    base = record.redirects[-1] if record.redirects else record.url
    changed = {redact_url(a) for a in allowed if isinstance(a, str)}
    found: list[str] = []
    limited = 0
    for name, value in record.headers:
        if name.lower() != "link":
            continue
        for link in parse_link(value).links:
            if JSONLD_CONTEXT not in link.relations:
                continue
            try:
                url = urljoin(base, link.target)
            except ValueError:
                continue  # a target that cannot be resolved names no context
            if url not in allowed and REMOVED in unquote(url) and url in changed:
                limited += 1
            else:
                found.append(url)
    return found, limited


def _imported(start: list[str], pinned: dict[str, list[str]], allowed: list[Any]) -> set[str]:
    """The references outside the allowlist that the pinned contexts reachable from ``start`` make."""
    foreign: set[str] = set()
    seen: set[str] = set()
    pending = [url for url in start if url in pinned]
    while pending:
        url = pending.pop()
        if url in seen:
            continue
        seen.add(url)
        for reference in pinned[url]:
            if reference not in allowed:
                foreign.add(reference)
            elif reference in pinned:
                pending.append(reference)  # an allowed context without a pinned copy is judged by its URL
    return foreign


@register("data.context", capability="data.context", params=ContextParams)
def context_check(ctx: CheckContext) -> CheckOutcome:
    allowed = ctx.params.get("allowed_contexts")
    if not isinstance(allowed, list) or not allowed:
        return blocked("DATA.CONTEXT.NO_ALLOWLIST", "The test purpose gives no allowlist of contexts.")
    params = _params(ctx, ContextParams)
    if isinstance(params, CheckOutcome):
        return params
    pinned = _pinned_contexts(ctx, params)
    if isinstance(pinned, CheckOutcome):
        return pinned
    got = _documents(ctx, params)
    if isinstance(got, CheckOutcome):
        return got
    counted = [_contexts(document, allowed) for document in got.documents]
    # A Link header applies to the one fetched document. It never applies to a sample, a
    # credential payload, or an HTML page.
    fetched = params.source in (None, "item", "model")
    linked, limited = _link_contexts(got.record, allowed) if fetched else ([], 0)
    if linked or limited:
        entries, found = counted[0]
        counted[0] = (entries + len(linked) + limited, found | {url for url in linked if url not in allowed})
    start = [r for document in got.documents for r in _references(document)[0] if isinstance(r, str)] + linked
    foreign = sorted(set().union(*(found for _, found in counted), _imported(start, pinned, allowed)))
    summary: dict[str, JsonValue] = {
        "document": params.document,
        "contexts": sum(entries for entries, _ in counted),
        "not_allowed": list[JsonValue](foreign),
    }
    observation = got.observation(ctx, summary)
    if missing := sum(1 for entries, _ in counted if not entries):
        message = (
            "The document names no context." if len(counted) == 1 else f"{missing} documents name no context."
        )
        return completed(False, "DATA.CONTEXT.MISSING", message, [observation])
    if foreign:
        message = f"{len(foreign)} context references are not in the pinned allowlist. No context is fetched."
        return completed(False, "DATA.CONTEXT.NOT_ALLOWED", message, [observation])
    if limited:
        message = (
            "A context link of the answer has a target that redaction changed. It equals the redacted "
            "form of an allowed context, so the two cannot be compared exactly."
        )
        return CheckOutcome(
            status=ExecutionStatus.BLOCKED,
            reason_code="DATA.CONTEXT.LINK_UNREADABLE",
            message=message,
            observations=(observation,),
        )
    return completed(
        True, "DATA.CONTEXT.OK", "Every context reference is in the pinned allowlist.", [observation]
    )


def _compare(left: int | Decimal, op: str, right: int | Decimal) -> bool:
    return {
        "lt": left < right,
        "le": left <= right,
        "eq": left == right,
        "ge": left >= right,
        "gt": left > right,
    }[op]


def _is_number(value: Any) -> bool:
    """An integer (not a boolean) or a finite exact decimal. A binary float is never accepted."""
    return type(value) is int or (type(value) is Decimal and value.is_finite())


def _string_at(document: Any, path: str) -> Any:
    """The value at a pointer: ``MISSING``, a string, or None for a present value of another type."""
    value = resolve_pointer(document, parse_pointer(path))
    return value if value is MISSING or isinstance(value, str) else None


@dataclass
class PatternBudget:
    """The pattern work that one rule can still use on an answer, and whether a match did not run."""

    left: int = MAX_PATTERN_WORK
    limited: bool = False


def rule_holds(  # noqa: PLR0912 - one branch per rule kind
    rule: _Judgment, document: Any, now: datetime, budget: PatternBudget | None = None
) -> bool:
    """True if the document obeys the rule. ``required_fields`` and ``forbidden`` judge absence.

    A present value of the wrong type breaks the rule, so a reshaped document fails and is
    never blocked. With a budget, a match that would exceed it does not run: the value counts as
    holding, and ``budget.limited`` is set, so the caller reports the rule as not judged.
    """
    if rule.kind == "each":
        items = resolve_pointer(document, parse_pointer(rule.path))
        if items is MISSING:
            return True
        inner = rule.rule if isinstance(rule, Rule) else None
        return (
            isinstance(items, list)
            and inner is not None
            and all(rule_holds(inner, e, now, budget) for e in items)
        )
    if rule.kind == "forbidden":
        return resolve_pointer(document, parse_pointer(rule.path)) is MISSING
    if rule.kind == "pattern":
        value = _string_at(document, rule.path)
        if value is MISSING:
            return True
        # A longer value breaks the rule without a match: it is not an engine limit.
        if value is None or len(value) > rule.max_length:
            return False
        if budget is not None:
            if len(value) ** 2 > budget.left:
                budget.limited = True
                return True  # not judged; a later element can still fail within the budget
            budget.left -= len(value) ** 2
        return bool(re.fullmatch(rule.pattern, value, re.ASCII))
    if rule.kind == "equals":
        left = _string_at(document, rule.path)
        right = rule.value if rule.other is None else _string_at(document, rule.other)
        if left is MISSING or right is MISSING:
            return True
        return left is not None and left == right
    if not isinstance(document, Mapping):
        return False  # an element of each that is not an object, where a dotted field needs one
    if rule.kind == "required_fields":
        return all(dig(document, name) not in (MISSING, None) for name in rule.fields)
    if rule.kind == "relationship":
        left, right = dig(document, rule.left), dig(document, rule.right)
        if left is MISSING or right is MISSING:
            return True
        return _is_number(left) and _is_number(right) and _compare(left, rule.op, right)
    value = dig(document, rule.field)
    if value is MISSING:
        return True
    if rule.kind == "unit":
        return value in rule.allowed
    if rule.kind == "range":
        if not _is_number(value):
            return False
        return (rule.min is None or value >= rule.min) and (rule.max is None or value <= rule.max)
    if rule.max_age_days is None:
        return True
    try:
        updated = parse_stamp(str(value))
    except ValueError:
        return False
    # The limit is inclusive: an age of exactly max_age_days passes. An update time after the
    # evaluation time is not a real last update, as for the trust status snapshot (integrity.py).
    return timedelta(0) <= now - updated <= timedelta(days=rule.max_age_days)


def _rule_packs(ctx: CheckContext, params: RulesParams) -> list[RulePack] | CheckOutcome:
    """The rule pack of the parameter, or else the rule packs of the profile."""
    paths = (params.rule_pack,) if params.rule_pack is not None else ctx.profile.rule_packs
    if not paths:
        return blocked("DATA.RULES.MISSING", "The profile names no rule pack.")
    try:
        parameter = params.rule_pack is not None
        return [load_model(_pinned_path(ctx, path, parameter=parameter), RulePack) for path in paths]
    except (CatalogueError, ValidationError):
        return blocked("DATA.RULES.MISSING", "A pinned rule pack cannot be read or is not valid.")


@register("data.rules", capability="data.rules", params=RulesParams)
def rules_check(ctx: CheckContext) -> CheckOutcome:  # noqa: PLR0912 - one exit per outcome of the check
    params = _params(ctx, RulesParams)
    if isinstance(params, CheckOutcome):
        return params
    kind = params.document
    packs = _rule_packs(ctx, params)
    if isinstance(packs, CheckOutcome):
        return packs
    # Exact decimals: a third-party passport may hold 97.5, and a binary float would make close
    # values equal. The summary below holds rule ids only, so no Decimal reaches the decision body.
    got = _documents(ctx, params, decimals=True)
    if isinstance(got, CheckOutcome):
        return got
    facts = facts_from(ctx.ics, ctx.profile)
    failed: list[Rule] = []
    limited: list[Rule] = []
    applied = 0
    for rule in (r for pack in packs for r in pack.rules if r.document == kind):
        if rule.when is not None:
            try:
                applies = evaluate(rule.when, facts).value
            except ApplicabilityError:
                return blocked(
                    "DATA.RULES.MISSING", f"The condition of rule {rule.id} does not fit the declared facts."
                )
            if applies is Tri.UNKNOWN:
                message = f"The applicability of rule {rule.id} is unknown. Unknown is not treated as false."
                return blocked("DATA.RULES.APPLICABILITY_UNKNOWN", message)
            if applies is Tri.FALSE:
                continue
        applied += 1
        # A rule fails if any embedded document breaks it. A fail found before the budget ends counts.
        # The documents of an HTML page share the budget of the rule, so many scripts cannot multiply it.
        budget = PatternBudget()
        if not all(rule_holds(rule, document, ctx.evaluation_time, budget) for document in got.documents):
            failed.append(rule)
        elif budget.limited:
            limited.append(rule)
    summary: dict[str, JsonValue] = {
        "document": kind,
        "rule_packs": [f"{p.rulepack_id} {p.version}" for p in packs],
        "rules_applied": applied,
        "failed_rules": [r.id for r in failed],
        "failed_engineering_rules": [r.id for r in failed if r.basis.basis_class == "engineering"],
    }
    observation = got.observation(ctx, summary)
    if not applied:
        # No rule judged the document, so a pass would claim what was never checked.
        return blocked(
            "DATA.RULES.NONE_APPLIED",
            f"No rule of the pinned rule packs applies to the {kind}-level document.",
        )
    if not failed and limited:
        # A limit never hides a fail: it applies only when no rule failed.
        message = (
            f"The pattern work of these rules on the answer exceeds {MAX_PATTERN_WORK} units each, so "
            f"they are not judged: {', '.join(r.id for r in limited)}."
        )
        return CheckOutcome(
            status=ExecutionStatus.BLOCKED,
            reason_code="DATA.RULES.WORK_LIMIT",
            message=message,
            observations=(observation,),
        )
    if not failed:
        return completed(
            True, "DATA.RULES.OK", f"The document obeys the {applied} rules that apply.", [observation]
        )
    kinds = {r.rule.kind if r.rule else r.kind for r in failed}  # each gives the code of its rule
    code = next(code for name, code in _PRECEDENCE if name in kinds)
    return completed(
        False,
        code,
        f"{len(failed)} of {applied} rules failed: {', '.join(r.id for r in failed)}.",
        [observation],
    )
