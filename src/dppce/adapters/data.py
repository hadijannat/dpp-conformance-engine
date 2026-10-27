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
    not_200,
    resource_url,
    schema_errors,
    unassertable_formats,
    unusable,
    validator,
)
from dppce.adapters.jose import JoseParams, _Finding, _judge, finding_of
from dppce.applicability import ApplicabilityError, evaluate, facts_from
from dppce.catalogue import CatalogueError, load_data, load_model
from dppce.evidence.canonical import CanonicalizationError, parse_strict
from dppce.evidence.jose_profiles import JoseError
from dppce.evidence.manual import SAMPLE_PREFIX
from dppce.infrastructure.clock import parse_stamp
from dppce.infrastructure.interfaces import Record
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
FILE_PARAMS: Final = {"data.jsonschema": "schema", "data.rules": "rule_pack"}
# When more than one rule fails, the first kind in this order names the reason code.
_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("required_fields", "DATA.COMPLETENESS.MISSING"),
    ("unit", "DATA.UNIT.INVALID"),
    ("range", "DATA.RANGE.VIOLATED"),
    ("relationship", "DATA.RELATIONSHIP.VIOLATED"),
    ("freshness", "DATA.FRESHNESS.STALE"),
)


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


class Rule(Model):
    id: str
    kind: Literal["required_fields", "unit", "range", "relationship", "freshness"]
    document: DocumentKind
    basis: Basis
    when: Expr | None = None
    fields: tuple[str, ...] = ()
    field: str = ""
    allowed: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    left: str = ""
    op: Literal["lt", "le", "eq", "ge", "gt"] = "le"
    right: str = ""
    max_age_days: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _judges_something(self) -> Self:
        # A rule without the fields of its kind always holds. It would count as applied and pass.
        needed: dict[str, bool] = {
            "required_fields": bool(self.fields) and all(self.fields),
            "unit": bool(self.field and self.allowed),
            "range": bool(self.field) and (self.min is not None or self.max is not None),
            "relationship": bool(self.left and self.right),
            "freshness": bool(self.field) and self.max_age_days is not None,
        }
        if not needed[self.kind]:
            raise ValueError(f"a {self.kind} rule needs the fields of its kind")
        return self


class RulePack(Model):
    schema_version: Literal["dppce.rulepack/1"]
    rulepack_id: str
    version: str
    rules: tuple[Rule, ...]


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
    try:
        return (value,) if isinstance(value, str) and _relative_file(value) else ()
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


def _contexts(document: dict[str, Any], allowed: list[Any]) -> tuple[int, set[str]]:
    """(top-level context entries, context references outside the allowlist) of one document."""
    declared = document.get("@context")
    entries = declared if isinstance(declared, list) else [declared] if declared is not None else []
    # A JSON-LD processor also reads a scoped @context in any nested node, so each one counts.
    # A work list, not recursion: a deeply nested document must not stop the check.
    every: list[Any] = []
    pending: list[Any] = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            value = node.get("@context")
            if value is not None:
                every.extend(value if isinstance(value, list) else [value])
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    # An inline context object is not a pinned reference, so it is never in the allowlist.
    return len(entries), {
        str(e) if isinstance(e, str) else "<inline context>" for e in every if e not in allowed
    }


@register("data.context", capability="data.context", params=ContextParams)
def context_check(ctx: CheckContext) -> CheckOutcome:
    allowed = ctx.params.get("allowed_contexts")
    if not isinstance(allowed, list) or not allowed:
        return blocked("DATA.CONTEXT.NO_ALLOWLIST", "The test purpose gives no allowlist of contexts.")
    params = _params(ctx, ContextParams)
    if isinstance(params, CheckOutcome):
        return params
    got = _documents(ctx, params)
    if isinstance(got, CheckOutcome):
        return got
    counted = [_contexts(document, allowed) for document in got.documents]
    foreign = sorted(set().union(*(found for _, found in counted)))
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


def rule_holds(rule: Rule, document: dict[str, Any], now: datetime) -> bool:
    """True if the document obeys the rule. Only ``required_fields`` judges an absent field."""
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
def rules_check(ctx: CheckContext) -> CheckOutcome:
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
        # A rule fails if any embedded document breaks it.
        if not all(rule_holds(rule, document, ctx.evaluation_time) for document in got.documents):
            failed.append(rule)
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
    if not failed:
        return completed(
            True, "DATA.RULES.OK", f"The document obeys the {applied} rules that apply.", [observation]
        )
    kinds = {r.kind for r in failed}
    code = next(code for name, code in _PRECEDENCE if name in kinds)
    return completed(
        False,
        code,
        f"{len(failed)} of {applied} rules failed: {', '.join(r.id for r in failed)}.",
        [observation],
    )
