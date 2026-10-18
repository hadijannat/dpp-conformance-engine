"""Static checks of the catalogue, the profiles, and the test packs, and the trace matrix.

The lint protects the governance rules that a schema cannot express: protected standards stay
placeholders, an agent cannot approve, a standard is never presented as a legal obligation,
and every requirement traces to a source and to its tests in both directions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from dppce.applicability import fact_paths
from dppce.catalogue.loader import Catalogue
from dppce.models import (
    AuthorityClass,
    Compare,
    Expr,
    JsonValue,
    Model,
    Op,
    Profile,
    Requirement,
    ReviewStatus,
    SourceRecord,
    TestPack,
    TestPurpose,
)
from dppce.models.expr import All, AnyOf, Const, Not

_PROTECTED = ("european_standard", "international_standard", "national_standard")
_UNVERIFIED = ("secondary_only", "not_located", "unverified_recall")
_ORDERING = (Op.GT, Op.GE, Op.LT, Op.LE)
_INTERPRETED = (ReviewStatus.DRAFT, ReviewStatus.APPROVED)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Literal["error", "warning", "info"]
    location: str
    message: str


@dataclass(frozen=True)
class TraceRow:
    """One line of the trace: source provision to requirement to test purpose to check."""

    source_id: str
    citation: str
    source_version: str
    requirement_id: str
    pack_id: str
    authority_class: str
    review_status: str
    interpretations: tuple[str, ...]
    path_id: str
    test_purpose_id: str
    check: str


def _comparisons(expr: Expr) -> list[Compare]:
    if isinstance(expr, Compare):
        return [expr]
    if isinstance(expr, Not):
        return _comparisons(expr.operand)
    if isinstance(expr, All):
        return [c for part in expr.all for c in _comparisons(part)]
    if isinstance(expr, AnyOf):
        return [c for part in expr.any for c in _comparisons(part)]
    return []


def _expressions(requirement: Requirement) -> list[Expr]:
    out = [requirement.applicability]
    if requirement.declared_support is not None:
        out.append(requirement.declared_support)
    out.extend(p.applicability for p in requirement.assessment_paths if p.applicability is not None)
    return out


_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _fits(operand: object, fact_type: str) -> bool:
    """True if a literal operand can be compared with a fact of the declared type."""
    if fact_type == "integer":
        return type(operand) is int  # bool is a subclass of int, and true never equals 1
    if fact_type == "boolean":
        return type(operand) is bool
    if fact_type == "date":
        return isinstance(operand, str) and bool(_ISO_DATE.match(operand))
    return isinstance(operand, str)


def _operand_problem(comparison: Compare, name: str, fact_type: str) -> str | None:
    """Return why the operand of a comparison does not fit the fact, or None if it fits.

    The evaluator raises on such a pair. The lint finds it before a run does.
    """
    if comparison.op is Op.CONTAINS:
        return f"The fact '{name}' is a scalar. The operator 'contains' needs a list-valued fact."
    operands = comparison.value if isinstance(comparison.value, tuple) else (comparison.value,)
    if comparison.op in (Op.IN, Op.NOT_IN) and not isinstance(comparison.value, tuple):
        return f"The operator '{comparison.op.value}' needs a list operand."
    if comparison.op not in (Op.IN, Op.NOT_IN) and isinstance(comparison.value, tuple):
        return f"The operator '{comparison.op.value}' needs a single operand."
    bad = [repr(o) for o in operands if not _fits(o, fact_type)]
    if bad:
        return f"The operand {', '.join(bad)} does not fit the fact '{name}' of type {fact_type}."
    return None


def _fact_findings(expr: Expr, where: str, profiles: list[Profile]) -> list[Finding]:
    """CAT013: a fact that no selecting profile can supply, or an ordering on a wrong type."""
    found: list[Finding] = []
    for path in sorted(set(fact_paths(expr))):
        if not path.startswith(("ics.", "profile.")):
            found.append(
                Finding("CAT013", "error", where, f"The fact '{path}' is not under 'ics.' or 'profile.'.")
            )
    for comparison in _comparisons(expr):
        head, _, name = comparison.fact.rpartition(".")
        for profile in profiles:
            if head == "ics.characteristics":
                spec = profile.facts.get(name)
                if spec is None:
                    message = f"Profile '{profile.id}' does not declare the fact '{name}'."
                    found.append(Finding("CAT013", "error", where, message))
                elif comparison.op in _ORDERING and spec.type not in ("integer", "date"):
                    message = f"The fact '{name}' has type {spec.type}. Ordering needs an integer or a date."
                    found.append(Finding("CAT013", "error", where, message))
                elif (problem := _operand_problem(comparison, name, spec.type)) is not None:
                    found.append(Finding("CAT013", "error", where, problem))
            elif (
                head == "profile" and name not in ("id", "product_category") and name not in profile.constants
            ):
                message = f"Profile '{profile.id}' has no constant '{name}'."
                found.append(Finding("CAT013", "error", where, message))
    return found


def params_problem(model: type[Model], params: Mapping[str, JsonValue]) -> str | None:
    """Return why the parameters do not fit the model of a check, on one line, or None if they fit.

    A key name can come from a third-party test pack, so ascii() escapes it: a key with a line
    break cannot forge a line of output. The pydantic message does not repeat the input value.
    """
    try:
        model.model_validate(params)
    except ValidationError as exc:
        return "; ".join(
            f"{'.'.join(ascii(p) if isinstance(p, str) else str(p) for p in e['loc']) or 'value'}: {e['msg']}"
            for e in exc.errors()
        )
    return None


# Version tokens. The lookarounds keep a match from starting or ending inside a longer digit run,
# so a document number such as 15459 or 1781 is not a token.
_ISO_TOKEN = re.compile(r"(?<![0-9])[0-9]{4}-[0-9]{2}-[0-9]{2}(?![0-9])")
_DOTTED_TOKEN = re.compile(r"(?<![0-9.])[0-9]+(?:\.[0-9]+)+(?![0-9])")
_YEAR_TOKEN = re.compile(r"(?<![0-9])(?:19|20)[0-9]{2}(?![0-9])")
_EIGHT_DIGITS = re.compile(r"(?<![0-9])[0-9]{8}(?![0-9])")
_DAY_MONTH_YEAR = re.compile(r"(?<![0-9])[0-9]{1,2}\.[0-9]{1,2}\.((?:19|20)[0-9]{2})(?![0-9])")
_ISO_FORM = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _version_tokens(text: str) -> set[str]:
    tokens = {
        *_ISO_TOKEN.findall(text),
        *_DOTTED_TOKEN.findall(text),
        *_YEAR_TOKEN.findall(text),
        *_DAY_MONTH_YEAR.findall(text),
    }
    for eight in _EIGHT_DIGITS.findall(text):
        iso = f"{eight[:4]}-{eight[4:6]}-{eight[6:]}"
        try:
            date.fromisoformat(iso)
        except ValueError:
            continue
        tokens |= {iso, eight[:4]}
    return tokens


def _version_findings(requirement: Requirement, source: SourceRecord, where: str) -> list[Finding]:
    """CAT020 and CAT021: compare the cited version with the source record. Text only.

    The rules do not show that a cited version is the correct one. A structured version key
    per source (D2-04) would replace this heuristic.
    """
    if requirement.authority_class is AuthorityClass.ILLUSTRATIVE:
        return []
    found: list[Finding] = []
    version = requirement.source.version
    cited, record = _version_tokens(version), _version_tokens(source.edition_or_version)
    if record and not cited & record:
        message = (
            f"The cited version {version!a} shares no version token with the source record '{source.id}'."
        )
        found.append(Finding("CAT020", "error", where, message))
    latest = max((t for t in cited if _ISO_FORM.fullmatch(t)), default=None)
    if latest is not None:
        later = sorted(t for t in record if _ISO_FORM.fullmatch(t) and t > latest)
        later += [
            a.identifier for a in source.amendment_history if _ISO_FORM.fullmatch(a.date) and a.date > latest
        ]
        if later:
            message = (
                f"The source record '{source.id}' shows a later version or amendment than the cited "
                f"version: {', '.join(later)}."
            )
            found.append(Finding("CAT021", "warning", where, message))
    return found


def _date_literals(expr: Expr) -> list[str]:
    operands = [
        o for c in _comparisons(expr) for o in (c.value if isinstance(c.value, tuple) else (c.value,))
    ]
    # The CAT013 selector: any literal that the evaluator treats as a date, including full-width
    # digits and a trailing newline, so each one must be a recorded date.
    return [o for o in operands if isinstance(o, str) and _ISO_DATE.match(o)]


def _legal_date_findings(requirement: Requirement, source: SourceRecord, where: str) -> list[Finding]:
    """CAT022: a date literal of a legal obligation is a date that its source record lists."""
    if requirement.authority_class is not AuthorityClass.LEGAL_OBLIGATION:
        return []
    recorded = {d.date for d in source.applicable_dates}
    literals = {literal for expr in _expressions(requirement) for literal in _date_literals(expr)}
    return [
        Finding(
            "CAT022",
            "error",
            where,
            f"The date {literal!a} is not in applicable_dates of the source '{source.id}'.",
        )
        for literal in sorted(literals - recorded)
    ]


def lint(  # noqa: PLR0912, PLR0915 - a flat list of independent rules, one block for each rule
    catalogue: Catalogue,
    profiles: Mapping[str, Profile],
    testpacks: Mapping[str, TestPack],
    known_checks: Mapping[str, type[Model]],
    data_root: Path | None = None,
) -> list[Finding]:
    """Return every finding, sorted. An empty list means the catalogue is clean."""
    out: list[Finding] = []
    sources = {s.id: s for s in catalogue.sources}
    purposes: dict[str, TestPurpose] = {}
    for testpack_id, testpack in sorted(testpacks.items()):
        for candidate in testpack.test_purposes:
            if candidate.id in purposes:
                # The planner refuses a profile that selects both copies. Say so before a run.
                message = "Defined in more than one test pack. An identifier names one test purpose."
                out.append(Finding("CAT016", "error", f"{testpack_id}/{candidate.id}", message))
            purposes.setdefault(candidate.id, candidate)
    owners: dict[str, str] = {}
    requirements: dict[str, Requirement] = {}
    for pack_id, pack in sorted(catalogue.packs.items()):
        for requirement in pack.requirements:
            if requirement.id in owners:
                message = f"Also defined in pack '{owners[requirement.id]}'."
                out.append(Finding("CAT002", "error", f"{pack_id}/{requirement.id}", message))
            owners.setdefault(requirement.id, pack_id)
            requirements.setdefault(requirement.id, requirement)

    for requirement_id, requirement in sorted(requirements.items()):
        where = f"{owners[requirement_id]}/{requirement_id}"
        selecting = [p for p in profiles.values() if owners[requirement_id] in p.packs]
        source = sources.get(requirement.source.source_id)
        if source is None:
            message = f"The source '{requirement.source.source_id}' is not in sources.yaml."
            out.append(Finding("CAT001", "error", where, message))
        else:
            human = any(i.author_kind == "human" for i in requirement.interpretations)
            if source.source_type in _PROTECTED:
                if requirement.paraphrase and not human:
                    message = "A requirement from a protected standard has a paraphrase but no human author."
                    out.append(Finding("CAT007", "error", where, message))
                if requirement.review_status is ReviewStatus.PLACEHOLDER and requirement.source.citation:
                    message = "A placeholder for a protected standard must not state a clause."
                    out.append(Finding("CAT007", "error", where, message))
                if any(i.author_kind == "agent" for i in requirement.interpretations):
                    message = "An agent must not write an interpretation of a protected standard."
                    out.append(Finding("CAT007", "error", where, message))
            legal = requirement.authority_class is AuthorityClass.LEGAL_OBLIGATION
            if legal and not source.source_type.startswith("eu_"):
                message = f"A legal obligation cannot rest on a source of type '{source.source_type}'."
                out.append(Finding("CAT009", "error", where, message))
            if requirement.review_status in _INTERPRETED and source.verification_level in _UNVERIFIED:
                message = f"The source verification level is only '{source.verification_level}'."
                out.append(Finding("CAT011", "warning", where, message))
            out.extend(_version_findings(requirement, source, where))
            out.extend(_legal_date_findings(requirement, source, where))
        for interpretation in requirement.interpretations:
            if interpretation.author_kind == "agent" and interpretation.status is ReviewStatus.APPROVED:
                message = f"Interpretation '{interpretation.id}' is agent-authored and marked approved."
                out.append(Finding("CAT008", "error", where, message))
            if interpretation.unresolved:
                count = len(interpretation.unresolved)
                message = f"Interpretation '{interpretation.id}' has {count} unresolved points."
                out.append(Finding("CAT012", "info", where, message))
        for other in (
            *requirement.supersedes,
            *([requirement.superseded_by] if requirement.superseded_by else []),
        ):
            if other not in requirements:
                out.append(
                    Finding("CAT010", "error", where, f"Supersession names unknown requirement '{other}'.")
                )
        # A stale entry that stays "approved" would be assessed next to its successor, and in
        # reviewed mode it could be the only one. A draft can stay: an imported approved entry
        # supersedes a shipped draft, and no mode gives that draft a reviewed claim.
        if requirement.superseded_by and requirement.review_status is not ReviewStatus.SUPERSEDED:
            message = "The entry names a successor, so its status must be 'superseded'."
            out.append(Finding("CAT010", "error", where, message))
        for other in requirement.supersedes:
            old = requirements.get(other)
            if old is not None and old.review_status is ReviewStatus.APPROVED:
                message = f"The entry supersedes '{other}', which is still 'approved'."
                out.append(Finding("CAT010", "error", where, message))
        for expr in _expressions(requirement):
            out.extend(_fact_findings(expr, where, selecting))
        mapped = [t for path in requirement.assessment_paths for t in path.tests]
        if not mapped and requirement.review_status in _INTERPRETED:
            out.append(
                Finding(
                    "CAT015", "info", where, "No test purpose is mapped. The verdict will be inconclusive."
                )
            )
        for test_id in mapped:
            purpose = purposes.get(test_id)
            if purpose is None:
                out.append(Finding("CAT003", "error", where, f"The test purpose '{test_id}' is not defined."))
            elif requirement_id not in purpose.requirements:
                message = (
                    f"The test purpose '{test_id}' does not list this requirement. The trace is one-way."
                )
                out.append(Finding("CAT005", "warning", where, message))

    for test_id, purpose in sorted(purposes.items()):
        for requirement_id in purpose.requirements:
            target = requirements.get(requirement_id)
            if target is None:
                message = f"The requirement '{requirement_id}' is not defined."
                out.append(Finding("CAT004", "error", test_id, message))
            elif test_id not in [t for path in target.assessment_paths for t in path.tests]:
                message = (
                    f"Requirement '{requirement_id}' does not list this test purpose. The trace is one-way."
                )
                out.append(Finding("CAT005", "warning", test_id, message))
        if not purpose.manual and purpose.stimulus.check not in known_checks:
            message = (
                f"The check '{purpose.stimulus.check}' is not registered. The step will be 'unsupported'."
            )
            out.append(Finding("CAT006", "warning", test_id, message))
        model = known_checks.get(purpose.stimulus.check)
        if model is not None and (problem := params_problem(model, purpose.stimulus.params)) is not None:
            message = f"The parameters do not fit the check '{purpose.stimulus.check}': {problem}"
            out.append(Finding("CAT019", "error", test_id, message))
        out.extend(_fact_findings(purpose.applicability, test_id, list(profiles.values())))
        if purpose.verdict_rules.on_unreachable == "fail":
            named = [requirements[r] for r in purpose.requirements if r in requirements]
            if not named or any(
                r.review_status is not ReviewStatus.APPROVED
                or r.authority_class is AuthorityClass.ILLUSTRATIVE
                for r in named
            ):
                message = (
                    "Only an approved test method may call an unreachable system a failure. "
                    "A requirement of this test purpose is not approved."
                )
                out.append(Finding("CAT017", "error", test_id, message))
        if not isinstance(purpose.applicability, Const) and _can_leave_a_passable_path(
            test_id, requirements, purposes
        ):
            # The ICS decides such an expression, and the supplier of the system writes the ICS.
            message = (
                "A step with an applicability that reads a fact can leave its path, and the "
                "automated steps that remain can then pass alone."
            )
            out.append(Finding("CAT018", "warning", test_id, message))

    for profile_id, profile in sorted(profiles.items()):
        for name in profile.packs:
            if name not in catalogue.packs:
                out.append(
                    Finding("CAT014", "error", profile_id, f"The requirement pack '{name}' is not found.")
                )
        for name in profile.testpacks:
            if name not in testpacks:
                out.append(Finding("CAT014", "error", profile_id, f"The test pack '{name}' is not found."))
        if data_root is not None:
            resources = (
                profile.item_schema,
                profile.model_schema,
                profile.api_contract,
                profile.access_policy,
            )
            for resource in (*resources, *profile.rule_packs):
                if resource and not (data_root / resource).is_file():
                    out.append(
                        Finding("CAT014", "error", profile_id, f"The resource '{resource}' is not found.")
                    )

    return sorted(
        out, key=lambda f: ({"error": 0, "warning": 1, "info": 2}[f.severity], f.code, f.location, f.message)
    )


def _can_leave_a_passable_path(
    test_id: str, requirements: Mapping[str, Requirement], purposes: Mapping[str, TestPurpose]
) -> bool:
    """True if some path lists ``test_id`` next to automated steps only.

    Without the step, such a path can still pass. A path that keeps a manual step cannot pass
    in this version, so the step leaving it changes no verdict.
    """
    for requirement in requirements.values():
        for path in requirement.assessment_paths:
            if test_id not in path.tests:
                continue
            others = [purposes.get(t) for t in path.tests if t != test_id]
            if others and all(p is not None and not p.manual for p in others):
                return True
    return False


def trace(catalogue: Catalogue, testpacks: Mapping[str, TestPack]) -> list[TraceRow]:
    """The trace from source provision to executable check. A requirement with no test gets one row."""
    purposes = {t.id: t for pack in testpacks.values() for t in pack.test_purposes}
    rows: list[TraceRow] = []
    for pack_id, pack in sorted(catalogue.packs.items()):
        for requirement in pack.requirements:
            steps = [(p.id, t) for p in requirement.assessment_paths for t in p.tests] or [("", "")]
            for path_id, test_id in steps:
                purpose = purposes.get(test_id)
                rows.append(
                    TraceRow(
                        source_id=requirement.source.source_id,
                        citation=requirement.source.citation,
                        source_version=requirement.source.version,
                        requirement_id=requirement.id,
                        pack_id=pack_id,
                        authority_class=requirement.authority_class.value,
                        review_status=requirement.review_status.value,
                        interpretations=tuple(i.id for i in requirement.interpretations),
                        path_id=path_id,
                        test_purpose_id=test_id,
                        check=purpose.stimulus.check if purpose else "",
                    )
                )
    return sorted(rows, key=lambda r: (r.requirement_id, r.path_id, r.test_purpose_id))
