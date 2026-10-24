"""Persistence, registry, and Asset Administration Shell adapters.

Each of these checks states a limit that its verdict must not hide:

- A few observations cannot prove that a passport stays available for the life of a product.
  Changed content is not by itself unlawful: the check compares with the declared update rule.
- A failed or unauthorized registry lookup does not prove that a registration is missing.
- A valid Asset Administration Shell is not a complete DPP conformance statement.
"""

from __future__ import annotations

import re
import zipfile
import zlib
from datetime import datetime
from io import BytesIO
from itertools import pairwise
from typing import Any, Literal
from xml.etree import ElementTree
from xml.parsers import expat

from pydantic import Field

from dppce.adapters.common import (
    MISSING,
    blocked,
    completed,
    dig,
    fetch_once,
    json_object,
    not_200,
    not_done,
    resource_url,
    same_json,
    unusable,
)
from dppce.evidence.canonical import CanonicalizationError, digest, parse_strict
from dppce.infrastructure.clock import parse_instant
from dppce.models import CheckOutcome, ExecutionStatus, Model
from dppce.testdefs.registry import CheckContext, register


@register("persistence.versions", capability="persistence.versions")
def versions(ctx: CheckContext) -> CheckOutcome:
    versions_url = resource_url(ctx, "versions", "PERSISTENCE")
    if isinstance(versions_url, CheckOutcome):
        return versions_url
    item_url = resource_url(ctx, "item", "PERSISTENCE")
    if isinstance(item_url, CheckOutcome):
        return item_url
    history, item = fetch_once(ctx, versions_url), fetch_once(ctx, item_url)
    for record in (history, item):
        if (
            problem := unusable(ctx, record) or not_200(ctx, "PERSISTENCE", record, [history, item])
        ) is not None:
            return problem
    listing, current = json_object(history), json_object(item)
    entries = listing.get("versions") if listing else None
    if not isinstance(entries, list) or not entries or current is None:
        observation = ctx.observation(
            0, kind="exchange", records=[history, item], summary={"status": history.status}
        )
        return completed(
            False, "PERSISTENCE.RESPONSE.NOT_JSON", "The version history is not usable JSON.", [observation]
        )
    problems: list[str] = []
    numbers = [e["version"] for e in entries if isinstance(e, dict) and type(e.get("version")) is int]
    if len(numbers) != len(entries) or any(a >= b for a, b in pairwise(numbers)):
        problems.append("version numbers do not strictly ascend")
    # Instants, not text: an offset or a fraction changes the text order.
    stamps = [_instant(e.get("updated_at") if isinstance(e, dict) else None) for e in entries]
    known = [stamp for stamp in stamps if stamp is not None]
    if len(known) != len(stamps):
        problems.append("an update time is missing or is not an RFC 3339 date-time with an offset")
    elif any(a > b for a, b in pairwise(known)):
        problems.append("an update time goes back")
    last = entries[-1].get("content_digest") if isinstance(entries[-1], dict) else None
    try:
        current_digest: str | None = digest(current)
    except CanonicalizationError:
        current_digest = None
    if current_digest is not None and last != current_digest:
        problems.append("the last digest is not the digest of the current passport")
    summary: dict[str, Any] = {"entries": len(entries), "problems": problems}
    observation = ctx.observation(0, kind="exchange", records=[history, item], summary=summary)
    limit = "A few observations cannot prove lifetime availability."
    if problems:
        message = f"The history breaks the declared update rule: {'; '.join(problems)}. {limit}"
        return completed(False, "PERSISTENCE.UNDECLARED_CHANGE", message, [observation])
    if current_digest is None:
        # The passport holds a number outside the canonical range, so its digest cannot be compared.
        message = "The current passport has no canonical form, so the engine cannot compare its digest."
        return blocked("PERSISTENCE.DIGEST.NOT_COMPARABLE", message)
    return completed(
        True, "PERSISTENCE.OK", f"The version history obeys the declared update rule. {limit}", [observation]
    )


def _instant(value: Any) -> datetime | None:
    try:
        return parse_instant(value) if isinstance(value, str) else None
    except ValueError:
        return None


@register("registry.consistency", capability="registry.mock")
def registry_consistency(ctx: CheckContext) -> CheckOutcome:
    record_url = resource_url(ctx, "registry_record", "REGISTRY")
    if isinstance(record_url, CheckOutcome):
        return record_url
    item_url = resource_url(ctx, "item", "REGISTRY")
    if isinstance(item_url, CheckOutcome):
        return item_url
    lookup = fetch_once(ctx, record_url)
    if (problem := unusable(ctx, lookup)) is not None:
        return problem
    if lookup.status in (401, 403, 404):
        observation = ctx.observation(0, kind="exchange", records=[lookup], summary={"status": lookup.status})
        message = (
            f"The lookup answers {lookup.status}. A failed lookup does not prove a missing registration."
        )
        return completed(False, "REGISTRY.LOOKUP.NOT_CONCLUSIVE", message, [observation], no_answer=True)
    item = fetch_once(ctx, item_url)
    if (problem := unusable(ctx, item)) is not None:
        return problem
    for record in (lookup, item):
        if (problem := not_200(ctx, "REGISTRY", record, [lookup, item])) is not None:
            return problem
    entry, passport = json_object(lookup), json_object(item)
    if entry is None or passport is None:
        observation = ctx.observation(
            0, kind="exchange", records=[lookup, item], summary={"status": lookup.status}
        )
        return completed(
            False,
            "REGISTRY.RESPONSE.NOT_JSON",
            "The registry record or the passport is not usable JSON.",
            [observation],
        )
    pairs = {
        "identifier": (entry.get("identifier", MISSING), dig(passport, "id")),
        "operator_identifier": (
            entry.get("operator_identifier", MISSING),
            dig(passport, "operator.identifier"),
        ),
    }
    # A field absent on either side was not compared, so it cannot agree (rule 7).
    missing = sorted(name for name, pair in pairs.items() if MISSING in pair or None in pair)
    compared = sorted(set(pairs) - set(missing))
    # JSON values, not Python equality: true is not 1.
    different = [name for name in compared if not same_json(*pairs[name])]
    summary = {"compared": compared, "different": different, "missing": missing}
    observation = ctx.observation(0, kind="exchange", records=[lookup, item], summary=summary)
    if different:
        message = f"The registry record differs from the passport in: {', '.join(different)}."
        return completed(False, "REGISTRY.INCONSISTENT", message, [observation])
    if missing:
        message = f"The registry record or the passport has no value for: {', '.join(missing)}."
        return completed(False, "REGISTRY.FIELD.MISSING", message, [observation])
    return completed(
        True,
        "REGISTRY.OK",
        "The registry record agrees with the passport. This was a passive lookup.",
        [observation],
    )


_AAS_FORMATS = ("json", "xml", "aasx")
_AAS_VERSION = re.compile(r"[0-9]+\.[0-9]+")
# The metamodel version that an AAS XML namespace names, for example https://admin-shell.io/aas/3/0.
_AAS_NAMESPACE = re.compile(r"\{https://admin-shell\.io/aas/([0-9]+)/([0-9]+)\}")
_AAS_LIMIT = "A valid Asset Administration Shell is not a complete DPP conformance statement."
# ponytail: fixed caps. A sample above them is an AAS.INVALID fail; raise them if a real package needs it.
_AASX_MAX_MEMBERS = 1_000
_AASX_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_AASX_MAX_RATIO = 100


class AasParams(Model):
    artifact: str = Field(
        default="aas_file", min_length=1, description="Name of the IXIT sample that holds the AAS file."
    )
    format: Literal["json", "xml", "aasx"] = Field(
        default="json", description="Serialization of the sample: json, xml, or an aasx package."
    )
    metamodel_version: str = Field(
        default="3.0",
        pattern=r"^[0-9]+\.[0-9]+$",
        description=(
            "AAS metamodel version that the sample claims. A version that the wrapped release does "
            "not verify gives unsupported, not a fail."
        ),
    )


class _NotReadableError(Exception):
    """The wrapped validator cannot read the sample as the declared format. The argument says why."""


class _VersionError(Exception):
    """The sample names a metamodel version that the wrapped validator does not verify."""


def _read_json(aas_file: Any, body: bytes, version: str, supported: list[str]) -> Any:
    try:
        # Strict: two parsers must not read one sample in two ways. CanonicalizationError is a ValueError.
        document = parse_strict(body)
    except ValueError:
        raise _NotReadableError("JSON, or it has a repeated key, NaN, or Infinity") from None
    return aas_file.check_json_data(document, version)


def _clark(name: str) -> str:
    # expat gives "namespace}local" with the chosen separator; ElementTree spells it "{namespace}local".
    return f"{{{name}" if "}" in name else name


def _parse_xml(body: bytes) -> ElementTree.Element:
    """Parse XML into an ElementTree, and refuse a document type declaration at the parser.

    An AAS serialization has no DTD. The parser refuses one before any entity is declared, whatever
    the encoding of the body, so entity expansion and external entities cannot reach it. defusedxml
    is not a dependency.
    """
    builder = ElementTree.TreeBuilder()
    parser = expat.ParserCreate(None, "}")
    parser.buffer_text = True

    def refuse(*_: object) -> None:
        raise _NotReadableError("XML without a document type declaration")

    parser.StartDoctypeDeclHandler = refuse
    parser.StartElementHandler = lambda name, attributes: builder.start(
        _clark(name), {_clark(k): v for k, v in attributes.items()}
    )
    parser.EndElementHandler = lambda name: builder.end(_clark(name))
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(body, True)
    except expat.ExpatError:
        raise _NotReadableError("well-formed XML") from None
    return builder.close()


def _gate_version(root: Any, supported: list[str]) -> Any:
    # An AAS namespace names its metamodel version; other XML (OPC parts) has no AAS namespace.
    namespace = _AAS_NAMESPACE.match(root.tag)
    if namespace is not None and (declared := f"{namespace[1]}.{namespace[2]}") not in supported:
        raise _VersionError(declared)
    return root


def _read_xml(aas_file: Any, body: bytes, version: str, supported: list[str]) -> Any:
    return aas_file.check_xml_data(_gate_version(_parse_xml(body), supported), version)


def _read_aasx(aas_file: Any, body: bytes, version: str, supported: list[str]) -> Any:
    try:
        package = zipfile.ZipFile(BytesIO(body))
    except zipfile.BadZipFile:
        raise _NotReadableError("a ZIP package") from None
    # The library reads every member it is pointed at. Bound the package before it does, so that a
    # compressed bomb or a DTD inside an XML part cannot reach the parser.
    members = package.infolist()
    if len(members) > _AASX_MAX_MEMBERS or any(
        m.file_size > _AASX_MAX_MEMBER_BYTES or m.file_size > _AASX_MAX_RATIO * max(m.compress_size, 1)
        for m in members
    ):
        raise _NotReadableError("an AASX package within the size limits of the check")
    # Each part goes through the engine's own parsers first: the library reads JSON parts with a
    # lenient parser, and two parsers must not read one sample in two ways.
    for member in members:
        name = member.filename.lower()
        try:
            if name.endswith((".xml", ".rels")):
                # The same version gate as a plain XML sample, so a 3.1 part is unsupported (rule 7).
                _gate_version(_parse_xml(package.read(member)), supported)
            elif name.endswith(".json"):
                try:
                    parse_strict(package.read(member))
                except ValueError:
                    raise _NotReadableError("JSON, or it has a repeated key, NaN, or Infinity") from None
        except _NotReadableError as problem:
            raise _NotReadableError(f"an AASX package whose part {member.filename} is {problem}") from None
        # A corrupt, encrypted, or unsupported member raises out of ZipFile.read. That is an
        # unreadable sample, not a crash (rule 7).
        except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError):
            raise _NotReadableError(f"an AASX package whose part {member.filename} can be read") from None
    result = aas_file.check_aasx_data(package, version)
    # The wrapped validator only warns about a package with no AAS part, so an empty package would pass.
    root = aas_file.Relationship("ROOT", "/")
    aas_file.read_opc(package, root, aas_file.AasTestResult("opc"), aas_file.DEPRECATED_TYPES)
    origins = root.sub_rels_by_type(aas_file.TYPE_AASX_ORIGIN)
    if not any(origin.sub_rels_by_type(aas_file.TYPE_AASX_SPEC) for origin in origins):
        raise _NotReadableError("an AASX package with an AAS specification part")
    return result


_READERS = {"json": _read_json, "xml": _read_xml, "aasx": _read_aasx}


@register("aas.validate", capability="aas.validate", params=AasParams)
def aas_validate(ctx: CheckContext) -> CheckOutcome:
    try:
        from aas_test_engines import file as aas_file  # noqa: PLC0415 - optional dependency of the `aas` extra
    except ImportError:
        message = "aas-test-engines is not installed. Install the 'aas' extra."
        return not_done(ExecutionStatus.UNSUPPORTED, "AAS.DEPENDENCY_MISSING", message)
    serialization = ctx.params.get("format", "json")
    version = ctx.params.get("metamodel_version", "3.0")
    if (
        serialization not in _AAS_FORMATS
        or not isinstance(version, str)
        or not _AAS_VERSION.fullmatch(version)
    ):
        message = "The parameters 'format' or 'metamodel_version' are not valid. Nothing is read."
        return blocked("AAS.PARAMS.INVALID", message)
    # The library accepts any version string and then checks nothing, so the gate is here (rule 7).
    supported = sorted(aas_file.supported_versions())
    covered = f"The wrapped validator verifies metamodel {', '.join(supported)} only"
    if version not in supported:
        message = f"{covered}, not {version}. The sample was not read."
        return not_done(ExecutionStatus.UNSUPPORTED, "AAS.VERSION.UNSUPPORTED", message)
    record = ctx.acquirer.artifact(str(ctx.params.get("artifact", "aas_file")))
    if record.error is not None:
        return blocked("AAS.SAMPLE.MISSING", "The Asset Administration Shell sample is not available.")
    summary: dict[str, Any] = {"format": str(serialization), "metamodel_version": version}
    try:
        valid = bool(_READERS[str(serialization)](aas_file, record.body, version, supported).ok())
    except _VersionError as declared:
        message = f"{covered}. The XML namespace of the sample names metamodel {declared}."
        return not_done(ExecutionStatus.UNSUPPORTED, "AAS.VERSION.UNSUPPORTED", message)
    except _NotReadableError as problem:
        observation = ctx.observation(
            0, kind="artifact", records=[record], summary={**summary, "readable": False}
        )
        return completed(False, "AAS.INVALID", f"The sample is not {problem}.", [observation])
    observation = ctx.observation(
        0,
        kind="artifact",
        records=[record],
        summary={**summary, "valid": valid},
        transformations=("aas_test_engines",),
    )
    limit = f"The check covers the {serialization} serialization of metamodel {version} only. {_AAS_LIMIT}"
    if not valid:
        return completed(
            False, "AAS.INVALID", f"The wrapped validator rejects the file. {limit}", [observation]
        )
    return completed(True, "AAS.VALID", f"The wrapped validator accepts the file. {limit}", [observation])
