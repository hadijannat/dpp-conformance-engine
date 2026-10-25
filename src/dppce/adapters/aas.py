"""Asset Administration Shell file adapters.

A valid Asset Administration Shell is not a complete DPP conformance statement.
"""

from __future__ import annotations

import re
import zipfile
import zlib
from io import BytesIO
from typing import Any, Literal
from xml.etree import ElementTree
from xml.parsers import expat

from pydantic import Field

from dppce.adapters.common import blocked, completed, not_done
from dppce.evidence.canonical import parse_strict
from dppce.models import CheckOutcome, ExecutionStatus, Model
from dppce.testdefs.registry import CheckContext, register

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
