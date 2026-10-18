"""Load sources, requirement packs, profiles, test packs, and declarations from local files.

YAML is data. It is parsed with a safe loader, has a size limit, and may not repeat a key.
JSON is parsed with ``parse_strict``.
Nothing in a file is evaluated as code or as a template.
"""

from __future__ import annotations

import re
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from dppce.evidence.canonical import digest, parse_strict
from dppce.models import ICS, IXIT, Model, Profile, RequirementPack, SourceRecord, TestPack

MAX_FILE_BYTES = 5 * 1024 * 1024
REDACTED = "<redacted>"


class CatalogueError(ValueError):
    """A catalogue, profile, test pack, or declaration file is not valid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe loader that rejects a repeated mapping key instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError:
                raise yaml.constructor.ConstructorError(
                    None, None, "a mapping key must be a scalar", key_node.start_mark
                ) from None
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_data(path: Path) -> Any:
    """Parse one YAML or JSON file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CatalogueError(f"{path}: cannot read: {exc.strerror}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise CatalogueError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
    try:
        if path.suffix == ".json":
            # Strict: a repeated key, NaN, or Infinity is refused, as in every verified document.
            return parse_strict(raw)
        return yaml.load(raw, Loader=_UniqueKeyLoader)  # noqa: S506 - _UniqueKeyLoader extends SafeLoader
    # A nesting deeper than the parser handles is an input error, not a crash.
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        raise CatalogueError(f"{path}: not valid YAML or JSON: {exc}") from exc


def load_model[T: Model](path: Path, model: type[T]) -> T:
    """Parse one file and validate it against a contract."""
    try:
        return model.model_validate(load_data(path))
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        raise CatalogueError(f"{path}: {problems}") from exc


def _load_all[T: Model](paths: Sequence[Path], model: type[T], key: str) -> dict[str, T]:
    out: dict[str, T] = {}
    for path in sorted(paths):
        item = load_model(path, model)
        ident = str(getattr(item, key))
        if ident in out:
            raise CatalogueError(f"{path}: duplicate {key} '{ident}'")
        out[ident] = item
    return out


@dataclass(frozen=True)
class Catalogue:
    legal_as_of: str
    sources: tuple[SourceRecord, ...]
    packs: dict[str, RequirementPack]

    def sources_hash(self) -> str:
        return digest([s.model_dump(mode="json") for s in self.sources])

    def pack_hashes(self) -> dict[str, str]:
        return {pack_id: digest(pack) for pack_id, pack in sorted(self.packs.items())}

    def hash(self) -> str:
        return digest({"sources": self.sources_hash(), "packs": self.pack_hashes()})


def load_catalogue(root: Path, extra_packs: Sequence[Path] = ()) -> Catalogue:
    """Load ``root/catalogue``. ``extra_packs`` are imported packs; the shipped files stay unchanged."""
    document = load_data(root / "catalogue" / "sources.yaml")
    if not isinstance(document, dict) or document.get("schema_version") != "dppce.sources/1":
        raise CatalogueError(f"{root}/catalogue/sources.yaml: schema_version must be 'dppce.sources/1'")
    try:
        sources = tuple(SourceRecord.model_validate(s) for s in document.get("sources", []))
    except ValidationError as exc:
        raise CatalogueError(f"{root}/catalogue/sources.yaml: {exc}") from exc
    if len({s.id for s in sources}) != len(sources):
        raise CatalogueError(f"{root}/catalogue/sources.yaml: duplicate source id")
    shipped = sorted((root / "catalogue" / "packs").glob("*.yaml"))
    packs = _load_all([*shipped, *extra_packs], RequirementPack, "pack_id")
    return Catalogue(legal_as_of=str(document.get("legal_as_of", "")), sources=sources, packs=packs)


def load_profiles(root: Path) -> dict[str, Profile]:
    """Load ``root/profiles/<family>/<name>.yaml``. Deeper directories hold profile resources."""
    return _load_all(list((root / "profiles").glob("*/*.yaml")), Profile, "id")


def load_testpacks(root: Path, extra_testpacks: Sequence[Path] = ()) -> dict[str, TestPack]:
    """Load ``root/testpacks``. ``extra_testpacks`` are imported; the shipped files stay unchanged."""
    shipped = list((root / "testpacks").glob("*.yaml"))
    return _load_all([*shipped, *extra_testpacks], TestPack, "testpack_id")


def load_ics(path: Path) -> ICS:
    return load_model(path, ICS)


def load_ixit(path: Path) -> IXIT:
    return load_model(path, IXIT)


def sanitized_ixit(ixit: IXIT) -> dict[str, Any]:
    """Return the IXIT with every secret reference removed. This form is what gets hashed."""
    data = ixit.model_dump(mode="json")
    for identity in data["identities"]:
        if identity["secret_ref"] is not None:
            identity["secret_ref"] = REDACTED
    return data


_FACT_TYPES: dict[str, type] = {"integer": int, "string": str, "boolean": bool, "date": str}
# ASCII digits only. date.fromisoformat alone would also accept 20270301 and 2027-W09-1.
_CALENDAR_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _is_calendar_date(value: str) -> bool:
    if not _CALENDAR_DATE.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def check_ics(ics: ICS, profile: Profile) -> list[str]:
    """Return the problems that make an ICS unusable with a profile. Empty means usable."""
    problems: list[str] = []
    if ics.profile != profile.id:
        problems.append(f"The ICS names profile '{ics.profile}', not '{profile.id}'.")
    if ics.product_category not in ("unknown", profile.product_category):
        problems.append(
            f"The ICS product category '{ics.product_category}' is not '{profile.product_category}'."
        )
    for name, value in sorted(ics.characteristics.items()):
        spec = profile.facts.get(name)
        if spec is None:
            problems.append(f"The characteristic '{name}' is not a fact of profile '{profile.id}'.")
        elif value != "unknown" and type(value) is not _FACT_TYPES[spec.type]:
            problems.append(f"The characteristic '{name}' must be of type {spec.type}.")
        elif spec.type == "date" and value != "unknown" and not _is_calendar_date(str(value)):
            # The value is not repeated: the supplier of the system under test wrote it.
            problems.append(f"The characteristic '{name}' must be a calendar date written YYYY-MM-DD.")
    return problems
