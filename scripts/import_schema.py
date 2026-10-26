"""Bundle a published JSON Schema set into one file with local ``$ref`` values.

Usage: ``uv run python scripts/import_schema.py ROOT.json --out BUNDLE.json``

The script reads only local files. It never fetches a URL. Download the set first, pinned at a
commit (see docs/how-to/pin-an-oracle.md). Every file under the directory of ROOT.json is in the set.
A reference resolves by the ``$id`` of a file or by its path relative to the referring file.
The bundle keeps the ``$schema`` of the root and moves every other file into the definitions
keyword of that dialect. Exit status: 0 for success, 1 for an unresolved reference or a bad file.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urldefrag, urljoin

DRAFT_07 = "http://json-schema.org/draft-07/schema#"


_ANCHORS = {"$id", "$anchor", "$dynamicAnchor", "$dynamicRef", "$recursiveRef"}


class BundleError(Exception):
    pass


def _container(root: dict[str, Any]) -> str:
    # ponytail: draft-07 and 2020-12 only, the dialects that the engine validates.
    return "definitions" if str(root.get("$schema", "")).rstrip("#") == DRAFT_07.rstrip("#") else "$defs"


def _escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


class _Bundler:
    def __init__(self, root_path: Path) -> None:
        self.base = root_path.resolve().parent
        self.root_path = root_path.resolve()
        self.documents: dict[Path, Any] = {}
        self.ids: dict[str, Path] = {}
        for path in sorted(self.base.rglob("*.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise BundleError(f"cannot read {path}: {exc}") from exc
            self.documents[path] = document
            if isinstance(document, dict) and isinstance(document.get("$id"), str):
                self.ids[urldefrag(document["$id"])[0]] = path
        if self.root_path not in self.documents:
            raise BundleError(f"{root_path} is not a JSON file")
        root = self.documents[self.root_path]
        if not isinstance(root, dict):
            raise BundleError("the root schema is not an object")
        self.container = _container(root)
        self.names: dict[Path, str] = {}
        self.moved: dict[str, Any] = {}

    def _target(self, reference: str, origin: Path) -> Path | None:
        """The file that ``reference`` names, or None if the reference stays inside ``origin``."""
        address, _ = urldefrag(reference)
        if not address:
            return None
        origin_id = self.documents[origin].get("$id") if isinstance(self.documents[origin], dict) else None
        absolute = urljoin(origin_id, address) if isinstance(origin_id, str) else address
        if absolute in self.ids:
            return self.ids[absolute]
        if "://" not in address:
            candidate = (origin.parent / unquote(address)).resolve()
            if candidate in self.documents:
                return candidate
        raise BundleError(f"reference {reference!r} in {origin.name} is not in the set")

    def _name(self, path: Path) -> str:
        if path not in self.names:
            stem = path.relative_to(self.base).with_suffix("").as_posix().replace("/", "_")
            name, n = stem, 1
            while name in self.names.values():
                n += 1
                name = f"{stem}_{n}"
            self.names[path] = name
            # Reserve the name first so that a cycle finds it, then rewrite the body.
            self.moved[name] = None
            self.moved[name] = self._rewrite(copy.deepcopy(self.documents[path]), path)
        return self.names[path]

    def _rewrite(self, node: Any, origin: Path, *, top: bool = True) -> Any:
        if isinstance(node, list):
            return [self._rewrite(v, origin, top=False) for v in node]
        if not isinstance(node, dict):
            return node
        if top:
            for key in ("$schema", "$id"):
                node.pop(key, None)
        elif origin != self.root_path and _ANCHORS & node.keys():
            # The rewritten pointers assume one base per moved file.
            raise BundleError(f"a nested identifier or anchor in {origin.name} is not supported")
        out = {k: self._rewrite(v, origin, top=False) for k, v in node.items()}
        reference = out.get("$ref")
        if isinstance(reference, str):
            out["$ref"] = self._ref(reference, origin)
        return out

    def _ref(self, reference: str, origin: Path) -> str:
        target = self._target(reference, origin)
        _, fragment = urldefrag(reference)
        if fragment and not fragment.startswith("/"):
            raise BundleError(f"reference {reference!r} in {origin.name} has a plain-name fragment")
        if target is None:
            return self._local(fragment, origin)
        if target == self.root_path:
            return "#" + fragment
        return f"#/{self.container}/{_escape(self._name(target))}" + fragment

    def _local(self, fragment: str, origin: Path) -> str:
        if origin == self.root_path or not fragment:
            return "#" + fragment
        return f"#/{self.container}/{_escape(self._name(origin))}" + fragment

    def run(self) -> dict[str, Any]:
        root = copy.deepcopy(self.documents[self.root_path])
        out = self._rewrite(root, self.root_path, top=False)
        if self.moved:
            holder = out.setdefault(self.container, {})
            for name, body in sorted(self.moved.items()):
                if name in holder:
                    raise BundleError(f"the root already defines {name!r} in {self.container}")
                holder[name] = body
        return out  # type: ignore[no-any-return]  # a dict by the check in __init__


def bundle(root: Path) -> dict[str, Any]:
    return _Bundler(root).run()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("root", type=Path, help="the root schema file; its directory holds the whole set")
    parser.add_argument("--out", type=Path, required=True, help="the bundle file to write")
    args = parser.parse_args(argv)
    try:
        result = bundle(args.root)
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
