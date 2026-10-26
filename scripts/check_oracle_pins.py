"""Check the pinned oracle files against catalogue/oracle-pins.yaml.

Usage: ``uv run python scripts/check_oracle_pins.py`` checks the SHA-256 of each file. It is
offline and runs in the fast tests. Exit status: 0 if every digest matches, 1 otherwise.

``--refresh`` is a maintainer step. It calls the GitHub CLI (``gh``) to fetch each file at its pinned
commit and at the default branch, then reports a changed pinned object and upstream drift. No
test runs it (CLAUDE.md, rule 3).
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "catalogue" / "oracle-pins.yaml"

Fetcher = Callable[[str, str, "str | None"], bytes]


def load_pins(path: Path) -> list[dict[str, Any]]:
    pins = yaml.safe_load(path.read_text(encoding="utf-8"))["pins"]
    return list(pins)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(pins: list[dict[str, Any]], root: Path) -> list[str]:
    problems = []
    for pin in pins:
        path = root / pin["path"]
        if not path.is_file():
            problems.append(f"{pin['id']}: {pin['path']} is missing")
        elif _digest(path.read_bytes()) != pin["sha256"]:
            problems.append(f"{pin['id']}: {pin['path']} does not match the pinned SHA-256")
    return problems


def gh_fetch(repo: str, path: str, ref: str | None) -> bytes:
    endpoint = f"repos/{repo}/contents/{path}" + (f"?ref={ref}" if ref else "")
    done = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        ["gh", "api", "-H", "Accept: application/vnd.github.raw", endpoint],  # noqa: S607 - gh from PATH
        capture_output=True,
        check=True,
    )
    return done.stdout


def refresh(pins: list[dict[str, Any]], fetch: Fetcher) -> list[str]:
    problems = []
    for pin in pins:
        if _digest(fetch(pin["repo"], pin["upstream_path"], pin["commit"])) != pin["sha256"]:
            problems.append(f"{pin['id']}: the object at the pinned commit differs from the pinned SHA-256")
        if _digest(fetch(pin["repo"], pin["upstream_path"], None)) != pin["sha256"]:
            problems.append(f"{pin['id']}: drift, the default branch of {pin['repo']} holds another file")
    return problems


def main(argv: list[str]) -> int:
    pins = load_pins(MANIFEST)
    problems = check(pins, ROOT)
    if "--refresh" in argv:
        try:
            problems += refresh(pins, gh_fetch)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"refresh failed: {exc}", file=sys.stderr)
            return 1
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"{len(pins)} pins; {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
