"""Check that each commit of a pull request has a DCO sign-off.

Usage: ``python3 scripts/check_dco.py BASE_SHA HEAD_SHA`` in the repository. Both are full
40-character hashes. Standard library only, so CI runs it with the system Python.

A commit passes when it has a ``Signed-off-by`` trailer with its author's email address, or when
a self-signed sign-off commit in BASE..HEAD names its full hash in the line form of DCO.md.

Exit status: 0 when each commit has a sign-off; 1 when a commit has none (one
``DCO.SIGNOFF.MISSING <hash>`` line each); 2 on wrong input or a Git failure.
"""

from __future__ import annotations

import re
import subprocess
import sys

HASH = re.compile(r"^[0-9a-f]{40}$")
EMAIL = re.compile(r"<([^<>]+)>\s*$")
COVER = re.compile(r"^I, .+, hereby add my Signed-off-by to this commit: ([0-9a-f]{40})$", re.MULTILINE)
FORMAT = "%H%x1f%ae%x1f%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x1d)%x1f%B"


def fail(code: str, text: str) -> int:
    print(f"{code}: {text}", file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    # The hex rule also keeps option-like arguments away from git.
    if len(argv) != 2 or not all(HASH.match(arg) for arg in argv):
        return fail("DCO.INPUT.INVALID", "usage: check_dco.py BASE_SHA HEAD_SHA (full 40-character hashes)")
    base, head = argv
    try:
        done = subprocess.run(  # noqa: S603 - fixed arguments, local repository
            ["git", "log", "-z", "--reverse", f"--format={FORMAT}", f"{base}..{head}"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return fail("DCO.GIT.FAILED", "git log exited 127")
    if done.returncode != 0:
        return fail("DCO.GIT.FAILED", f"git log exited {done.returncode}")

    commits: list[tuple[str, bool]] = []
    covered: set[str] = set()
    for record in filter(None, done.stdout.split("\0")):
        parts = record.split("\x1f", 3)
        if len(parts) < 4:
            return fail("DCO.GIT.FAILED", "git log exited 0 with a malformed record")
        sha, author, signers, body = parts
        signed = any(
            (match := EMAIL.search(value)) is not None and match.group(1).casefold() == author.casefold()
            for value in signers.split("\x1d")
        )
        commits.append((sha, signed))
        # Only a self-signed sign-off commit can cover other commits.
        if signed:
            covered.update(COVER.findall(body))
    if not commits:
        print("DCO.RANGE.EMPTY: no commit in BASE..HEAD", file=sys.stderr)
        return 2

    # Print hashes only: author-controlled text must not reach the log as a workflow command.
    missing = [sha for sha, signed in commits if not signed and sha not in covered]
    for sha in missing:
        print(f"DCO.SIGNOFF.MISSING {sha}")
    print(f"checked {len(commits)} commits; {len(missing)} without sign-off")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
