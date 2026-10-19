"""The DCO check of a pull request: own sign-off, follow-up sign-off commit, and bad input."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_dco.py"
TRAILER = "Signed-off-by: Test Author <AUTHOR@example.org>"
# Inherited from a git hook or a rebase --exec, these would point git at another repository.
_GIT_LOCATION = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_PREFIX",
        "GIT_CEILING_DIRECTORIES",
    }
)


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = {
            **{name: value for name, value in os.environ.items() if name not in _GIT_LOCATION},
            # Keep the owner's gpgsign, hooks, and templates out of the temporary repository.
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(root),
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "author@example.org",
            "GIT_COMMITTER_EMAIL": "author@example.org",
        }
        self.git("init", "-q", "-b", "main")
        self.base = self.commit("root")

    def git(self, *args: str) -> str:
        done = subprocess.run(  # noqa: S603 - fixed arguments, local temporary repository
            ["git", *args],  # noqa: S607 - git from PATH, local temporary repository
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def commit(self, subject: str, *paragraphs: str) -> str:
        args = ["commit", "-q", "--allow-empty", "-m", subject]
        for paragraph in paragraphs:
            args += ["-m", paragraph]
        self.git(*args)
        return self.git("rev-parse", "HEAD")

    def check(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed arguments, local temporary repository
            [sys.executable, str(SCRIPT), *argv],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )


def sign_off_body(covered: str) -> str:
    return (
        "DCO sign-off for agent commits\n\n"
        f"I, Test Author <author@example.org>, hereby add my Signed-off-by to this commit: {covered}"
    )


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


def test_an_inherited_git_location_does_not_redirect_the_temporary_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A git hook or a rebase --exec exports GIT_DIR; the fixture must still use its own repository.
    # The two direct git calls get a clean environment too: an inherited GIT_WORK_TREE stops
    # `git init --bare` (exit 128).
    clean = {name: value for name, value in os.environ.items() if name not in _GIT_LOCATION}
    other = tmp_path / "other.git"
    subprocess.run(  # noqa: S603 - fixed arguments, local temporary repository
        ["git", "init", "-q", "--bare", str(other)],  # noqa: S607 - git from PATH
        env=clean,
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("GIT_DIR", str(other))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "elsewhere"))
    (tmp_path / "own").mkdir()
    repo = Repo(tmp_path / "own")
    assert (tmp_path / "own" / ".git").is_dir()
    untouched = subprocess.run(  # noqa: S603 - fixed arguments, local temporary repository
        ["git", "--git-dir", str(other), "rev-parse", "--verify", "-q", "HEAD"],  # noqa: S607
        env=clean,
        capture_output=True,
        check=False,
    )
    # 1 is "no such ref"; a git error (128) must not pass as an untouched repository.
    assert untouched.returncode == 1
    assert repo.check(repo.base, repo.commit("feat: signed", TRAILER)).returncode == 0


def test_commit_signed_by_its_author_passes(repo: Repo) -> None:
    head = repo.commit("feat: signed", TRAILER)
    done = repo.check(repo.base, head)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "checked 1 commits; 0 without sign-off" in done.stdout


def test_unsigned_commit_fails_with_its_hash(repo: Repo) -> None:
    head = repo.commit("feat: unsigned")
    done = repo.check(repo.base, head)
    assert done.returncode == 1
    assert f"DCO.SIGNOFF.MISSING {head}" in done.stdout
    assert "checked 1 commits; 1 without sign-off" in done.stdout


def test_sign_off_commit_covers_an_unsigned_commit(repo: Repo) -> None:
    agent = repo.commit("feat: agent commit")
    head = repo.commit(sign_off_body(agent), TRAILER)
    done = repo.check(repo.base, head)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "checked 2 commits; 0 without sign-off" in done.stdout


def test_unsigned_sign_off_commit_covers_nothing(repo: Repo) -> None:
    agent = repo.commit("feat: agent commit")
    head = repo.commit(sign_off_body(agent))
    done = repo.check(repo.base, head)
    assert done.returncode == 1
    assert f"DCO.SIGNOFF.MISSING {agent}" in done.stdout
    assert f"DCO.SIGNOFF.MISSING {head}" in done.stdout


def test_sign_off_of_another_address_does_not_count(repo: Repo) -> None:
    head = repo.commit("feat: signed by someone else", "Signed-off-by: Someone Else <other@example.org>")
    done = repo.check(repo.base, head)
    assert done.returncode == 1
    assert f"DCO.SIGNOFF.MISSING {head}" in done.stdout


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("no_arguments", "DCO.INPUT.INVALID"),
        ("abbreviated_hash", "DCO.INPUT.INVALID"),
        ("empty_range", "DCO.RANGE.EMPTY"),
        ("unknown_hash", "DCO.GIT.FAILED"),
    ],
)
def test_bad_input_exits_2(repo: Repo, case: str, code: str) -> None:
    head = repo.commit("feat: signed", TRAILER)
    argv = {
        "no_arguments": [],
        "abbreviated_hash": [repo.base, head[:7]],
        "empty_range": [head, head],
        "unknown_hash": [repo.base, "0" * 40],
    }[case]
    done = repo.check(*argv)
    assert done.returncode == 2
    assert code in done.stderr
