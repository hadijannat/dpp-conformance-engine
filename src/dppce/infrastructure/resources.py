"""Locate the bundled catalogue, profiles, and test packs."""

from __future__ import annotations

from pathlib import Path


def data_root(override: Path | None = None) -> Path:
    """Return the directory that holds ``catalogue``, ``profiles``, and ``testpacks``.

    An installed wheel ships them under ``dppce/_bundled``. A source checkout uses the
    repository root.
    """
    if override is not None:
        return override
    package = Path(__file__).resolve().parent.parent
    bundled = package / "_bundled"
    return bundled if bundled.is_dir() else package.parent.parent
