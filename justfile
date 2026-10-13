# Run with `uv run just <recipe>`. A native `just` also works.
set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

# Fast gates: format, lint, types, fast tests. No network.
check: fmt-check lint types test

fmt:
    uv run ruff format src tests scripts validation

fmt-check:
    uv run ruff format --check src tests scripts validation

lint:
    uv run ruff check src tests scripts validation

types:
    uv run mypy

# Fast tests. Expected negative-fixture verdicts are passing tests when the assertions match.
test:
    uv run pytest -m "not validation"

# Fast tests with the line and branch coverage gate on the core packages.
cov:
    uv run pytest -m "not validation" --cov --cov-report=term-missing --cov-report=xml

# Regenerate the JSON Schemas from the Pydantic models.
schemas:
    uv run python scripts/gen_schemas.py

# Full milestone validation: fault catalogue, five-run replays, and the coverage gate. Slow.
validate:
    uv run pytest --cov --cov-report=term-missing
    uv run python -m validation.run

# Build the documentation site and fail on a broken link or a warning.
docs:
    uv run --group docs mkdocs build --strict

# Style checks. Needs the `vale` binary, which this project does not install.
style:
    vale docs README.md
