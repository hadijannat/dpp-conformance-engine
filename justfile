# Run with `uv run just <recipe>`. A native `just` also works.
set shell := ["bash", "-euo", "pipefail", "-c"]

# The core packages for the coverage gate. Keep this list equal to the one in docs/readiness.md.
core := "src/dppce/applicability.py,src/dppce/migrations.py,src/dppce/models/*,src/dppce/catalogue/*,src/dppce/verdicts/*,src/dppce/orchestrator/*,src/dppce/evidence/*,src/dppce/verifier/*,src/dppce/testdefs/*,src/dppce/infrastructure/transport.py,src/dppce/infrastructure/replay.py,src/dppce/infrastructure/redaction.py,src/dppce/infrastructure/authorization.py,src/dppce/infrastructure/keys.py,src/dppce/infrastructure/clock.py,src/dppce/infrastructure/resources.py"

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

# Line and branch coverage. The 90 percent gate applies to the core packages only.
cov:
    uv run pytest -m "not validation" --cov --cov-report=xml --cov-report=
    @echo "--- all modules (information only) ---"
    uv run coverage report --fail-under=0
    @echo "--- core packages (gate: 90 percent) ---"
    uv run coverage report --include="{{core}}" --fail-under=90

# Regenerate the JSON Schemas from the Pydantic models.
schemas:
    uv run python scripts/gen_schemas.py

# Full milestone validation: fault catalogue, five-run replays, and the coverage gate. Slow.
validate: check cov
    uv run pytest -m validation
    uv run python -m validation.run

# Build the documentation site and fail on a broken link or a warning.
docs:
    uv run --group docs mkdocs build --strict

# Style checks. Needs the `vale` binary, which this project does not install.
style:
    vale docs README.md
