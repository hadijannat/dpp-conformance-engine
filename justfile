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
    just cov-report

# Report coverage from the last run. Fails if the core packages are below 90 percent.
cov-report:
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

# Mutation testing of the verdict, evidence, verifier, transport, redaction, and authorization code. Slow. Results: `uv run mutmut results`.
mutation:
    uv run mutmut run

# Write a CycloneDX SBOM of the locked environment to dist/sbom.cdx.json.
sbom:
    mkdir -p dist
    uv run --group release cyclonedx-py environment .venv --output-format JSON --output-file dist/sbom.cdx.json

# Regenerate the dependency license report from the installed environment.
licenses:
    uv run python scripts/gen_license_report.py

# Regenerate the generated reference pages: command line, capabilities, schemas, verdict truth table, and reason codes.
reference:
    uv run python scripts/gen_reference_docs.py

# Build the documentation site and fail on a broken link or a warning.
docs: reference
    uv run --group docs mkdocs build --strict

# Publish one version of the documentation site with mike. Needs a human decision: it pushes
# to the `gh-pages` branch of the remote. It has never run.
docs-publish version:
    uv run --group docs mike deploy --push --update-aliases {{version}} latest

# Style checks with Vale and the project rules in styles/STE. `uvx` downloads Vale on first use.
style:
    uvx vale docs README.md
