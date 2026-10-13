# syntax=docker/dockerfile:1
# Status: written, not built. Docker was not available in the development session (OQ-004, BL-003).
# The base images are pinned by tag. Pin them by digest before the first release (BL-005).

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.9.24 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Dependencies first, from the lockfile only, so that this layer changes only when uv.lock changes.
COPY pyproject.toml uv.lock README.md NOTICE ./
COPY LICENSES ./LICENSES
RUN uv sync --frozen --no-dev --all-extras --no-install-project
COPY src ./src
COPY catalogue ./catalogue
COPY profiles ./profiles
COPY testpacks ./testpacks
RUN uv sync --frozen --no-dev --all-extras --no-editable

FROM python:3.12-slim
LABEL org.opencontainers.image.title="dpp-conformance-engine" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Conformance test engine for Digital Product Passports. Its reports are not certificates."
# A fixed, unprivileged user. The engine needs no root right and writes only to mounted volumes.
RUN groupadd --gid 10001 dppce && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin dppce
COPY --from=build --chown=root:root /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["dppce"]
CMD ["--help"]
