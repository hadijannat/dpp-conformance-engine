# Backlog

Audience: maintainers and contributors.
Purpose: give each deferred task a local identifier that code comments and documents can cite.
Prerequisites: none.

A `TODO` in the code must cite one of these identifiers, for example `TODO(BL-003)`.
An item here is not an implemented feature.

| ID | Item | Acceptance criteria | Milestone | Status |
| --- | --- | --- | --- | --- |
| BL-001 | Hash the retrievable source artifacts listed in `catalogue/sources.yaml`. | Each source with `hash_permitted: true` has a SHA-256 value, a retrieval date, and the retrieved URL. A bot-challenge page is detected and is not hashed. | M0 | open |
| BL-002 | Run the Vale style checks locally. | `vale docs README.md` runs with the `styles/STE` rules and the result is recorded. | M1 | done 2026-10-15: `uv run just style` runs Vale 3.22.0 with the `styles/STE` rules. The result is in `docs/readiness.md`, section 2. |
| BL-003 | Build and run the container image and the Docker Compose integrations. | The image builds as a non-root user. The Compose reference system starts and the offline test suite passes against it. | M5 | open: the owner built and smoke-tested the image on 2026-10-15 (`docs/readiness.md`, section 2). The Compose reference system has not run. |
| BL-004 | Validate RFC 3161 timestamp evidence in the verifier. | A trusted timestamp token over the decision digest is checked against a configured timestamp authority certificate. The `timestamp` dimension can give `pass`. Tests use a local mock authority. | post-0.1.0 | done 2026-10-18: the imprint covers the report signature value, not the decision digest (ADR 0015). Tests build tokens in-process with TEST-ONLY keys. |
| BL-005 | Pin the container base images by digest. | The `Dockerfile` names each base image with a `@sha256:` digest, and Dependabot updates the digests. | M6 | done 2026-10-15: index digests of `python:3.12-slim` and `ghcr.io/astral-sh/uv:0.9.24`, read with `docker buildx imagetools inspect` by the owner. |
| BL-006 | Apply the status rule of `integrity.jws` before its body rules. | A non-200 answer of the signed passport with a body coding or a truncated body gives `INTEGRITY.TOKEN.NOT_AVAILABLE`, not `blocked`. `integrity.jose` and `identity.did` already use this order. A test shows each case. | M8 | open: found in the wave 3 integration review of program P2 on 2026-10-26. |
