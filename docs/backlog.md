# Backlog

Audience: maintainers and contributors.
Purpose: give each deferred task a local identifier that code comments and documents can cite.
Prerequisites: none.

A `TODO` in the code must cite one of these identifiers, for example `TODO(BL-003)`.
An item here is not an implemented feature.

| ID | Item | Acceptance criteria | Milestone | Status |
| --- | --- | --- | --- | --- |
| BL-001 | Hash the retrievable source artifacts listed in `catalogue/sources.yaml`. | Each source with `hash_permitted: true` has a SHA-256 value, a retrieval date, and the retrieved URL. A bot-challenge page is detected and is not hashed. | M0 | open |
| BL-002 | Run the Vale style checks locally. | `vale docs README.md` runs with the `styles/STE` rules and the result is recorded. | M1 | blocked by OQ-005 |
| BL-003 | Build and run the container image and the Docker Compose integrations. | The image builds as a non-root user. The Compose reference system starts and the offline test suite passes against it. | M5 | blocked by OQ-004 |
| BL-004 | Validate RFC 3161 timestamp evidence in the verifier. | A trusted timestamp token over the decision digest is checked against a configured timestamp authority certificate. The `timestamp` dimension can give `pass`. Tests use a local mock authority. | post-0.1.0 | open |
