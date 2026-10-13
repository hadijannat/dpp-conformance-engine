# Contributing

Audience: people who want to change the code, the catalogue, or the documentation.
Purpose: state the rules that keep the engine traceable and honest.
Prerequisites: Python 3.12 or later, and uv.

## Set up

```bash
uv sync --all-extras
```

```bash
uv run pre-commit install
```

## Before you open a pull request

```bash
uv run just check
```

Run the full validation if you changed a check, a verdict rule, or the evidence code.

```bash
uv run just validate
```

## Rules

1. Read the [architecture contract](docs/explanation/architecture.md). If you change behavior
   that the contract describes, change the contract in the same pull request.
2. Do not weaken a test to make it pass. Find which side contradicts the contract.
3. Tests use loopback and local fixtures only. A test that contacts another host fails.
4. Do not add the text of an EN, ISO, IEC, or DIN document, in any form. Use bibliographic
   metadata only. Do not invent a clause number.
5. Do not set a requirement to `approved`. Only a documented human review can do that. Use the
   [review template](catalogue/templates/interpretation-review.md).
6. Do not add a number that no command produced: no test count, no coverage figure, no score.
7. A key in this repository is a test key. Its file name starts with `TEST-ONLY-`.
8. A `TODO` cites an identifier from [docs/backlog.md](docs/backlog.md).

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/). Versions follow
[Semantic Versioning](https://semver.org/). Record each user-visible change in `CHANGELOG.md`.

## Developer Certificate of Origin

Each commit needs a `Signed-off-by` line from its author. See [DCO.md](DCO.md).
Sign only your own work. Never add a sign-off for a different person.

## Documentation style

The target is Simplified Technical English in the style of ASD-STE100. Procedures: at most
20 words in a sentence. Descriptions: at most 25. Use active voice and one term for one
concept: see the [glossary](docs/reference/glossary.md). The Vale rules in `styles/STE` find
likely problems. They are heuristics, and full conformity needs a human review.
