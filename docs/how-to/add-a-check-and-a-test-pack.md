# How to add a check and a test pack

Audience: contributors who add a check, and maintainers who add a test pack.
Purpose: add, register, and test one check, and write a test pack that uses it.
Prerequisites: a development environment from `uv sync --all-extras`. Read the
[architecture contract](../explanation/architecture.md), sections 6, 8, and 9. Read ADR 0002,
ADR 0005, and ADR 0011 in the [decision records](../adr/README.md).

## Part A: a check

A new check is a contract change. The owner approves the change of the architecture contract
and of the test list.

1. Write a function `(CheckContext) -> CheckOutcome` in a module of `src/dppce/adapters`.
2. Reach the system only through `ctx.acquirer`, for example with `fetch_once`.
3. Read the time only from `ctx.evaluation_time`. Do not read the system clock.
4. Declare a closed parameter model. Use `dppce.models.Model`, which forbids an unknown key.
5. Give each field a default that equals the behavior when the key is absent.
6. Give each field a description. The capability page shows it.
7. Register the function with the decorator.

```python
@register("<area>.<name>", capability="<capability id>", params=<Model>)
```

8. Import a new module in `src/dppce/adapters/__init__.py`. There is no plugin discovery.
9. Add a capability entry to `_ENTRIES` in `src/dppce/adapters/capabilities.py`.
10. Give the entry a state, a description, an optional import, and acceptance criteria.

Without a capability entry, the planner gives the step `unsupported`. It never gives a pass.

### Outcomes and reason codes

1. Return each outcome through a helper of `src/dppce/adapters/common.py`.
2. Use `completed`, `blocked`, `not_done`, `no_answer`, or `unusable`.
3. Give no pass when the check did not execute.
4. Give each new reason code the format `AREA.TOPIC.DETAIL` (architecture, section 8).
5. State the limit of the check in its message.
6. Write no payload value into an observation summary.

### Contract and tests

1. Add the check to the registry table in the architecture contract, section 8.
2. Add the check name to `CONTRACT_CHECKS` in `tests/test_check_params.py`.
3. Write the tests first, against the loopback reference system. Tests never use the network.
4. State the expected outcome of a seeded fault before the check exists.
5. The fault catalogue `validation/fault-catalogue.yaml` is a protected file. The owner approves a change.
6. Regenerate the reference pages. The capability page and the reason-code page change.

```bash
uv run just reference
uv run just check
```

## Part B: a test pack

A test pack is a YAML file of test purposes.
`testpacks/battery-core.yaml` is a shipped example.

| Field | Meaning |
| --- | --- |
| `id` | The identifier of the test purpose. |
| `title` | A short title. |
| `requirements` | The requirements that the test purpose assesses. |
| `profiles` | The profile identifiers, or `'*'` for all. |
| `applicability` | The applicability expression of the step. |
| `roles` | The roles that the step uses. |
| `stimulus.check` | The name of a registered check. |
| `stimulus.params` | The parameters. The parameter model of the check must accept them. |
| `expected_evidence` | The evidence that the step records. |
| `permitted_modes` | The execution modes that can run the step. |
| `requires_scope` | The authorization scope that the step needs. |
| `verdict_rules` | Optional. How a failed check and a missing answer map to a verdict. |
| `manual` | Optional. `true` for a manual step. |

A shipped test pack is listed under `testpacks:` in a profile.
For a test pack outside the repository, read
[import an approved pack](import-an-approved-pack.md), section 5.

Lint the test pack.

```bash
dppce catalogue lint --import-testpack FILE
```

| Finding | Meaning |
| --- | --- |
| `CAT006` | The check is not registered. The step will be `unsupported`. |
| `CAT016` | A shipped test pack already uses the test purpose identifier. |
| `CAT019` | The parameters do not fit the check. |
