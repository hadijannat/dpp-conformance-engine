# Import an approved pack

Audience: maintainers who hold interpretations that a human reviewer approved.
Purpose: check an approved pack and use it in a run in reviewed mode, without a change to the shipped catalogue.
Prerequisites:

- You installed the engine and you can run `uv run dppce`.
- A human reviewer completed one review record for each requirement. Use the template `catalogue/templates/interpretation-review.md`.
- You keep each signed review record at a stable path or address.
- You read [decision record 0007](../adr/0007-only-a-documented-human-approval-makes-an-interpretation-approved.md).

An agent cannot approve an interpretation. Agreement between agents is not a human approval.
A human review is not accreditation. A result in reviewed mode is not a statement of legal compliance.

## 1. The three execution modes

| Mode | Requirements that a run can assess | Claim level of a result | Typical use |
| --- | --- | --- | --- |
| `illustrative` | Requirements with the authority class `illustrative` only. | `illustrative` | Demonstrate the engine with the synthetic rules. |
| `exploratory` | Requirements with the review status `draft-needs-review` or `approved`, illustrative ones, and placeholders. | `diagnostic`, or `illustrative`; `none` for a placeholder | Find problems early with draft interpretations. |
| `reviewed` | Requirements with the review status `approved` only. | `reviewed` | Report against interpretations that a human approved. |

A run lists each requirement that the mode does not permit as an exclusion with a reason code.
A test purpose runs only in a mode that its field `permitted_modes` lists.

The shipped catalogue has no approved requirement.
In reviewed mode, a run with the shipped catalogue alone plans zero requirements and lists every entry as an exclusion.

## 2. Write the pack outside the repository

1. Create one YAML file in a directory that is not part of the repository.
2. Give the pack a new `pack_id`. Do not use the identifier of a shipped pack.
3. Give each requirement a new `id`. The lint rejects an identifier that a shipped pack already uses.
4. Name a `source_id` that is in `catalogue/sources.yaml`.
5. Give `source.citation` and `source.version`. State the exact version that the reviewer examined.
6. Set `review_status: approved` and add the `approval` record from the review record.
7. Record the reviewed interpretation with `author_kind: human`.
8. Add `supersedes` with the identifier of each draft that the entry replaces.
9. Name the test purposes in `assessment_paths`. Read section 5 before you do this.

The engine has no command that writes an approval record. A person writes it.

This example shows the structure. A text between angle brackets is a field to fill in. The file does not load until you fill in each field.

```yaml
schema_version: dppce.pack/1
pack_id: <organization>/eu-battery-reviewed
version: 1.0.0
title: <title of the pack>
legal_as_of: '<YYYY-MM-DD>'
scope_statement: <what the pack covers and what it does not cover>
requirements:
- id: <NEW-ID-001>
  title: <title>
  source:
    source_id: reg-eu-2023-1542
    citation: <provision, for example "Art. 77(1)">
    version: <exact version that the reviewer examined>
  authority_class: legal_obligation
  modality: mandatory
  paraphrase: <the approved paraphrase>
  applicability: <expression tree>
  testability: <automated, manual, or mixed>
  review_status: approved
  interpretations:
  - id: <NEW-ID-001-I1>
    text: <the interpretation text that the reviewer approved>
    status: approved
    author_kind: human
    source_version: <same version as above>
  assessment_paths:
  - id: default
    tests:
    - <test purpose identifier>
  approval:
    reviewer: <name and role of the human reviewer>
    date: '<YYYY-MM-DD>'
    rationale: <why the reviewer approved the interpretation>
    source_version: <same version as above>
    artifact: <path or address of the signed review record>
  supersedes:
  - EUBAT-77-1
```

The loader rejects `review_status: approved` without the `approval` record.
The lint rejects an interpretation with `author_kind: agent` and `status: approved`.

## 3. Check the pack

1. Run the lint with the pack and the test pack of section 5.

   ```bash
   uv run dppce catalogue lint \
     --import-pack /path/to/pack.yaml --import-testpack /path/to/testpack.yaml
   ```

2. Make sure that the last line starts with `0 errors`. The exit status is `0`.
3. Read each finding. Correct the pack until no error stays.

| Code | Meaning | Correction |
| --- | --- | --- |
| `CAT001` | The source is not in `sources.yaml`. | Use an identifier from the source catalogue. |
| `CAT002` | A shipped pack already has this requirement identifier. | Give the requirement a new identifier. |
| `CAT003` | A test purpose is not defined. | Read section 5. |
| `CAT005` | The trace is one-way. | Make the test purpose list the requirement. |
| `CAT008` | An agent-authored interpretation is marked approved. | Only a human-authored interpretation can be approved. |
| `CAT009` | A legal obligation rests on a source that is not an EU act. | Change the authority class or the source. |
| `CAT010` | `supersedes` names a requirement that does not exist, or one that is still `approved`. An entry with `superseded_by` does not have the status `superseded`. | Correct the identifier, or set the old entry to `superseded`. |
| `CAT016` | Two test packs define the same test purpose identifier. | Give your test purpose a new identifier. |
| `CAT017` | A test purpose sets `on_unreachable: fail`, and a requirement that it names is not approved. | Remove the rule, or use it only for approved requirements. |
| `CAT018` | Warning: a step has an applicability that reads a fact, and its path holds other steps. The step can leave its path, and the other steps can then pass alone. | Use a constant, or accept that the step can leave its path. |
| `CAT019` | The parameters of a test purpose do not fit its check. | Use the parameters in the [capability reference](../reference/capabilities.md). |
| `CAT020` | The cited version has no version token of the source record. | Cite the edition that `sources.yaml` records. |
| `CAT021` | Warning: the source record shows a later version or amendment. | Check if the cited version is still the correct one. |
| `CAT022` | A date in a legal obligation is not in `applicable_dates` of its source. | Use a date that the source record lists. |
| `CAT023` | The check probes a role that the test purpose does not list in `roles`. | Add the role to `roles`, or change the parameter `role`. |

`dppce plan`, `dppce run`, and `dppce replay` refuse a test pack whose parameters do not fit its check.

You can see the trace from the provision to the check with this command.

```bash
uv run dppce catalogue trace \
  --import-pack /path/to/pack.yaml --import-testpack /path/to/testpack.yaml
```

## 4. Use the pack in reviewed mode

1. Show the plan. `--import-pack` loads the pack file. `--pack` selects it for the profile.
   `--import-testpack` and `--testpack` do the same for the test pack.

   ```bash
   uv run dppce plan --mode reviewed \
     --import-pack /path/to/pack.yaml --pack <organization>/eu-battery-reviewed \
     --import-testpack /path/to/testpack.yaml --testpack <organization>/eu-battery-reviewed-tests \
     --profile battery/ev --ics /path/to/ics.yaml --ixit /path/to/ixit.yaml
   ```

2. Read the exclusions. Each shipped draft and each placeholder has the reason code `MODE.NOT_APPROVED`,
   except a draft that a selected approved entry supersedes. That draft has `STATUS.SUPERSEDED_BY_SELECTED`.
3. Make sure that the plan has your approved requirements and their steps.
4. Start the run with the same options and the options of `dppce run`. See the [command line reference](../reference/cli.md).

`--pack` works only together with `--import-pack` for a pack that is not shipped.
Without the file, the command stops with the message "requirement pack not found".
`--testpack` and `--import-testpack` work in the same way. Without the file, the message is "test pack not found".

The shipped files stay unchanged. The engine reads the imported files. It writes nothing to `catalogue/`, `profiles/`, or `testpacks/`.
The report names the catalogue and each pack by a digest, so a recipient can see which pack a run used.
The run manifest also names each selected test pack by a digest.

`dppce run` writes the paths of the imported files and the selected identifiers to `inputs.json`.
`dppce replay` reads the files again from these paths. Do not move or change the files after a run.
A changed file stops the replay with exit code 2 before it evaluates. The message names the changed pack or test pack by its identifier.
A file that the engine cannot read again gives an input error that names its path.

## 5. Test purposes for reviewed mode

An approved requirement needs test purposes that permit reviewed mode.
The shipped test purposes `TP-EU-...` permit exploratory mode only. In reviewed mode they are exclusions.

If a path names a test purpose that is not available in the mode, the step is "not run" and the requirement verdict is `inconclusive`.
It is never `pass`.

To run steps in reviewed mode, do these steps.

1. Create one YAML test pack file in a directory that is not part of the repository.
2. Give the test pack a new `testpack_id`. The loader rejects the identifier of a shipped test pack.
3. Give each test purpose a new `id`. Set `permitted_modes: [reviewed]`.
4. Make each test purpose list the approved requirement, and make the requirement list the test purpose.
5. Add `--import-testpack /path/to/testpack.yaml` to each command of sections 3 and 4.
6. Add `--testpack <organization>/eu-battery-reviewed-tests` to `dppce plan` and `dppce run`.

This example shows the structure. A text between angle brackets is a field to fill in.

```yaml
schema_version: dppce.testpack/1
testpack_id: <organization>/eu-battery-reviewed-tests
version: 1.0.0
title: <title of the test pack>
test_purposes:
- id: <NEW-TP-001>
  title: <title>
  requirements:
  - <NEW-ID-001>
  profiles:
  - battery/ev
  applicability:
    const: 'true'
  stimulus:
    check: <check name from the registry>
  permitted_modes:
  - reviewed
```

A test purpose identifier names one test purpose.
If a shipped test pack already uses the identifier, the lint reports `CAT016`.
`dppce plan` and `dppce run` stop with exit status `2` if they select the two test packs.
Each shipped profile selects each shipped test pack.

A human must approve the test method too. The review record states which steps the reviewer accepted.

A step with `manual: true` and the check `manual.review` needs a signed manual result.
The operator supplies it with `--manual-result`. The check verifies it (architecture, section 8.1).
Without a result, the step has the status `manual_unavailable`, and its path gives `inconclusive`.
A manual step with a different check always has the status `manual_unavailable`.

## 6. What `supersedes` does

`supersedes` says that an approved entry replaces a draft.

- The lint checks that each named requirement exists, and that it is not still `approved` (`CAT010`).
- An entry with `superseded_by` must have the status `superseded`. The planner then excludes it.
- The planner excludes a draft with the reason code `STATUS.SUPERSEDED_BY_SELECTED` if all of these are true:
  - The approved entry is in a selected pack. Use `--import-pack` and `--pack`.
  - The mode permits the approved entry.
  - The status of the named entry is `draft-needs-review`.
  - Both entries are illustrative, or neither is.
- This exclusion applies in each mode. The reason names the approved entry. The plan assesses the approved entry, not the draft.
- The planner does not read the ICS for this rule. It does not change the shipped pack.
- If one condition is false, `supersedes` has no effect on the plan.

Without such a selected approved entry, a draft leaves all modes only when its own entry has `review_status: superseded`.
That is a change to the shipped pack. Make it with a reviewed change to the repository, not with an imported file.

## 7. Limits

- The steps of sections 2 to 5 follow the loader, the lint, and the planner as they are in this version.
- The project checked `--import-pack` and `--pack` with a draft entry.
- The test suite checks `--import-pack`, `--pack`, `--import-testpack`, and `--testpack` in reviewed mode.
  It uses a TEST-ONLY fixture with a synthetic approval record. No review took place.
- The test suite checks `supersedes` with a TEST-ONLY approved entry that supersedes a shipped draft. No review took place.
- The project did not run these options with a real approved entry, because no review record exists.
- A pack that you import is your responsibility. The engine checks its form. It does not check that an interpretation is correct.
