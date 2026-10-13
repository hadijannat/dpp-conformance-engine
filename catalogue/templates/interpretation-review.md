# Interpretation review record

Audience: a human reviewer who approves or rejects one requirement interpretation.
Purpose: record one review decision in a form that maps to the `approval` fields of a requirement.
Prerequisites:

- You have the legal text or a lawful copy of the standard in the exact version that you examine.
- You read [decision record 0007](../../docs/adr/0007-only-a-documented-human-approval-makes-an-interpretation-approved.md).
- You are a human. An agent must not fill in this record.

## Rules

- An agent cannot approve an interpretation.
- Agreement between agents is not a human approval.
- A human review is not accreditation. It is not a statement of legal compliance.
- One record covers one requirement and one version of its source.
- Do not change the shipped draft to record an approval. Write an approved pack outside the repository.
  See `docs/how-to/import-an-approved-pack.md`.
- For an EN, ISO, IEC, or DIN document, do not copy text of the document into this record.

Make one copy of this file for each requirement. Fill in each field. Sign the completed record and keep it.

## 1. Requirement

| Field | Value |
| --- | --- |
| Requirement identifier of the draft | |
| Pack and version of the draft | |
| Identifier of the interpretation | |
| Author of the interpretation (agent or human) | |

## 2. Source provision and version examined

| Field | Value |
| --- | --- |
| Source identifier in `catalogue/sources.yaml` | |
| Provision (article, paragraph, point, or annex point) | |
| Exact version examined (for an EU act: the CELEX number and the date) | |
| Authentic text compared (for example the Official Journal reference and each corrigendum) | |
| Where you read the text (address or document) | |
| Date on which you read the text | |

## 3. Interpretation text reviewed

Copy the paraphrase, the interpretation text, and the applicability expression that you reviewed. Copy them without a change.

```text
Paraphrase:

Interpretation text:

Applicability expression:

Assessment path (test purposes):
```

## 4. Unresolved points

List each point of the field `unresolved` of the draft. State how you resolved it, or state that it stays open.

| Unresolved point | Resolution, or "open" |
| --- | --- |
| | |

## 5. Decision

Mark one decision.

- [ ] Approved as written
- [ ] Approved with the changes in section 6
- [ ] Rejected

A decision "approved" covers the paraphrase, the applicability expression, and the assessment path.

## 6. Rationale

State why the interpretation is correct or why it is not. Name each change that you require.

```text

```

## 7. Reviewer

| Field | Value |
| --- | --- |
| Name | |
| Role and organization | |
| Qualification for this review | |
| Date of the decision (YYYY-MM-DD) | |
| Declared conflicts of interest, or "none" | |
| Signature | |

## 8. Where the signed record is kept

| Field | Value |
| --- | --- |
| Path or address of the signed record | |
| Digest of the signed record, if one exists | |

## 9. How this record maps to the approval fields

A maintainer copies these values into the `approval` record of the approved requirement.
The engine has no command that writes this record.

| Field of `approval` | Value from this record |
| --- | --- |
| `reviewer` | Section 7: name and role |
| `date` | Section 7: date of the decision, as `YYYY-MM-DD` |
| `rationale` | Section 6 |
| `source_version` | Section 2: exact version examined |
| `artifact` | Section 8: path or address of the signed record |

The loader accepts `review_status: approved` only if all five fields have a value.
The approved requirement names the draft in its field `supersedes`.

```yaml
review_status: approved
approval:
  reviewer: <section 7: name and role>
  date: '<section 7: YYYY-MM-DD>'
  rationale: <section 6>
  source_version: <section 2: exact version examined>
  artifact: <section 8: path or address of the signed record>
supersedes:
- <section 1: requirement identifier of the draft>
```

A decision "rejected" has no `approval` record. Keep the signed record and report the reason to the maintainers.
