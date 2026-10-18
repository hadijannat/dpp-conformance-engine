# Scope and legal mapping

Audience: decision makers, assessors, and reviewers who must know what a result means.
Purpose: state what the engine tests, what it does not claim, and how the catalogue relates to the law.
Prerequisites: read the [glossary](../reference/glossary.md). For the evidence behind this page, read the [source audit](../research/source-audit.md).

This page is not legal advice. It makes no statement of legal compliance.
The legal status date for all statements is 2026-10-13.

## 1. What the engine tests

The engine observes a Digital Product Passport system through registered checks.
A check is deterministic code. No language model takes part in a run.

| Area | What a check observes |
| --- | --- |
| Data carrier | A supplied image of a QR code decodes to one symbol with text. |
| Identifier | The identifier has the syntax of its declared scheme. It resolves. It is the same in each place. |
| Interface | A response matches the API contract that the owner of the system pins. |
| Data | A document matches a pinned schema, a context allowlist, and a rule pack. |
| Access | A role does not get a field that the declared access policy withholds. |
| Integrity | A signature is valid, its issuer is trusted, and its certificate is valid. |
| Lifecycle | The version history obeys the declared update rule. A mock registry record agrees with the passport. |

Each result belongs to one requirement of the selected catalogue.
Each requirement names its source, its authority class, and its review status.
The output of a run is a conformance test report.

## 2. What the engine does not claim

- **No legal compliance.** The overall outcome is the outcome for the selected catalogue scope. It is not a statement on the law.
- **No coverage of a law or a standard.** A coverage figure counts catalogue entries. The scope statement of each pack says what the pack covers.
- **No accreditation.** A report states the issuer and the accreditation status that the operator gives. The default is "not accredited".
- **No certificate.** A conformance test report is not a certificate.
- **No physical authenticity.** Digital consistency does not prove that a battery is genuine.
- **No truth of the data.** A valid signature does not prove that the signed values are true.
- **No product safety statement.** The engine tests a passport system. It does not test a battery.

The shipped catalogue has no approved interpretation.
A result from the pack `eu-battery/draft` has the claim level `diagnostic`. A person must review it before any use.

Without a signed manual result, no verdict from the pack `eu-battery/draft` is `pass` or `fail`, in any mode.
Each verdict is then `inconclusive` or `not_applicable`. The one exception is `error`, for a check that raises an exception.

- Each assessment path holds a manual step. Without a manual result, a manual step gives `inconclusive`.
- One `inconclusive` step makes its path `inconclusive`. Such a path cannot give `pass`.
- In exploratory mode, the operator can supply a signed manual result with `--manual-result`. See ADR 0013.
- A manual result with the outcome `pass` lets its path give `pass` if every other step passes. The outcome `fail` gives `fail`.
- The engine does not perform the review. A valid signature shows who signed the result. It does not show that the review was correct.
- Each automated step gives `inconclusive` when its check does not pass. No step can give `fail`.
- No entry has a `declared_support` expression. A declaration of the owner cannot give `fail`.
- The modes `illustrative` and `reviewed` do not assess these entries. The engine lists each entry as an exclusion.

See rows OQ-015 and OQ-016 of the [open questions](../open-questions.md).

## 3. Authority classes

Each requirement has one authority class. The engine reports each class separately.

| Authority class | Meaning | Shipped content |
| --- | --- | --- |
| `legal_obligation` | An obligation in an EU regulation or in an EU act. | Pack `eu-battery/draft`: 36 agent-authored drafts. None is approved. |
| `standard_method` | A method or requirement of a standard. | Pack `en-jtc24/placeholders`: 8 placeholders with no content. |
| `implementation_contract` | A contract that the owner of the system declares, for example an API contract. | None. |
| `guidance` | A statement of a guidance document that is not binding. | None. |
| `illustrative` | A synthetic rule that shows how the engine behaves. | Pack `illustrative/core`. |

The classes stay separate for three reasons.

1. A guidance statement is not law. A report must not show it as an obligation.
2. The use of a harmonised standard is voluntary. A standard is one means to show conformity, not the obligation.
3. A synthetic rule has no authority. A pass on it says nothing about the law.

The catalogue lint enforces the separation.
A legal obligation can rest only on a source whose type starts with `eu_`.
An entry for an EN, ISO, IEC, or DIN document stays a placeholder until a human writes its interpretation.
An agent cannot mark an interpretation as approved.

Commission guidance and the Commission FAQ are sources in the catalogue. No requirement rests on them.
The draft interpretations name them only as an aid that is not binding.

## 4. The two Regulations

Two Regulations use the term "passport".

- Regulation (EU) 2023/1542 (the Batteries Regulation) sets the **battery passport** in its Articles 77 and 78 and its Annex XIII.
- Regulation (EU) 2024/1781 (the ESPR) sets the **digital product passport** in its Articles 9 to 15 and its Annex III.

The ESPR passport becomes a duty for a product group only through a delegated act under its Article 4.
The audit located no adopted delegated act of that kind as of 2026-10-13.
The battery passport is a duty of the Batteries Regulation itself, from 2027-02-18.

### 4.1 The explicit links that the audit found

| Link | Where | What it does |
| --- | --- | --- |
| Upload of the unique identifier | Article 77(10) of Regulation (EU) 2023/1542. Article 78 of the ESPR inserted it. | The economic operator uploads the unique identifier of the battery to the registry of Article 13(1) of the ESPR. |
| Content of the registry | Article 13(1), third subparagraph, of the ESPR | The registry stores the unique identifiers of the batteries of Article 77(3) of Regulation (EU) 2023/1542. |
| Registration arrangements | Implementing Regulation (EU) 2026/1778, Articles 1(1)(b), 2, and 8(7) | The registry rules cover the batteries of Article 77. For that act only, "digital product passport" includes the battery passport. |
| Interoperability | Article 78, point (a), of Regulation (EU) 2023/1542 | The battery passport must be interoperable with the other passports that Union ecodesign law requires. The point does not name the ESPR. |
| Coherent development | Recital 126 of Regulation (EU) 2023/1542 | A recital. It has no operative effect. |

The draft pack uses two of these links: `EUBAT-77-10` for the registry and `EUBAT-78-A` for interoperability.
Each entry names the link in its interpretation text.

Implementing Regulation (EU) 2026/1778 is the registry act of the ESPR.
It is not the implementing act that Article 77(9) of Regulation (EU) 2023/1542 requires.

### 4.2 Where the audit found no link

The audit found no provision that applies these parts of the ESPR to a battery passport.

| ESPR provision | Subject | Treatment in the catalogue |
| --- | --- | --- |
| Article 9 and Annex III | Content of the passport | Not transferred. The content of the battery passport is Annex XIII of Regulation (EU) 2023/1542. |
| Article 10 | Essential requirements, a copy for dealers, and a back-up copy with a service provider | Not transferred. See the unresolved point of `EUBAT-78-E`. |
| Article 11 | Technical design, the list of actors with access, and service providers | Not transferred. The access groups of the battery passport are in Article 77(2). |
| Article 12 | Unique identifiers and issuing agencies | Not transferred. Article 77(3) has its own rule for identifiers. |
| Articles 14 and 15 | Web portal and customs controls | Not transferred. |
| Article 41(2) | Presumption of conformity from cited standards | Not transferred. See section 4.3. |

Article 1(2) of the ESPR does not exclude batteries from its scope.
No provision that the audit read says which Regulation prevails for batteries. The catalogue assumes nothing on that question.

Both Regulations name the same dated editions of ISO/IEC 15459. Each does so in its own text.
A change of the ESPR rule does not change Article 77(3) of Regulation (EU) 2023/1542.

### 4.3 Standards

"Published" and "cited in the Official Journal" are two facts. The catalogue keeps them in separate fields.

| Standards | Published by CEN and CENELEC | Cited in the Official Journal |
| --- | --- | --- |
| EN 18216:2026, EN 18219:2026, EN 18220:2026, EN 18221:2026, EN 18222:2026, EN 18223:2026 | 2026-05-27 | Yes, by Implementing Decision (EU) 2026/1736, under the ESPR |
| EN 18239:2026, EN 18246:2026 | 2026-09-16 | Not located as of 2026-10-13 |

The citation gives a presumption of conformity for Articles 10 and 11 of the ESPR.
It gives that presumption only for the requirements that a standard covers.
The audit found no citation of these standards under Regulation (EU) 2023/1542.

The standardisation request behind these standards names ecodesign policy and batteries policy.
That does not change the legal basis of the citation.

Under Regulation (EU) 2023/1542 the audit located one decision on harmonised standards, Implementing Decision (EU) 2026/2048.
It cites EN 18060:2025. It does not mention Article 77 or the battery passport.

The pack `en-jtc24/placeholders` therefore has no content.
The draft pack transfers no presumption of conformity to a battery passport.
No entry states, quotes, or summarizes the content of a standard.

## 5. Dates that the draft pack encodes

| Provision | Start | State on 2026-10-13 |
| --- | --- | --- |
| Article 77(1): battery passport | 2027-02-18 | Fixed in the text. |
| Article 13(6): QR code on all batteries | 2027-02-18 | Fixed in the text. |
| Annex XIII, point 1(d): responsible sourcing | Follows the due diligence date of 2027-08-18 | Fixed by Regulation (EU) 2025/1561. The exemption of Article 47 can apply. |
| Annex XIII, point 1(c): carbon footprint | Follows Article 7 | Not fixed. The acts of Article 7 were not located as adopted. |
| Annex XIII, point 1(e): recycled content | Follows Article 8(1) | Not fixed for industrial and electric vehicle batteries: the delegated act was not located as adopted. For LMT batteries the text gives 2033-08-18. |
| Article 13(1) to (3): labels | The later of 2026-08-18 and 18 months after an implementing act | Not fixed. The act was not located as adopted. |
| Article 77(9): access rights act | Deadline for the Commission: 2026-08-18 | Not located as adopted. |

The passport duty covers each LMT battery, each industrial battery with a capacity greater than 2 kWh, and each electric vehicle battery.
The capacity limit is for industrial batteries only. The comparison is "greater than", not "at least".
The trigger in the Regulation is the placing on the market or the putting into service.

Putting into service is the first use of a battery that was not placed on the market before (Article 3(1), point (18)).
A later put-into-service date therefore cannot bring a battery that was placed on the market earlier into scope.
The expressions read the placing-on-the-market date only. A date on or after 2027-02-18 gives `true`, an earlier date gives `false`.
A battery that is put into service without ever being placed on the market can declare that date only as `unknown`.
It then always gives `unknown`. The expression language has no value that means "never placed on the market".
A human must accept or reject this trade-off (OQ-021).

The three entries on a change of status (EUBAT-77-7A, EUBAT-77-7B, EUBAT-77-8) do not use the placing date to exclude a battery.
A battery placed on the market earlier can change status later. Whether it then needs a passport is open (OQ-010).

The draft pack never invents a date. Where a date is not fixed, the applicability is `unknown` and the entry gives the reason.
A missing fact gives `unknown`. It never gives `false` and never gives `not_applicable`.

## 6. Out of scope

- The other chapters of Regulation (EU) 2023/1542: sustainability, safety, due diligence duties, and waste management.
- Portable batteries and SLI batteries. No profile exists for them.
- A physical test of a battery, of a label, or of a marking.
- The content of any EN, ISO, IEC, or DIN document.
- A digital product passport under an ESPR delegated act. No such act was located as adopted.
- Any act or proposal that was not law on 2026-10-13.
- Contact with the Commission registry or its test environment. The engine reads a mock registry only.
- Regulation (EU) 2024/2847 as it applies to a passport system.
- Legal advice, accreditation, and certification.

Specifications such as the Asset Administration Shell templates, the UNTP credentials, and the GS1 identifiers are implementation options.
The catalogue lists them as sources. It does not treat them as legal requirements.

## 7. Open points

The main open points are in [open questions](../open-questions.md), rows OQ-006 to OQ-017.
Each draft entry lists its own unresolved points in the field `unresolved`.
