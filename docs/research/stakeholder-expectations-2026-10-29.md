# What stakeholders need from DPP conformance testing

Audience: system owners, developers, laboratories, assessors, and contributors.
Purpose: connect public evidence about stakeholder needs to the scope and gaps of DPP-CE.
Prerequisites: none. The [glossary](../reference/glossary.md) explains project terms.

Research date: **2026-10-29**. A development agent prepared this review. No person has reviewed it.

## Main finding

Stakeholders need more than a valid JSON document. They need the right people to obtain useful, consistent product information across systems and over time.
A test tool can help expose gaps and preserve evidence. A test result alone cannot establish data truth or legal compliance.

The strongest immediate opportunity for DPP-CE is a clear, repeatable diagnostic workflow with explicit coverage limits.
Its present evidence supports experiments with synthetic systems. It does not establish readiness for production or acceptance by an authority.

## Method and evidence limits

This review used public primary sources: legislation, Commission announcements, project publications, and the documentation of related test tools.
It compared those sources with the local [capability manifest](../reference/capabilities.md), [readiness record](../readiness.md), and operational guides.
The repository comparison describes the current source checkout, which can differ from the published `v0.1.0rc1` release.

The evidence has four classes:

- **Legal requirement:** an obligation on a passport or its responsible operator. It is not automatically a requirement on this test engine.
- **Published consultation:** a project reports input from stakeholders. Its sample and method limit the conclusions.
- **Project description:** a tool publisher describes its own goals or functions. This is not an independent evaluation.
- **Tooling inference:** this review proposes a useful test behavior from the evidence. It is not a verified customer request.

No interviews, surveys, usability sessions, or customer acceptance tests were conducted for DPP-CE.
This review establishes neither market size nor willingness to pay. It establishes no endorsement by the cited organizations.

## What people need, and what the engine can show

Each proposed test behavior below is a **tooling inference**. The cited source gives its basis.
“Available” describes a function in the source, not validation against an independent passport system.

| Stakeholder and practical question | Source basis | Useful test behavior | DPP-CE today and remaining gap |
| --- | --- | --- | --- |
| **Manufacturers and importers:** Which requirements apply to this product, and what needs correction? | ESPR Article 9 and Batteries Regulation Article 77 establish product scope and information duties ([S1](#sources), [S2](#sources)). | State the product category, rule version, applicability, missing evidence, and next action. | Profiles, applicability rules, reason codes, exclusions, and report hints exist. Battery data schemas are synthetic. All shipped legal interpretations remain unapproved. |
| **Small businesses and new adopters:** Where do we start, and which result can we rely on? | CIRPASS-2 reports information and organizational readiness gaps in its preliminary consultation ([S3](#sources)). | Give a local example, explain terms, and distinguish diagnostic results from approved interpretations. | A local reference system, tutorials, `dppce init`, and execution modes exist. No onboarding study with SMEs has established ease of use. |
| **Developers and integrators:** Can we detect a regression before delivery? | CIRPASS-2 offers configurable validation; UNTP provides test tooling for implementations ([S5](#sources), [S6](#sources)). | Run deterministic checks in CI; identify the tested contract; export actionable machine-readable results. | The CLI, pinned contracts, JSON reports, JUnit XML, SARIF, replay, and run comparison exist. The Python import surface is not a stable API. |
| **Vendors and service providers:** Does our implementation exchange data with other systems? | ESPR Article 10 and Batteries Regulation Article 78 require interoperable information exchange ([S1](#sources), [S2](#sources)). | Test identifiers, resolution, representation, schemas, and declared API behavior across independent implementations. | Web, GS1 resolver, AAS, and credential profiles exist. Several checks are experimental. No recorded campaign against independent real systems establishes interoperability. |
| **Data owners and providers:** Can authorized roles work without exposing restricted information? | Batteries Regulation Article 78 addresses access, security, integrity, and limits on data use ([S2](#sources)). | Exercise allowed and withheld fields, record the policy tested, and protect captured data. | Declared-policy checks, synthetic canaries, explicit authorization, redaction, and encrypted recordings exist. They do not establish all legal access rights. Run inputs and the recording index include clear-text metadata. |
| **Laboratories, assessors, and report recipients:** Can another party inspect how this result arose? | The Commission describes verification and accountability needs; BatteryPass-Ready separates testing from certification ([S4](#sources), [S7](#sources)). | Link requirements to observations; sign reports; verify them independently; preserve replay inputs. | Traceability, salted record commitments, signed reports, and a standalone verifier exist. Replay needs the data key. No independent validation or human security audit is recorded. |
| **Consumers, repairers, and recyclers:** Can we find the information needed to choose, repair, reuse, or recycle? | ESPR Article 9 identifies access and understanding; battery Annex XIII includes restricted dismantling and replacement-parts information ([S1](#sources), [S2](#sources)). | Test resolution and authorized data availability; add task-based checks with actual users. | Some technical checks can expose broken links and missing declared fields. They do not assess consumer comprehension, repair usefulness, accessibility of the tested passport, or physical authenticity. |
| **Operators and long-term users:** Will access and history survive changes or provider failure? | ESPR Article 11 and Batteries Regulation Article 78 address continued availability ([S1](#sources), [S2](#sources)). | Test updates, history, backup restoration, and access over time. | Version-history checks are experimental. Scheduled acquisition and backup integration are deferred. A single run cannot establish lifetime availability. |
| **Economic operators and authorities:** Is registry integration ready? | The Commission announced its registry and testing environment on 2026-07-20 ([S7](#sources)). | Keep authorized registry tests separate from passport-host checks and registration operations. | `registry.mock` performs passive mock lookup. `registry.official` is `interface_only`. DPP-CE makes no request to the official registry. |

The source comparison supports these test priorities. It does not show that every stakeholder needs every function in one product.

## What published stakeholder evidence actually says

CIRPASS-2's publisher summary reports surveys and interviews from December 2025 to March 2026.
It describes regulatory information as insufficient or hard to access, alongside broader organizational challenges.
It also identifies an educational burden for service providers. The project calls the analysis preliminary and descriptive ([S3](#sources)).

These findings support clear explanations of scope, terminology, and next steps.
They do not establish demand for a particular CLI, signature scheme, interface, or subscription model.

CE-RISE reports consultation with industry, repair and reuse organizations, recyclers, and consumers ([S8](#sources)).
Only its publication summary was read here. This review makes no claim about the report's detailed findings or participant counts.

BatteryPass-Ready describes lifecycle scenarios, controlled data access, completeness, and plausibility checks ([S4](#sources)).
These are relevant comparison points for a test engine. Its stated goals do not establish that those capabilities are complete or independently validated.

## Related tools and the questions they address

These descriptions summarize the publishers' pages as accessed on the research date.
No tool was installed or compared experimentally. None is presented as a certification authority.

| Tool or service | Question its publisher addresses | Boundary for DPP-CE |
| --- | --- | --- |
| [BatteryPass-Ready](https://thebatterypass.eu/battery-pass-ready/faq/) | Can battery passport implementations exercise lifecycle and interoperability scenarios? | A testing and learning platform. Its FAQ targets full public release in Q1/2027, with gradual prototype access in 2026. |
| [CIRPASS-2 DPP Validator](https://github.com/CIRPASS-2/dpp-validator/blob/main/README.md) | Does a JSON or JSON-LD payload satisfy a JSON Schema or SHACL template? | Payload validation is one part of system testing. Its publisher explicitly describes the artifacts as exploratory and non-normative. |
| [UNTP test tools](https://uncefact.github.io/tests-untp/docs/introduction/) | Can implementations issue and validate UNTP credentials and explore interoperability? | A protocol-specific reference implementation and test ecosystem. Its documentation states that interfaces and models remain provisional. |
| [EU DPP registry testing environment](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en) | Can economic operators prepare their registry integration? | Official registry testing has a separate scope. DPP-CE currently tests a mock only. |

## Priorities to validate next

These are recommendations from this review, not an approved roadmap or promises of delivery.

1. **Approve a bounded requirement pack.** Obtain qualified human review of each interpretation and record its source, version, scope, and approval.
2. **Run an authorized independent pilot.** Test an external system with known controls and seeded faults. Preserve disagreements and missing coverage.
3. **Use a real sector data model.** Pin its version and license, then test applicability and completeness against reviewed requirements.
4. **Check report usefulness with recipients.** Ask developers, laboratories, and assessors to diagnose representative failures from the report and evidence.
5. **Test access with circular-economy users.** Include repair and recycling tasks. Separate information availability from the quality of the information itself.
6. **Define separate registry and continuity work.** Obtain authorization for an official test environment. Specify backup, recovery, and time-based evidence independently.

For the README, the immediate consequence is simpler: show the purpose, a real example report, a local demo, and explicit capability boundaries.
Link detailed coverage and evidence records so readers can investigate a claim before relying on it.

## Sources

All sources below were accessed on **2026-10-29**. Links identify the evidence used, rather than a general project homepage.

| ID | Primary source and publication date | What was checked and its limit |
| --- | --- | --- |
| S1 | [Regulation (EU) 2024/1781, ESPR](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1781), 2024-06-28 | Indexed EUR-Lex text for Articles 9–11. DPP details depend on applicable delegated acts. Direct retrieval met a bot challenge. |
| S2 | [Regulation (EU) 2023/1542, consolidated 2025-07-31](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX%3A02023R1542-20250731) | Indexed EUR-Lex text for Articles 77–78 and Annex XIII. Direct retrieval met a bot challenge. This is a dated consolidation, not assurance of current consolidated law. |
| S3 | [CIRPASS-2 project results: DPP Readiness](https://cirpass2.eu/project-results/), entry dated 2026-04-10 | Publisher's summary of preliminary survey and interview findings. The full report link could not be retrieved; its sample and analysis were not rechecked. |
| S4 | [BatteryPass-Ready FAQ](https://thebatterypass.eu/battery-pass-ready/faq/), undated page | Intended users, scenarios, access plans, release target, and non-certification statement. Project self-description. |
| S5 | [CIRPASS-2 DPP Validator README](https://github.com/CIRPASS-2/dpp-validator/blob/main/README.md), live `main` | JSON Schema and SHACL payload validation, APIs, version selection, and scope disclaimer. Mutable source; no installation or runtime check. |
| S6 | [UNTP test tools introduction](https://uncefact.github.io/tests-untp/docs/introduction/), displayed version `0.7.0` | Reference implementation, playground, test-suite plans, and pre-release warning. Project self-description; no runtime check. |
| S7 | [Commission: DPP Registry is now live](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en), 2026-07-20 | Registry and test-environment announcement. The registry API, account access, and operational behavior were not tested. |
| S8 | [CE-RISE D1.1: Mapping DPP Knowledge Gap and Stakeholder Needs](https://ce-rise.eu/download/d1-1-mapping-dpp-knowledge-gap-and-stakeholder-needs/), 2024-09-06 | Publication summary identifies consultation groups. Full report findings were not used. |

This review did not audit all amendments, delegated acts, implementing acts, or harmonized-standard references.
It provides a research basis for documentation and test planning, not legal advice or an assessment of compliance.
