# Source audit

Audience: maintainers, reviewers, and assessors who must know how far each source was verified.
Purpose: give the method and the results of the source audit of 2026-10-13, and state what the audit could not verify.
Prerequisites: read the [architecture contract](../explanation/architecture.md), section 4. Keep `catalogue/sources.yaml` open: it holds the full record of each source.

This page is not legal advice. It makes no statement of legal compliance.
The legal status date for all statements is 2026-10-13.

## 1. Method

### 1.1 Two passes

1. **Research pass.** Nine research groups examined one source group each.
   Each group wrote one file: `docs/research/raw/<group>.json`.
2. **Independent check.** A second agent tried to refute the high-risk claims of three groups.
   The groups are `batteries-regulation`, `commission-2026-acts`, and `en-jtc24`.
   Each check wrote one file: `docs/research/raw/<group>.refutation.json`.

The other six groups had no independent check. Their sources have the value `not_checked`.
An agreement between two agents is not a human review.

### 1.2 Verification levels

| Level | Meaning |
| --- | --- |
| `substantive` | The audit read the provisions or the content at an official location. |
| `metadata_only` | The audit read bibliographic data or a catalogue record at an official location. It did not read the content. |
| `secondary_only` | The audit found only non-official sources or search excerpts. |
| `not_located` | The audit searched and found no document. This is a failed lookup. It is not proof that no document exists. |
| `unverified_recall` | A statement from recall with no source. No record has this level. Some fields say so for one statement, for example reuse terms. |

The catalogue never upgrades a level. Where two groups examined one source, the merged record has the level that the strongest evidence supports.

### 1.3 Independent check values

| Value | Meaning |
| --- | --- |
| `confirmed` | Each checked claim about the source was confirmed. |
| `not_confirmed` | One or more checked claims could not be confirmed. No claim was refuted. |
| `refuted` | One or more checked claims were refuted. The catalogue holds the corrected statement. |
| `not_checked` | No independent check has a claim about this source. |

The weakest verdict wins when a source has more than one checked claim.
A `confirmed` value covers the checked claims only. It does not cover every field of the record.

### 1.4 Limits of the method

- The audit read page text through a summarizing fetch tool. The wording in the raw files is paraphrase.
  It was not verified character by character against the source.
- The exception is Article 77(1) to (4) and (7) to (10) of Regulation (EU) 2023/1542.
  For those paragraphs the audit obtained short exact quotations.
- EUR-Lex returned empty pages for most address forms. The audit read the legal texts at the Publications Office.
  The independent check found that EUR-Lex addresses that end in `/eng` return content.
- The audit read consolidated versions. A consolidated version is a documentation tool and has no legal effect.
  The Official Journal text with its corrigenda and amending acts is authentic.
- No artifact was hashed. Each record has `sha256: null` and names backlog item BL-001.
  The catalogue cannot detect a later change of a source.
- For EN, ISO, IEC, and DIN documents the audit read bibliographic data only.
  No standard was obtained or opened.
- The audit did not contact a digital product passport system, a registry, or a registry test environment.

### 1.5 Untrusted content

The audit treated each page as data. One catalogue page of a standards publisher held text that asked the reader to format a response in a given way.
The fetch tool reported it and did not follow it. A search tool added a line about the format of sources. The audit did not act on it.

### 1.6 From raw files to the catalogue

The nine raw files hold 156 source records. Several files describe the same source with different identifiers.
The catalogue merges them: it has 127 audited sources and one project resource, 128 records in total.
Each record keeps at most three evidence entries.

| Verification level | Sources |
| --- | --- |
| `substantive` | 40 |
| `metadata_only` | 71 |
| `secondary_only` | 8 |
| `not_located` | 9 |
| `unverified_recall` | 0 |

| Independent check | Sources |
| --- | --- |
| `confirmed` | 29 |
| `not_confirmed` | 1 |
| `refuted` | 1 |
| `not_checked` | 97 |

## 2. Results for each source group

Each table gives the catalogue identifier, a short status, the verification level, and the independent check.
The status is a summary. The record in `catalogue/sources.yaml` has the full status, the dates, the evidence, and the uncertainties.

### 2.1 Batteries Regulation and its acts

Raw files: `batteries-regulation.json` and `commission-2026-acts.json`. Both had an independent check.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `reg-eu-2023-1542` | Regulation (EU) 2023/1542 (Batteries Regulation) | In force. Consolidated version of 2026-08-13 examined. | `substantive` | `confirmed` |
| `reg-eu-2025-1561` | Regulation (EU) 2025/1561 (due diligence dates) | In force since 2025-07-31. | `substantive` | `confirmed` |
| `reg-eu-2026-1738` | Regulation (EU) 2026/1738 (end-of-life vehicles; amends Annex I) | In force. Its amendment of Annex I applies from 2026-08-13. | `substantive` | `not_checked` |
| `del-reg-eu-2025-606` | Delegated Regulation (EU) 2025/606 (recycling efficiency) | Adopted and published, per a Commission page. Not opened. | `metadata_only` | `not_checked` |
| `impl-dec-eu-2026-2048` | Implementing Decision (EU) 2026/2048 (cites EN 18060:2025) | In force since 2026-09-16. | `substantive` | `confirmed` |
| `batteries-art-77-9-implementing-act` | Implementing act of Article 77(9) (access rights) | Not located as adopted as of 2026-10-13. | `not_located` | `confirmed` |
| `draft-impl-reg-labelling-art-13-10` | Draft implementing regulation on labels (Article 13(10)) | Draft, notified to the WTO. Not adopted. | `metadata_only` | `confirmed` |
| `draft-del-reg-carbon-footprint-ev-art-7-1` | Draft delegated regulation on the carbon footprint (Article 7(1)) | Draft. Adopted act not located. | `secondary_only` | `confirmed` |
| `draft-del-reg-recycled-content-art-8-1` | Draft delegated regulation on recycled content (Article 8(1)) | Draft, reported by secondary sources. Adopted act not located. | `secondary_only` | `confirmed` |

### 2.2 ESPR and its acts

Raw files: `espr.json`, `commission-2026-acts.json`, and `en-jtc24.json`. The group `espr` had no independent check of its own.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `reg-eu-2024-1781` | Regulation (EU) 2024/1781 (ESPR) | In force since 2024-07-18. | `substantive` | `not_checked` |
| `impl-reg-eu-2026-1778` | Implementing Regulation (EU) 2026/1778 (registry) | In force since 2026-08-06. | `substantive` | `confirmed` |
| `impl-dec-eu-2026-1736` | Implementing Decision (EU) 2026/1736 (cites six EN standards) | In force since 2026-07-15. | `substantive` | `confirmed` |
| `sreq-m-604-dpp` | Standardisation request M/604 (C(2024) 5423) | Adopted and amended once. Text not retrieved. | `metadata_only` | `not_confirmed` |
| `dpp-service-providers-delegated-act` | Delegated act on service providers (Article 11 ESPR) | Not adopted as far as located. | `metadata_only` | `not_checked` |
| `espr-art-12-4-identifiers-delegated-act` | Delegated act on identifiers (Article 12(4) ESPR) | Not located. | `not_located` | `not_checked` |
| `espr-art-11-credentials-implementing-act` | Implementing act on credentials (Article 11 ESPR) | Not located. | `not_located` | `not_checked` |
| `espr-art-4-product-delegated-acts` | Product delegated acts (Article 4 ESPR) | No adopted act located. | `metadata_only` | `not_checked` |
| `espr-unsold-products-acts-2026` | ESPR acts on unsold consumer products | Adopted, per a Commission page. Not about the passport. | `metadata_only` | `not_checked` |

### 2.3 Commission guidance and web pages

These sources are not binding. No requirement rests on them.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `ec-guidance-battery-passport-data-points` | Commission guidance: battery passport data points, version 2.0 | Not binding. Updated continuously. | `substantive` | `confirmed` |
| `ec-faq-dpp-batteries` | Commission FAQ for batteries, 1st edition | Not binding. | `substantive` | `refuted` |
| `ec-dpp-registry-user-guide` | Registry user guide for economic operators | Not binding. Not opened. | `metadata_only` | `not_checked` |
| `ec-dpp-batteries-webpage-and-timeline` | Commission battery passport page and timeline | Information pages. The timeline is indicative. | `substantive` | `confirmed` |
| `commission-notice-batteries-battery-passport` | Commission notice on the battery passport | Not located. | `not_located` | `not_checked` |
| `guidelines-due-diligence-art-48-5` | Due diligence guidelines (Article 48(5)) | Not located. | `not_located` | `not_checked` |

### 2.4 Pending legislative proposals

A proposal is not law. The catalogue tracks these sources and encodes none of them.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `proposal-com-2025-504-omnibus-iv-digitalisation` | Proposal COM(2025) 504 (procedure 2025/0134(COD)) | Proposal. Not adopted. | `substantive` | `confirmed` |
| `proposal-com-2025-501-omnibus-iv-small-mid-caps` | Proposal COM(2025) 501 (procedure 2025/0130(COD)) | Proposal. Not adopted. | `metadata_only` | `confirmed` |
| `proposal-com-2025-981-omnibus-viii-batteries` | Proposals COM(2025) 981 and 982 (procedures 2025/0397(COD), 2025/0395(COD)) | Proposals. Not adopted. | `metadata_only` | `confirmed` |

### 2.5 European standards

Raw files: `en-jtc24.json` and `commission-2026-acts.json`. Bibliographic data only. "Published" and "cited" are separate facts.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `en-18216-2026` | EN 18216:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18219-2026` | EN 18219:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18220-2026` | EN 18220:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18221-2026` | EN 18221:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18222-2026` | EN 18222:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18223-2026` | EN 18223:2026 | Published 2026-05-27. Cited in OJ L, 2026/1736 under Regulation (EU) 2024/1781. | `metadata_only` | `confirmed` |
| `en-18239-2026` | EN 18239:2026 | Published 2026-09-16. Citation in the Official Journal not located. | `metadata_only` | `confirmed` |
| `en-18246-2026` | EN 18246:2026 | Published 2026-09-16. Citation in the Official Journal not located. | `metadata_only` | `confirmed` |
| `en-18060-2025` | EN 18060:2025 | Cited under Regulation (EU) 2023/1542. Publication not checked. | `metadata_only` | `confirmed` |

### 2.6 Identifiers, data carriers, and battery data specifications

Raw file: `identifiers-carriers.json`. For the ISO, IEC, and DIN documents the audit read bibliographic data only.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `gs1-digital-link-uri-syntax-1-7-0` | GS1 Digital Link Standard: URI Syntax | GS1 standard, release 1.7.0, ratified August 2026. | `metadata_only` | `not_checked` |
| `gs1-conformant-resolver-1-2-1` | GS1-Conformant Resolver Standard | GS1 standard, release 1.2.1, ratified August 2026. | `metadata_only` | `not_checked` |
| `gs1-ip-policy-and-disclaimer` | GS1 Intellectual Property Policy and GS1 standards disclaimer | GS1 policy, adopted 2025-03-24. | `substantive` | `not_checked` |
| `iec-61406-1-2022` | IEC 61406-1:2022 Identification Link | Published International Standard, Edition 1.0, stability date 2026. | `metadata_only` | `not_checked` |
| `iec-61406-2-2024` | IEC 61406-2:2024 Identification link | Published International Standard, Edition 1.0, stability date 2027. | `metadata_only` | `not_checked` |
| `iec-ts-61406-predecessor-unverified` | IEC TS 61406 (reported predecessor) | Unresolved lead from one national catalogue. | `secondary_only` | `not_checked` |
| `iec-61406-part-3-not-located` | IEC 61406 Part 3, or a further part | Not located. | `not_located` | `not_checked` |
| `iso-iec-15459-1-2014` | ISO/IEC 15459-1:2014 | Published International Standard. | `metadata_only` | `confirmed` |
| `iso-iec-15459-2-2015` | ISO/IEC 15459-2:2015 | Published International Standard. | `metadata_only` | `confirmed` |
| `iso-iec-15459-3-2014` | ISO/IEC 15459-3:2014 | Published International Standard. | `metadata_only` | `confirmed` |
| `iso-iec-15459-4-2014` | ISO/IEC 15459-4:2014 | Published International Standard. | `metadata_only` | `confirmed` |
| `iso-iec-15459-5-2014` | ISO/IEC 15459-5:2014 | Published International Standard. | `metadata_only` | `confirmed` |
| `iso-iec-15459-6-2014` | ISO/IEC 15459-6:2014 | Published International Standard. | `metadata_only` | `confirmed` |
| `din-dke-spec-99100-2025-02` | DIN DKE SPEC 99100:2025-02 | Current DIN DKE SPEC (PAS). Not a standard and not law. | `metadata_only` | `not_checked` |
| `bp-content-guidance` | Battery Passport Content Guidance (Battery Pass consortium) | Project resource, not law. | `metadata_only` | `not_checked` |
| `bp-data-attribute-longlist` | Battery Passport Data Attribute Longlist (Battery Pass v1.2; ... | Project resource, not law. | `metadata_only` | `not_checked` |
| `bp-technical-guidance` | Battery Passport Technical Guidance (Battery Pass consortium) | Project resource, not law. | `metadata_only` | `not_checked` |
| `bp-data-model-github-v1-2-0` | Battery Pass Data Model repository (GitHub, Battery Pass project, v1.2.0) | Project resource, not law. | `substantive` | `not_checked` |
| `bp-ready-data-model-v2` | BatteryPass-Ready Data Model (successor repository, v2.0) | Project resource, not law. | `substantive` | `not_checked` |

### 2.7 Asset Administration Shell and IDTA

Raw file: `aas-idta.json`. No independent check.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `iec-63278-1-2023` | IEC 63278-1:2023 ED1 | Published International Standard. | `metadata_only` | `not_checked` |
| `en-iec-63278-1-2024` | EN IEC 63278-1:2024 | Published EN, per a national catalogue. | `secondary_only` | `not_checked` |
| `iec-63278-2` | IEC 63278-2 ED1 | In development. | `secondary_only` | `not_checked` |
| `iec-63278-3` | IEC 63278-3 ED1 | In development. | `secondary_only` | `not_checked` |
| `iec-63278-4` | IEC 63278-4 | Not located. | `not_located` | `not_checked` |
| `iec-63278-5` | IEC 63278-5 ED1 | In development. | `secondary_only` | `not_checked` |
| `iec-63278-6` | IEC 63278-6 | Not located. | `not_located` | `not_checked` |
| `idta-01001-metamodel` | Specification of the Asset Administration Shell Part 1: Metamodel | Published. | `metadata_only` | `not_checked` |
| `idta-01002-api` | Specification of the Asset Administration Shell Part 2: Application ... | Published. | `metadata_only` | `not_checked` |
| `idta-01003a-iec61360` | Specification of the Asset Administration Shell Part 3a: Data Specification ... | Published. | `metadata_only` | `not_checked` |
| `idta-01003b-units` | Specification of the Asset Administration Shell Part 3b: Data Specification ... | Published. | `metadata_only` | `not_checked` |
| `idta-01004-security` | Specification of the Asset Administration Shell Part 4: Security | Published. | `metadata_only` | `not_checked` |
| `idta-01005-aasx` | Specification of the Asset Administration Shell Part 5: Package File Format ... | Published. | `metadata_only` | `not_checked` |
| `idta-02099-1-dpp-metadata` | Digital Product Passport - Part 1: Metadata | IDTA Submodel Template, Published. | `substantive` | `not_checked` |
| `idta-02035-1-dbp-digital-nameplate` | Digital Battery Passport, Part 1: Digital Nameplate | Published. | `substantive` | `not_checked` |
| `idta-02035-2-dbp-handover-documentation` | Digital Battery Passport, Part 2: Handover Documentation | Published. | `substantive` | `not_checked` |
| `idta-02035-3-dbp-product-carbon-footprint` | Digital Battery Passport, Part 3: Product Carbon Footprint | Published. | `substantive` | `not_checked` |
| `idta-02035-4-dbp-technical-data` | Digital Battery Passport, Part 4: Technical Data | Published. | `substantive` | `not_checked` |
| `idta-02035-5-dbp-product-condition` | Digital Battery Passport, Part 5: Product Condition | Published. | `substantive` | `not_checked` |
| `idta-02035-6-dbp-material-composition` | Digital Battery Passport, Part 6: Material Composition | Published. | `substantive` | `not_checked` |
| `idta-02035-7-dbp-circularity` | Digital Battery Passport, Part 7: Circularity | Published. | `substantive` | `not_checked` |
| `idta-submodel-templates-repo` | IDTA Submodel Templates for AAS (repository admin-shell-io/submodel-templates) | Active repository. | `substantive` | `not_checked` |
| `idta-iec63278-companion-repo` | Additional materials to the IEC 63278 series (repository ... | Active repository. | `metadata_only` | `not_checked` |

### 2.8 W3C and UNTP

Raw file: `w3c-untp.json`. No independent check.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `w3c-vcdm-2-0` | Verifiable Credentials Data Model v2.0 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `w3c-vc-jose-cose` | Securing Verifiable Credentials using JOSE and COSE | W3C Recommendation; two versions exist. | `metadata_only` | `not_checked` |
| `w3c-vc-data-integrity-1-0` | Verifiable Credential Data Integrity 1.0 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `w3c-vc-di-ecdsa-1-0` | Data Integrity ECDSA Cryptosuites v1.0 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `w3c-vc-di-eddsa-1-0` | Data Integrity EdDSA Cryptosuites v1.0 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `w3c-bitstring-status-list-1-0` | Bitstring Status List v1.0 | W3C Recommendation. | `substantive` | `not_checked` |
| `w3c-cid-1-0` | Controlled Identifiers v1.0 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `untp-dcc-0-7-0` | UN Transparency Protocol, Conformity Credential page (Digital Conformity ... | Pre-1.0 release, not final. | `substantive` | `not_checked` |
| `untp-dcc-schema-0-7-0` | UNTP DCC JSON Schema v0.7.0 (ConformityCredential.json and ... | Schema file of the pre-1.0 release 0.7.0. | `substantive` | `not_checked` |
| `untp-vocabulary-context-0-7-0` | UNTP Core Types vocabulary and JSON-LD context 0.7.0 | Published context for the pre-1.0 0.7.0 release. | `substantive` | `not_checked` |
| `untp-dcc-wip-0-8-0` | UNTP Conformity Credential, Work in Progress (v0.8.0 artefacts, candidate ... | Draft (work in progress). | `substantive` | `not_checked` |
| `untp-dcc-0-6-x` | UNTP Digital Conformity Credential v0.6.0 / v0.6.1 (unmaintained) | Unmaintained. | `substantive` | `not_checked` |
| `untp-versions-page` | UNTP Documentation Versions page | Versions page of the project. | `substantive` | `not_checked` |
| `untp-spec-repository` | UNTP specification repository (GitLab, successor to archived GitHub repo) | Active repository. | `substantive` | `not_checked` |
| `untp-tests-issue-1096` | uncefact/tests-untp issue #1096: Track the UNTP changes since v0.7.0 and the ... | Issue tracker content, not a specification. | `secondary_only` | `not_checked` |

### 2.9 Engineering references

Raw file: `engineering-references.json`. No independent check.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `cra-reg-2024-2847` | Regulation (EU) 2024/2847 (Cyber Resilience Act) | In force since 2024-12-10. Applies in phases. | `substantive` | `not_checked` |
| `cra-commission-guidance-c2026-5252` | Commission guidance on the Cyber Resilience Act | Non-binding Commission guidance. | `metadata_only` | `not_checked` |
| `ehds-reg-2025-327` | Regulation (EU) 2025/327 (amends the Cyber Resilience Act) | In force since 2025-03-25. | `substantive` | `not_checked` |
| `asd-ste100` | ASD-STE100 Simplified Technical English, Issue 9 (Standard for Technical ... | Issue 9 exists and is the current issue offered by ASD. | `metadata_only` | `not_checked` |
| `wcag-2-2` | Web Content Accessibility Guidelines (WCAG) 2.2 | W3C Recommendation. | `metadata_only` | `not_checked` |
| `iso-iec-17025-2017` | ISO/IEC 17025:2017 | Published International Standard. | `metadata_only` | `not_checked` |
| `rfc-8785` | JSON Canonicalization Scheme (JCS) | Informational RFC. | `metadata_only` | `not_checked` |
| `rfc-9162` | Certificate Transparency Version 2.0 | Experimental RFC. | `metadata_only` | `not_checked` |
| `rfc-3161` | Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) | Proposed Standard. | `metadata_only` | `not_checked` |
| `rfc-7515` | JSON Web Signature (JWS) | Proposed Standard. | `metadata_only` | `not_checked` |
| `rfc-9052` | CBOR Object Signing and Encryption (COSE): Structures and Process | Internet Standard. | `metadata_only` | `not_checked` |
| `cyclonedx-specification` | CycloneDX Bill of Materials specification (OWASP CycloneDX; Ecma standard ... | Current specification version is 1.7. | `metadata_only` | `not_checked` |
| `iso-iec-dis-27055-claimed` | ISO/IEC DIS 27055 | Not located at the publisher. | `not_located` | `not_checked` |
| `reuse-specification` | REUSE Specification | Version 3.3 is the current specification as of 2026-10-13 on the pages read. | `metadata_only` | `not_checked` |
| `slsa-specification` | Supply-chain Levels for Software Artifacts (SLSA) specification | Version 1.2 is marked 'Approved' on slsa.dev and is the latest version listed. | `metadata_only` | `not_checked` |
| `openssf-scorecard` | OpenSSF Scorecard | Actively maintained software project. | `metadata_only` | `not_checked` |
| `openssf-best-practices-badge` | OpenSSF Best Practices Badge (formerly CII Best Practices Badge) | Active program. | `metadata_only` | `not_checked` |
| `diataxis` | Diataxis documentation framework | Maintained framework description. | `metadata_only` | `not_checked` |

### 2.10 Tools and repositories

Raw file: `tools-repos.json`. No independent check.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `aas-test-engines` | aas-test-engines (Official test tooling for the Asset Administration Shell) | Released software, latest PyPI release 1.0.3. | `substantive` | `not_checked` |
| `cir4fun-eu-github-org` | CIR4FUN-EU GitHub organization (Cir4Fun project) | Organization exists; repositories from 2026-05-21. | `substantive` | `not_checked` |
| `cir4fun-java-dpp-sdk` | java-dpp-sdk (Cir4Fun Java SDK for DPP system components) | Public repository, pre-1.0. | `substantive` | `not_checked` |
| `cir4fun-python-dpp-sdk` | python-dpp-sdk (Cir4Fun Python SDK; PyPI distribution dpp-sdk) | Published on PyPI. | `substantive` | `not_checked` |
| `cir4fun-edc-client` | edc-client (OpenAPI generated client for the Eclipse Dataspace Connector) | Public repository, not archived. | `metadata_only` | `not_checked` |
| `cir4fun-sdk-demo` | sdk-demo (interactive demo of Cir4Fun SDK components including dataspace ... | Public repository, not archived. | `metadata_only` | `not_checked` |
| `cir4fun-other-repos` | CIR4FUN-EU project information repositories | Public repositories, none archived. | `metadata_only` | `not_checked` |
| `cirpass2-test-environment-description` | CIRPASS-2 Open Source Test Environment (description report, Zenodo) | Project result. | `metadata_only` | `not_checked` |
| `cirpass2-github-repositories` | CIRPASS-2 repositories | Active public repositories. | `substantive` | `not_checked` |
| `oss4dpp-eclipse` | Open Source for the Digital Product Passport (Eclipse Foundation initiative, ... | Pre-launch initiative. | `substantive` | `not_checked` |
| `pypi-zxing-cpp` | zxing-cpp (Python bindings of the ZXing-C++ barcode library) | Released, Development Status 5 Production/Stable classifier. | `metadata_only` | `not_checked` |
| `pypi-rfc8785` | rfc8785 (pure-Python implementation of RFC 8785 JSON Canonicalization Scheme) | Released, Development Status 4 Beta. | `metadata_only` | `not_checked` |
| `pypi-pyshacl` | pySHACL (Python SHACL validator) | Released, Development Status 5 Production/Stable. | `metadata_only` | `not_checked` |
| `pypi-cryptography` | cryptography (pyca) | Released. | `metadata_only` | `not_checked` |
| `pypi-joserfc` | joserfc (JOSE RFCs implementation) | Released. | `metadata_only` | `not_checked` |
| `pypi-schemathesis` | Schemathesis (API testing from OpenAPI and GraphQL schemas) | Released, Development Status 5 Production/Stable. | `metadata_only` | `not_checked` |

### 2.11 Project resources

The synthetic rules of the project. They are not part of the audit.

| Identifier | Source | Status | Verification level | Independent check |
| --- | --- | --- | --- | --- |
| `dppce-illustrative` | dppce illustrative rules | Synthetic rules. Not a law and not a standard. | `substantive` | `not_checked` |

## 3. Differences from the project brief

The project brief made assumptions about some sources. The audit found these differences.

| Topic | Assumption in the brief | Finding of the audit |
| --- | --- | --- |
| Implementing Regulation (EU) 2026/1778 | A candidate for the implementing act of Article 77(9) of Regulation (EU) 2023/1542. | It is the registry act under Article 13(5) of Regulation (EU) 2024/1781. It is not the Article 77(9) act. Batteries of Article 77 are in its scope for registration. Two independent checks confirmed this. |
| Implementing act of Article 77(9) | The brief named Implementing Regulation (EU) 2026/1778 as the candidate. It also warned not to infer adoption from the deadline. | Not located as adopted or published as of 2026-10-13. The warning holds: the deadline of 2026-08-18 is addressed to the Commission and does not show adoption. Commission pages say that the act is in preparation. |
| EN 18216, 18219, 18220, 18221, 18222, 18223 | Standards of CEN/CLC/JTC 24. The brief gave no year. | Published by CEN and CENELEC on 2026-05-27 as the 2026 editions. Implementing Decision (EU) 2026/1736 cites the six references in the Official Journal under Regulation (EU) 2024/1781. The presumption of conformity is for Articles 10 and 11 of that Regulation. |
| EN 18239 and EN 18246 | Cited with the other six. | Published by CEN and CENELEC on 2026-09-16. No citation in the Official Journal was located as of 2026-10-13. |
| Harmonised standards for the battery passport | Not stated. | No harmonised standard for the battery passport is cited under Regulation (EU) 2023/1542. The one decision located under that Regulation, Implementing Decision (EU) 2026/2048, cites EN 18060:2025. It does not mention Article 77. |
| Dates of performance, durability, and state of health data | Later than the passport date. | Article 10(1) and Article 14 have applied since 2024-08-18. That is earlier than the passport date of 2027-02-18. |
| Amendments of Regulation (EU) 2023/1542 | An omnibus or simplification act of 2025 or 2026. | Regulation (EU) 2025/1561 moves the due diligence date only. Regulation (EU) 2026/1738 changes Annex I only. Four omnibus proposals are pending and are not law. |
| CIRPASS-2 test environment | An environment with access conditions. | Official sources describe example tools that a user deploys locally. They carry a non-normative disclaimer. No hosted instance is documented. |
| CIR4FUN-EU SDK | One SDK. | Two repositories, `java-dpp-sdk` and `python-dpp-sdk`. The Python distribution is named `dpp-sdk`. |
| Eclipse initiative on open source for the digital product passport | A project with a status, repositories, and licenses. | Only an initiative page exists. It states that no working group and no project exist yet. |
| Battery Pass resources | One data model repository and one attribute list of the Battery Pass consortium. | Two data models exist. The current attribute list comes from a successor project and shows no license. |
| UNTP Digital Conformity Credential | Version 0.7.0 and its specification repository. | Version 0.7.0 exists and is not final. Its page has the title "Conformity Credential". The former repository location is archived; a different host has the maintained one. |

The audit also confirmed one warning of the brief: the items of Annex XIII are not all due on one date.
Point 1(d) follows the due diligence date of 2027-08-18. Points 1(c) and 1(e) wait for acts that were not located as adopted.

## 4. What could not be verified

### 4.1 Law and Commission acts

- Whether a draft of the Article 77(9) act was published after September 2026. The consultation portal and the comitology register were not readable.
- The start dates of the labels of Article 13(1) to (3), of Annex XIII point 1(c), and of point 1(e). Each waits for an act that was not located as adopted.
- Whether the Commission published the due diligence guidelines of Article 48(5). None was located.
- The content of Article 57 and of Article 74(1), points (a) to (f), of Regulation (EU) 2023/1542. The audit did not read them.
- The agreed texts of the pending omnibus proposals, and their effect on Annex XIII and on Article 47.
- The moment at which a registration under Article 77(10) is due, and the data that it needs.
- The text of the standardisation request M/604. That "M/604 Amd 1" is Implementing Decision C(2025) 8024 is not confirmed.
- The reuse notice of EUR-Lex. The reuse terms for EU legal texts are stated from recall.
- Corrigenda in languages other than English. Corrigenda differ by language edition.

### 4.2 Standards

- Which requirements each standard covers. No standard was obtained or opened.
- Whether a decision that cites EN 18239:2026 and EN 18246:2026 exists. None was located.
- The meaning of "or their equivalent" in Article 77(3), and the relation of the ISO/IEC 15459 editions to EN 18219:2026 and EN 18220:2026.
- The current status of several ISO and IEC documents at the publisher. The publisher pages were not readable for some of them.
- The status of the parts of IEC 63278 that are in development. The data come from mirrors and aggregators.

### 4.3 Specifications, tools, and repositories

- The six groups without an independent check: `espr`, `identifiers-carriers`, `aas-idta`, `w3c-untp`, `engineering-references`, and `tools-repos`.
- The license terms of ASD-STE100 Issue 9 at the publisher. The publisher pages were not readable.
- Whether `aas-test-engines` works on Python 3.12 in all cases, and whether it is still maintained. Its last release is dated 2025-08-05.
- The description document of the CIRPASS-2 test environment. The file could not be parsed.
- The source `jsonschema`. No raw file has a record for it.

## 5. Reuse decisions

The versions come from `uv.lock`. The licenses come from the raw file `tools-repos.json`, unless the row says otherwise.
A decision here records the state of `pyproject.toml`. It is not a legal opinion on a license.

| Component | Decision | Version in `uv.lock` | License | Reason |
| --- | --- | --- | --- | --- |
| zxing-cpp | Reuse as an optional dependency (extra `qr`). | 3.1.1 | Apache-2.0 | The check `carrier.qr_decode` needs a QR decoder. The audit recorded a stable release and binary wheels for CPython 3.12. The core runs without it: the check is then `unsupported`. |
| aas-test-engines | Reuse as an optional dependency (extra `aas`). Wrap it; do not copy it. | 1.0.3 | Apache-2.0 from the license detection of the repository host. The package index has no license field. | The check `aas.validate` wraps it. The audit found no release since 2025-08-05 and no declared support for Python 3.12. The engine must not use its hosted validation service. |
| rfc8785 | Reuse as a core dependency. | 0.1.4 | Apache-2.0 from the classifier. The license fields of the package index are empty. | It gives the canonical JSON form of the decision body. The audit recorded a beta status and no release since 2024-09-27. |
| cryptography | Reuse as a core dependency. | 50.0.2 | Apache-2.0 OR BSD-3-Clause | The engine uses it for the encryption of records, for signature keys, and for certificate checks. |
| joserfc | Reuse as a core dependency. | 1.7.5 | BSD-3-Clause | It gives JWS Compact Serialization for the signing profile. The audit did not examine which RFCs it implements. |
| jsonschema | Reuse as a core dependency. | 4.26.0 | MIT, read from the installed package metadata on 2026-10-13. The source audit has no record for this package. | The checks `data.jsonschema` and `api.contract` use it. Its source record is missing: see the open questions. |
| pySHACL | Do not add it now. | not installed | Apache-2.0 | No registered check uses SHACL. The audit did not examine its dependency tree. Add it only with a check that needs it. |

## 6. Risk register

Each risk comes from an uncertainty of a source.

| ID | Risk | Effect on the engine | Mitigation in the catalogue |
| --- | --- | --- | --- |
| R-01 | The implementing act of Article 77(9) is not adopted. | The access rights for Annex XIII points 2 and 4 are not defined. | `EUBAT-78-B` and `EUBAT-78-F` have applicability `unknown`. No access role is encoded. Each affected entry lists the point as unresolved. |
| R-02 | The acts of Article 7, Article 8(1), and Article 13(10) are not adopted. | The start dates of Annex XIII points 1(c) and 1(e) and of the labels are not fixed. | The entries use `const: unknown` with the reason. No date is invented. |
| R-03 | The wording is paraphrase from a summarizing tool. | A draft interpretation can misstate a provision. | Every EU entry is `draft-needs-review` and runs in exploratory mode only. A human must review it with the template. |
| R-04 | The consolidated text is not authentic, and corrigenda change the meaning. | A copy of the 2023 text gives a wrong reference in Annex XIII point 1(q) and in Article 1(6). | Each entry names the consolidated version of 2026-08-13. The source record lists the corrigenda. |
| R-05 | No artifact was hashed. | The engine cannot detect that a source changed. | `sha256` is `null`. The catalogue has the date `legal_as_of`. Backlog item BL-001 is open. |
| R-06 | "Published" and "cited in the Official Journal" are confused. | A result could claim a presumption of conformity that does not exist. | The two facts are separate fields. EN 18239:2026 and EN 18246:2026 have the citation status `not_located`. |
| R-07 | The six cited standards are cited under Regulation (EU) 2024/1781, not under Regulation (EU) 2023/1542. | A battery passport result could use a presumption from a different Regulation. | The EU entries transfer no presumption. The EN entries are placeholders with no content. |
| R-08 | Four omnibus proposals are pending. One has an indicative plenary date of 2026-10-19. | Annex XIII, Article 47, or a date can change after 2026-10-13. | The proposals are sources of type `other`. No entry encodes a proposal. Check the status again before each release. |
| R-09 | The expression language has no fact for the evaluation time. The profiles have no fact for several conditions. | Applicability stays `unknown` for the items that depend on them, and the verdict is `inconclusive`. | The entries say which fact is missing. The contract changes are in the open questions. |
| R-10 | "Or their equivalent" in Article 77(3) is not defined. | The engine cannot decide whether an identifier scheme is acceptable. | `EUBAT-77-3-STD` has a manual step only. No parser check is mapped to it. |
| R-11 | The engine must not contact the Commission registry. Its own registry check reads a mock. | An automated result could look like evidence of registration. | `EUBAT-77-10` has a manual step that uses the proof of registration. The mock check is not mapped. |
| R-12 | The automated checks compare with declarations of the system owner and with synthetic resources. | A check result is not evidence for or against a legal obligation. | Each EU path has a manual step. A failed automated step gives `inconclusive`. |
| R-13 | Only three of nine groups had an independent check. | An error in an unchecked source can stay in the catalogue. | The field `independent_check` shows the state. Every EU entry rests on Regulation (EU) 2023/1542, which was checked. |
| R-14 | The public catalogue page of EN 18221:2026 lists EN 18239:2026 and EN 18246:2026 as normative references. | A cited standard has a relation to two references that are not located as cited. | The catalogue records the relation as a catalogue fact. It is an open question for the human reviewer. |
| R-15 | The reuse terms for EU legal texts are stated from recall. | A long quotation could exceed the reuse terms. | The catalogue holds paraphrase in its own words and no long quotation. |
