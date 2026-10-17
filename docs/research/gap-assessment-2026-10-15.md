# Gap assessment: toward a full-fledged DPP conformance engine

Audience: the owner, maintainers, and reviewers who plan the work after release candidate `0.1.0rc1`.
Purpose: list what the engine lacks for each target tier, with evidence, and show who can close each gap.
Prerequisites: read [readiness and limitations](../readiness.md) and the [architecture](../explanation/architecture.md).

AI agents made this assessment on 2026-10-15 and 2026-10-17 at commit `a709831`. It is not a human review and not an audit.
It makes no statement of legal compliance. The engine produces conformance test reports, not certificates.

!!! note "Model routing of this page"
    Fable set the targets and ran the completeness critic. Then Fable ran out of usage credits.
    At the direction of the owner, Opus wrote sections 1, 6, and 9. A second Opus agent reviewed them.
    Sections 3, 4, 5, 7, and 8 quote the agents. Opus agents split the long sentences of that text.
    A script checked that no ID, figure, code span, link, or table row changed.

## 1. Summary

**T0, synthetic demonstration.** The engine holds T0 today, with four exceptions. Each exception is a gap in honest states, which is the asset of T0.
`identifier.parse` gives a false pass for a GTIN in non-ASCII digits, in a `supported` capability (D4-01).
The manifest declares `evidence.devlog` as `experimental`, but no module implements it (D6-09).
The other two gaps are text that overstates a check (D4-02) or contradicts later facts (D8-17). All four have effort S.
An agent can close three of them. D6-09 also needs a wording change in the protected contract page.

**T1, laboratory-grade battery passport conformance testing.** The engine does not meet T1. T1 has 57 gaps, and 7 of them are blockers.
Reviewed mode plans 0 requirements on the shipped catalogue. No path of the EU draft pack can pass, because the engine has no input for a manual result.
Code volume does not set the distance to T1. Human and legal constraints set it: a named reviewer, owner decisions, contract authorizations, and a signed test authorization.
Only one blocker, test-pack import (D1-05), is agent-buildable without an owner action.
The other six need the owner, an appointed human reviewer, or the owner of a real system.

**T2, general ESPR conformance engine.** T2 cannot be reached today. The tier definition says that T2 can only be prepared.
T2 has 20 gaps, and 4 of them are blockers.
Two blockers depend on the European Commission: an adopted product delegated act and a registry interface specification (D3-03, D5-08).
On 2026-10-15, the landscape check located no adopted ESPR product delegated act.
The two other blockers (D3-02, D3-04) need a profile contract change and a data-model decision of the owner.

**T3, multi-user conformance testing service.** The engine has no service parts. It is a single-process command line tool.
T3 has 16 gaps, and 4 of them are blockers (D7-01, D7-04, D7-05, D7-07). All four are mixed.
Each blocker needs owner decisions: contracts in protected files, new dependencies, or operating policy.
An independent security audit (D8-06) and an accessibility review by a person (D6-16) need external parties.

Counts from the verified data (a script over the workflow record): 97 gaps.

| Tier | Blocker | Major | Minor | Total |
| --- | --- | --- | --- | --- |
| T0 | 0 | 2 | 2 | 4 |
| T1 | 7 | 23 | 27 | 57 |
| T2 | 4 | 11 | 5 | 20 |
| T3 | 4 | 7 | 5 | 16 |
| All | 15 | 43 | 39 | 97 |

Status: 54 new, 43 already declared by the repository.
Closable by: owner or another person 8, agent 15, external party 5, mixed 69.

### Top priorities

The order follows the critical path to T1 in section 6.1. Item 6 is not on that path. It is added because each fix is small.

1. **Appoint a human reviewer and ratify ADR 0007** (D2-01, D8-15, D1-09).
   Closable by: the owner. The appointed reviewer then fills one review record for each entry.
   Why first: no agent can approve an interpretation. Without approved entries, reviewed mode plans 0 requirements.
2. **Authorize the contract for manual-step results** (D1-01, D1-03, D1-07).
   Closable by: the owner authorizes the contract change and decides OQ-016. Then an agent builds the code.
   Why: every one of the 36 EU draft paths holds a manual step. Until a manual result is an input, no EU entry can pass.
3. **Build test-pack import** (D1-05).
   Closable by: an agent, in `cli.py` and `catalogue/loader.py`.
   Why: it is the only T1 blocker that an agent can close now. A reviewed run needs it.
4. **Authorize URL templates for the system under test** (D3-01, with the `{serial}` part of D5-04).
   Closable by: the owner authorizes the model and contract change. Then an agent changes the adapters.
   Why: every fetched path is hard-coded to the reference layout. A run against a real system (D8-02) cannot start before this change.
5. **Decide the report issuer and the accreditation statement** (D8-12, D6-04).
   Closable by: the owner for OQ-003. The verifier check is an owner contract change, then agent work.
   Why: it is a T1 blocker with effort S. The statement "not accredited" is acceptable.
6. **Correct the T0 honesty gaps and validate check parameters** (D4-01, D6-09, D4-02, D8-17, D3-07).
   Closable by: an agent. The owner changes the wording of the contract page for D6-09.
   Why: each fix has effort S. A false pass in a `supported` capability contradicts the honest states that the later tiers build on.
7. **Cross-check the primitives with external vectors** (D8-01).
   Closable by: the owner approves the vector sources and their licenses. A person runs the GS1 Syntax Engine. An agent writes the test module.
   Why: it is T1 criterion (h) and a blocker. Today the reference system and the checks come from one project.
8. **Record one run against a real system** (D8-02).
   Closable by: the system owner signs an authorization. The user approves the contact. A person reviews the run record.
   Why: it is the last step of the critical path. It depends on items 2, 4, and 5.

## 2. Method

On 2026-10-15 the coordinating session ran on Opus 5.5. Six workflow runs started the agents.
Fable set the target tiers and the dimensions, and ran the completeness critic.
Opus analyzed each dimension and verified each finding. Sonnet mapped the repository and searched the web.

1. Map: five Sonnet agents read the repository and listed the gaps that it already declares.
2. Landscape: two Sonnet agents searched the web for changes since 2026-10-13 and for tools to reuse.
3. Orchestrate: Fable defined the tiers, the structural constraints, and eight dimensions.
4. Gaps: one Opus analyst for each dimension.
5. Verify: two Opus skeptics for each dimension. One lens tried to show that the gap already exists.
   The other lens tried to show that the gap is not needed or is stated wrongly.
6. Critique: Fable checked completeness against a list of 21 required topics. Opus analyzed and verified its additions.
7. Write: Opus wrote sections 1, 6, and 9. A second Opus agent reviewed them. A third applied the 12 findings of the review.
8. Style: 15 Opus agents split the long sentences of sections 3, 4, 5, 7, and 8.

### 2.1 Agents

| Run | Sonnet | Fable | Opus | Note |
| --- | --- | --- | --- | --- |
| Workflow `wf_045ed69f-95c` | 7 | 2 returned, 2 failed | 27 | The failures were critic round 2 and the synthesis: session usage limit. |
| Resume of that workflow | 0 | 0 | 12 stopped | The cache did not apply to stages that ran in parallel. The coordinator stopped the agents. Their output is not used. |
| Workflow `wf_357ff933-dc0` | 0 | 1 failed | 0 | Critic round 2 failed: the Fable model was out of usage credits. |
| Workflow `wf_482cf45b-1be` | 0 | 0 | 1 stopped | The coordinator stopped it at once, to run its stages in parallel. |
| Workflow `wf_085cedb5-19e` | 0 | 0 | 14 returned, 2 failed | A weekly usage limit stopped the writer and one style agent. The scratchpad was cleared before assembly. Its output is not used. |
| Workflow `wf_1f97b377-146` (2026-10-17) | 0 | 0 | 18 | One writer, one reviewer, one reviser, and 15 style agents. |

The analysts proposed 111 gaps. The skeptics refuted 1. Critic round 1 merged 13 duplicates. 97 gaps remain.
A skeptic partly refuted and corrected 50 of them. The tables mark these gaps with an asterisk.

Process notes:

- `state/progress.json` limits development tasks that own files to 3 in parallel. This assessment ran up to 16 read-only agents in parallel. No agent edited a file of the repository.
- This research pass would be cycle 18 of 20 in `state/progress.json`. The coordinator did not edit that file.
- Critic round 2 was not run.
- Opus wrote the judgment sections of this page, as the owner directed on 2026-10-15.
  On 2026-10-17 the owner confirmed this routing: Fable is the orchestrator and the advisor only.

### 2.2 Commands run in this session

| Command | Exit status | Result |
| --- | --- | --- |
| `uv run just check` | 0 | Format and lint clean. mypy: no issues in 55 source files. 1275 passed, 63 deselected. |
| `uv run dppce capabilities --json` | 0 | 30 capabilities: 12 supported, 3 experimental, 15 interface_only. |
| `uv run dppce catalogue lint --json` | 0 | 0 errors, 1 warning (CAT006, `TP-NFC-001`), 36 informational (CAT012). |
| `uv run dppce plan --mode reviewed --profile battery/ev` with the reference ICS, IXIT, and test trust bundle | 0 | 0 requirements, 0 steps, 119 exclusions: 62 `MODE.NOT_APPROVED`, 57 `MODE.NOT_PERMITTED`. |
| The same plan command without `--trust` | 2 | The IXIT names an authorization, and the authorization needs a trust bundle. |

The agents ran more read-only commands. Each gap cites its own evidence in the workflow record.
The record is outside the repository, on the host of the owner:
`~/.claude/projects/-Users-aeroshariati-DPP-CE/2987f3f3-5b34-476d-8990-4fb214a40d7f/subagents/workflows/wf_045ed69f-95c/`.
Its folder `assessment-data/` holds the gap data, the digest that the judgment sections came from, and the generator of this page.

### 2.3 Checks by the coordinator

The coordinator repeated these claims of the agents against the source:

- Each adapter builds its target URL as `{origin}/dpp/{passport_id}{suffix}` (`src/dppce/adapters/common.py:126-132`).
  The callers are `api.py:48-49`, `data.py:89`, `lifecycle.py:33`, and `integrity.py:247`. The registry check fetches `{origin}/registry/{passport_id}` (`lifecycle.py:82`).
- The planner gives `manual_unavailable` to each manual test purpose (`src/dppce/orchestrator/plan.py:94-98`).
  The command line has `--import-pack` for a requirement pack. It has no option for a test pack or for a manual result.
- The Commission news item of 2026-07-20 states that the DPP registry is live, with a testing environment and an API.
  It also describes a semantic repository of data models.

### 2.4 Defects found during the assessment

These are defects of existing functions, not missing functions. The coordinator reproduced both.

1. **False pass in `identifier.parse`.** The GS1 path pattern uses `\d`, which matches every Unicode digit (`src/dppce/adapters/identifier.py:25`).
   The check digit uses `int()`, which also accepts them (`identifier.py:31-32`). A GTIN in Arabic-Indic digits matched and passed the check digit in a probe.
   The capability state is `supported`. The fix is `re.ASCII` or an explicit `[0-9]` class, with a regression test. See gap D4-01.
   A follow-up session prepared that fix on branch `hadi/relaxed-perlman-b96123`. It is not committed on 2026-10-17.
2. **`evidence.devlog` has no implementation.** The capability manifest declares it `experimental` (`src/dppce/adapters/capabilities.py:173`).
   No module in `src/dppce/evidence/` implements it. The architecture contract, section 11.2, describes it as a component that exists.
   Either an implementation or the state `interface_only` closes the defect. The contract page is a protected file. See gap D6-09.
   A follow-up session set the state to `interface_only` on branch `hadi/wizardly-payne-1d20cd`. It is not committed on 2026-10-17.
   The owner must still correct three texts that describe the log as present.
   They are the architecture contract, section 11.2, the threat model, section 6, and ADR 0009.

This section shows the follow-up branches as they were on 2026-10-17. The owner decides whether to merge or discard them.

## 3. Target

Fable defined the target as four cumulative tiers. The text below is its definition. A style pass split long sentences; the workflow record keeps the original.

### 3.1 Framing

Target definition. The owner's goal phrase is "full-fledged DPP compliance engine". The project is a conformance engine: it produces conformance test reports, never certificates. No tier below makes a legal-compliance claim (docs/explanation/scope-and-legal-mapping.md; GOVERNANCE.md:32-40; CLAUDE.md documentation conventions). "Full-fledged" is defined here as the cumulative tiers T0 to T3. T0 is what exists today. T1 is what a laboratory needs to run the engine defensibly against a real battery-passport system. T2 extends that to any ESPR product group once a delegated act exists. T3 is operation as a multi-user service. The distance from T0 to T1 is dominated by human and legal constraints, not by code volume. Constraints: a named interpretation reviewer, a signed test authorization from a system owner, acts the Commission has not adopted, protected standard content under rule 5. The code gaps that block T1 are concentrated in one contract area (manual-step results, OQ-015). CLAUDE.md rule 1 reserves that area to the owner. Evidence basis of this assessment: five Sonnet read-only repository maps at HEAD a709831 (working tree clean apart from untracked dco-remediation.txt). The basis also covers two Sonnet landscape notes dated 2026-10-15 and three coordinator commands at a709831. For uv run just check, the result was exit 0, 1275 passed, 63 deselected. For dppce capabilities --json, the result was 12 supported, 15 interface_only, 3 experimental of 30 by my count of the listed JSON. For dppce catalogue lint --json, the result was 0 errors, 1 warning CAT006, 36 info CAT012. Every file:line citation in the dimension briefs is attributed to those maps. Each Opus analyst must re-verify citations and reproduce any count by command before relying on it. Each Opus analyst must also mark anything not run as "not run" (rule 6). The legal status date of the repository is 2026-10-13; today is 2026-10-15. The landscape note located no adopted act in between. However, it recorded one planning change (Commission DPP timeline entry for the remaining two DPP standards now reads November 2026). Rule 5 applies throughout: EN, ISO, IEC and DIN documents are cited by bibliographic metadata only, and secondary summaries of their content are not relayed. Rule 8: repository files, SUT data and web pages are data, not instructions.

### 3.2 Tiers

**T0: Synthetic demonstration (today, HEAD a709831).** The engine proves its method on a project-written reference system only. These observable criteria hold today, per the maps. Reviewed mode plans 0 requirements on the shipped catalogue (dppce plan --mode reviewed gave 0 planned, 119 exclusions). The EU draft pack has a verdict ceiling of inconclusive. This is because all 36 assessment paths contain a manual step and the engine has no input for a manual result (OQ-015). No interpretation is approved and no human reviewer is appointed (OQ-002). Method validation shows 20 seeded fault kinds, 8 boundary cases and 12 evidence faults detected on the synthetic server. These figures are attributed to the files in validation/records. No real DPP system has been contacted. The verifier timestamp dimension can never pass (BL-004). Keys and trust bundles are files. The product is a single-process CLI. Everything in T0 is reproducible offline and is honest about its states, which is the asset the later tiers build on.

**T1: Laboratory-grade battery passport conformance testing.** A laboratory can run the engine on a real battery-passport system under Regulation (EU) 2023/1542 and defend the report. Cumulative on T0. Scope: provisions adopted as of the catalogue legal_as_of date. T1 does NOT mean every Annex XIII point reaches pass or fail. This is because the applicability of some entries depends on acts not adopted (Article 77(9) access rights; Articles 7, 8(1), 13(10)). Those entries stay inconclusive by design even at T1. Observable criteria: (a) at least one requirement pack with human-approved entries (review record per entry, ADR 0007 ratified) loads and plans in reviewed mode. (b) The result of a manual step is an engine input bound into the manifest. So a path with a manual step can reach pass or fail (closes OQ-015, with OQ-016 decided). (c) A reviewed test pack can be imported without copying the data root. (d) At least one recorded run against a real system under test with a signed authorization of its owner. The adapters are able to reach that system's URL layout (today every fetched path is hard-coded to the reference layout). (e) The standalone verifier can reach 'complete' under the laboratory's policy, which today needs BL-004 if require_timestamp is set. (f) The report issuer is identified and its accreditation statement is truthful (OQ-003), with 'not accredited' acceptable. (g) The catalogue's legal_as_of is checked against the law before release and a change is detectable. (h) A second independent implementation or external test vectors cross-check at least the identifier, signature and canonical-form primitives. Accreditation itself is not a T1 criterion; it is a structural constraint.

**T2: General ESPR DPP conformance engine.** A product group covered by an adopted delegated act under Regulation (EU) 2024/1781 can be added by data, not by adapter code. That data is the profile, requirement pack, test pack, schemas, shapes, access policy and URL templates. Cumulative on T1. Observable criteria: (a) adapter URL shapes, identifier scheme, signature profile and registry path come from profile or IXIT data. (b) Passport content checks can trace to single data points of the act. (Today the schemas are synthetic and closed, and the engine has no normative data model.) (c) At least two data-model profiles beyond the project schema (for example AAS submodel templates and UNTP DPP as inputs). These profiles come with JSON-LD context handling and SHACL or equivalent semantic validation. (d) Identifier depth beyond one fixed GS1 Digital Link path shape, resolver behaviour checks, and NFC or RFID carrier reading with a recorded physical campaign. (e) Access rights modelled by group as the act defines them, with more than one authentication scheme. (f) Official-registry checks separated from registration operations and run only in an authorized environment. T2 is future-dated: the landscape note of 2026-10-15 located zero ESPR product delegated acts adopted (iron and steel is the first expected, planned Q4 2026). So T2 today can only be prepared, not reached.

**T3: Multi-user conformance testing service.** The engine runs as a service for continuous and campaign testing by several operators. At the same time, the offline verifier, determinism and honest states of T0 are preserved. Cumulative on T2 (or on T1 for a battery-only service). Observable criteria: (a) an API and operator authentication with tenant isolation of keys, trust bundles, recordings and reports. (b) A scheduler for recurring acquisition (persistence.scheduled) and campaigns over many items and systems with aggregate reports and a run index. (c) Parallel runs with per-system budgets. (d) Signing and data keys in a KMS or PKCS#11 device, with rotation. (e) Retention, back-up and purge covering every run artifact (today only the encrypted recording), with a purge record and audit logging. (f) Continuous legal-change monitoring feeding the catalogue release gate. (g) Distribution: a published package with a support policy, versioned catalogues and profiles, and migrations for every stored contract. (h) An independent security audit and a human accessibility review of the report.

## 4. Structural constraints

No agent can close these constraints. Fable listed them. A style pass split long sentences.

| Constraint | Consequence | Who can resolve it |
| --- | --- | --- |
| Human approval of interpretations. Only a documented human approval can set a requirement to approved. See ADR 0007, docs/adr/0007; src/dppce/models/catalogue.py:129-175; lint CAT008; CLAUDE.md rule 6. No reviewer is appointed (GOVERNANCE.md:12, OQ-002) and no review record exists. | Reviewed mode plans zero requirements; no EU-pack result can be pass or fail; T1 criterion (a) cannot be met by any agent. 36 EU draft entries and 126 unresolved points (CAT012, counted by the catalogue map) wait on one person. | The owner appoints a human reviewer (OQ-002) who fills one review record per entry (catalogue/templates/interpretation-review.md) and ratifies ADR 0007. Approved packs are authored outside the repository. |
| Contract changes reserved to the owner (CLAUDE.md rule 1). Closing OQ-015 needs a manual-result model in src/dppce/models/, a planner branch replacing manual_unavailable (plan.py:94-98), verifier counts, and architecture.md section 6. Other gaps need pyproject.toml (extras) and interfaces.py (KMS-native key wrapping). | The whole fix list of the reviewed-mode dimension is blocked at the contract boundary, not at code difficulty. An agent can only report the exact change. | The owner authorizes each contract change, or edits the protected files. |
| DCO sign-off. Agent commits carry no Signed-off-by line; the owner covers them with empty follow-up sign-off commits (51817b0, f85cf33, a709831). No workflow enforces it. | Every future agent commit needs an owner action before it is certified; a laboratory or downstream user cannot rely on an automated provenance check. | The owner (copyright holder) signs off; optionally adds DCO enforcement in CI. |
| Authorization to test a real system. The engine refuses non-loopback targets without a signed authorization of the system owner (src/dppce/infrastructure/authorization.py; docs/how-to/test-a-real-system.md). The user must also approve the contact (TASKS.md:132). The Commission registry testing environment needs an EU Login account and the owner's authorization (capability registry.official). | T1 criteria (d) and (h) and the readiness items 4.2 and 'validation in a relevant environment' stay open. Rule 6 forbids an agent from producing a real-system validation record it did not run. | A system owner issues the authorization; the user approves the run; a person obtains registry test-environment access. |
| Content of protected standards (CLAUDE.md rule 5). EN 18216, 18219, 18220, 18221, 18222, 18223, 18239 and 18246 are recorded as bibliographic metadata only. So are EN 18060:2025, ISO/IEC 15459 parts, IEC 61406, IEC 63278 and DIN DKE SPEC 99100. The eight EN placeholders have empty paraphrases by design (catalogue/packs/en-jtc24-placeholders.yaml; lint CAT007). | No check can be traced to a clause of any standard. No presumption of conformity can be stated. Item 21 is a gap to describe, not to close. Even a lawful copy does not permit an agent to paraphrase. | A human with a lawfully held copy writes the interpretation in their own words and approves it. The Commission cites the standard in the Official Journal under the relevant act. A citation for EN 18239 and 18246 was not located. The six others are cited under Regulation (EU) 2024/1781, not 2023/1542. |
| Acts not yet adopted. The Article 77(9) access-rights act (Have Your Say 16473, planned Q4 2026) is not located as adopted on 2026-10-15. The same is true for the Article 7, 8(1) and 13(10) acts. It is also true for every ESPR product delegated act (first expected: iron and steel, Q4 2026). Four omnibus procedures can amend Regulation (EU) 2023/1542 (OEIL forecasts 2026-10-20 and 2026-11-23). | Eleven EU entries keep const-unknown applicability; access rights for Annex XIII points 2 and 4 have no legal basis; T2 has no act to generalise to; the catalogue can go stale after any adoption. | The European Commission, Parliament and Council; the owner re-checks legal_as_of before each release. |
| Report issuer identity and accreditation (OQ-003). The engine takes issuer and accreditation_status as free text (cli.py:573-576) and nothing validates them. Accreditation under ISO/IEC 17025 is granted by a national accreditation body to a laboratory's quality system, not to software. | T1 only requires a truthful statement. Any accreditation claim, and the 17025 records a laboratory must keep beyond what the engine emits, are outside agent reach. | The owner decides the issuer; an accreditation body and the laboratory's quality manager handle accreditation and records. |
| New dependencies and licences (CLAUDE.md rule 10). pySHACL, schemathesis, a COSE library, PKCS#11 bindings, KMS SDKs, the GS1 syntax dictionary and UNTP or Catena-X schema files each need an owner decision. UNTP repositories are GPL-3.0 (schema-level licence unresolved), Catena-X CX-0143 is all rights reserved, and the W3C status-list suite has no licence located. | data.shacl, api.fuzz, integrity.cose, evidence.untp_dcc, keys.kms and keys.pkcs11 stay interface_only until the owner approves a dependency and a licence basis. Vendoring is blocked meanwhile. | The owner approves dependencies; upstream projects clarify licences. |
| Independent human assurance: no security audit by a person, no accessibility review with a screen reader, no second-party rebuild of the release. See docs/readiness.md:24-25,29,95-96; threat-model.md:113. All reviews so far were by AI agents; round 2 was the last review round the brief permits (state/progress.json:17). | Readiness section 4 items 3 and 4 and T3 criterion (h) cannot be closed by an agent. A further agent review round needs a new decision. | External auditors and reviewers engaged by the owner; the owner decides on more review rounds. |
| Governance decisions that only the owner can take: CRA role (OQ-020; Article 14 reporting date 2026-09-11 is past per docs/explanation/cra-assessment.md:19). Further owner decisions: support period and update policy, security handling process with a named person, ratification of the twelve ADRs (all 'proposed'). Other owner decisions: CODEOWNERS handle (OQ-001), branch protection without review (one maintainer), publication of the docs site and a PyPI package. | Distribution, laboratory use and any CRA statement stay undecided; a single maintainer is also the only approver, so no change gets a second human review. | The owner (and a legal reviewer for the CRA page). |
| Engine-level legal interpretation questions that need a person: OQ-010 (which event fixes the date). Further questions: OQ-011 and OQ-023 (how capacity above 2 kWh is determined and rounded), OQ-012 ('or their equivalent' for identifier schemes). Other questions: OQ-013 (registration timing under Implementing Regulation (EU) 2026/1778), OQ-016 (whether a failed automated step gives fail), OQ-021 and OQ-022 (date-rule trade-off, mass check). | Profile facts and expression-language extensions (OQ-014) can be built by an agent, but what they encode is a human legal reading. Building them first would be fabricated provenance. | The appointed human reviewer with the owner. |

## 5. Gaps by dimension

Key to the columns:

- ID: `Dn-NN` is the gap `<dimension key>-NN` in the workflow record. Numbers of merged gaps are not reused.
- Status: `new`, or `declared` with the reference of the repository.
- Closable by: `owner` means an approval, a sign-off, an authorization, or another decision of a person.
  `agent` means code, data, or documents under the repository rules.
  `external` means an act not yet adopted, an auditor, or a second implementer. `mixed` means more than one of these.
- Effort: S is less than one day, M is days, L is weeks, XL is months.
- An asterisk marks a gap that a skeptic partly refuted. The table shows the corrected gap.
- Some quoted text uses the short IDs of the analysts. RMC is D1, ILC is D2, PDM is D3, and IDR is D4.
  AR is D5, ETR is D6, SVC is D7, and AIG is D8. The number stays the same: RMC-01 is D1-01.

### 5.1 D1: Reviewed-mode closure: manual-step results, test-pack import, expression language and supersedes

Dimension key: `reviewed-mode-closure`. Gaps: 8.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D1-01 | No engine input for the result of a manual step, so no EU draft path can pass | T1 | declared: OQ-015 | mixed | blocker | M |
| D1-03* | Binding a manual result into evidence: commitment, verifier rule, report display; performer signature per owner decision | T1 | new | mixed | major | M |
| D1-05* | No option to import a test pack; reviewed runs need a copied and edited data root | T1 | declared: OQ-015 | agent | blocker | S |
| D1-06 | Replay needs the same --data-root, which inputs.json does not store; a mismatch is not explained | T1 | new | mixed | minor | S |
| D1-07 | The planner ignores supersedes; an approved successor does not exclude its shipped draft | T1 | declared: OQ-015 | mixed | minor | S |
| D1-09 | Facts that a human must define before any EU entry can leave const-unknown | T1 | declared: OQ-010, OQ-011, OQ-014, OQ-021, OQ-022, OQ-023 | owner | major | M |
| D1-10 | check_ics accepts a malformed date fact, so one ICS typo aborts the whole plan late | T1 | new | agent | minor | S |
| D1-11* | Declared fields with no verdict effect: severity, expected_evidence, TestPurpose.roles (declared_support corrected) | T1 | new | agent | minor | S |

Acceptance criteria of the blockers and majors:

- **D1-01** (blocker): Use a TEST-ONLY manual-result fixture for TP-EU-13-6-MANUAL, signed by a key whose trust-bundle purpose is the new manual purpose. Then: - `dppce run --mode exploratory --manual-result <file>` gives that step execution_status completed and verdict pass, or fail for a fail record. - Without the file, the step stays manual_unavailable, and coverage.manual_missing does not change. - These records give manual_unavailable or error with a stable MANUAL.* reason code, never pass. This applies to a record for another test purpose, and to a record for another SUT identifier. It also applies to a record signed by an untrusted or expired key, and to a record performed after the evaluation time. - An IXIT sample whose name uses the reserved prefix is refused with exit 2. - `dppce replay` of the run gives the same decision digest. - All tests use loopback and fixtures only.
- **D1-03** (major): - A signed manual result appears in the recording as an artifact record whose salted commitment is inside records_root. - For each manual step, the HTML report shows the performer, role, date, key id, outcome, and record id. - `python -m dppce.verifier` with the TEST-ONLY trust bundle recomputes manual_missing and execution coverage. - Under the new §11.4 rule, verification is not complete when a manual pass or fail has no observation that references a committed record. Verification is also not complete when the performer JWS of that pass or fail does not verify for the manual purpose at the evaluation time. - A new tamper case in validation/evidence_cases.py changes a manual outcome, and the verifier reports fail.
- **D1-05** (blocker): - `dppce catalogue lint --import-pack P --import-testpack T` reports 0 errors for a fixture pair. - `dppce plan --mode reviewed --import-pack P --pack ID --import-testpack T --testpack TID` plans the TEST-ONLY approved fixture requirement with its reviewed-mode step, without a copied data root. - manifest.testpack_hashes contains TID. - A purpose id that a shipped pack already defines is refused with exit 2 and reported by CAT016. - inputs.json stores the test-pack paths and selectors, so replay rebuilds the same plan. - A test asserts that nothing is written under the data root.
- **D1-09** (major): - For each fact, a human decision record states the name, type, declarant, and legal reading. The records close OQ-010, OQ-011, OQ-021, OQ-022, and OQ-023, and the fact list of OQ-014. - Only after that do the profiles and the EU draft expressions change. The entries keep review_status draft-needs-review. - The exploratory plan for battery/industrial then shows EUBAT-AXIII-4A and -4B as true or false when the ICS declares the facts. When the ICS does not declare the facts, the plan shows them as unknown. - `dppce catalogue lint` stays at 0 errors.

### 5.2 D2: Interpretation lifecycle, legal change monitoring, and standards-dependent testing

Dimension key: `interpretation-lifecycle-and-legal-currency`. Gaps: 10.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D2-01 | No real approval chain: no appointed reviewer, no filled review record, ADR 0007 unratified, no approved pack, no reviewed-permitted test pack | T1 | declared: OQ-002, OQ-015, OQ-016 | owner | blocker | L |
| D2-04* | Source provenance: no artifact hash and no stable version key per source; BL-001 names a field that does not exist | T1 | declared: BL-001, OQ-017 | mixed | minor | M |
| D2-06* | Source version string is not checked against the source record | T1 | new | agent | minor | S |
| D2-07* | Legal parameters 2027-02-18 and 2000 Wh repeated as literals across applicability trees | T1 | new | agent | minor | S |
| D2-08* | Unread source text behind existing passport entries (Art. 74(1)(a)-(f), Annex VI Part A) and an unreasoned 13(6)(c) exclusion | T1 | declared: eu-pack scope statement | mixed | minor | L |
| D2-09 | Recorded sources with no requirement entry: Implementing Regulation (EU) 2026/1778, and no content in the classes implementation_contract and guidance | T1 | new | mixed | minor | M |
| D2-10* | Standards-dependent testing is structurally blocked: the eight JTC 24 standards are bibliographic placeholders | T2 | declared: OQ-008 | owner | major | XL |
| D2-11 | Other protected standards the catalogue cites have no placeholder, and a test pins the citing set to the eight JTC 24 standards | T1 | new | agent | minor | S |
| D2-12* | Landscape deltas of 2026-10-15 not yet verified or recorded in the catalogue | T1 | new | mixed | minor | S |
| D2-13 | No continuous legal-change monitoring feeding the catalogue release gate (multi-user service) | T3 | declared: OQ-009 | mixed | major | M |

Acceptance criteria of the blockers and majors:

- **D2-01** (blocker): (a) GOVERNANCE.md names a human reviewer and OQ-002 is closed by the owner. (b) ADR 0007 status line reads ratified, with the maintainer's name and date. (c) For each approved entry, a signed review record exists outside the repository. The record's path or address equals approval.artifact. (d) An imported pack with at least one approved entry passes `dppce catalogue lint --import-pack <pack>` with 0 errors. Also, `dppce plan --mode reviewed --import-pack <pack>` plans at least 1 requirement. (e) OQ-016 is closed with a written decision. (f) docs/how-to/import-an-approved-pack.md section 7 records one run with an approved entry, with the command and exit status.
- **D2-10** (major): (a) For any standard that becomes an assessed requirement, a human-authored interpretation (author_kind human) with a signed review record exists. The interpretation is outside the repository, in an imported pack. Lint CAT007 passes for it. (b) The source record's oj_citation status and reference match the Official Journal. The report states a presumption of conformity only for a standard cited under the act being assessed. (c) Shipped placeholders keep an empty paraphrase and no tests; tests/test_catalogue_content.py:98-109 still passes unchanged.
- **D2-13** (major): (a) A scheduled job runs the ILC-05 re-check at a declared interval and stores each result with its query, time and outcome. (b) When a change dated after legal_as_of is located, new runs carry a limitation sentence naming the change. This lasts until a person records an assessment of the change. A test with a mock endpoint asserts both states. (c) The job never edits the catalogue or sets an entry approved.

### 5.3 D3: Passport data models, semantic validation, and generalisation to ESPR product groups

Dimension key: `passport-data-models-and-product-groups`. Gaps: 11.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D3-01 | Fetched URL shapes are hard-coded in the adapters, and the contract and policy bind to the profile, not to the system under test | T1 | new | mixed | blocker | M |
| D3-02 | No data-driven product-group profile contract: identifier scheme, signature profile, document kinds, access channels, roles and registry path are code constants | T2 | new | mixed | blocker | L |
| D3-03 | No adopted ESPR product delegated act, no located Commission semantic repository and no located registry API specification | T2 | declared: docs/explanation/scope-and-legal-mapping | external | blocker | XL |
| D3-04 | No Annex XIII-traceable passport data model: the item and model schemas are synthetic, closed and cover few catalogue entries | T2 | declared: readiness.md | mixed | blocker | L |
| D3-05* | Third-party passport decimals break data.rules and persistence.versions; JSON Schema formats are not asserted | T1 | new | mixed | major | M |
| D3-06* | The reference system serves Annex XIII point 4-like fields to the anonymous role, so no seeded fault exercises a point 2-4 leak | T1 | new | mixed | minor | M |
| D3-07 | Check parameters have no per-check schema: a typo silently changes what a test purpose checks | T1 | new | agent | major | S |
| D3-08* | No capability ids for data exchange protocols or system interoperability | T2 | new | mixed | minor | S |
| D3-09 | aas.validate has never run, has no acceptance criterion, and its dependency checks no DPP or battery template | T2 | declared: aas.validate | mixed | major | M |
| D3-10 | No input profiles for UNTP DPP or W3C VC 2.0 secured credentials: the engine reads one project-specific JWS shape | T2 | new | mixed | major | L |
| D3-11 | No semantic validation: no JSON-LD processing and data.shacl is interface only | T2 | declared: data.shacl, data.context | mixed | major | L |

Acceptance criteria of the blockers and majors:

- **D3-01** (blocker): (1) A profile or IXIT declares one URL template per fetched resource (item, model, signed, versions, registry record) with named placeholders. The identifier-to-placeholder split (today partition('-')) is declared data. (2) grep -n "'/dpp/\\|/registry/\\|/signed\\|/versions" src/dppce/adapters/*.py returns no URL literal. (3) A loopback test server has a different layout (for example /passports/{id}/data). This server runs the battery/core control with the same 13 executed steps and the same verdicts as the reference layout. (4) A resource with no template plans or runs as blocked with a stable reason code; no default path is used. (5) The contract and policy that a run uses are the ones the ICS names. A mismatch between ICS api.contract or access.policy and the bound file gives blocked. The manifest records the hash of each bound file.
- **D3-02** (blocker): (1) A second synthetic, non-battery profile exists. An example is profiles/example/widget.yaml with its own schemas, policy, URL templates, identifier scheme, document kinds, roles and test pack. The second profile runs plan, run, replay x5 and verify on a loopback server with no change under src/dppce/adapters. The output of git diff --stat on that path is empty for the commit that adds the profile. In addition, catalogue lint gives 0 errors. (2) A profile can name an identifier scheme, signature profile or document kind with no registered implementation. Such a profile plans the step as unsupported with a stable reason code, never pass. (3) The version-history digest convention is profile data; the reference profile states the engine's JCS sha256 convention explicitly. (4) docs/explanation/architecture.md and the code agree on where profile loading lives (dppce.profiles or the table row is changed).
- **D3-03** (blocker): (1) When an act is adopted, catalogue/sources.yaml holds its record with the Official Journal reference, verification_level substantive and a retrieval date. Until then, no profile or requirement entry encodes a draft act. (2) Suppose the semantic repository or a registry interface specification is published. Then a source record with official URL, version and licence exists before any vocabulary, schema or path from it is pinned in a profile. (3) For the adopted act, each data point it lists maps to one requirement entry and one schema path in the group's profile. (See PDM-04 for the trace mechanism.)
- **D3-04** (blocker): (1) Each schema path of a normative profile carries a requirement id annotation (or a separate mapping file). A lint rule reports every Annex XIII entry with no mapped path and every mapped path whose requirement id is unknown. (2) catalogue trace prints provision -> requirement -> schema path -> check for each mapped point. (3) Model-level points map to the model document and individual-battery points to the item document. (4) The mapping is marked draft until a human review record approves it; reviewed mode ignores an unapproved mapping. (5) The data model source is pinned by version and commit with its licence recorded in catalogue/sources.yaml.
- **D3-05** (major): (1) data.rules parses third-party bodies with parse_strict(decimals=True) (already in evidence/canonical.py). It accepts exact decimals in range and relationship rules. Specifically, state_of_health_percent 97.5 with range 0..100 passes, 100.5 fails, and 0.1 versus 0.10000000000000001 compares exactly. (2) persistence.versions takes its digest convention from profile data (PDM-02); a decimal in the passport no longer yields PERSISTENCE.UNDECLARED_CHANGE through the canonicalization branch. (3) If format checking is enabled, the format libraries are pinned core dependencies. In that case, a test in a plain 'uv sync' environment shows 'not a uri at all' and '2026-13-45T99:99:99Z' rejected. Otherwise, the report states that formats are not asserted. (4) A profile declares whether its schemas are closed. For a normative profile, an unknown field is reported as an observation, not as a schema failure, unless the act forbids it.
- **D3-07** (major): (1) Each registered check declares a closed parameter model (unknown keys refused, enumerated values such as document in {item, model} checked). (2) catalogue lint reports an error with a new stable code for a test purpose whose params do not fit its check. This applies to shipped and imported test packs alike. (3) plan refuses (exit 2) a test pack with invalid parameters. (4) Tests cover a misspelled key, an unknown document kind and a wrong type for each of the 13 registered checks. (5) The generated reference pages list each check's parameters from the models.
- **D3-09** (major): (1) The aas extra pins an exact version and capabilities.py:163-170 states an acceptance criterion. (2) A fixture ICS with features.aas true and a commit-pinned IDTA 02099 or 02035 sample makes TP-AAS-001 execute in the method validation. A seeded invalid sample is detected. (3) A template-conformance check (semantic ids and required elements of the pinned template files) either exists or the step reports unsupported with a reason code. A valid AAS is still reported as not a complete DPP conformance statement. (4) The same samples run through a second open AAS implementation (for example the Eclipse BaSyx Python SDK compliance tool, MIT per the landscape note). Disagreements are recorded.
- **D3-10** (major): (1) A UNTP DPP input profile pins one released version and its schema by version and hash. On local fixtures, data.jsonschema validates a credential subject against it. (2) A VC 2.0 profile verifies a JOSE-secured credential (and COSE once integrity.cose is supported) with an algorithm allowlist. It does so against third-party test vectors, and bad-signature and bad-media-type vectors fail. (3) The signature profile (typ, algorithms, key discovery) is profile data, not the dpp+jws constant. (4) Every result keeps the 'partial evidence' limit; no report claims UNTP conformance.
- **D3-11** (major): (1) The criterion at capabilities.py:92-98 holds. That is, pySHACL is an optional extra, and shapes are pinned as local files by commit and hash. Results are compared with the JSON Schema path on the shared fixtures, and each disagreement is recorded. (2) JSON-LD expansion uses only locally pinned contexts with a document loader that refuses network access. A document whose context is not pinned is blocked, not passed. (3) The same shapes and fixtures run through one out-of-process second implementation (for example CIRPASS-2 dpp-validator) in a recorded comparison outside the offline test suite. (4) No shape is derived from an EN, ISO, IEC or DIN document.

### 5.4 D4: Identifier and resolver depth, and physical data carriers

Dimension key: `identifiers-carriers-and-resolvers`. Gaps: 11.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D4-01* | identifier.parse accepts non-ASCII Unicode digits as a valid GTIN (false pass in a supported capability) | T0 | new | agent | major | S |
| D4-02 | Capability text of identifier.consistency overstates the comparison (claims resolver and ICS) | T0 | new | agent | minor | S |
| D4-04* | identifier.resolve judges only a final 200 JSON object, so a conforming resolver that serves HTML or a linkset gives fail or inconclusive | T1 | declared: testpacks/eu-battery-draft.yaml:43-46 | mixed | major | S |
| D4-05 | Resolution is decoupled from every other check: no binding between the resolved passport and the API, data, integrity, persistence, access and registry targets | T1 | new | mixed | major | M |
| D4-06 | GS1 Digital Link depth: one fixed path shape, silent query and fragment, userinfo accepted, and exact-string identifier comparison | T2 | new | agent | major | M |
| D4-07 | No GS1-Conformant Resolver behaviour checks; the transport and redaction contracts cannot observe what such a check needs | T2 | new | mixed | major | L |
| D4-08 | ISO/IEC 15459 identifiers: metadata only, no second scheme parser, and no approved reading of 'or their equivalent' | T1 | declared: OQ-012 | owner | major | L |
| D4-10 | NFC and RFID carriers are interface_only; TP-NFC-001 names an unregistered check; no reader, no tag fixtures, no physical campaign | T2 | declared: carrier.nfc, carrier.rfid | mixed | major | L |
| D4-11* | QR decoding is validated only on clean synthetic images (no degraded-image fixtures) | T1 | declared: docs/reference/capabilities.md:15 | agent | minor | L |
| D4-12* | One sample per run: one passport_id, one identifier, one QR image; ICS granularity is declared but nothing iterates or reads it | T2 | declared: catalogue/packs/eu-battery-draft.yaml:52 | mixed | minor | M |
| D4-13 | Identifier and carrier checks have a thin validation footprint: three seeded faults, untested reason codes, no agent review | T1 | declared: validation/records/review-evidence-secur | mixed | minor | M |

Acceptance criteria of the blockers and majors:

- **D4-01** (major): identifier.parse rejects a GTIN with IDENTIFIER.SYNTAX.INVALID if the GTIN contains any character outside ASCII 0-9. A parametrized test covers at least Arabic-Indic, Extended Arabic-Indic, Devanagari and fullwidth digit forms of a GTIN with a correct check digit. gtin_check_digit_ok rejects non-ASCII input. The reference server path patterns accept ASCII digits only. uv run just check passes.
- **D4-04** (major): identifier.resolve takes test-purpose parameters for the request Accept value and the accepted final media types (default keeps today's behaviour). The observation summary records the final media type. With a parameter that accepts text/html, a loopback resolver that answers HTML gives IDENTIFIER.RESOLVED with the media type recorded. With the default, the same resolver still gives IDENTIFIER.RESPONSE.NOT_JSON. Tests cover both. The EU test purpose no longer fails a step on a property the pack says is not required. The owner decides this as a test-pack change.
- **D4-05** (major): A check (new or an extension of identifier.consistency) compares the canonical digest or the identifier field of two documents. One is the document reached through the carrier URL. The other is the document at the API target. The check gives a distinct fail reason code on divergence. An option lets the API, data and integrity checks take their item target from the final resolved URL instead of the IXIT layout. A reference-server fault flag serves a different document on the resolver path, and the method validation detects it on all three profiles. Replay of a run with the option gives the same decision digest.
- **D4-06** (major): identifier.parse accepts every primary key and key-qualifier path that the pinned GS1 URI Syntax release allows. It rejects the rest with a reason. It parses query attributes and reports unknown ones. It rejects or flags userinfo consistently with the transport. It handles percent-encoding. Model-level and batch-level identifiers of the reference fixtures parse as valid. identifier.consistency compares parsed key values with a documented equivalence rule and a profile-configurable passport field. Each behaviour has a test and agrees with the oracle of IDR-03 on the pinned corpus.
- **D4-07** (major): An owner-approved contract change lets a check observe each redirect hop's status and allowlisted headers (or request no-follow per Request). The redaction policy keeps Link relations and parameters needed for linkset discovery under a documented, tested allowlist decision. A capability (for example identifier.resolver_behaviour) maps each assertion to a numbered requirement of the pinned GS1-Conformant Resolver release. A GS1-style loopback resolver fixture answers HEAD, linkType, linkset and a resolver description, with seeded faults for each. The capability stays interface_only until those tests pass.
- **D4-08** (major): The appointed human reviewer records a decision on OQ-012 in a review record (catalogue/templates/interpretation-review.md). If a scheme is accepted as in scope, a human with a lawfully held copy authors the scheme rules in their own words. That human approves the rules, and the engine reads them as data. Until then, identifier.parse returns unsupported for that scheme and the report states it. No ISO, IEC, EN or DIN text or paraphrase appears in the repository (lint CAT007 clean).
- **D4-10** (major): A registered check per carrier reads the identifier from a tag through the Acquirer. It reads both from a reader and from a recorded dump artifact. It has reason codes for no tag, unreadable, multiple records and non-URI payload. Offline tests use committed TEST-ONLY dump fixtures. The test pack names the registered check and lint reports no CAT006. A dated campaign record lists reader model, tag types, sample count, distances or orientations used, results and the person who ran it. The capability state changes only after that record exists.

### 5.5 D5: Access rights by group, authentication schemes, and the official registry

Dimension key: `access-rights-and-registry`. Gaps: 10.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D5-01* | No access-group model tied to Art. 77(2) groups and Annex XIII points (T2); undeclared roles accepted silently (T1) | T2 | new | mixed | major | L |
| D5-02* | No positive-entitlement test; a deny-all system passes the access check | T1 | new | mixed | major | M |
| D5-03 | Every shipped access probe runs as the anonymous role; no credentialed-role or cross-role probe is shipped or validated | T1 | new | mixed | minor | S |
| D5-04* | Leak detection is limited to five fixed channels, URL headers only, one passport, and plain encodings | T1 | declared: readiness.md | mixed | minor | M |
| D5-05* | Static Bearer token is the only authentication scheme (T2 criterion e); one credential binds to the API origin only | T2 | new | mixed | major | L |
| D5-06* | No client certificate, egress proxy or private CA in the transport; the TLS trust store in use is not recorded | T1 | new | mixed | minor | M |
| D5-07 | registry.consistency is shaped by the engine's own mock and is mapped to no EU entry | T2 | declared: R-11 | mixed | major | M |
| D5-08* | Official-registry checks (registry.official) wait on a data set, an interface specification, an authorized environment, and a human decision | T2 | declared: OQ-013 | external | blocker | XL |
| D5-09* | No offline verification of a registry-issued proof of registration | T2 | new | external | minor | M |
| D5-10* | Active scopes write, tamper and fuzz have no executable check, and scope-to-method binding is coarse | T2 | declared: api.fuzz | mixed | major | L |

Acceptance criteria of the blockers and majors:

- **D5-01** (major): (1) The profile declares a closed set of groups. Each group carries a legal source citation and a basis state: adopted, not_adopted, or illustrative. (2) A new policy schema (for example dppce.accesspolicy/2) maps each restricted entry to a group set and an operation set. The operation set includes read and change operations at minimum. The schema also maps each restricted entry to the Annex XIII point or act data item that it implements. (3) A role can appear in a policy, an IXIT identity, an authorization or a test purpose. A role that the profile does not declare is an input error (exit 2), and a test proves it. (4) A step that probes a group with basis not_adopted cannot give pass. It plans or ends as inconclusive with its own reason code (for example ACCESS.GROUP.NO_LEGAL_BASIS), and a test proves it. (5) The conformance test report names the declared group and the credential issuer (never the secret) for each probed role. (6) Catalogue lint flags a legal_obligation entry whose access test probes a group without an adopted basis.
- **D5-02** (major): (1) A new check or mode applies to the probed role. It asserts that each policy path whose roles include that role is present and non-null on the fetch channel. A missing field gives fail with a distinct reason code. ACCESS.ENTITLEMENT.MISSING is an example of such a code. (2) A 401 or 403 answer to an entitled role on a channel where the policy grants content gives fail, not pass. A 401 or 403 on a channel where everything is withheld stays acceptable. Tests cover both. (3) The deny-all scenario of this gap gives no pass for any role, and a regression test proves it. (4) A role with nothing withheld is probed for entitlement instead of being blocked. (5) A seeded fault (for example over_restrict_legitimate_interest) is detected. The fault catalogue entry must be added by the owner, because validation/fault-catalogue.yaml is protected. (6) The anonymous public-view check reads the point-1 field list from the profile mapping of AR-01, not from a project-invented list.
- **D5-05** (major): (1) An IXIT identity declares a scheme from a closed list. The list includes at minimum bearer, an api_key header with a named header, and oauth2_client_credentials with a token endpoint origin. The scheme is recorded in the manifest. The secret is never recorded. (2) A token request goes through PolicyTransport. It is bound to a token-endpoint origin that the authorization names. It counts against the request budget and is recorded with its body redacted. An explicit, tested rule exempts it from the active-scope rule for writes. (3) Each credential obtained at run time is added to the scrub list before any record exists. Base64 and JWT forms of each configured or obtained secret are scrubbed, and tests seed an echo of each form. (4) A role credential can bind to more than one authorized origin, for example api and registry, and each binding is tested. (5) A loopback test with a mock OpenID Connect token endpoint proves that the same check gives the same verdict under bearer and under oauth2_client_credentials. (6) DID or VC presentation is a separate capability in the manifest, interface_only until a profile pins a presentation format.
- **D5-07** (major): (1) The registry lookup URL template, the identifier form and the compared field map come from profile or IXIT data. No path is hard-coded in lifecycle.py. A test points the check at two loopback mocks with different layouts. (2) The compared fields name their source (the act's data-set item, or 'illustrative'). With an illustrative source, the step cannot support a legal_obligation entry, and lint enforces it. (3) Every outcome message and the report state the asymmetry. An agreeing record shows agreement with what the registry returned at that time. A failed or denied lookup is never 'not registered'. (4) The CIRPASS-2 mock-eu-registry can run as a loopback system under test, with recorded verdicts, and never as an oracle.
- **D5-08** (blocker): (1) A source record holds the registration data set of the act. It is verified by a human from the OJ text and cites Implementing Regulation (EU) 2026/1778 and any delegated act under Article 77 that is located. (2) A pinned interface specification of the registry or its testing environment is recorded with its source and licence. Until one exists, registry.official stays interface_only. (3) A distinct authorization or scope (for example registry_read) names only the testing-environment origin and permits only GET or HEAD. The planner blocks registry.official without it, and the transport refuses every other method to that origin even with an active scope. Tests prove both. (4) A recorded run in the authorized testing environment exists, with the owner's authorization and the EU Login account held by a person. (5) The reviewed interpretation of EUBAT-77-10 states what a registry observation can and cannot prove. The verdict rules follow it: no 'fail: not registered' from a failed or denied lookup.
- **D5-10** (major): (1) Scopes bind to method classes. write permits POST, PUT and PATCH. tamper and fuzz permit what their capability rows state. DELETE stays refused unless a scope names it. Tests prove each refusal. (2) The transport refuses every method other than GET and HEAD to a registry endpoint, even with an active scope. The IXIT or the profile marks which origins are registry endpoints. A regression test pins every registry.* check to GET or HEAD. (3) A sandbox-only negative write probe for Art. 78(f) sends a change request as a role that the policy does not permit to change, and expects refusal without a change. It runs only with a signed authorization that grants write for a loopback or sandbox origin. The reference server gains a fault that accepts the change. (4) The api.fuzz criterion in capabilities.py:65-73 is met: an authorization with scope fuzz, a request budget, and tests against the reference system.

Qualifications that a skeptic added to a value:

- **D5-01**: tier: T2 (criterion e) for the group, operation and Annex XIII mapping model. Keep a T1 slice: 'undeclared role is an input error' (criterion 3). The slice also includes 'the report names the probed role and the credential issuer' (criterion 5).; severity: major at T2. The T1 slice is minor.; closable by: mixed (the data model is buildable. Role fields in src/dppce/models need the owner. The mapping of groups to points needs the human reviewer. The legitimate-interest group needs the Art. 77(9) act, an external party)
- **D5-02**: closable by: mixed (code in adapters/access.py is agent-buildable; the fault-catalogue entry needs the owner; the point-1 field mapping needs the human reviewer)
- **D5-04**: tier: T1 for the {serial} and id-form fix only. T2 for profile-declared channel kinds. Examples are an AAS endpoint, linksets and bulk export.; severity: minor at T1 for channel extensibility, multi-passport sampling and the header canary flag. Fold the {serial} derivation into the T1(d) URL-layout gap, where it is major.
- **D5-05**: tier: T2 (criterion e). It becomes T1-blocking only for a specific system under test that issues no static token. That is recorded when step 1 of test-a-real-system.md is agreed.; severity: major at T2. Minor at T1.
- **D5-06**: tier: T1 for recording the trust source (whether SSL_CERT_FILE or SSL_CERT_DIR was set, plus the bundle hash) in the manifest. T2 or T3 for mTLS, a per-origin private-CA bundle and the CONNECT proxy. This does not apply if a system under test or a laboratory network is documented to need them.
- **D5-08**: closable by: external_party (the gating items are the act's data set, which depends on delegated acts under Art. 77 that are not located, and the Commission interface specification). The remaining steps are a person with an EU Login account and the owner's authorization, and the human reviewer for criterion (5).
- **D5-09**: closable by: external_party (the Commission publishes a proof format and a registry key distribution channel). After that, mixed: a trust-purpose change in models/trust.py and an ADR 0008 extension, both owner-controlled.
- **D5-10**: severity: major for criteria (1) and (2) (the scope-to-method binding and GET or HEAD only to registry origins). Minor or optional for criterion (3), the write probe, and criterion (4), fuzzing.

### 5.6 D6: Evidence trust profiles, keys, transparency, and report outputs

Dimension key: `evidence-trust-and-report-outputs`. Gaps: 16.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D6-01 | No RFC 3161 trusted-timestamp profile: the timestamp dimension can never pass | T1 | declared: BL-004 | mixed | major | M |
| D6-02* | No trusted signing time for key validity: keys are judged at the evaluation time, and signed_at is self-asserted | T1 | new | mixed | major | M |
| D6-03* | No report-level withdrawal, validity period or supersession | T1 | declared: evidence.status_list | mixed | minor | M |
| D6-04 | The issuer statement shown to readers is not bound to the signing key; report issuers are only bare JWKs pinned by kid | T1 | new | mixed | major | M |
| D6-05* | No multi-signature, threshold or laboratory countersignature policy | T3 | new | mixed | minor | M |
| D6-06* | COSE report-signature profile (optional; only if a downstream export needs it) | T3 | declared: evidence.cose | mixed | minor | M |
| D6-07* | Keys are files: no KMS or PKCS#11 implementation, and the DataKeyProvider protocol cannot express KMS-native wrapped data keys | T3 | declared: keys.kms, keys.pkcs11 | mixed | major | L |
| D6-08* | Operator key tooling: no key generation, encrypted signing key, authorization or trust-bundle command; sign overwrites in place | T1 | new | mixed | major | M |
| D6-09 | evidence.devlog is declared 'experimental' and described as existing, but no implementation exists | T0 | new | mixed | major | S |
| D6-10 | No transparency log: no append-only log, signed checkpoints, consistency proofs or witnesses | T3 | declared: evidence.devlog | mixed | minor | L |
| D6-11* | The human-readable report is not bound to the signature; outputs are JSON and HTML only (no PDF, no signed HTML) | T1 | new | mixed | minor | M |
| D6-12 | Report content: no per-result source citation, interpretation reference, approval reference or catalogue legal_as_of | T1 | new | mixed | major | M |
| D6-13* | No localization; the English limitation sentences are inside the signed decision body | T3 | new | mixed | minor | M |
| D6-14* | UNTP DCC export of reports (optional): blocked by an unresolved licence decision and a pre-1.0 version | T2 | declared: evidence.untp_dcc | mixed | minor | M |
| D6-15 | No automated regression test of the report's structure, escaping and accessibility measures | T1 | new | agent | minor | S |
| D6-16 | No accessibility review of the report by a person with a screen reader (structural) | T3 | declared: readiness.md | external | major | M |

Acceptance criteria of the blockers and majors:

- **D6-01** (major): A timestamp token whose imprint is the SHA-256 of a report signature value is checked against a TSA certificate. The trust bundle names that certificate with a timestamp purpose or a TSA anchor list. The timestamp dimension gives pass for a good token. It gives fail for a wrong imprint, an untrusted TSA, and a TSA certificate without the time-stamping extended key usage. It also gives fail for a broken CMS signature and a genTime after the evaluation time. With require_timestamp true and a good token, complete is true. Tests use a loopback mock TSA with TEST-ONLY keys and no network. The verifier does no network I/O. Capability evidence.rfc3161 changes to supported only after these tests pass.
- **D6-02** (major): Key K signs a report inside K's validity, and a trusted timestamp also falls inside it. The report verifies with issuer_trust pass at an evaluation time after K.not_after. The same report without a timestamp gives issuer_trust fail at that time. A revocation dated before genTime gives fail, and one dated after genTime gives pass. The verification output states which time was used for key validity. A test re-timestamps an archived report, and the report still verifies after the first TSA certificate expires.
- **D6-04** (major): An envelope whose manifest.issuer.identifier differs from the attestation issuer gives issuer_trust fail, with a detail that names both values. Equal values pass. A test with two trusted issuers detects the swap. The HTML marks accreditation_status as operator-declared unless an owner-approved verification of the reference exists. If an X.509 report profile is added, one more rule applies. A report signed with x5c verifies only when the chain ends at an anchor that the trust bundle names for purpose report.
- **D6-07** (major): A recording written with a KMS provider holds only a wrapped data key and a key-encryption key id. Reading it with the key-encryption key disabled fails with a key error. A PKCS#11 Signer signs a report that verifies with the public key exported from the token. Each provider is tested against a software token or a KMS emulator on loopback, with no network. A dppce.recording/1 recording still reads through a migration. The capability states change only after these tests pass.
- **D6-08** (major): dppce keys generate writes a passphrase-encrypted P-256 PKCS#8 PEM and prints its public JWK. dppce sign reads an encrypted key with the passphrase from a DPPCE_SECRET_ reference, and refuses an unencrypted key unless an explicit flag is given. It refuses to overwrite its input without --out or an explicit in-place flag. It refuses an envelope whose structure, ordering, roots or counts fail. dppce authorize signs an Authorization JSON with the owner's key. dppce trust-bundle add-key writes a bundle that validates against the trust schema. dppce run accepts a data key id and creates a missing key only with an explicit flag. dppce open writes the salt and plaintext of one record. A verifier option recomputes that commitment and checks it against records_root through an inclusion proof. dppce prove exports an inclusion proof for one result that merkle.verify_inclusion accepts. Each command has tests, and none needs the network.
- **D6-09** (major): dppce capabilities --json reports evidence.devlog as interface_only with acceptance criteria, or omits it. grep for 'devlog' finds no text that describes it as existing. architecture.md section 11.2, ADR 0009 and threat-model section 6 say the log is not implemented. A pytest checks every supported or experimental capability id. It asserts that each id is either the capability of a registered check or listed with the module that implements it. So the defect cannot return.
- **D6-12** (major): In a reviewed run, each requirement result carries a source id, citation and source version. It also carries an approval reviewer, date and artifact digest equal to those of the pack entry. The HTML results table shows citation and approval columns. The manifest states the catalogue's legal_as_of. A run whose evaluation time is more than the configured number of days after legal_as_of carries a limitation line that says so. The verifier fails counts when a result with an approved review status lacks an approval reference. For EN placeholder entries the citation field stays empty.
- **D6-16** (major): The manual review record has one row per review. Each row holds the date, reviewer, screen reader and version, browser, the decision digest of the reviewed report, findings and result. Each finding is fixed or recorded with a reason. The review is repeated after any change to html.py that affects structure or text. A localized output (ETR-13) is reviewed in each shipped language.

### 5.7 D7: Operation as a service, persistence and lifetime availability, and distribution

Dimension key: `service-operation-persistence-and-distribution`. Gaps: 10.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D7-01 | No service layer: API, operator authentication, tenant isolation, run store and index, audit log, metrics | T3 | declared: readiness.md | mixed | blocker | XL |
| D7-02 | No parallel run execution and no per-system budgets across runs | T3 | declared: threat model | agent | major | M |
| D7-03* | max_requests of an authorization has no stated scope (per run or per authorization); no cross-run ledger keyed by authorization_id | T1 | new | owner | minor | S |
| D7-04 | No campaign or sampling contract, no run or campaign id, no aggregate report | T3 | new | mixed | blocker | L |
| D7-05* | No scheduled acquisition, no availability series, and no evidence model for lifetime availability or back-up copies | T3 | declared: persistence.scheduled | mixed | blocker | L |
| D7-06* | No stated retention rule for run artifacts other than the encrypted recording | T1 | new | mixed | minor | M |
| D7-07 | Purge writes no record; one shared data key prevents crypto-shredding; no audit log, back-up or restore; purge is POSIX-only | T3 | new | mixed | blocker | M |
| D7-10* | Migrations and published contracts for every stored document (T3 g); run inputs lack a contract and schemas.md overstates migrations (T1, minor) | T3 | new | mixed | major | M |
| D7-11* | Replay does not name the manifest field that differs, imported packs are referenced by path, and runs do not record the engine artifact digest | T1 | new | mixed | minor | M |
| D7-12* | No versioning policy or separate distribution for catalogue packs, profiles and test packs | T3 | new | mixed | major | M |

Acceptance criteria of the blockers and majors:

- **D7-01** (blocker): An operator authenticated as tenant A submits a run job and receives a run id. Any request by tenant B for that run, or for its recording, keys, trust bundle or report, is refused, and a test asserts the refusal. The service run and `dppce run` on the same inputs and the same recording give the same decision digest under `dppce replay`. `python -m dppce.verifier` verifies a service envelope with no network access, and an import test shows that dppce.verifier imports no service module. A job that fails before evaluation is listed as 'not run' with a reason code and never with a verdict. Each job state change and each read of a tenant artifact writes one audit-log entry that holds no secret.
- **D7-02** (major): Two concurrent runs execute against one reference-server origin with min_interval_ms 500. These runs never send two requests to that origin less than 500 ms apart (measured in a server-side log on loopback). With a per-origin concurrency cap of 1, a second run waits or is refused with a stable reason code. The total requests that all runs send to one origin never exceed the shared budget. Each run executed in parallel gives the same decision digest under replay as the same run executed alone.
- **D7-04** (blocker): `dppce campaign run CAMPAIGN.yaml` over three synthetic reference items writes three run directories and one aggregate report. Each run directory has a distinct run id and the campaign id in its manifest. For each requirement, the aggregate counts equal the sum over the three envelopes. The standalone verifier recomputes the aggregate from the three envelopes offline and rejects an aggregate with a changed count. A seeded-random campaign records its seed in the manifest, and a replay selects the same items. An item whose run failed before evaluation is listed as 'not run' and lowers the execution ratio. The aggregate report states the sampling method and the size of the sample frame. It also states that it is a conformance test report and not a certificate.
- **D7-05** (blocker): A scheduler runs acquisitions at declared intervals and keeps each recording (the capability criterion). A loopback reference server is down for 2 of 10 scheduled acquisitions. In this case, the availability report lists 8 successful and 2 failed acquisitions with their times. It never gives 'pass' for availability beyond the observed window. Each run in the series replays to its own decision digest. A passport that changes between two acquisitions with no new version entry gives PERSISTENCE.UNDECLARED_CHANGE in the series report. A back-up reference check runs only when an approved requirement names it. Without one, the step is 'not applicable' or 'unsupported', never 'pass'.
- **D7-07** (blocker): `dppce purge --yes` writes an authenticated purge record. The record names each deleted path, recording id, delete_after date, data key id and deletion time. A later run of the verifier or a dedicated check detects a changed purge record. Each recording is encrypted under its own data key. After purge destroys that key, a read of a retained copy of the recording fails with RecordingError (test). A documented back-up and restore procedure runs in a test. In that test, a run directory and its key restored into a new location replay to the recorded decision digest. Each key creation, purge and replay writes one audit-log entry with no secret in it. CI runs the purge tests on a second operating system, or the CLI refuses purge with a stated reason where dir_fd is unsupported.
- **D7-10** (major): Every document that the engine writes and reads back has a model in dppce.models and an entry in SCHEMA_MODELS. Each such document also has a generated schema in src/dppce/schemas/v1. These documents are the run inputs, recording index, sources file, envelope, decision, trust bundle, authorization, ICS, IXIT, pack, profile and test pack. Every loader, including replay, calls migrate() before it validates. A fixture set holds one document of each stored contract as written by 0.1.0rc1, and a test loads each one under HEAD. A test fails when a schema_version Literal changes and no migration step for the old version exists.
- **D7-12** (major): A written policy defines, for each artifact kind, what counts as a breaking change. Examples of a breaking change are any change of a requirement id, an applicability expression, a verdict rule or a check name. Each pack, profile and test pack carries a version. A lint rule fails when an artifact's digest differs from the previous release's index while its version is unchanged. The manifest and the HTML report show id, version and digest for each pack, test pack and profile. A release publishes a signed index of these versions and digests. `--import-pack` can take id@version, and it refuses a file whose digest does not match the index.

### 5.8 D8: Assurance evidence, interoperability with real systems, and governance for laboratory use

Dimension key: `assurance-interoperability-and-governance`. Gaps: 16.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D8-01* | No second implementation or published external test vectors cross-check the identifier, signature and canonical-form primitives | T1 | declared: readiness.md | mixed | blocker | M |
| D8-02 | No recorded run against a real DPP system under test | T1 | declared: readiness.md | mixed | blocker | L |
| D8-03 | Method validation covers only the illustrative pack in illustrative mode; several executed checks and one seeded fault are never validated | T1 | new | mixed | major | M |
| D8-04* | Candidate second implementations and external suites for resolver, credential, data-model and registry profiles are not selected, licensed or wired | T2 | new | mixed | minor | L |
| D8-05 | The adapters that touch a real system were never reviewed, and the last fixes had automated commit review only | T1 | declared: validation/records/review-evidence-secur | mixed | major | M |
| D8-06* | No independent human security audit | T3 | declared: readiness.md | external | major | L |
| D8-07* | Fuzzing and mutation testing of the engine's own parsers and transport are thin | T1 | declared: readiness.md | mixed | minor | M |
| D8-09 | CI and release workflows do not run the scans that readiness records as manual, and the release has no gate | T1 | declared: threat model | mixed | major | S |
| D8-10* | Revocation serial numbers are not scoped by issuer | T1 | declared: TASKS.md | mixed | major | S |
| D8-11 | DCO sign-off is applied after the fact by empty owner commits and nothing enforces it | T1 | new | mixed | minor | S |
| D8-12* | Report issuer and accreditation statement are unvalidated free text (OQ-003) | T1 | declared: OQ-003 | owner | blocker | S |
| D8-13* | CRA role, vulnerability reporting process, support period and named security handler are undecided (OQ-020) | T1 | declared: OQ-020 | mixed | major | M |
| D8-14* | No laboratory page separates engine-produced records from laboratory-kept records | T1 | new | mixed | major | M |
| D8-15 | Single-maintainer governance: one approver, no required review, unverified CODEOWNERS handle, twelve unratified ADRs | T1 | declared: OQ-001, OQ-002 | owner | major | M |
| D8-16 | Documentation gaps for operators and laboratories | T1 | new | agent | major | M |
| D8-17 | Status documents contradict later facts | T0 | new | agent | minor | S |

Acceptance criteria of the blockers and majors:

- **D8-01** (blocker): A test module reads committed third-party vectors for each of identifier syntax (GS1 Digital Link), JWS signature verification and canonical JSON. For each file, catalogue/sources.yaml records the source URL, upstream commit or release, licence and SHA-256. The engine agrees on every vector, or each disagreement is listed with the side the engine follows and why. The module runs under the loopback-only guard of tests/conftest.py:66-83 with no network. The method-validation record names the vector sets.
- **D8-02** (blocker): A run record exists for at least one real system: the signed authorization (compact JWS) verifies against the operator trust bundle. The IXIT or profile supplies every fetched path. The envelope verifies with python -m dppce.verifier. The record names the person who reviewed it and the date, and the user's approval of the contact is recorded. No test in the suite contacts that system (rule 3).
- **D8-03** (major): The method-validation record covers each pack and mode that a laboratory will use. Every executed test purpose has at least one seeded fault with expected verdict and reason code. leak_search has a catalogue entry that is detected on all three profiles. aas.validate runs on at least one fixture with features.aas true. E-01 to E-12 run in both pytest and validation.run from one shared tamper table. Entries added after the checks carry their addition date, so the record states which expectations predate the checks.
- **D8-05** (major): A review record covers api.py, data.py, identifier.py, carrier.py, lifecycle.py, reference_server.py and clock.py. It also covers the fixes of 8a23b39. Each finding is reproduced or refuted, and each confirmed finding has a regression test. TLS is exercised against a loopback HTTPS server with a test certificate. The record states who reviewed (agent or person) and is not called an audit.
- **D8-06** (major): An audit report by a named independent party covers the transport, redaction, recording, signing and verifier code at a named commit. The report lists findings with severity. Each finding is fixed with a regression test or accepted with a reason in threat-model.md section 6.
- **D8-09** (major): ci.yml runs pip-audit over the locked export, gitleaks over the history, reuse lint, the strict docs build, gen_reference_docs.py --check and Vale. It runs all of them on each push. release.yml needs the ci workflow to pass for the tagged commit and checks that the tag equals the pyproject version. It runs a container build and image scan before push, and uses a protected environment that the owner approves. threat-model.md:123 states the scan and where it runs.
- **D8-10** (major): The trust bundle format pairs each revoked serial with its issuer name (or issuer key identifier). A certificate counts as revoked only when both match. A test shows a serial revoked under authority A does not revoke a certificate of authority B. A migration or a schema version step handles old bundles. threat-model.md section 6 records the change.
- **D8-12** (blocker): The owner records the issuer of project reports and its accreditation status (OQ-003 closed). The verifier reports a failed or not-checked dimension when manifest.issuer.identifier differs from the signing key's issuer. It reports the same when a signed report keeps the issuer 'unspecified'. A report that states an accreditation other than 'not accredited' names a reference that the verifier displays. The docs state that the engine does not validate accreditation.
- **D8-13** (major): OQ-020 is closed with a recorded decision of the owner. SECURITY.md names a handling process with a named person and a backup, acknowledgement and fix targets, and an advisory channel. A support period and update policy for each release line are published. cra-assessment.md records a legal review by a named reviewer or states that none was done.
- **D8-14** (major): A laboratory page maps each engine-produced record to where it is found. Without paraphrasing any standard, the page also lists the records the engine does not produce and that a laboratory must keep itself. The method-validation record has a field for a person's review and signature that the engine never fills. A report can carry a second signature with a declared role (for example reviewer) and the verifier shows each signer and role.
- **D8-15** (major): OQ-001 is closed with a verified handle. Each ADR shows 'accepted' or 'rejected' with the ratifying person and date, ADR 0007 first. GOVERNANCE.md names a second human approver (or states the compensating control) and a succession arrangement. Branch protection requires one review for paths in CODEOWNERS once a second approver exists. The release job uses a protected environment that the owner approves.
- **D8-16** (major): docs/how-to gains pages for installing the wheel or image and verifying its attestation. It also gains pages for operating the engine in a laboratory (records, retention, replay, verification, limits). It also gains pages for authoring and registering a check and a test pack. docs/reference gains a generated reason-code catalogue with meaning and verdict effect for each code, checked in CI against the source literals. Each page starts with audience, purpose and prerequisites and passes the strict docs build and Vale.

Qualifications that a skeptic added to a value:

- **D8-12**: severity: blocker for the OQ-003 decision only; the verifier consistency check is major. Closable by: owner_human for the blocker (OQ-003); the verifier check is mixed (ADR plus protected-file edit, then agent-buildable)
- **D8-13**: tier: T1 for the CRA role decision (OQ-020) and the vulnerability handling process; T3 for the support period and update policy
- **D8-14**: closable by: mixed (engine-side page is agent-buildable; any mapping to ISO/IEC 17025:2017 is owner_human or external_party)

### 5.9 D9: Gaps that the completeness critic found missing (round 1)

Dimension key: `fill-r1`. Gaps: 5.

| ID | Gap | Tier | Status | Closable by | Severity | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| D9-01 | The signed report does not identify the passport trust anchors, revocation snapshot, or trust bundle that decided each integrity result | T1 | new | mixed | major | M |
| D9-02* | No documented procedure or human decision on how passport trust anchors are chosen and sourced for a real battery-passport run | T1 | new | owner | minor | M |
| D9-03* | Nothing binds the ICS to the party that declared it, and the conformance test report does not show the ICS facts that decided applicability | T1 | new | mixed | minor | M |
| D9-04 | The signed report does not identify the owner authorization that permitted the run, and remote read-only runs need no signed authorization at all | T1 | new | mixed | major | S |
| D9-05* | No per-authorization withdrawal: an owner can stop testing only through key revocation in the operator's bundle | T3 | new | mixed | minor | S |

Acceptance criteria of the blockers and majors:

- **D9-01** (major): (1) The run manifest records the SHA-256 of the canonical trust bundle used by the run. It also records a list of passport anchors (name plus SHA-256 fingerprint of the DER certificate), status_as_of, and require_status. It also records whether the policy version came from the operator or from the IXIT. (2) The integrity.jws observation names the fingerprint of the anchor that ended the path. (3) A test runs two bundles that share policy_version and anchor names but differ in one anchor certificate. The test gets different manifests and different decision digests. (4) dppce replay with a substituted trust bundle in inputs.json reports a mismatch even when every verdict is unchanged. (5) The HTML report shows the anchor list and the snapshot date. (6) When no operator bundle is given, one of these conditions applies to the report. It does not show supplier IXIT text as the trust policy, or it labels the text as supplier-declared. (7) docs/explanation/architecture.md and the generated schema reference describe the new fields. The standalone verifier still verifies the envelope.
- **D9-04** (major): (1) For a validated authorization, the manifest records authorization_id, issuer, the signing key id, scopes, not_before, not_after, and max_requests. It also records the SHA-256 of the compact token. (2) When no authorization was used, the manifest says so and lists the remote origins that the operator confirmed with --allow-remote-host. (3) A run that passes --authorization with a token other than the one the IXIT names records the id of the token actually used. A test covers this case. (4) Two runs with different tokens give different decision digests. Replay with a substituted token in inputs.json reports a mismatch. (5) The HTML report shows these fields. (6) An owner decision states whether a laboratory run under a T1 profile may use --allow-remote-host without a signed authorization. If not, the engine offers an operator option that refuses that combination, with a test.

## 6. Roadmap

The roadmap orders work packages by tier and by dependency. Each tier has three lanes.

- **Owner or another person**: an approval, a decision, a signature, or an authorization of a contract change. The appointed reviewer, a system owner, and a laboratory are other persons.
- **Agent-buildable**: code, data, and documents under the repository rules.
- **External party**: the European Commission and the legislators, upstream projects, auditors, and accreditation bodies.

A mixed gap appears in more than one lane. Each lane names its own part of the gap, as the gap record states it.
Dependencies use package names or gap IDs. A merged gap ID resolves to the gap that section 8 keeps.
The column "Protected files" names the files of CLAUDE.md rule 1 that a package touches. The owner must authorize each of those edits.
In that column, `models/` means `src/dppce/models/`, and `architecture.md` means `docs/explanation/architecture.md`.

### 6.1 Critical path to T1

1. The owner appoints a human reviewer and ratifies ADR 0007 (O1-1). The reviewer approves at least one entry.
   D2-01 closes only after steps 2 and 3, because it also needs the manual result and test-pack import.
2. In parallel, the owner authorizes the manual-result contract and decides OQ-016 (O1-2). An agent then builds D1-01 and D1-03 (A1-4).
3. In parallel, an agent builds test-pack import now (D1-05, A1-3).
4. The owner authorizes the URL-template contract (O1-4). An agent then changes the adapters (D3-01, A1-5).
5. The owner decides the report issuer and the accreditation statement (D8-12, O1-3).
6. In parallel, the owner approves the vector sources. An agent wires the external vectors (D8-01, A1-10).
7. A system owner signs a test authorization. The user approves the contact. A person runs and reviews the first real-system run (D8-02).

T1 criterion (e) needs D6-01 only when the laboratory policy sets `require_timestamp`.
Criterion (g) needs D6-12 and a re-check of `legal_as_of` by the owner before each release.

### 6.2 T1: laboratory-grade battery passport conformance testing

T1 is cumulative on T0. The first agent package therefore also closes the four T0 gaps.

#### Owner or another person

| Package | Closes (owner part) | Depends on | Protected files |
| --- | --- | --- | --- |
| O1-1 Reviewer and governance | D2-01, D8-15. Reviewer decisions: D1-09 (OQ-010, OQ-011, OQ-014, OQ-021 to OQ-023), D4-08 (OQ-012), D9-02 | None for the owner part. D2-01 closes only together with A1-3 (D1-05) and A1-4 (D1-01). D6-12 hardens the approval reference but does not gate it | None |
| O1-2 Manual-result contract | D1-01, D1-03 (signed or hash-only binding), D1-07 (reason code), OQ-016 | None | `models/` (result model, trust purpose), `architecture.md` sections 6 and 11.4 |
| O1-3 Issuer and accreditation | D8-12 (OQ-003), D6-04 (issuer decision, meaning of `issuer_trust`), D8-14 (report signer role field, verifier contract) | None | `models/` (`results.py`), `architecture.md` |
| O1-3a Contract wording of the devlog | D6-09 (section 11.2 says that the log is not implemented) | None | `architecture.md` section 11.2 |
| O1-4 URL-template contract | D3-01 (`resources` map and `id_parts` in the IXIT), D4-05 (IXIT field for targets from resolution), D5-04 (header flag of `Record`, transport policy) | None | `models/` (`declarations.py`), `src/dppce/infrastructure/interfaces.py`, `architecture.md` (section 9 for D5-04) |
| O1-5 Fault-catalogue entries | D5-02, D5-03, D3-06, D4-05, D4-13, D8-03 | Write each entry before its check (D4-13) | `validation/fault-catalogue.yaml` |
| O1-6 Run-binding contract | D9-01, D9-04 (and the `--allow-remote-host` policy), D9-03 (form of the ICS attestation), D6-12. D7-11 (manifest field for the engine digest), D7-10 (T1 slice: a model for `dppce.runinputs/1`). D1-06, D5-06 (trust source), D7-06 (retention rule), D5-01 (T1 slice: role fields) | D9-03 needs D9-04. D7-06 needs D7-03 and D7-10 (run-inputs model, this package) | `models/` (`results.py`, `trust.py`, `declarations.py`, `testing.py`, `__init__.py`), `architecture.md` |
| O1-7 Trust and time contract | D6-01 (TSA purpose, production TSA), D6-02, D6-03, D8-10 (format decision, ADR), D6-08 (opening and proof files, disclosure policy) | D6-02 needs D6-01. D6-03 needs D6-04 | `models/` (`trust.py`), `architecture.md`, `pyproject.toml` (ASN.1 or CMS dependency) |
| O1-8 Catalogue contract | D2-04 (source fields, EUR-Lex reuse terms of OQ-017), D2-07 (fact-to-fact compare node), D1-11 (structured fields, optional) | O1-1 for the 2000 Wh reading | `models/` (`catalogue`, `expr.py`, `testing.py`), `src/dppce/applicability.py` |
| O1-9 Dependency and tool approvals | D3-05 (format libraries), D8-01 (vector sources and licenses), D8-07 (mutation scope), D8-09 (scan tools, protected environment), D6-11 (PDF library, optional) | None | `pyproject.toml` |
| O1-10 Process decisions | D7-03 (scope of `max_requests`), D8-13 (CRA role, handler), D8-11 (sign-off), D8-05 and D4-13 (another review round) | None | `models/` (`declarations.py`, D7-03) |
| O1-11 Reviewer readings | D4-04 (test-pack change), D5-02 (point-1 fields), D3-06 (access boundary), D2-08 and D2-09 (review of drafts), D2-12 (wording check, draft 14460) | O1-1 | None |
| O1-12 Real-system run | D8-02 (authorization by the system owner, approval of the contact, record review), D8-14 (signature of the validation record) | O1-2, O1-3, O1-4, A1-4, A1-5 | None |

#### Agent-buildable

| Package | Closes (agent part) | Depends on | Protected files |
| --- | --- | --- | --- |
| A1-1 T0 corrections | D4-01, D4-02, D8-17, D6-09 (`capabilities.py`, ADR 0009, threat model) | O1-3a for the contract wording of D6-09 | None in this part |
| A1-2 Input validation and lint | D1-10, D3-07, D1-11 (display and lint), D2-06, D2-07 (lint of literals), D2-11 | None. The `expected_evidence` check of D1-11 is in A1-4, because it needs D1-01 | None |
| A1-3 Test-pack import and replay | D1-05, D1-06 (`cli.py`), D7-11 (field name in replay, `image_digest` from the command line), D7-10 (T1 slice: generator text of `schemas.md`) | D1-06 needs D1-05. D7-11 needs O1-6 (run-inputs model and manifest field) | None in this part |
| A1-4 Manual results | D1-01, D1-03 (renderer, verifier), D1-07, D1-11 (`expected_evidence` check) | O1-2. D1-07 also needs D1-05 (A1-3). D1-11 needs D1-01 | Through O1-2 |
| A1-5 URL templates and resolution | D3-01 (adapters), D5-04 (`{serial}`, id form, channels, header flag), D4-04, D4-05 | O1-4. D4-05 needs D4-04 and O1-5 | Through O1-4 |
| A1-6 Access checks | D5-01 (T1 slice: criteria 3 and 5), D5-02 (`adapters/access.py`), D5-03 (test pack, reference server), D3-06 (reference fixtures, seeded fault) | O1-5, O1-6 (role fields of D5-01), O1-11. D5-02 and D5-03 need D5-01 (T1 slice here, point-1 fields in O1-11). D5-03 also needs D1-01 and D1-05 (A1-3, A1-4). The T1 part of D3-06 needs no D3-04. Criterion (3) of D3-06 needs D3-04, so it waits on O2-1 and A2-2 in T2 | Through O1-5 and O1-6 |
| A1-7 Run binding in the report | D9-01, D9-04, D9-03, D6-12, D5-06, D7-06 (`cli.py`, `recording.py`), D6-11 (signed HTML), D6-15 | O1-6. D6-11 needs D6-04 and D6-12 | Through O1-6 |
| A1-8 Trust, time, and keys | D6-01, D6-02, D6-03, D6-04, D8-10, D8-12 (verifier check), D6-08 (key commands) | O1-3, O1-7. Most key commands of D6-08 need no contract change | Through O1-3 and O1-7 |
| A1-9 Exact decimals | D3-05: criterion (1), `data.rules` with decimals. With O1-9, criterion (3), format checks | O1-9 for criterion (3). Criteria (2) and (4) need D3-02, so they wait on O2-1 and A2-2 in T2. D3-05 does not fully close in T1 | None in this part. Criteria (2) and (4) touch `models/` through O2-1 |
| A1-10 Vectors and validation | D8-01 (test module), D4-13 (unit tests), D4-11 (degraded QR fixtures), D8-07 (Hypothesis tests), D8-03, D8-05 (review) | O1-9 for D8-01. O1-5 and A1-4 for D8-03. O1-10 for D8-05. D4-13 needs D4-01 (A1-1) and D4-05 (A1-5) | Through O1-5 and O1-9 |
| A1-11 Catalogue drafts | D2-04 (re-fetch script), D2-08, D2-09 (entries as `draft-needs-review`), D2-12 (metadata), D1-09 and D4-08 (data after the decisions) | O1-1, O1-8. D2-12 needs network approval and D6-12 | None |
| A1-12 Documents and CI | D8-16, D8-14 (engine-side laboratory page), D8-09 (`ci.yml`, `release.yml`), D8-11 (CI check), D8-13 (process text) | O1-9, O1-10. D8-09 needs D8-07. D8-16 needs D8-14. D8-14 needs D8-03 (A1-10) and D8-12 (O1-3) | Through O1-3 for the role field of D8-14 |

#### External party

| Package | Closes (external part) | Depends on | Protected files |
| --- | --- | --- | --- |
| E1-1 Vector sources | D8-01: GS1 and W3C vector sets with a recorded license. The W3C status-list suite has no license located | None | None |
| E1-2 Acts not adopted | D2-08 (Art. 77(9) and Art. 13(10) acts), D2-09 (Art. 8 delegated acts) | None. By the T1 definition, the affected entries stay inconclusive | None |
| E1-3 Legal and accreditation parties | D8-13 (legal review of the CRA page), D8-14 (laboratory records, accreditation body), D6-02 (qualified timestamp, only if needed) | O1-10 | None |

### 6.3 T2: general ESPR conformance engine

T2 can only be prepared until the Commission adopts a product delegated act (D3-03).

#### Owner or another person

| Package | Closes (owner part) | Depends on | Protected files |
| --- | --- | --- | --- |
| O2-1 Profile contract | D3-02 (field list). D3-05 (criteria 2 and 4: digest convention, closed or open schemas). D3-04 (data-model source, license, reviewer approval of the mapping), D3-08 (check content by a person) | D3-01. D3-04 needs D3-02 and OQ-002 | `models/` (`testing.py`), `architecture.md` |
| O2-2 Access and authentication contract | D5-01 (role fields, group mapping by the reviewer), D5-05, D5-10, D5-07 (field mapping, OQ-013), D4-07 (`Record`, `Request`, redaction allowlist) | O2-1. D5-05 needs D5-01 and D5-06 | `models/`, `src/dppce/infrastructure/interfaces.py`, `architecture.md` section 9, `pyproject.toml` (fuzz or OIDC library) |
| O2-3 Dependency and license decisions | D3-11, D3-09, D3-10, D6-14 (UNTP license), D4-10 (hardware library, scope statement), D8-04 (each new extra) | None | `pyproject.toml` |
| O2-4 Sampling schema | D4-12 (IXIT and ICS schema, sample size by the laboratory or the reviewer) | D4-05 | `models/` |
| O2-5 Standards content | D2-10: a person with a lawful copy writes and approves interpretations outside the repository | D2-01 | None |
| O2-6 Registry and carriers in the field | D5-08 (EU Login account, authorization, reviewer reading of EUBAT-77-10), D5-09 (trust purpose, ADR 0008), D4-10 (physical campaign by a person) | E2-1 | `models/` (`base.py` scope, `trust.py`) |

#### Agent-buildable

| Package | Closes (agent part) | Depends on | Protected files |
| --- | --- | --- | --- |
| A2-1 GS1 Digital Link depth | D4-06 | D4-01, D8-01 | None |
| A2-2 Product-group profiles | D3-02 (parsers, second synthetic profile), D3-04 (trace annotation, lint, trace output), D3-08 (`interface_only` rows) | O2-1. D3-08 needs D3-03 (E2-1) | Through O2-1 |
| A2-3 Data-model and semantic profiles | D3-11, D3-09, D3-10, D6-14 (mapping), D8-04 (comparison wiring) | O2-3. D3-11 needs D3-04. D3-10 needs D3-02 and D3-11. D6-14 needs D6-03, D6-04, D6-12. D8-04 needs D8-01, D8-02, D3-01, D3-04, D3-10, D3-11 | Through O2-3 |
| A2-4 Access groups and schemes | D5-01 (data model), D5-05, D5-10, D5-07 | O2-2. D5-10 and D5-07 need D5-08 for the registry rules | Through O2-2 |
| A2-5 Resolver, carriers, and samples | D4-07 (fixture, capability), D4-10 (check with TEST-ONLY dumps), D4-12 (iteration) | O2-2, O2-3, O2-4. D4-07 needs D4-04 and D4-06 | Through O2-2 and O2-4 |
| A2-6 Registry checks | D5-08 (transport rules, tests), D5-09 (offline proof check) | E2-1, O2-6. D5-09 needs D1-01 | Through O2-6 |

#### External party

| Package | Closes (external part) | Depends on | Protected files |
| --- | --- | --- | --- |
| E2-1 Commission acts and specifications | D3-03, D5-08 (data set, interface specification), D5-09 (proof format, key channel), D5-01 (Art. 77(9) act) | None | None |
| E2-2 Citation of standards | D2-10 (Official Journal citation of EN 18239 and EN 18246) | None | None |
| E2-3 Upstream licenses and releases | D6-14 (UN/CEFACT schema license), D3-10 (UNTP release), D8-04 (licenses of candidate suites) | None | None |

### 6.4 T3: multi-user conformance testing service

#### Owner or another person

| Package | Closes (owner part) | Depends on | Protected files |
| --- | --- | --- | --- |
| O3-1 Service decisions | D7-01 (deployment target, tenancy model, web, OIDC, and database dependencies) | T1 or T2 | `models/` (job model), `architecture.md`, `pyproject.toml` |
| O3-2 Run, campaign, and contract policy | D7-04 (ids, meaning of a sample), D7-05 (schedule and series, back-up rule), D7-10 (models for the other stored documents). D7-12 (versioning policy), D8-13 (support period) | D7-10 first. D7-04 needs D7-03 | `models/`, `architecture.md` |
| O3-3 Keys and purge | D6-07 (SDK and PKCS#11 approvals), D7-07 (`DataKeyProvider`, back-up location) | D6-08, D7-06 | `src/dppce/infrastructure/interfaces.py`, `pyproject.toml` |
| O3-4 Report signature contracts | D6-05 (roles), D6-06 (COSE library), D6-10 (log proof field), D6-13 (limitations, review of translations), D9-05 (withdrawal process) | D6-04, D6-03, D6-09, D9-04 | `models/`, `architecture.md`, `pyproject.toml` |
| O3-5 Legal monitoring and engagements | D2-13 (network approval, legal effect by a person), D8-06 and D6-16 (the owner engages the reviewers) | D2-04, D6-12 | None |

#### Agent-buildable

| Package | Closes (agent part) | Depends on | Protected files |
| --- | --- | --- | --- |
| A3-1 Parallel runs and budgets | D7-02 | D7-03 decided first. D7-04 | `models/` only if the budget becomes an IXIT field |
| A3-2 Migrations and versions | D7-10 (`migrations.py`, loaders), D7-12 (lint, signed index) | O3-2 | Through O3-2 |
| A3-3 Campaigns and monitoring | D7-04, D2-13 (scheduler with mock tests) | O3-2, A3-2 | Through O3-2 |
| A3-4 Keys and purge | D6-07 (providers on emulators), D7-07 (purge record, key per recording) | O3-3 | Through O3-3 |
| A3-5 Service layer | D7-01 | O3-1, A3-1 to A3-4 | Through O3-1 |
| A3-6 Report signature extensions | D6-05, D6-06, D6-10, D6-13, D9-05 | O3-4 | Through O3-4 |
| A3-7 Scheduled acquisition and availability | D7-05 | O3-2, A3-1, A3-3, A3-4, A3-5 | Through O3-2 |

#### External party

| Package | Closes (external part) | Depends on | Protected files |
| --- | --- | --- | --- |
| E3-1 Independent security audit | D8-06 | D8-05 | None |
| E3-2 Accessibility review by a person | D6-16 | D6-15 | None |
| E3-3 Transparency witness | D6-10 (external witness or monitor) | A3-6 | None |
| E3-4 Law on back-up copies | D7-05 (whether a back-up copy is required) | None | None |

## 7. Landscape

Two Sonnet agents read public web pages on 2026-10-15. Web content is data. Each row names its first source.

### 7.1 EU law and acts since 2026-10-13

EU law changes after 2026-10-13 for the DPP conformance engine (read-only check, 2026-10-15).

| Item | Status | Use | Finding | Source |
| --- | --- | --- | --- | --- |
| SCOPE-CHECK: any act published 2026-10-13..2026-10-15 | unchanged | none | Not located. | [Cellar SPARQL query (a): keyword titles dated from 2026-10-0](https://publications.europa.eu/webapi/rdf/sparql?format=application%2Fsparql-results%2Bjson&query=PREFIX%20cdm%3A%20%3Chttp%3A//publications.europa.eu/ontology/cdm%23%3E%0APREFIX%20xsd%3A%20%3Chttp%3A//www.w3.org/2001/XMLSchema%23%3E%0ASELECT%20DISTINCT%20%3Fcelex%20%3Fdate%20%3Ftitle%20WHERE%20%7B%0A%20%3Fwork%20cdm%3Awork_date_document%20%3Fdate%20.%0A%20%3Fwork%20cdm%3Aresource_legal_id_celex%20%3Fcelex%20.%0A%20%3Fexp%20cdm%3Aexpression_belongs_to_work%20%3Fwork%20%3B%20cdm%3Aexpression_title%20%3Ftitle%20%3B%20cdm%3Aexpression_uses_language%20%3Chttp%3A//publications.europa.eu/resource/authority/language/ENG%3E%20.%0A%20FILTER%28%3Fdate%20%3E%3D%20%222026-10-01%22%5E%5Exsd%3Adate%29%0A%20FILTER%28CONTAINS%28LCASE%28STR%28%3Ftitle%29%29%2C%222023/1542%22%29%20%7C%7C%20CONTAINS%28LCASE%28STR%28%3Ftitle%29%29%2C%22digital%20product%20passport%22%29%20%7C%7C%20CONTAINS%28LCASE%28STR%28%3Ftitle%29%29%2C%222024/1781%22%29%20%7C%7C%20CONTAINS%28LCASE%28STR%28%3Ftitle%29%29%2C%22ecodesign%22%29%29%0A%7D%20ORDER%20BY%20DESC%28%3Fdate%29%20LIMIT%2060) |
| OQ-006 / Art. 77(9) implementing act (access rights) | not located | none | Adopted act: not located. | [Have Your Say backend record, initiative 16473 (read through](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/16473) |
| OQ-007 / Art. 7 acts (carbon footprint of electric vehicle batteries) | not located | none | Adopted acts: not located (no Cellar title hit in queries (a) and (b) of SCOPE-CHECK). | [Have Your Say backend record, initiative 13877 (carbon footp](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/13877) |
| OQ-007 / Art. 8(1) acts (recycled content methodology) | not located | none | Adopted act: not located. | [Have Your Say backend record, initiative 14858 (recycled con](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/14858) |
| OQ-007 / Art. 13(10) act (labelling implementing regulation) | not located | none | Adopted act: not located. | [Have Your Say backend record, initiative 14456 (batteries la](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/14456) |
| HYS 14460: untracked draft delegated regulation under Regulation (EU)  | context | none | Yes, as a draft. | [Have Your Say backend record, initiative 14460 (minimum valu](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/14460) |
| OQ-008 / OJ citation of EN 18239:2026 and EN 18246:2026 | not located | none | Not located. | [CEN project page, EN 18239:2026 (metadata fields only)](https://standards.cencenelec.eu/ords/f?p=205:110:::::FSP_PROJECT:81494&cs=1C97AB3E731BCF82E3BD2A04D9D8DC8CD) |
| Commission DPP timeline entry for the decision on the remaining two DP | changed | none | Yes, as observed on 2026-10-15. | [Digital Product Passport page, indicative timeline](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport_en) |
| OQ-008 / harmonised standard for the battery passport under Regulation | not located | none | Not located. | [Commission Implementing Decision (EU) 2026/2048 (harmonised ](https://eur-lex.europa.eu/eli/dec_impl/2026/2048/oj) |
| Procedure 2025/0395(COD) (COM(2025) 982, suspension of EPR rules for b | context | none | OEIL shows: committee vote in first reading 2026-10-05 (ENVI), committee report A10-0266/2026 tabled 2026-10-09. It also shows forecasts of a plenary debate on 2026-10-19 and a plenary vote on 2026-10-20; stage 'Awaiting … | [Procedure file 2025/0395(COD)](https://oeil.europarl.europa.eu/oeil/en/procedure-file?reference=2025/0395(COD)) |
| Procedure 2025/0397(COD) (COM(2025) 981, Omnibus VIII batteries and in | unchanged | none | Unchanged: OEIL shows stage 'Awaiting committee decision', proposal COM(2025) 981 of 2025-12-10, committee referral 2026-02-09. It also shows rapporteur Susana Solis Perez (EPP, appointed 2026-03-24, per OEIL), indicative plenary … | [Procedure file 2025/0397(COD)](https://oeil.europarl.europa.eu/oeil/en/procedure-file?reference=2025/0397(COD)) |
| Procedures 2025/0134(COD) (COM(2025) 504, Omnibus IV digitalisation) a | unchanged | none | Unchanged for both. 2025/0134(COD): OEIL shows 'Awaiting Parliament's position in 1st reading', committee approval of the text agreed in interinstitutional negotiations on 2026-07-14, indicative plenary date … | [Procedure file 2025/0134(COD)](https://oeil.europarl.europa.eu/oeil/en/procedure-file?reference=2025/0134(COD)) |
| ESPR Art. 4 delegated acts that set DPP requirements for a product gro | not located | none | Not located. | [Have Your Say backend record, initiative 17672 (iron and ste](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/17672) |
| ESPR working plan 2025-2030: product groups (context for generalising  | context | none | COM(2025) 187 final, 'Ecodesign for Sustainable Products and Energy Labelling Working Plan 2025-2030', dated 2025-04-16. (Read from the Cellar text through a summarizing fetch tool, so treat the list as unverified … | [Communication COM(2025) 187 final, ESPR and Energy Labelling](http://publications.europa.eu/resource/cellar/142f4a23-1ac8-11f0-b1a3-01aa75ed71a1.0001.03/DOC_1) |
| Art. 11 ESPR delegated act on DPP service providers | not located | none | Adopted act: not located. | [Have Your Say backend record, initiative 14382 (DPP service ](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/14382) |
| DPP web portal and registry acts beyond Implementing Regulation (EU) 2 | not located | none | Not located. | [Have Your Say backend record, initiative 16052 (DPP registry](https://ec.europa.eu/info/law/better-regulation/brpapi/groupInitiatives/16052) |

### 7.2 Tools, test suites, data models, and pilots

Comparable conformance tooling, test suites, data models and pilots for a DPP conformance engine.

| Item | Status | Use | Finding | Source |
| --- | --- | --- | --- | --- |
| gs1-digital-link-uri-syntax-1-7-0 | unchanged | target requirement source | ref.gs1.org still shows Release 1.7.0, 'Ratified Aug 2026', as both this version and latest (same as catalogue/sources.yaml:2063). | [GS1 Digital Link Standard: URI Syntax (release 1.7.0)](https://ref.gs1.org/standards/digital-link/uri-syntax/) |
| gs1-conformant-resolver-1-2-1 | unchanged | target requirement source | ref.gs1.org shows Release 1.2.1, header 'Ratfied Aug 2026' (sic), same as sources.yaml:2154. | [GS1-Conformant Resolver Standard (release 1.2.1)](https://ref.gs1.org/standards/resolver/) |
| gs1-resolver-test-suite | context | second implementation | Yes. ref.gs1.org/test-suites/ lists two suites; one is the GS1 Resolver Test Suite. | [GS1 Resolver Test Suite](https://ref.gs1.org/test-suites/resolver/) |
| gs1-syntax-dictionary | context | dependency | The GS1 Barcode Syntax Resource page describes a Syntax Dictionary and Syntax Tests (C linters). The Syntax Dictionary is a plain text file of all assigned Application Identifiers with the components for valid syntax. | [GS1 Barcode Syntax Resource](https://ref.gs1.org/tools/gs1-barcode-syntax-resource/) |
| gs1-syntax-engine | context | second implementation | github.com/gs1/gs1-syntax-engine: Apache-2.0, 858 commits, recent commits 2026-10-08 ('Freshen docs') and 2026-08-29. | [gs1/gs1-syntax-engine](https://github.com/gs1/gs1-syntax-engine) |
| gs1-digital-link-toolkit-js | context | none | github.com/gs1/GS1DigitalLinkToolkit.js: Apache-2.0, 51 commits, last commit 2025-05-01 (commits page), README disclaimer calls it a pre-alpha release. | [gs1/GS1DigitalLinkToolkit.js](https://github.com/gs1/GS1DigitalLinkToolkit.js) |
| gs1-resolver-community-edition | context | second implementation | github.com/gs1/GS1_DigitalLink_Resolver_CE: Apache-2.0, README for version 3.0.0, 276 commits, no archive notice. | [gs1/GS1_DigitalLink_Resolver_CE](https://github.com/gs1/GS1_DigitalLink_Resolver_CE) |
| untp-dcc-wip-0-8-0 | unchanged | target requirement source | No. untp.unece.org/versions still lists Work in Progress (Testing), 0.7.0 (Pilots) and 0.6.0 (Unmaintained). The list has no dates and no 0.8.0 or 1.0 row (sources.yaml:5173). | [UNTP documentation versions](https://untp.unece.org/versions) |
| untp-spec-repository | changed | target requirement source | Yes. | [spec-untp project page (GitLab)](https://opensource.unicc.org/un/unece/uncefact/spec-untp) |
| untp-tests-issue-1096 | unchanged | target requirement source | No change located. | [Track the UNTP changes since v0.7.0 and the work each produc](https://github.com/uncefact/tests-untp/issues/1096) |
| untp-test-service-tiers | context | second implementation | Yes. | [UNTP Test Service](https://spec-untp-fbb45f.opensource.unicc.org/docs/tools-and-support/TestService/) |
| tests-untp-repository | context | second implementation | README lists a reference implementation (issue, store, verify credentials), test suites (technical interoperability, semantic interoperability, graph validation), a playground, and a documentation site. | [uncefact/tests-untp](https://github.com/uncefact/tests-untp) |
| untp-dpp-0-7-0 | context | target requirement source | The 0.7.0 DPP page (pilot status) links a full-credential JSON Schema, a Product-only schema and three sample instances. The sample instances are copper concentrate, copper cathode and a 75 kWh battery (Germany). | [UNTP Digital Product Passport 0.7.0](https://untp.unece.org/docs/0.7.0/specification/DigitalProductPassport) |
| untp-release-0-8-0-or-1-0 | not located | none | Not located. | [Tags, spec-untp](https://opensource.unicc.org/un/unece/uncefact/spec-untp/-/tags) |
| open-question-untp-licence | context | none | Unresolved. | [spec-untp project page (GitLab)](https://opensource.unicc.org/un/unece/uncefact/spec-untp) |
| w3c-vcdm-2-0 | unchanged | target requirement source | No. | [History of VC Data Model 2.0](https://www.w3.org/standards/history/vc-data-model-2.0/) |
| w3c-vc-jose-cose | unchanged | target requirement source | Confirmed. | [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/) |
| w3c-vc-jose-cose-test-suite | context | fixture source | w3c/vc-jose-cose-test-suite has a tests/input folder listing 23 signed .txt files. They are JOSE, COSE and SD-JWT credentials and presentations, including files named bad-signature and bad-media-type. The folder also lists 5 key JSON files … | [tests/input, vc-jose-cose-test-suite](https://github.com/w3c/vc-jose-cose-test-suite/tree/main/tests/input) |
| w3c-vc-data-model-2.0-test-suite | context | second implementation | w3c/vc-data-model-2.0-test-suite: interoperability tests for issuers and verifiers through VC-API style endpoints (/credentials/issue, /credentials/verify, /presentations/verify). | [w3c/vc-data-model-2.0-test-suite](https://github.com/w3c/vc-data-model-2.0-test-suite) |
| w3c-vc-di-test-suites | context | second implementation | w3c/vc-di-eddsa-test-suite (BSD-3-Clause, 215 commits, eddsa-rdfc-2022 and eddsa-jcs-2022, latest commits 2026-08-27) and w3c/vc-di-ecdsa-test-suite (BSD-3-Clause, 436 commits, ecdsa-rdfc-2019 and ecdsa-sd-2023; … | [w3c/vc-di-eddsa-test-suite](https://github.com/w3c/vc-di-eddsa-test-suite) |
| w3c-bitstring-status-list-test-suite | context | none | w3c/vc-bitstring-status-list-test-suite: interoperability tests for issuers and verifiers (tags BitstringStatusList plus Revocation or Suspension), includes a generator (npm run generate-vcs), 236 commits, latest … | [w3c/vc-bitstring-status-list-test-suite](https://github.com/w3c/vc-bitstring-status-list-test-suite) |
| aas-test-engines | unchanged | dependency | No change. | [admin-shell-io/aas-test-engines](https://github.com/admin-shell-io/aas-test-engines) |
| idta-02099-1-dpp-metadata | unchanged | target requirement source | The IDTA content hub lists DPP Part 1: Metadata (IDTA 02099), version 1.0, Published, as 'the first part in a planned series'. The scope and timing of later parts 'have not yet been determined'. | [IDTA submodel templates content hub](https://industrialdigitaltwin.org/en/content-hub/submodels) |
| idta-submodel-templates-repo | unchanged | fixture source | No change after the recorded push of 2026-10-05. The newest commits are 2026-10-05 ('SMT AID v1.2', pull request 336) and 2026-09-25 ('Keep released files unchanged; rebuild bug-fix AASX from their JSON'). | [admin-shell-io/submodel-templates](https://github.com/admin-shell-io/submodel-templates) |
| idta-dpp-templates-in-development | context | target requirement source | The content hub lists templates that are In Development and described as relevant to the DPP. They are Product Material Compliance (IDTA 02088), Supply Chain Event Data Collection (02089) and Environmental Product Declaration Type III … | [IDTA submodel templates content hub](https://industrialdigitaltwin.org/en/content-hub/submodels) |
| idta-02099-part-2 | not located | none | Not located. | [IDTA submodel templates content hub](https://industrialdigitaltwin.org/en/content-hub/submodels) |
| aas-second-implementations | context | second implementation | Eclipse BaSyx Python SDK (MIT, 2,226 commits) is a monorepo with a Compliance Tool. The tool checks AAS JSON, XML or AASX against the official schema. The releases section on the page is empty. aas-core3.0-python (SDK to manipulate, … | [eclipse-basyx/basyx-python-sdk](https://github.com/eclipse-basyx/basyx-python-sdk) |
| bp-data-model-github-v1-2-0 | unchanged | fixture source | Unchanged: page shows 75 commits (same count as the catalogue evidence at sources.yaml:3097). README says the project concluded in April 2025, the repository is no longer actively maintained and for reference only; no … | [batterypass/BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel) |
| bp-ready-data-model-v2 | unchanged | target requirement source | Unchanged: the GEFEG GitLab project page shows 201 commits, 2 branches, 0 tags, created 2025-10-27 (same as sources.yaml:3171). | [BatteryPassDataModel project page (GEFEG GitLab)](https://git.gefeg.com/bp/BatteryPassDataModel) |
| batterypass-ready-test-environment | context | none | Fraunhofer IPK news of 2026-06-24 says the BatteryPass-Ready test environment 'has gone live'. The news lists templates and guidelines, data validation for completeness and EU regulatory compliance, and eleven scenarios in three use … | [BatteryPass-Ready launches test environment for digital batt](https://www.ipk.fraunhofer.de/en/media/news/20260624-batterypass-ready-launches-test-environment-for-digital-battery-passport.html) |
| fraunhofer-ipk-open-source-test-system | not located | none | Not located. | [The Standards for the Digital Product Passport are Here](https://www.ipk.fraunhofer.de/en/media/media-information/20260601-die-standards-fuer-den-digitalen-produktpass-sind-da.html) |
| catenax-sldt-battery-pass-aspect-model | context | fixture source | eclipse-tractusx/sldt-semantic-models (CC-BY-4.0 per repository page, 2,972 commits, no archive banner) holds folder io.catenax.battery.battery_pass. The folder has versions 3.0.0, 3.0.1, 4.0.0, 5.0.0, 6.0.0 and 6.1.0. | [io.catenax.battery.battery_pass folder](https://github.com/eclipse-tractusx/sldt-semantic-models/tree/main/io.catenax.battery.battery_pass) |
| catenax-cx-0143-dpp-standard | context | target requirement source | CX-0143 'Use Case Circular Economy - Digital Product Passport'. | [CX-0143 introduction](https://catenax-ev.github.io/docs/standards/CX-0143-UseCaseCircularEconomyDigitalProductPassportStandard/introduction) |
| catenax-tractusx-dpp-implementations | context | none | eclipse-tractusx/digital-product-pass (Apache-2.0 code, CC-BY-4.0 non-code, v4.0.1) was archived by its owner on 2025-10-02 and marked deprecated. It recommends the Industry Core Hub. … | [eclipse-tractusx/digital-product-pass](https://github.com/eclipse-tractusx/digital-product-pass) |
| cirpass2-github-repositories | changed | second implementation | Yes. | [CIRPASS-2 GitHub organisation](https://github.com/CIRPASS-2) |
| cirpass2-mock-eu-registry | context | second implementation | CIRPASS-2/mock-eu-registry: example DPP metadata registry (Java, Apache-2.0, 49 commits, PostgreSQL or MariaDB, OIDC roles). | [CIRPASS-2/mock-eu-registry](https://github.com/CIRPASS-2/mock-eu-registry) |
| cirpass2-test-environment-description | unchanged | none | The Zenodo record page (v1, 2026-06-16, CC BY 4.0, file CIRPASS2_TestEnvironment_Description.pdf) has no abstract. For this reason, it does not state whether a hosted instance exists. | [CIRPASS-2 Open Source Test Environment](https://zenodo.org/records/20749604) |
| cirpass2-project-results | context | target requirement source | The results page has a newest dated item of 2026-09-24. It lists D4.1 Reference Architecture (Zenodo record 20720002, CC BY 4.0, file named V1.1, 2026-06-16; page has no abstract). It also lists 'DPP Standardisation Initiatives Worldwide' … | [CIRPASS-2 project results](https://cirpass2.eu/project-results/) |
| cirpass-1-deliverables | not located | none | Not located. | [DPP project results to be presented at final event](https://hadea.ec.europa.eu/news/digital-product-passport-project-results-be-presented-final-event-2024-02-29_en) |
| ec-dpp-registry-testing-environment | context | none | Yes. | [The Digital Product Passport Registry is now live](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en) |
| ec-dpp-registry-user-guide | unchanged | target requirement source | Unchanged. | [DPP resources and documentation](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport/resources-documentation_en) |
| ec-dpp-registry-api-specification | not located | none | Not located. | [DPP resources and documentation](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport/resources-documentation_en) |
| ec-dpp-semantic-repository | not located | none | Not located as a published resource. | [The Digital Product Passport Registry is now live](https://single-market-economy.ec.europa.eu/news/digital-product-passport-registry-now-live-2026-07-20_en) |
| ec-dpp-batteries-webpage-and-timeline | changed | target requirement source | Yes. | [Digital product passport (timeline)](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport_en) |
| oss4dpp-eclipse | unchanged | none | No change. dpp.eclipse.org still says 'Sources checked 24 July 2026'. The site still shows no DPP Working Group, no formal Eclipse project, no deliverables, no repositories (matches sources.yaml:6591). | [Open Source for the Digital Product Passport](https://dpp.eclipse.org/) |
| opendpp-catalogue | context | none | The cirpass2.eu catalogue page lists tools. They include OpenEPCIS Digital Link Toolkit (Apache 2.0), TracePath DPP Open Schemas and TracePass schema and profile repositories (Apache 2.0). They also include Eclipse BaSyx DPP API (MIT), open-dpp … | [OpenDPP Catalogue](https://cirpass2.eu/open-source-dpp-catalogue/) |
| third-party-open-source-dpp-validators | context | second implementation | OpenDPP/opendpp-interop: Apache-2.0, 103 commits, 4 stars, Node CLI that runs offline. Check categories: aas, untp, semanticids, registry, shacl, sdjwt, en18223, epcis, gs1. It says its SHACL shapes and EN 18223 check are … | [OpenDPP/opendpp-interop](https://github.com/OpenDPP/opendpp-interop) |
| ce-rise-dpawb | context | none | No. | [Digital Passport Model Assessment Workbench](https://ce-rise-software.codeberg.page/dp-assessment-workbench/) |
| official-open-source-dpp-conformance-suite | not located | none | Not located. | [OpenDPP Catalogue](https://cirpass2.eu/open-source-dpp-catalogue/) |
| ieee-p3828 | context | none | IEEE P3828, 'Draft Standard for Digital Product Passport - Reference Architecture and Technical Requirements', active PAR approved 2024-09-26. Its working group is DPPWG under the IEEE Consumer Technology Society. | [IEEE P3828 project page](https://standards.ieee.org/ieee/3828/11761) |

## 8. Refuted findings and merged duplicates

Refuted by a skeptic:

- **D8-08** Fuzzing of the system under test (api.fuzz) has no executable path. Lens: necessity-accuracy. No tier criterion (T0 to T3) requires active fuzzing of the system under test.

Merged by critic round 1 (the first gap is kept as the second):

- **D6-17** into **D8-01**. Same gap (external vectors and a second implementation for identifier, signature, canonical-form), listed as major in ETR-17 and blocker in AIG-01.
- **D4-03** into **D8-01**. The identifier-syntax oracle (GS1 syntax dictionary or engine) is the identifier slice of AIG-01. The covered reason of AIG-01 already names those tools. Keep the dependency-decision detail of IDR-03 as a sub-item.
- **D4-09** into **D8-04**. AIG-04 lists the GS1 resolver test suite among the T2 comparators; IDR-09 is the same item for resolvers only.
- **D2-05** into **D6-12**. Report display of legal_as_of (ILC-05) and of the approval record (ILC-02) is stated three times.
- **D2-02** into **D6-12**. Report display of legal_as_of (ILC-05) and of the approval record (ILC-02) is stated three times.
- **D7-08** into **D8-09**. Both say the release workflow has no gate.
- **D7-09** into **D8-13**. The support period and update policy appear in both (cra-missing-3).
- **D7-13** into **D7-11**. image_digest never set (results.py:95) is the same item as 'runs do not record the engine artifact digest'.
- **D1-02** into **D1-01**. RMC-02 is a list of contract-change requests, not a gap; its content belongs in the closable_by notes of RMC-01, RMC-03, RMC-04 and RMC-08.
- **D1-04** into **D1-01**. RMC-02 is a list of contract-change requests, not a gap; its content belongs in the closable_by notes of RMC-01, RMC-03, RMC-04 and RMC-08.
- **D1-08** into **D1-01**. RMC-02 is a list of contract-change requests, not a gap; its content belongs in the closable_by notes of RMC-01, RMC-03, RMC-04 and RMC-08.
- **D2-03** into **D8-15**. OQ-001, the unverified CODEOWNERS handle and the one-approver rule are in both.
- **D5-11** into **D2-08**. The reviewed-mode 'covered without gap' entry and the T1 definition treat an external constraint as by design. The Article 77(9) dependency is already that constraint. EUBAT-78-B and 78-F stay inconclusive (catalogue/packs/eu-battery-draft.yaml:459, :1036).

## 9. Limits of this assessment

**Who made it.** AI agents made this assessment. It is not a human review and not an audit.
The page describes commit `a709831`. It does not assess changes after that commit.

**One project.** The project wrote both the reference system and the checks. Method validation therefore shows agreement inside one project only.
No second implementation and no external test vectors cross-check the results yet (D8-01).

**Reproduced claims.** The coordinator repeated only the claims that sections 2.3 and 2.4 list.
All other findings are claims of the agents. Each gap cites its own evidence in the workflow record, and the coordinator did not run that evidence again.

**Critic rounds.** Critic round 1 ran. Critic round 2 was not run.
So no second completeness check covers the five gaps that round 1 added (D9-01 to D9-05).

**Models.** Fable ran out of usage credits on 2026-10-15. Critic round 2 and the synthesis failed on usage limits (section 2.1).
At the direction of the owner, Opus wrote sections 1, 6, and 9.
On 2026-10-17, the owner limited Fable to the roles of orchestrator and advisor. This is a change from the model routing that section 2 describes.

**Contested gaps.** A skeptic partly refuted 50 of the 97 gaps. The tables show the corrected gaps and mark them with an asterisk.
The original claims of the analysts are in the workflow record only.

**Counts.** Some fields of a gap hold a value and a qualification, for example "major at T2, minor at T1".
The counts in section 1 use the leading value of each such field. Sections 5.5 and 5.8 list the qualifications.

**Open inconsistencies of critic round 1.** The critic recorded eleven inconsistencies. This page treats them as follows.

- Resolved by the leading value: prose in fields that must hold one value. The fields are tier, severity, and closable by.
  The gaps are D5-01, D5-02, D5-04, D5-05, D5-06, D5-08, D5-09, D5-10, D8-12, D8-13, and D8-14.
- Resolved by a merge: the critic asked whether the Art. 77(9) gap is a T1 gap. Round 1 merged it into D2-08 (section 8).
- Resolved by the constraint notes of the gap record. Each roadmap lane uses the part that the record assigns to it.
  - D1-11 and D2-07 stay agent-buildable for display and lint. The contract changes in protected files belong to the owner.
    The `expected_evidence` check of D1-11 is agent work after the manual-result contract of O1-2 (A1-4).
  - D1-05 names `cli.py` and `catalogue/loader.py`, which are not protected. So the value agent-buildable holds.
  - D6-01 and D7-05 stay mixed. Their records name owner steps that the declared backlog rows do not show.
- Still open in the tables:
  - D7-02 is agent-buildable but depends on an owner decision (D7-03). The roadmap puts D7-03 first.
  - D8-11 and D8-03 have status new. The critic states that the repository already declares part of each.
  - D2-10 is a T2 gap. The critic states that it moves to T1 if the Official Journal cites the standards under Regulation (EU) 2023/1542 (OQ-008).
  - The wording "clear-text token" for the stored run inputs is not corrected in the records.
    The critic states that `inputs.json` holds no role secret, only a `secret_ref`. The coordinator did not check this claim.

**Snapshot dates.** The web research is a snapshot of 2026-10-15. Web pages and planned dates can change after that day.
The legal status date of the repository is 2026-10-13. The assessment located no adopted act between those two dates.

**Protected standards.** CLAUDE.md rule 5 applied to every agent.
The gap records cite these documents by bibliographic metadata only, and no finding rests on their content.
The page cites these documents by bibliographic metadata only. So this assessment cannot state what any of these standards requires.
