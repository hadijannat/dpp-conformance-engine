# Practical-use delta assessment and program P2

Audience: the owner, maintainers, and reviewers who plan the work after the T1 program.
Purpose: show what blocks use of the engine on real systems, and state the packages of program P2 that close the gaps.
Prerequisites: read the [gap assessment of 2026-10-15](gap-assessment-2026-10-15.md), [readiness and limitations](../readiness.md), and the [architecture](../explanation/architecture.md).

AI agents made this assessment on 2026-10-25 at commit `4990be0`. It is not a human review and not an audit.
It makes no statement of legal compliance. It states no technology readiness level.
The engine produces conformance test reports, not certificates.

## 1. Summary

**Today.** The engine tests one path end to end.
The path is an item-level GS1 Digital Link, HTTPS resolution, and a JSON passport with an ES256 JWS.
Other implementation families get a wrong verdict, a blocked step, or no step at all.

**Gates for persons.** Four gates block use on real systems. Only persons can close them.

1. An appointed reviewer for the draft interpretations (OQ-002).
2. A signed test of a real system, with the authorization of its owner.
3. An independent security audit.
4. DCO sign-off of agent commits.

**What P2 adds.** Program P2 has 29 packages in 11 waves. Each wave adds checks for one or more implementation families.

| Family | What P2 adds |
| --- | --- |
| Plain web | Honest schema dialects, more format checkers, an HTML passport source, a content-negotiation probe |
| GS1 resolver | Full Digital Link grammar, linkset and description file checks, final status checks |
| AAS | AAS file checks, the IDTA 02099 DPP template, API read profiles, resource names for AAS endpoints |
| Verifiable credentials (UNTP) | JOSE profiles, did:web with offline copies, Bitstring Status List, credential payload as data |
| Data space | Documented data-plane tests with an operator token; a catalog check stays deferred |

## 2. Method

One workflow (`wf_5e8acfdb-31b`) made this assessment.

| Step | Agents | Output |
| --- | --- | --- |
| Read the code and the earlier assessment | 6 Sonnet readers | 194 items in reader maps |
| Check the web landscape | 1 Sonnet agent | One landscape page |
| Judge, group, and order | 1 Opus judge | 29 packages, 17 owner decisions |
| Critique the plan | 1 Opus completeness critic | 13 missing items, corrections to packages |

The orchestrator ran the baseline command `uv run just check` at `4990be0`.
The command ended with exit 0: 2591 passed, 97 deselected.
No agent ran the method validation or a mutation run for this page ("not run").
The plan came from reading the code. The plan notes executed checks for findings V1 and V2 only.

## 3. Verified findings

Each finding was re-read in the code at `4990be0`.
Codes in the Effect column name the wave of the fix.

| # | Finding | Evidence | Effect |
| --- | --- | --- | --- |
| V1 | A `draft-07` keyword such as `dependencies` is ignored, which gives a false pass. | `adapters/common.py` builds only a 2020-12 validator | Rule 7 defect, W1 |
| V2 | `date-time` is not asserted, so real schemas are `blocked`. | `common.py` `_FORMATS` | Blocks EPCIS, UNTP, VC schemas, W1 |
| V3 | A 200 `application/linkset+json` answer gives `IDENTIFIER.RESOLVED`. | `adapters/identifier.py` `resolve` | False pass for GS1 and UNTP resolvers, W1 |
| V4 | A valid JWS JSON serialization gives `INTEGRITY.TOKEN.MALFORMED`. | `adapters/integrity.py` `jws_check` | Engine limit shown as SUT defect, W1 |
| V5 | `identifier.parse` fails GTIN-only, lot, and path-prefix URLs that GS1 permits. | `identifier.py` `_GS1_PATH` | False fail for the GS1 family, W2 |
| V6 | `registry.consistency` and `persistence.versions` hard-code field names and the digest. | `adapters/lifecycle.py` | Third-party layouts fail, W2 |
| V7 | `integrity.jws` reads keys from `x5c` only, `ES256` only, type `dpp+jws` only. | `integrity.py`, `evidence/jws.py` | No verdict for VC, AAS, or token passports, W3 |
| V8 | `TrustedKey` already has purpose `passport` and `public_jwk`. | `models/trust.py` | Pinned-key VC-JOSE needs no models change |
| V9 | `redact_link` drops a `Link` value whose `rel` is outside a short list. | `infrastructure/redaction.py` | `linkset` and `gs1:*` relations are invisible, W8 to W9 |
| V10 | `SAFE_METHODS` is `GET` and `HEAD`; OPTIONS needs an active scope. | `infrastructure/transport.py` | CORS and resolver probes need contract text, W8 |
| V11 | `Record.redirects` keeps hop URLs, not hop status. | `interfaces.py`, `transport.py` | 301 and 307 look the same, W9 |
| V12 | The reference system has `do_GET` only and ignores method and `Accept`. | `infrastructure/reference_server.py` | Probes need a richer loopback target, W1 |
| V13 | `effective_url` maps `public_origin` to the loopback override. | `common.py` | did:web works on loopback without a TLS reference server |
| V14 | `ResourceName` is a closed list of five names. | `models/declarations.py` | AAS routes need new names, W8 |
| V15 | Seeded faults are reference flags or rig setups. | `validation/cases.py` | New faults add rows to `cases.py` |
| V16 | Fault F-34 fixes the outcome for an image with two QR symbols. | `validation/fault-catalogue.yaml` | `carrier.symbols` is deferred |
| V17 | A `blocked` or `unsupported` step gives an `inconclusive` requirement verdict. | `docs/reference/verdict-truth-table.md` rows 26, 27 | New boundary cases expect `inconclusive` |
| V18 | Fault `class` values are free strings. | `validation/cases.py` `_case` | New faults reuse existing class names |
| V19 | `load_profiles` globs `profiles/*/*.yaml`. | `catalogue/loader.py` | Family profiles are loaded from `profiles/family/` |

The critic found more gaps in the plan. The main ones:

- HTTP 429 gives a false fail today. Package P2-31 (lane B) closes it.
- An OpenAPI 3.0 contract with `nullable` gives a false fail. P2-01 adds a version gate.
- A credential passport body is a JWS, so data checks see no JSON. P2-24 adds a payload source.
- Only `profiles/battery/` exists, so other families run the battery profile. P2-30 adds family profiles.
- The report names the system, not the tested item. P2-21 adds test items to the manifest.

## 4. Landscape since 2026-10-19

A Sonnet agent checked public sources on 2026-10-25. Its page is a draft.
Many EU items rest on secondary sources, such as search snippets.
The agent did not reach EUR-Lex, the legislative observatory, or the Commission pages.
This page gives bibliographic metadata for standards only.

| Topic | Result | Source basis |
| --- | --- | --- |
| ESPR product delegated acts | None adopted; only Delegated Regulation (EU) 2026/296 (unsold goods) exists | Secondary only |
| Battery Regulation Art. 77(9) implementing act | Not adopted; the Commission lists Q4 2026 | Secondary only |
| Procedures 2025/0395(COD), 2025/0397(COD) | Plenary agenda 19 to 22 October 2026 for the first; outcome not found. Committee stage in July 2026 for the second | Secondary only |
| Procedures 2025/0130, 2025/0134 | Nothing found | Not checked on a primary page |
| Standards EN 18216 to 18223 | Cited by Implementing Decision (EU) 2026/1736 of 14 July 2026 | Secondary only |
| prEN 18239, prEN 18246 | Still draft in July 2026 sources; citation not confirmed | Secondary only |
| DPP registry | Regulation (EU) 2026/1778 of 16 July 2026; registry and test environment live from 20 July 2026 | Secondary only |
| GS1 Digital Link URI Syntax 1.7.0 | Ratified August 2026 | Primary page (ref.gs1.org) |
| GS1 Resolver standard 1.2.1 | Ratified August 2026 | Primary page (ref.gs1.org) |
| GS1 Web Vocabulary | Page gave HTTP 403 | Not checked |
| UNTP | Versions 0.7.0 and 0.6.0 are work in progress toward 1.0; pilot only. The GitHub repository was archived on 2026-04-24 after release 0.6.1 | Primary page |
| W3C VC Data Model 2.0, Bitstring Status List 1.0, Data Integrity 1.0 and its EdDSA and ECDSA suites | Recommendations of 2025-05-15 | Primary page |
| W3C VC-JOSE-COSE | Page shows a Recommendation dated 13 October 2026; the agent did not verify it | Primary page, date unverified |
| W3C DID 1.1 | Candidate Recommendation Snapshot of 2026-03-05; the did:web W3C URL gave 404 | Primary page |
| did:webvh 1.0 | DIF ratified; no date found | Secondary only |
| IDTA 02099-1 DPP Part 1 Metadata v1.0 | Released 2026-05-28 | Not marked by the agent |
| AAS specification Parts 1 and 2 v3.2 | PDFs dated July 2026; release status unconfirmed | Not marked by the agent |
| Catena-X CX-0143 and CX-0160 | Not found; CX-0134 exists; battery passport standard planned for 26.06 | Secondary only |

The agent also read PyPI metadata for candidate libraries.
This metadata is a primary source for package versions and licenses.

| Package | Version | License |
| --- | --- | --- |
| aas-test-engines | 1.0.3 | Field empty; LICENSE file present (Apache-2.0 in the installed copy, per the critic) |
| joserfc | 1.7.7 | BSD-3 |
| pyld | 3.3.0 | BSD-3 |
| rdflib | 7.6.0 | BSD-3 |
| pyshacl | 0.40.1 | Apache-2.0 |
| cbor2 | 6.1.5 | MIT |
| pycose | 1.1.0 | BSD-3 |
| zxing-cpp | 3.1.1 | Apache-2.0 |
| multiformats | 0.3.1.post4 | Field empty |
| base58 | 2.1.1 | MIT |
| signxml | 5.2.0 | Apache |
| schemathesis | 4.32.4 | MIT |

## 5. Program P2

The wave table below replaces section 3 of the plan.
The orchestrator revised it after the completeness critic.
Lane B means the package needs an owner-approved change to a protected contract.

| Wave | Packages |
| --- | --- |
| W1 | P2-01 schema dialect honesty, format checkers, OpenAPI version gate |
| | P2-02 false-verdict guards (linkset, JWS JSON serialization) |
| | P2-03 reference system v2 |
| | P2-30 family profiles and family test packs |
| W2 | P2-04 GS1 Digital Link grammar and granularity |
| | P2-05 GS1 resolver checks (linkset, description file, final status) |
| | P2-06 lifecycle field maps (history, registry) |
| W3 | P2-07 JOSE profiles for credentials (`integrity.jose`) |
| | P2-08 did:web resolution with operator-supplied offline copies by default |
| | P2-09 AAS files and the IDTA 02099 DPP template |
| W4 | P2-10 cross-family identity sources and GS1 equivalence |
| | P2-11 DID key source and W3C Bitstring Status List |
| | P2-12 client TLS options (private CA, client certificate) |
| W5 | P2-13 more identifier schemes |
| | P2-14 content-negotiation probe |
| | P2-15 AAS API read profiles through the engine transport |
| W6 | P2-17 oracle pinning tools and external vectors |
| | P2-18 review record open items |
| | P2-31 HTTP 429 and Retry-After as no answer (lane B) |
| W7 | P2-20 family examples, guides, and family controls in the method validation |
| | P2-21 report provenance and identification of the test item (lane B) |
| | P2-32 comparison of envelopes from repeated runs |
| W8 | P2-22 transport vocabulary: OPTIONS, CORS, Link relations (lane B) |
| | P2-23 resource names for AAS endpoints and views (lane B) |
| | P2-24 document sources, verified credential payload, embedded JSON-LD (lane B) |
| W9 | P2-25 redirect hop status (lane B) |
| | P2-26 rule pack version 2 and contexts by Link header (lane B) |
| | P2-27 semantic extra: JSON-LD expansion and SHACL (lane B, optional extra) |
| W10 | P2-28 credential schemes and OAuth 2.0 client credentials (lane B) |
| W11 | P2-19 mutation survivor classification |
| | P2-29 method validation, status documents, readiness, `TASKS.md`, `state/progress.json` |

Rules for every package:

- Tests come first, on loopback and local fixtures only.
- Defaults keep today's behavior, so existing recordings replay to the same decision digest.
- Every new check has a closed parameter model, a capability entry at `experimental` at most, and stable reason codes.
- An engine limit gives `blocked` or `unsupported`, never `pass`.
- A move to `supported` is a person step.

## 6. Owner decisions of 2026-10-25

The owner chose the recommended option for four questions.

| Question | Answer, quoted |
| --- | --- |
| Protected files | "Same terms as T1 (Recommended)" |
| Dependencies | "Optional extras only (Recommended)" |
| Oracles | "Fetch open sources (Recommended)" |
| Landing | "Land and push like T1 (Recommended)" |

The orchestrator took two defaults. The owner may change them.

| Id | Default | Alternative |
| --- | --- | --- |
| OD-04 | A linkset given as the passport gives `blocked` (`IDENTIFIER.RESPONSE.LINKSET`). A resolver may serve a linkset legitimately, and `resolver.linkset` judges it. | `fail` |
| OD-05 | A JWS JSON serialization gives `blocked` (`INTEGRITY.FORMAT.UNSUPPORTED`). Support lives in `integrity.jose`. | Support in `integrity.jws` |

Other decisions in the plan stay with the packages that need them, for example OD-06 to OD-14 for protected contract text.

## 7. Deferred items

The plan defers these items. Each has a short reason.

| Item | Reason |
| --- | --- |
| `carrier.symbols` | Changes the outcome class of fault F-34; needs an owner decision first |
| NFC, RFID, and EPC carrier checks | Need tag keys, reader hardware, or a table that an implementer must read first |
| Carrier control hash | No published algorithm |
| `api.fuzz` | Needs a 5xx exception in the transport rules; risky on live systems |
| `api.write_ops`, `persistence.erasure` | Destructive; need a disposable sandbox and an owner authorization |
| `data.html_parity` | Needs the `view` resource (P2-23) first |
| COSE checks | No common family serves COSE passports (OD-18) |
| Data Integrity proofs, `did:webvh`, issuer and digest binding | Medium or low value; build after P2-11 |
| Trust anchors, EU trusted list, OPC signature | Need a new trust schema or an XML-DSig dependency |
| Ledger proof, claim attestation, EPCIS lineage | Niche families or thin oracles |
| Lifecycle link and status names, backup | No technical specification of the names |
| Service and campaign concerns (T3) | Out of the practical read-only scope |
| Generic ESPR profile | No adopted product-group act |
| Official registry checks | No published registry API; live contact is forbidden |
| Semantic repository check | The Commission repository is not published |
| Qualified seal, UNTP conformance credential | Naming policy (reports are not certificates), license, trust service provider |
| Dataspace catalog check | A POST request needs a rule on methods and scope; the critic asks for it as a later package |
| Validation against open-source family servers | The owner must run containers; recordings then become replay fixtures |
| Egress proxy | A CONNECT proxy routes around the pinned-address and public-address checks; needs its own design |
| Packaging of `fixtures/examples/` | A new bundled directory needs a `pyproject.toml` change |

The critic raised four risks that shape the packages:

- A third-party issuer host cannot be covered by the SUT owner's permission. P2-08 and P2-11 default to offline copies.
- P2-15 must use only positive calls, because negative probes break the 5xx rule.
- P2-15 changes IXIT files, so pinned digests change. The integrator regenerates them.
- P2-01 cannot seed its fault in wave 1, because the test purpose arrives with P2-24.

## 8. Gates that only persons can close

| Gate | Note |
| --- | --- |
| Approval of draft interpretations (OQ-002) | An agent never sets `approved` |
| Reviewer readings OQ-010, OQ-011, OQ-014, OQ-016, OQ-021, OQ-022, OQ-023 | Needs the appointed reviewer |
| Test of a real DPP system | Needs the signed authorization of its owner |
| Independent security audit; screen-reader accessibility review | External parties |
| DCO sign-off of agent commits | Three commits (`b406d33`, `15c32a7`, `801d712`) were reported as not covered; `scripts/check_dco.py` was not run to confirm |
| Ratification of ADR 0007, 0014, 0015, 0016 | Owner |
| Move of a capability from `experimental` to `supported` | Person step for every new check |
| Review of NFC Forum and NXP terms; ISO/IEC 15459 reading | Rule 5 limits agents on standards text |
| Commission acts: Battery Regulation Art. 77(9), ESPR delegated acts, registry interface | Outside the project |
| Legal date re-check before a release; continuous legal monitoring | Owner |
| Docker runs: compose stack, mock registry as a system under test | The owner runs docker |

## 9. Limits of this assessment

- Agents read the code. They did not run the method validation or a mutation run for this page.
- The baseline command ran once at `4990be0`. The counts apply to that commit only.
- The landscape check used snippets for most EU items. No primary EU page was read.
- The W3C VC-JOSE-COSE date is unverified.
- Value and effort ratings in the plan are agent judgments.
- Fault ids in the plan are placeholders. The integrator assigns real ids.
- This page contains no text of any EN, ISO, IEC, or DIN document.
- The page states no legal compliance and no technology readiness level.
