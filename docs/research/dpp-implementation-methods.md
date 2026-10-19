# Implementation methods for digital product passports

Audience: engine designers, test-pack authors, and reviewers who extend the engine to new kinds of DPP systems.
Purpose: classify the technical methods to implement a DPP, describe each method, and state what a black-box conformance engine can test for each.
Prerequisites: read the [architecture contract](../explanation/architecture.md), section 8, the [capability manifest](../reference/capabilities.md), and the [glossary](../reference/glossary.md).

This page is research. It is not normative for the code, and it is not legal advice. It makes no statement of legal compliance.
The legal and technical status date is 2026-10-19. Research agents wrote the evidence and the sections. No person reviewed them.

## 1. Summary

### 1.1 Main findings

- No single accepted classification of DPP implementations exists. The literature uses attribute grids, taxonomies, design spaces, reference architectures, and requirement lists.
- This page classifies on two axes: eleven layers (L01 to L11) and twelve families of implementation methods. Section 3 defines both.
- EU law prescribes properties, roles, and one central registry. It prescribes no protocol, media type, or signature algorithm for a passport that an operator hosts.
- Hybrid stacks are the norm. Battery Pass, Catena-X, CIRPASS-2, and UNTP each combine several families. Most faults of a hybrid occur at the seams between families.
- The engine supports one path end to end today: an item-level GS1 Digital Link, an HTTPS resolution, and a JSON passport with an ES256 JWS.
- That path belongs to the plain web and GS1 resolver families. For the other ten families, most test objectives need a new capability.
- The engine-mapping check judged 226 mappings from test objectives to engine checks: 172 correct, 36 overstated, and 18 wrong. It merged the proposals into 51 new capabilities.
- The DPP literature has almost no test methods of its own. Test methods come from AAS testing, REST API testing, access-control testing, and classic conformance testing.

### 1.2 Families at a glance

| Family | In one sentence | Engine support on 2026-10-19 | Section |
| --- | --- | --- | --- |
| Plain web passport | The operator serves HTML, JSON, or JSON-LD at one HTTPS URL. | Partial. The reference system implements this family. View parity and HTML accessibility checks are new. | 5.1 |
| GS1 web resolver | A GS1 Digital Link URI on the product, and a resolver that redirects or returns a linkset. | Partial. Resolver behavior, linksets, and the full URI grammar need new capabilities. | 5.2 |
| Asset Administration Shell | The passport is a shell with submodels behind the AAS API. | Partial. `aas.validate` checks generic AAS JSON only. Template conformance and API profiles are new. | 5.3 |
| Dataspace | The passport is a data asset behind a connector, reached through catalog, contract, and transfer. | Mostly new. Without credentials, a tester sees only version and refusal answers. | 5.4 |
| Verifiable credentials | Each statement is a signed W3C credential, often found through a resolver. | Mostly new: further JOSE profiles, DID keys, Data Integrity proofs, and status lists. | 5.5 |
| Event-based traceability | The passport links to EPCIS 2.0 event repositories. | Mostly new: event identifiers, event hashes, and REST probes. | 5.6 |
| Linked data | The passport is a set of RDF statements, often with SHACL shapes. | `data.context` is supported. JSON-LD processing and SHACL are new. | 5.7 |
| Distributed ledger | A digest or token on a ledger anchors an off-chain passport. | Mostly new: digest binding and ledger proofs. | 5.8 |
| Platforms and service providers | A hosted service issues identifiers and carriers and serves the passport. | Depends on the stack that the platform uses. | 5.9 |
| Hybrid stacks | Different families supply different layers. | Partial. Identifier consistency across layers is new. | 5.10 |
| Reference implementations and the EU registry | CIRPASS-2, Battery Pass, and the EU registry give the architectures. | `registry.mock` is supported. The official registry stays out of bounds for tests. | 5.11 |
| Other twin stacks | NGSI-LD, DTDL, OPC UA, oneM2M, Web of Things, and BIM. None is a DPP standard. | Mostly new or not researched. | 5.12 |

### 1.3 What to do first

Section 8 orders the proposed capabilities. Changes that remove a false verdict come first (CLAUDE.md rule 7). Five points stand out:

1. `aas.validate` must give `unsupported`, not a fail, for a format that it cannot read.
2. `identifier.parse` accepts `http` URLs, but the EU registry accepts only `https` identifiers. A profile must decide.
3. Resolver tests need the status of each redirect hop. The transport records hop URLs only, and the change touches a protected file.
4. Resolver conformance, the full GS1 Digital Link grammar, and further identifier schemes come next.
5. Further integrity profiles, JSON-LD processing, and SHACL need dependency decisions under CLAUDE.md rule 10.

Each change to a protected file needs an owner decision under CLAUDE.md rule 1. No requirement becomes `approved` through this page.

### 1.4 Facts that change often

- On 2026-10-19, a successful battery registration in the EU registry was not yet possible, according to the registry user guide.
- No ESPR product delegated act, service-provider act, or identifier act was adopted. The access act under Regulation (EU) 2023/1542 Art. 77(9) is not adopted.
- UNTP 0.7.0 is the pilot release. Catena-X CX-0160 1.1.0 is a preview. AAS 3.2 has no reusable conformance suite.
- Section 8 lists the oracle artifacts to pin by version and digest.

## 2. Method

### 2.1 Question and scope

The question was: which technical methods exist to implement a DPP, and what can a black-box conformance engine observe and test for each?
The research covered EU law, open specifications, open-source repositories, academic literature, and public pilot reports.
It did not cover the content of EN, ISO, IEC, or DIN documents (CLAUDE.md rule 5).

### 2.2 Stages

| Stage | Agents | Models | Output |
| --- | --- | --- | --- |
| 1. Sweep | 10 family deep dives, 3 literature sweeps, 1 repository inventory | Opus for 9 family files; Sonnet for the platform file, the literature, and the repositories | `m01` to `m10`, `l01` to `l03`, `r01` |
| 2. Independent check | 1 verifier for each file, 1 engine-mapping check, 1 completeness critic | Sonnet for the verifiers; Opus for the legal baseline, the mapping, and the critic | `*.verification.json`, `x01`, `x02` |
| 3. Gap files, round 1 | 4 files that the critic asked for, each with a verifier | Opus for 3 files; Sonnet for the version file and the verifiers | `f01` to `f04` |
| 4. Gap files, round 2 | 3 files for gaps of medium or low weight, each with a verifier | Opus for 2 files; Sonnet for 1 file and the verifiers | `g01` to `g03` |
| 5. Synthesis | 1 writer for each section of this page | Opus; Sonnet for the open questions | sections 3 to 8 and 10 |

All evidence files are in `docs/research/raw/implementation-methods/`.
The coordinating session wrote sections 1, 2, 9, 11, and 12, and assembled the page.
An advisor model reviewed the plan before stage 1 and before stage 5.

### 2.3 Tools

- Literature: Consensus and SciSpace search, and the OpenAlex and Crossref APIs for DOI checks.
- scite and Elicit refused access because of plan limits. Undermind was not used, because it writes to the owner's workspace.
- Web: a fetch tool and a search tool. MDPI pages returned HTTP 403, so the agents read DOI metadata instead.
- EUR-Lex `/eng` addresses returned empty pages on 2026-10-19. The agents read EU law at the Publications Office (Cellar).
- Repositories: read-only `gh api` calls. No agent contacted a live DPP system, resolver, registry, connector, wallet, or ledger node.

### 2.4 Rules that every agent followed

- Rule 5: each agent recorded EN, ISO, IEC, and DIN documents by number and title only. The AAS comes from IDTA specifications, and identification links come from GS1 specifications.
- Rule 6: each agent recorded only sources that it retrieved in the session, with an honest verification level.
- Rule 8: web pages, repositories, and papers were data. No agent followed an instruction in them.
- Each agent wrote in its own words. EU law was paraphrased and cited by article.

### 2.5 Verification levels

The levels are the same as in the [source audit](source-audit.md), section 1.2: `substantive`, `metadata_only`, `secondary_only`, and `not_located`.
A verifier tried to refute 28 to 42 claims of each file. It chose the claims with the highest risk and the highest effect on the engine.
The verdicts are `confirmed`, `refuted`, and `not_confirmed`. Section 9 gives the totals and the main corrections.

### 2.6 Interruptions

The account's five-hour usage limit stopped agents twice.
In stage 1, it stopped 7 of 14 agents. Six had saved complete drafts. New agents continued each draft with a handoff note from the transcript. The repository inventory ran again.
In stages 4 and 5, it stopped 16 writers, one gap file, and three verifiers.
Two of the stopped writers had saved complete parts. With four finished parts, six parts were complete and stayed unchanged.
The other 14 writers, the gap file, and the verifiers ran again after the limit reset.

### 2.7 What this method does not give

- The checked claims are a sample chosen by risk. The verifiers did not check every claim.
- Agreement between two agents is not a human review. No person reviewed this page or its evidence files.
- Most literature entries rest on the abstract that a search tool returned. Several full texts were not reachable.

## 3. Classification model

### 3.1 Two axes

The first axis is the layer. A layer is one group of duties that every DPP system must meet, whatever its technology. The model has eleven layers, L01 to L11.

The second axis is the family. A family is one implementation method: a coherent set of specifications, components, and flows. Section 5 describes twelve families.

EU law prescribes properties, roles, and one central component, the registry, but no technology (`m01`). The layers name duties that the law sets. The families name how specifications and projects meet them.

#### Why a faceted model

A single label per system does not work, for three reasons:

- Most family files tag more than one family. The platform file (`m10`) tags ten of the eleven tags in the research schema.
- Seven of the ten first-round family files carry the tag `hybrid`, but none defined it (`x02`).
- The prototype sweep (`l02`) states that hybrids are the norm. In the review sweep (`l01`), `hybrid` is the most frequent tag (17 papers).

The model is therefore faceted. A tester gives a system under test one family for each layer. Several families on one system make a hybrid stack.

#### Hybrids are the norm

The hybrid file (`f02`) defines a hybrid stack as a per-layer assignment. Different families supply different layers. They pass control to each other at a few hand-over points, mostly at L03.

In all five stacks that `f02` examined, EU law fixes the outer frame: carrier, unique identifier, operator storage, and registry upload. Inside that frame, each stack chooses its families (section 5.10).

`f02` finds the common faults of hybrids at the seams. Examples are relation names in linksets, identifier equality across layers, the byte form that is signed or hashed, and a change of access regime.

The critic proposes an ICS profile that declares a family per layer, and a cross-family mode of `identifier.consistency`. Neither exists in the engine today.

### 3.2 Layers

The last column names the engine checks that the engine-mapping check (`x01`) found most often for each layer. Its qualifiers use the `x01` verdicts, not the raw claims of the family files.

L01 to L08 reuse only the titles of the eight CEN/CLC/JTC 24 standards as labels. Section 4.8 lists these standards by number and title. This page did not use their content. L09 to L11 come from EU law and governance: the registry act, the lifecycle articles, and the rules for operators and service providers.

| Id | Layer | What it covers | Main engine checks |
| --- | --- | --- | --- |
| L01 | Unique identifiers | Product, operator, and facility identifiers; their syntax and granularity; equality of one identifier across carrier, passport, and registry. | `identifier.parse` (item-level GS1 Digital Link `/01/{GTIN}/21/{serial}` only); `identifier.consistency` (exact text). |
| L02 | Data carriers | QR code, Data Matrix, NFC, RFID; the payload text; data on the carrier itself (section 6.1). | `carrier.qr_decode` (decode only). The `carrier.nfc` and `carrier.rfid` capabilities are `interface_only`. |
| L03 | Data exchange protocols | HTTPS transport, redirects, content negotiation, linksets, and dataspace handshakes. | `identifier.resolve` (records hop URLs, not per-hop status codes). In `x01`, 17 of 39 L03 entries named no check. |
| L04 | APIs for lifecycle and searchability | Create, read, update, and search interfaces of the operator system or service. | `api.contract` (pinned OpenAPI 3.1 subset, `get` only, five passport resources). |
| L05 | System interoperability and data models | Schemas, JSON-LD contexts, ontologies, submodel templates, and aspect models. | `data.jsonschema`; `data.context` (allowlist only); `data.rules`; `aas.validate` (generic AAS validity, not template conformance). `data.shacl` is `interface_only`. |
| L06 | Storage, archiving, and persistence | Hosting, the back-up copy, and availability over time and after cessation of the operator. | Parts only: `identifier.consistency`, `registry.consistency`, `data.rules`. `x01` judged `persistence.versions` wrong in two of the three L06 entries that name it. |
| L07 | Access rights, security, and confidentiality | Access tiers by role, leaks on each channel, and tracking on public views. | `access.restricted_fields` (capability `access.policy`): fetch, search, export, error, and HTML channels. |
| L08 | Authentication, reliability, and integrity | Signatures, credentials, status lists, and ledger anchors. | `integrity.jws` (ES256, `typ` `dpp+jws`, `x5c` key only). In `x01`, 17 of 25 L08 entries named no check. |
| L09 | Registry and customs | Registration of the identifier, the registration identifier, and the customs check. | `registry.consistency` against `registry.mock` (two field pairs). `registry.official` is `interface_only`. |
| L10 | Lifecycle, versioning, and updates | Successive versions, links to a predecessor passport, and status values. | `persistence.versions` (experimental). `x01` judged it overstated in 6 and wrong in 3 of the 10 entries that name it. |
| L11 | Roles and governance | Economic operator, DPP service provider, owner of the identifier space, and third-party renderers. | `manual.review`. Few objectives have a black-box observable. |

The counts in this table come from a tabulation of `x01` for this page. `x01` itself checked 226 entries: 172 correct, 36 overstated, and 18 wrong.

### 3.3 Families

The table compares the twelve families of section 5. Each cell summarizes the family file.

The data on the carrier itself (`g02`) is not a family in this model. It adds data to L02 in several families, and section 6.1 describes it.

| Family | Defining trait | Identifier and resolution | Data model | Exchange | Trust anchor | Maturity on 2026-10-19 | Section |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Plain web passport | Documents behind an HTTPS URL that the operator controls. | HTTPS URL on the operator host. A direct `GET`, with no resolver standard. | HTML, JSON, or JSON-LD. HTML can embed JSON-LD in a `script` element. | HTTP `GET` with negotiation on `Accept`, or one URL for each representation. | TLS. A separate JWS is an option. | No passport-specific specification. General web specifications such as RFC 9110 and JSON-LD 1.1. | 5.1 |
| GS1 web resolver | The identifier on the product is a web address. A GS1-conformant resolver answers it. | GS1 Digital Link URI, mostly GTIN with qualifiers. Redirect to `gs1:defaultLink`, or an RFC 9264 linkset. | The resolver does not define the passport format. Link types come from the GS1 Web Vocabulary, with `gs1:dpp`. | HTTP redirect, `linkType` parameter, `application/linkset+json`, and `/.well-known/gs1resolver`. | TLS on the resolver host. An optional `gs1:jws` link target. | URI Syntax 1.7.0 and Resolver 1.2.1, both ratified in August 2026. Web Vocabulary 1.18.0. | 5.2 |
| Asset Administration Shell | The passport is assembled from a shell and its submodels. | `globalAssetId` and `specificAssetIds`. Discovery service, or an ID Link URL that returns a linkset. | AAS metamodel 3.2. DppMetadata submodel (IDTA 02099-1) and templates selected by `semanticId`. | AAS HTTP/REST API. A server lists its profiles at `/description`. | `$signed` returns a compact JWS (new in 3.2). | Specifications 3.2 (Release 26-01). No reusable conformance suite covers the 3.2 DPP features. | 5.3 |
| Dataspace | The passport is a data asset behind the connector of the provider. No public anonymous path exists. | Catena-X: `CX:<manufacturerPartId>:<partInstanceId>`, BPN discovery, and a Digital Twin Registry. | SAMM aspect models. The payload is JSON in the value-only form. | Dataspace Protocol 2025-1: catalog, contract negotiation, and transfer. A short-lived bearer token opens the data plane. | Decentralized Claims Protocol credentials bound to a DID. Usage policies in the connector. | DSP 2025-1 is stable. CX-0143 1.4.0 is current on CX-Titan. CX-0160 1.1.0 is a preview, not eligible for certification. | 5.4 |
| Verifiable credential and decentralized identity | Each DPP statement is a signed W3C verifiable credential. | Resolver URL on the carrier. Linkset with typed links such as `dpp`. Issuer DID, for example `did:web`. | VCDM 2.0. UNTP JSON Schema and JSON-LD contexts. | HTTPS fetch of the credential, for example `vc+jwt`. | Issuer signature, Bitstring Status List, and an identity anchor credential from a register. | VCDM 2.0 is a W3C Recommendation. UNTP 0.7.0 is the pilot release; no 1.0 was located. | 5.5 |
| Event-based traceability (EPCIS) | The passport links to visibility events. It does not contain them. | GS1 identifiers in events. A linkset entry `gs1:epcis` or `gs1:traceability` leads to a repository. | EPCIS 2.0 events with CBV 2.0 values. JSON and JSON-LD binding with a JSON Schema. | REST: `/capture`, `/events`, and `/queries`. `GS1-*` headers and `OPTIONS` discovery. | Authentication on every call. An Event Hash ID that a verifier can recompute. | EPCIS 2.0 and CBV 2.0 ratified in 2022; 2.0.1 is the latest release. No GS1 conformance test suite. | 5.6 |
| Linked data and semantic web | The passport is a set of RDF statements about the product, identified by IRIs. | HTTP(S) IRI, often a GS1 Digital Link. Content negotiation or a linkset. | JSON-LD 1.1 with `@context`. Ontologies such as CIRPASS-2 CORE. SHACL shapes. SAMM and LinkML variants. | HTTP negotiation: `application/ld+json`, `text/turtle`. Triplestores with SPARQL; Solid pods. | Optional Data Integrity proof over RDFC-1.0 canonical form. | Core W3C stack is at Recommendation. DPP ontologies are drafts. | 5.7 |
| Distributed ledger | A small trust anchor sits on a ledger. A larger document stays off chain. | Operator URL on the carrier. Ledger references in the passport: transaction hash, token id, or content identifier. | Off-chain document. Token metadata through `tokenURI`. | Operator REST API, plus a ledger read: JSON-RPC, IPFS gateway, or the EBSI Timestamp API. | Anchored digest. Inclusion proof against a pinned root. | No DPP-specific ledger specification. Components such as ERC-721 are final. Literature is mostly prototypes. | 5.8 |
| Platforms, DPP service providers, and sector programs | A hosted service stores the passport, issues identifiers and carriers, and serves views. | Mostly GS1 Digital Link URLs in QR codes. Redirect or content negotiation. | Vendor-specific. Sector programs use their own models. | REST API with OAuth 2.0 or OIDC. A public view and restricted views. | Varies. Many vendor pages state no integrity mechanism. | No standard fixes the architecture. The service-provider delegated act is not adopted. | 5.9 |
| Hybrid stacks | A per-layer assignment of families, with hand-over points between them. | One identity must hold across layers: GS1 URI, ID Link, URN, DID, or `urn:uuid`. | Mixed: for example AAS submodels with SAMM, or JSON Schema with XSD. | Hand-over at L03: redirect or linkset to an AAS, a credential, or a dataspace. | The family that supplies L08: credential signature, ledger digest, or TLS only. | No single specification. Components have mixed status. | 5.10 |
| Reference implementations, pilots, and the EU registry | A central EU registry plus decentralized operator hosting. CIRPASS and Battery Pass give the architectures. | URL-form unique product identifier (UPI) plus a registration identifier. | JSON-LD by default (CIRPASS-2 D4.1). JSON Schema or SHACL in the test environment. | Content negotiation; registry web form, file upload, or API. | Proof of registration with a qualified seal and a time stamp. D4.1 recommends credentials with JOSE proofs. | Registry operational since 2026-07-20 per the Commission. User guide v1.03 says successful registration is not yet possible. | 5.11 |
| Other twin and data-sharing stacks | Twin or IoT platforms that a DPP host can build on. None is a DPP standard. | Entity ids (NGSI-LD), DTMI (DTDL), or Thing Description ids. A gateway can add a resolver. | NGSI-LD JSON-LD, DTDL v4, WoT Thing Description 1.1, OPC UA models, IFC. | HTTP with JSON-LD, OPC UA sessions, and IoT bindings such as MQTT. | None native. Only an added envelope gives something to verify. | NGSI-LD V1.9.1 (ETSI group specification). WoT TD 1.1 is a W3C Recommendation. OPC 30450-1 V1.0.0 is listed. | 5.12 |

Notes on the table:

- The redirect code of a resolver is not fixed by the GS1 resolver standard or by a numbered UNTP requirement. A test oracle accepts any `3xx` with a `Location` header and records the code.
- The UNTP rule that issuers produce JOSE or COSE is marked Proposed in the work-in-progress text. It is not normative.
- `integrity.jws` cannot verify a `vc+jwt` credential with a DID key. The independent check corrected the hybrid file on this point.
- Whether the Battery Pass architecture uses a ledger is unresolved. One report claims a permissioned ledger (unverified). The technical guidance describes central services without a ledger.

### 3.4 How to recognize the family of a system under test

A tester can infer the families of a system under test from outside. The list gives black-box observations in a useful order.

The engine decides applicability from the ICS and the profile. These observations help a tester check an ICS declaration. They do not replace it.

1. Decode the carrier sample. A GS1 Digital Link path, such as `/01/{GTIN}`, points to the GS1 web resolver family.
2. A `CX:` triplet with no URL points to the dataspace family, in its Catena-X form.
3. A DID points to the credential family. A bare ledger reference points to the ledger family.
4. A signature attribute or a compressed segment in the payload is data on the carrier (section 6.1).
5. Send `GET` with no `Accept` header. A `3xx` to one default target suggests a resolver.
6. A direct `200` with `text/html` on the operator host suggests the plain web family.
7. Request `/.well-known/gs1resolver` on the carrier host. A description file confirms a GS1-conformant resolver.
8. Send `Accept: application/linkset+json`. Link types such as `gs1:dpp` confirm the GS1 family.
9. Linkset relations `aas` and `aas-service-endpoints` point to the AAS family through an ID Link.
10. Linkset relations `dpp`, `dcc`, `dte`, and `idr` together point to a UNTP stack: resolver plus credentials.
11. A credential with a JOSE `typ` of `vc+jwt`, or a `proof` object, points to the credential family.
12. A JSON-LD body with `@context` and `@id`, or a `text/turtle` answer, points to the linked data family.
13. A `Link` header with the JSON-LD context relation on entity resources suggests NGSI-LD (section 5.12).
14. Paths such as `/shells`, `/submodels`, and `/description` with profile identifiers point to the AAS family.
15. A `/.well-known/dspace-version` answer and `404` from protocol endpoints without credentials point to the dataspace family.
16. `GS1-*` headers on `OPTIONS`, `/events` resources, and `Link` pages with `rel=next` point to the EPCIS family.
17. A transaction hash, token id, or content identifier in the passport points to the ledger family.
18. Hosts of a DPP service provider in the redirect chain or the TLS certificate subject suggest the platform family.
19. Record one family for each layer. Different families mean a hybrid stack (section 5.10).

Two limits apply:

- The engine transport records hop URLs, but not the status code of each hop. It redacts many headers, for example CORS headers (`x01`). Steps 5, 13, and 16 need infrastructure changes before the engine can record all their observations.
- A dataspace shows little without credentials. A tester sees the version endpoint and the status of protocol endpoints, but not the passport.

### 3.5 Dimensions outside the layer grid

The critic (`x02`) found two dimensions that have no layer in the L01 to L11 grid.

#### Human-readable view and its parity with the data

One URL often serves a person with a phone browser and a machine client. The plain web file (`g01`) describes three patterns:

- Proactive content negotiation on `Accept`, with `Accept` listed in `Vary`.
- HTML that embeds the same data as a `script` element of type `application/ld+json`.
- HTML that points to the JSON-LD document through a `Link` header of relation `alternate`.

The view and the data can drift apart: the HTML can lag the JSON. Restricted fields can leak through the HTML page while the JSON view hides them (`m10`).

Renderers add a third party. The CIRPASS-2 renderer front end sits behind an OpenID Connect login, so it is a portal, not a consumer view (`g01`).

`access.restricted_fields` probes the HTML channel for withheld fields. No check compares the fields, the identifier, or the version of the HTML view with the machine-readable passport. The critic proposes one.

The law gives some anchors (`m01`). Toy and detergent passports need no registration or password for consumers. They allow no tracking beyond what the presentation strictly needs (Regulation (EU) 2025/2509, Art. 20(4) and (10); Regulation (EU) 2026/405, Arts 19 and 22).

The plain web file adds two points that the legal baseline does not cover (family file; not verified). First, no DPP article that it read requires accessibility for persons with disabilities. Second, toy and detergent passports must be in the languages that the Member State requires.

For tests, `g01` names WCAG 2.2 success criteria that a static parse can decide. Visual layout and contrast stay a manual step.

#### Static and dynamic data, and the data source

Some literature classifies passport data by its source and its change rate. Wiesner et al. (2024) give three classes: static data from one source, static data aggregated from several sources, and dynamic data. The independent check confirmed this paper from its full text.

Käser et al. (2025) make the update of dynamic data one of three design-space dimensions (abstract only). Wan et al. (2025) review the data source as one of four areas (abstract only).

The family files touch this dimension in a few places only:

- EPCIS 2.0 adds sensor data to an event, as the "how" of a visibility event (`f01`).
- Updates by third parties in the use phase, such as repairers, appear only in a CIRPASS-2 D4.1 recommendation (`m07`) and in Wan et al.

No first-round family file records the change rate of a passport as a field. The critic states the consequence. `persistence.versions` and the freshness rules of `data.rules` need a declared change class. The critic proposes it as an ICS value.

#### Other dimensions that the files record

The critic lists more dimensions from the literature that no family file uses:

- Deployment model (cloud, hybrid, on-premises) and standardized or custom API (Shamsir et al. 2025). The second decides whether `api.contract` has a public contract to pin.
- Decentralization level: identifier minting, data storage, and distributed storage (Sasdelli et al. 2025, abstract only).
- Nested passports from raw material to final product (Nowacki et al. 2023). No family gives a link mechanism that a check could verify.

### 3.6 Comparison with classification schemes in the literature

The review sweep (`l01`) found no single accepted classification. It sorts the schemes into five kinds: attribute grids, a morphological taxonomy, design-space dimensions, layered reference architectures, and requirement lists.

The same dimensions recur under different names, and they line up with the layers of this page.

The table lists only the schemes that the evidence files record. A link appears only where an evidence file gives an https address for the paper. "(abstract only)" marks a scheme read from an abstract or a search-tool excerpt.

| Paper (DOI link) | Scheme | How it maps to the layers and families |
| --- | --- | --- |
| [Shamsir et al. 2025](https://dl.gi.de/handle/20.500.12116/47551), `10.18420/inf2025_141` | Taxonomy with 21 dimensions in four meta-dimensions: organization, industrial applications, technology usage, and data types. | Technology dimensions map to families (AAS, blockchain) and to L01, L02, L05, and L08. Deployment model and API integration have no layer. |
| [Trienens et al. 2026](https://www.cambridge.org/core/product/identifier/S2732527X26105185/type/journal_article), `10.1017/pds.2026.10518` | Five levels plus lifecycle and granularity axes. The communication level is a seven-layer stack. | Communication layers map to L01, L03, L05, L07, and L08. The data-source layer and the lifecycle axis have no layer here. |
| [Wiesner et al. 2024](https://ris.utwente.nl/ws/files/453560583/978-3-031-59465-6_19.pdf), `10.1007/978-3-031-59465-6_19` | Three data classes by source and change rate. Model, batch, and item granularity. Four capability layers: data collection, exchange, processing, and access. | Exchange maps to L03 and L04, access to L07, and granularity to L01. Data classes are outside the grid (section 3.5). |
| Käser et al. 2025, `10.23919/cnsm67658.2025.11297523` | Three design-space dimensions: data carrier, online storage, and update of dynamic data (abstract only). | Maps to L02, L06, and L10. Update of dynamic data is partly outside the grid. |
| [Gering et al. 2024](https://publica.fraunhofer.de/handle/publica/520096), `10.24406/publica-9335` | Three service classes by operator: central services, DPP system services, and third-party services (abstract only). | Central services map to L09 and section 5.11. The operator split maps to L06 and L11. |
| Kranner et al. 2026, `10.1016/j.procs.2026.02.274` | Four-block stack: data space, AAS, semantic models and vocabularies, and GS1 identification and events (abstract only). | A hybrid stack of the families in sections 5.4, 5.3, 5.7, and 5.2. |
| Behdani et al. 2026, `10.1109/sose69681.2026.11622330` | Four interoperability layers: technical, syntactic, semantic, and governance (abstract only). | Maps to L03, L05, and L11. It does not separate the families. |
| Wan et al. 2025, `10.1016/j.spc.2025.01.014` | Four review areas: data carrier, data source, data security, and user access and verification (abstract only). | Maps to L02, L07, and L08. Data source is outside the grid. |
| Ebel et al. 2026, `10.1016/j.procir.2026.05.053` | Design elements from a twin characterization: data structures, access rights, interoperability, identifiers, storage, and carriers (abstract only). | Maps to L01, L02, L05, L06, and L07. |
| [Lyse et al. 2026](https://doi.org/10.3390/digital6020043), `10.3390/digital6020043` | Framework archetypes: data-centric, layered, technology-anchored, and ecosystem-oriented. A second axis for validation maturity (abstract only). | Archetypes are coarser than families. The validation axis can inform the wording of claim levels. |
| [Psarommatis et al. 2026](https://link.springer.com/content/pdf/10.1007/s43615-026-00927-x.pdf), `10.1007/s43615-026-00927-x` | Attribute grid with more than twenty attributes, for example architecture and technology stack (abstract only). | Architecture and technology stack attributes correspond to families. The class lists were not read. |
| [Nowacki et al. 2023](https://eprints.bournemouth.ac.uk/39250/1/2023%20-%20Digital%20Product%20Passports.pdf), `10.1109/dcoss-iot58021.2023.00067` | Lifecycle stages with nested passports, nine design goals, and smart-contract methods for versions. | The ledger family (section 5.8). Version methods map to L10. Nesting is outside the grid. |
| [Illán García et al. 2024](https://arxiv.org/abs/2410.15758), `10.48550/arxiv.2410.15758` | Nine requirements R-01 to R-09 from the ESPR passport articles, each with design alternatives. | The credential family (section 5.5). R-01 and R-02 map to L01, R-04 to L06, R-06 to L07, and R-07 to L08. |
| Sasdelli et al. 2025, `10.18420/inf2025_03` | Three decentralization levels: identifier minting, data storage, and distributed storage (abstract only). | Maps to L01 and L06. No family file records a decentralization level. |
| Nguyen et al. 2026, `10.5381/jot.2026.25.3.a21` | Two families of DPP representation: AAS with ECLASS, and ontology or knowledge graph (abstract only). | The families in sections 5.3 and 5.7. |
| Markou et al. 2025, `10.1016/j.cscm.2025.e04267` | Approaches to material passports: BIM-based, blockchain-based, platform-based, QR or RFID based, and Level(s)-based (abstract only). | BIM maps to section 5.12, blockchain to 5.8, and platforms to 5.9. QR and RFID map to L02. |
| Maló et al. 2025, `10.1109/dcoss-iot65416.2025.00163` | Proposed layers: AAS core, microservices, semantic data space, and certification (abstract only). | A hybrid of the AAS, dataspace, and linked data families. |

Notes on the table:

- The independent check corrected the first capability layer of Wiesner et al. to "data collection". The table uses the corrected name.
- For Shamsir et al., the review sweep read the full text, and the independent check confirmed it. The prototype sweep could not read it.
- For Illán García et al., the review sweep records one citation slip in the paper. The availability period is in ESPR Art. 9(2)(i), not (h). The independent check confirmed this correction.

Two schemes classify tests, not systems. Snelick and Gebase (2010) name three test environments: data instance validation, isolated systems testing, and peer-to-peer systems testing (abstract only). Kulvatunyou et al. (2005) name four content-level test types (not confirmed by the independent check).

## 4. The legal baseline

This section states the minimum DPP method that EU law prescribes, status on 2026-10-19. Section 5 describes each family as a delta against it. The main input is `docs/research/raw/implementation-methods/m01-law-baseline.json` with its independent check `m01-law-baseline.verification.json`. Back-up and availability also use `docs/research/raw/implementation-methods/f03-backup-failover-availability.json` and its verification file.

The research team read the law at the Publications Office (Cellar), because EUR-Lex `/eng` addresses returned empty pages on 2026-10-19. Commission guidance has no legal force. This section marks such documents "non-binding". They are the general DPP FAQ v1.0, the battery FAQ, the registry user guide v1.03, and the Commission timeline.

EU law does not prescribe a DPP technology. It prescribes properties, roles, and one central component: the Commission registry. It names no protocol, HTTP method, header, media type, or signature format for the passport host.

### 4.1 The ESPR passport chapter and Annex III

Regulation (EU) 2024/1781 (ESPR, `reg-eu-2024-1781`) is in force since 2024-07-18. On 2026-10-19 it has no amending act. Its passport duties stay dormant until a product delegated act under Art. 4 applies, and no such act exists yet.

Art. 2 holds the core definitions. Point (28) defines the passport and point (29) the data carrier. Point (30) defines the unique product identifier, which also enables a web link to the passport. Points (31) and (33) define the operator and facility identifiers.

Point (32) defines the DPP service provider as an independent third party that the operator who places the product on the market authorizes. Point (46) lists the economic operators, and a DPP service provider is not one of them.

Chapter III (Arts 9 to 15) holds the passport rules. Art. 9 tells each delegated act what to fix: data set, carrier, granularity, access rights, and availability period. Art. 10 sets a persistent identifier, a carrier on the product, open machine-readable data, and a back-up copy. Art. 11 lists design goals in points (a) to (h) and three further subparagraphs.

Arts 27 to 31 give duties per role. The manufacturer and the importer make sure that the passport and its back-up exist (Arts 27(1)(c) and 29(2)(c)). An authorized representative cannot take over these duties (Art. 28(1)). Distributors verify the passport link where relevant (Art. 30(2)(a)), and dealers make the passport easy to reach (Art. 31(2)).

Annex III is a menu, not a fixed data set. Each delegated act chooses the binding items (Art. 9(2)(a)). The menu includes the unique product identifier in point (b) and the GTIN in point (c). It also includes commodity codes, compliance documents, manuals, operator and facility identifiers, and importer data.

Point (j) of Annex III includes the EORI number of the importer. Point (l) names the DPP service provider that hosts the back-up. The second paragraph names ISO/IEC 15459-1:2014, -2:2015, -3:2014, -4:2014, -5:2014 and -6:2014, or an equivalent. This fallback applies until the Official Journal (OJ) cites harmonized standards (Arts 10(1)(c) and 12(1)).

Presumption of conformity with Arts 10 and 11 comes from cited harmonized standards, to the extent that they cover the requirements (Art. 41(2)). Common specifications under Art. 42 are a fallback that the Commission has not used.

### 4.2 The battery passport

Regulation (EU) 2023/1542 (`reg-eu-2023-1542`) applies in the consolidated version `02023R1542-20260813`. From 2027-02-18, LMT batteries, industrial batteries above 2 kWh, and EV batteries each need a passport (Art. 77(1)). On 2026-10-19 this is the earliest fixed start date of any passport.

- Identifier: the operator who places the battery on the market attributes a unique identifier. It enables a web link (Arts 3(1)(66) and 77(3)). Art. 77(3) keeps its own ISO/IEC 15459 reference.
- Carrier: from 2027-02-18 every battery bears a QR code (Art. 13(6)). For the three passport categories, it gives access to the passport.
- Placement: on the battery, or on packaging and documents where size prevents it (Art. 13(7)).
- Print: Annex VI Part C asks for high contrast and a size that a common reader can read. It names no symbology standard.
- Delegation: this operator can authorize another operator in writing (Art. 77(4)).
- Format: open standards, interoperable, machine-readable, and searchable (Art. 77(5)).
- Re-use: after repurposing or remanufacturing, the operator who places the new battery on the market issues a new passport linked to the original (Art. 77(7)).
- Waste: responsibility passes to the producer, the producer responsibility organization, or the waste operator (Art. 77(7)).
- End: the passport ceases to exist after recycling (Art. 77(8)).
- Registry: the operator uploads the unique identifier to the ESPR registry (Art. 77(10)).

Art. 78 repeats the design goals of ESPR Art. 11 in points (a) to (h).

Annex XIII has four groups of data. Point 1 holds public model data in items (a) to (s). Point 2 holds model data such as composition, part numbers, and dismantling information. Point 3 holds test report results, and point 4 holds data of the individual battery.

The independent check refuted the access split in the raw file. The corrected split is this:

| Actor | Annex XIII points | Note |
| --- | --- | --- |
| Public | Point 1. | Art. 77(2). |
| Notified bodies and market surveillance authorities | Point 3. | Annex XIII does not name them for point 2. |
| Commission | Points 1, 2, and 3. | None. |
| Persons with a legitimate interest | Points 2 and 4. | The Art. 77(9) act must define these persons. |

The status values in point 4(c) are original, repurposed, re-used, remanufactured, and waste. Item 1(k) applies only to EV batteries. Items 1(c) and 1(e) depend on acts that the raw file records as not adopted (not confirmed by the independent check).

The Art. 77(9) implementing act defines persons with a legitimate interest and their rights. Its deadline was 2026-08-18, and on 2026-10-19 it is not adopted. Thus, no role except the Commission has a defined right to point 2 data today.

The Batteries Regulation has no back-up duty, because Arts 77 and 78 contain none. The battery FAQ (Q10.3, non-binding) says that the Regulation has no service-provider concept. Decision (EU) 2026/1736 supports the ESPR only, so it gives no presumption for battery passports.

### 4.3 The registry under Implementing Regulation (EU) 2026/1778

ESPR Art. 13 makes the Commission set up a registry by 2026-07-19. It stores at least the unique identifiers, the commodity code for products in free circulation, and the battery identifiers (Art. 13(1)). The operator who places the product on the market uploads the data (Art. 13(4)). The registry returns a registration identifier, which is not proof of compliance (Art. 13(5)).

Only the Commission, national authorities, and customs have access by right (Art. 13(6)). Art. 14 requires a public web portal for search within access rights. On 2026-10-19 the portal is not launched.

Commission Implementing Regulation (EU) 2026/1778 (`impl-reg-eu-2026-1778`) was published on 2026-07-17. It entered into force on 2026-08-06 (computed from Art. 24). The Commission says that the registry is operational since 2026-07-20. The act covers ESPR products, batteries, construction products, toys, detergents, and other passport products (Art. 1(1)).

Art. 3 lists nine components in points (a) to (i):

1. A secure web interface.
2. An API.
3. A verification platform.
4. A scheme that generates registration identifiers.
5. Storage of identifiers and commodity codes.
6. A list of verified DPP service providers.
7. A semantic repository.
8. A log system.
9. Identification and authorization schemes.

Operator verification uses eIDAS means (Arts 4 and 5). The independent check corrected the raw file here.

Electronic identification at assurance level high is a route only for sole traders established in the Union. Legal persons use a qualified electronic seal or a qualified electronic attestation of attributes. Verified status lasts at most three years.

Art. 8 sets the registration flow:

1. A verified operator submits at model, batch, or item level.
2. Items link to batch and model; batches link to model.
3. The operator uses the web interface or the API.
4. The Commission checks semantic conformity, mandatory data, granularity, and the commodity code.
5. Where relevant, the Commission checks that the back-up link is valid (Art. 8(7)(e)).
6. The registry stores identifiers, registrant data, date, time, and integrity evidence.
7. The registry returns a persistent registration identifier through the same channel.

Art. 2(12) defines semantic conformity: required elements are present, meet their rules, and the repository can interpret them. Arts 11 and 12 make the semantic repository the source of versioned data models. It offers DCAT-AP metadata and public APIs free of charge.

Art. 9 sets the proof of registration. It holds the product identifier, the operator, a Commission time stamp, and a hash of the passport version. A qualified electronic seal protects it, and it is available for 90 calendar days. Art. 2(16) names no hash algorithm.

Art. 6a allows transfer of a registered passport to another verified operator. Art. 7 makes each Member State appoint a national administrator by 2027-02-18. Art. 10 versions each change and keeps data 10 years, unless Union law sets the period. Art. 14 keeps immutable logs for six months to five years.

Customs follow ESPR Art. 15. The declarant gives customs the registration identifier for products under an Art. 4 act. Customs release the goods only after they verify that identifier and the commodity code against the registry. Release is not proof of compliance.

The customs check becomes automatic through the EU CSW-CERTEX link. This link must work within four years of the entry into force of the registry act, that is by 2030-08-06 (computed). The battery FAQ (Q4.1, non-binding) says that the battery registration identifier does not go into the customs declaration.

#### What the registry user guide adds (non-binding)

The [registry user guide](https://single-market-economy.ec.europa.eu/document/download/a71b5d30-ed8b-4c27-809d-757cf5e6030f_en?filename=dpp_registry_user_guide_for_economic_operators.pdf) is non-binding documentation. Its cover says "Last Published 2026-09-16 v1.03". The [resources page](https://single-market-economy.ec.europa.eu/single-market/digital-product-passport/resources-documentation_en) calls it "V3, 14 September 2026".

- Enrollment: the legal representative signs or seals a PDF declaration in PAdES Baseline B, T, LT, or LTA.
- Means: a qualified seal or a qualified signature on a qualified device. The registry rejects `.p12` and `.pfx` files.
- Certificate subject: OIDs `2.5.4.10`, `2.5.4.6`, and `2.5.4.97`. A natural person uses `2.5.4.42`, `2.5.4.4`, `2.5.4.6`, and `2.5.4.5`.
- Channels: a web form, or a JSON or XML file of at most 100 passports and 1 GB.
- Outcomes: each request gets a correlation ID and the status `PROCESSING`, `SUCCESS`, or `FAILURE`. One invalid passport rejects the whole file.
- UPI: the Unique Product Identifier (UPI) is an `https://` URL of at most 2000 characters that resolves to the passport data.
- UPI format: the guide calls it compliant with "JTC 24 standards". This page records that pointer only; the content was not consulted.
- Returned identifier: the guide calls it "URI (Unique Registration Identifier)", which collides with the RFC 3986 term.

The guide gives three kinds of UPI error. A bad format, protocol, domain, or port gives "The UPI URL is invalid". An unresolvable UPI shows `NOT_RESOLVABLE_UPI` in a screenshot. Excessive redirects, a protocol downgrade, or an oversized response give the generic message "unable to process your request".

The guide publishes no redirect count, size limit, or list of allowed domains and ports. It lists the error "Semantic validation failed due to its unavailability". Only the product group "Batteries" is selectable, at item level. Successful battery registration is not yet possible, because the semantic catalog for that group is not defined.

The guide documents the web channel only. The "DPP Registry technical guidelines" section of the resources page holds no file. So no registry API specification is public on 2026-10-19.

The guide prints the test host as `http://registry.acc.product-passport.ec.europa.eu/`, although the registry refuses non-https UPIs. The research team contacted no registry host.

The guide offers support Monday to Friday, 08:00 to 20:00 CET. Art. 13(1) of Regulation (EU) 2026/1778 requires a helpdesk year-round from 08:00 to 20:00 Brussels time. This difference is not resolved.

### 4.4 The baseline layer by layer

Each layer gives the requirement, the citations, and what a black-box tester can observe.

**L01 Unique identifiers.** The law defines product, operator, and facility identifiers (ESPR Art. 2(30), (31), (33)). The product identifier is persistent and links to the passport through the carrier (Art. 10(1)(a)). The registry adds the registration identifier. The law sets no identifier syntax; the guide (non-binding) requires an https URL.

Observable: the carrier payload, its scheme and length, duplicates, and the identifier in the passport.

**L02 Data carriers.** The carrier is on the product, its packaging, or its documents (ESPR Art. 10(1)(b)). Dealers get a free digital copy within five working days (Art. 10(3)). Batteries use a QR code. The general DPP FAQ (Q26, non-binding) says that QR codes and NFC are under assessment.

Observable: whether a carrier sample decodes and where it leads.

**L03 Data exchange protocols.** The law names no protocol. Data is transferable through an open network without vendor lock-in (Art. 10(1)(d); Batteries Art. 77(5)). Full interoperability is required (Art. 11(a)), with no measurable criterion. Toy and detergent consumers need no registration or password.

Observable: https reachability, each redirect hop, the final status and media type.

**L04 APIs, lifecycle, and searchability.** Data must be searchable (Art. 10(1)(d)). The law prescribes no API for the operator host. The only API in binding law is the registry API, which has no public specification.

Observable: for an operator system under test, the law gives no API contract.

**L05 System interoperability and data models.** Content is set per product group: Annex III, Annex XIII, and the sectoral lists. The registry act adds versioned data models in the semantic repository (Arts 11 and 12). Voluntary data must be separate from mandatory data.

Observable: mandatory fields at the public tier, enumeration values, and later a pinned Commission model.

**L06 Storage, archiving, and persistence.** The operator, or a DPP service provider for it, stores the passport (ESPR Art. 11(c); Batteries Art. 78(c)). Section 4.5 gives the back-up rules.

Observable: retrievals over time, a back-up reference, and agreement of the two copies.

**L07 Access rights, security, and confidentiality.** Each delegated act decides who sees and changes which data (Art. 9(2)(f) and (g)). The passport holds no personal data of customers without explicit consent (Art. 10(1)(e)). Batteries use the corrected split of section 4.2. Toys and detergents forbid tracking beyond strict need.

For construction products, access levels are in CPR Art. 75(2)(c). The independent check corrected this pin-cite, which the raw file had shifted by one letter.

Observable: what each role receives on each channel, and leaks to anonymous requests.

**L08 Authentication, reliability, and integrity.** The law states outcomes, not mechanisms (ESPR Art. 11(g); Batteries Art. 78(g)). Art. 11 allows implementing acts on digital credentials, and none was located. Only the registry has concrete means: eIDAS verification and the sealed proof.

Observable: nothing from a passport alone; seal and time stamp of an operator-supplied proof.

**L09 Registry and customs.** Section 4.3 gives these rules. The live registry is out of bounds for testing.

Observable: operator-supplied artifacts, such as a proof of registration, a CSV export, or a registration file.

**L10 Lifecycle, versioning, and updates.** Data must be accurate and up to date (ESPR Art. 9(1); Batteries Art. 77(4)). A new passport for a product links to the original one (ESPR Art. 11(d)). The registry versions each change, but names no passport status values.

Observable: successive versions, a predecessor link, and status values.

**L11 Roles and governance.** A DPP service provider may not sell or re-use passport data beyond the service (ESPR Art. 11; Batteries Art. 78(d)). A delegated act will set provider requirements. The general DPP FAQ (Q25, non-binding) says that no general third-party certification of passport content exists.

Observable: operator identity on the public part; contracts are not observable.

### 4.5 Back-up and availability

Under the ESPR, the operator makes a back-up copy available through a DPP service provider (Art. 10(4)). The copy is the most up-to-date version (Arts 27(1)(c) and 29(2)(c)). Annex III point (l) lets the passport name the back-up provider. Toys and detergents copy this duty.

Passports stay available for the period of the delegated act (Art. 9(2)(i)). This also applies after insolvency, liquidation, or cessation of activity in the Union (Art. 11(e)). Batteries have the same continuity rule (Art. 78(e)) but no back-up duty.

- Digital instructions: at least 10 years (ESPR Art. 27(7)).
- Toys and detergents: 10 years.
- Construction products: the system stays accessible 25 years after the last product of a type. Operators keep passports at least 10 years (CPR Art. 75(2)(i)).
- Construction availability and back-up procedures: CPR Art. 75(2)(f), as the independent check corrected.

At registration, the Commission checks the back-up link where relevant (Regulation (EU) 2026/1778, Art. 8(7)(e)). The registry stores a provider reference (Art. 8(9)(c)). Recital 16 says that these checks do not prove compliance. The guide (non-binding) shows no back-up field or error, so nobody can observe this check today.

The registry must be available at all times, except for announced maintenance (Art. 15(2)). Art. 15(3) allows suspension without notice. No adopted act fixes back-up independence, a synchronization interval, an availability level, or a fallback route for users.

### 4.6 Sectoral passports

Four other Union acts create passports that reuse the ESPR infrastructure. Status on 2026-10-19:

| Act | Passport | Applies from | Notable rules |
| --- | --- | --- | --- |
| Regulation (EU) 2024/3110, construction products, Arts 75 to 80 | A passport system that a delegated act sets up. | The system: six months after the Art. 75 delegated act enters into force. The Art. 22(7) duty: 18 months later. | Access levels: Art. 75(2)(c). Create and update: Art. 75(2)(d) and (e). Back-up: Art. 75(2)(f). |
| Regulation (EU) 2025/2509, toys, Arts 19 to 24 | One passport per toy model. OJ date 12.12.2025. | 2030-08-01 (Art. 59). | No registration or password (Art. 20(4)). No tracking (Art. 20(10)). SME guidelines by 2029-08-01. |
| Regulation (EU) 2026/405, detergents, Arts 19 to 25 | One passport per model, plus a digital label. | 2029-09-23 (Art. 37). | Indelible carrier with a scan statement. Automated customs check from 2029-09-23 or the CSW-CERTEX link, whichever is later. |
| Regulation (EU) 2026/1738, vehicles, Art. 13 | Digital Circularity Vehicle Passport. | 2032-09-01 (Art. 13(1)). | Art. 2(3) to (5) exclude M2, M3, N2, N3, O, L, and special-purpose vehicles. Implementing acts due by 2030-08-14. |

Toys and detergents also need identical identifiers across passports, a registry upload, and the ESPR customs check. Art. 13 of the vehicle act fixes no carrier, identifier, or registry link. Annex VI of the toy and detergent acts was not researched. The passport-like rules of the Packaging and Packaging Waste Regulation and the Critical Raw Materials Act were not researched.

### 4.7 Acts not yet adopted

The research team re-checked these items on 2026-10-19. The independent check confirmed each status, unless the item says otherwise.

- ESPR Art. 4 product acts: none adopted. The non-binding timeline lists iron and steel for Q4 2026.
- Later Art. 4 acts: textiles, aluminum, and tires in Q3 to Q4 2027; furniture in 2028; mattresses and recycled content in 2029.
- Batteries Art. 77(9) act: not adopted. The battery FAQ expects a draft for feedback in October or November 2026.
- ESPR Art. 11 act on DPP service providers: not adopted. The timeline lists it under both Q2 2027 and Q3 2027.
- Same act: the "Have Your Say" record of initiative 14382 gives Q4 2026. The f03 independent check confirmed that record.
- ESPR Art. 12(4) act on identifier and carrier life cycle: not located.
- ESPR Art. 11 implementing act on digital credentials: not located.
- Second decision that cites EN 18239:2026 and EN 18246:2026: not located. The timeline says November 2026, and said September 2026 on 2026-10-13.
- CPR Art. 75 act on the construction passport system: Q2 2027 on the timeline.
- Commission data models and the registry API specification: not published.

The adopted text of the standardization request M/604 was not retrieved. The [ETSI mandates page](https://portal.etsi.org/EC-EFTA-Mandates) gives its expiry date as 2026-06-26.

### 4.8 The eight CEN/CLC/JTC 24 standards

CEN/CLC/JTC 24 published eight DPP standards. Commission Implementing Decision (EU) 2026/1736 cites six of them in the OJ, in force from 2026-07-15. Its legal basis is Art. 10(6) of Regulation (EU) No 1025/2012, in support of the ESPR.

| Number | Title | OJ citation status |
| --- | --- | --- |
| EN 18216:2026 | Digital product passport - Data exchange protocols | Cited by Decision (EU) 2026/1736, Annex row 1. |
| EN 18219:2026 | Digital product passport - Unique identifiers | Cited, Annex row 2. |
| EN 18220:2026 | Digital product passport - Data carriers | Cited, Annex row 3. |
| EN 18221:2026 | Digital product passport - Data storage, archiving, and data persistence | Cited, Annex row 4. The OJ title ends "and persistence". |
| EN 18222:2026 | Digital Product Passport - Application Programming Interfaces (APIs) for the product passport lifecycle management and searchability | Cited, Annex row 5. The OJ title omits "the". |
| EN 18223:2026 | Digital Product Passport - System interoperability | Cited, Annex row 6. |
| EN 18239:2026 | Digital product passport - Access rights management, information system security, and business confidentiality | Published, not cited. No presumption of conformity. |
| EN 18246:2026 | Digital product passport - Data authentication, reliability and integrity | Published, not cited. No presumption of conformity. |

The titles come from the [JTC 24 publications page](https://standards.cencenelec.eu/ords/f?cs=1FC22FDE02FD51137ADC6BE8CA4E10E8F&p=205%3A32%3A%3A%3A%3A%3AFSP_ORG_ID%2CFSP_LANG_ID%3A3342699%2C25). This page did not use the content of these standards. It records number, title, and citation status only.

An open question remains. Do the citations of EN 18219:2026 and EN 18220:2026 end the ESPR fallback to the ISO/IEC 15459 series, and from which date? The Batteries Regulation keeps its own reference in Art. 77(3).

### 4.9 What a tester can derive from the law alone

See [Capabilities](../reference/capabilities.md) and the [Glossary](../reference/glossary.md) for the check names and terms in this list.

- The law gives no protocol contract for the passport host. A protocol check rests on a declared profile.
- The guide (non-binding) supports an `https://` UPI of at most 2000 characters. `identifier.parse` also accepts `http`, so this rule is a gap.
- `identifier.resolve` bounds redirects but has no downgrade rule. It reports a long chain as inconclusive, never as a fail.
- The public battery tier must be readable without login. `access.restricted_fields` can test this with a law-derived policy file.
- Restricted battery data must not leak to anonymous requests. The authority role must not receive point 2.
- Tests of the legitimate-interest role give blocked or manual results until the Art. 77(9) act exists.
- Battery status values are a closed set of five. A rule pack can test this enumeration.
- A new passport after remanufacturing must link to the original. No check resolves that link today.
- A tester can compare a back-up copy with the primary copy at one point in time.
- Lifetime availability is not provable. `persistence.scheduled` is interface-only today.
- `data.rules` has no absence rule, so it cannot test for personal data.
- The hash in a proof of registration stays undecidable until the Commission publishes the algorithm and input.
- `registry.consistency` compares two pairs only: identifier and operator identifier.
- Interoperability, provider data re-use, and the five-day digital copy need manual review.

## 5. Implementation families

Each family below has the same structure. It gives the components, an end-to-end flow, and one row for each layer.
It then gives variants, versions, open-source implementations, the difference from the legal baseline, typical faults, and what the engine can test.
Real systems often combine families. Section 5.10 describes these hybrid stacks.

### 5.1 Plain web passport family

In the plain web passport family, the economic operator or a DPP service provider serves the passport at an HTTPS URL. The source is static files or the operator's own REST or JSON API. The family uses no resolver standard, no AAS, no dataspace connector, and no credential layer. A QR code holds the URL, so one URL must serve a phone browser and a machine client. The CIRPASS-2 test environment assumes this pattern, and academic prototypes use it. The engine reference system implements this family; we use it as an example, not as an authority.

#### Components

- **Data carrier.** A QR code that holds the passport URL as text.
- **Passport URL.** An HTTPS URL on a host that the operator controls. It can be the identifier itself or a path in the shape of a GS1 Digital Link.
- **Passport host.** Static files on object storage or a CDN, or an application server with a database.
- **Representations.** JSON with an operator schema, JSON-LD with `@context`, and HTML for people.
- **Content negotiation.** The server selects a representation from `Accept` and `Accept-Language` (RFC 9110 section 12.1).
- **Human-readable view.** Server-rendered HTML, or a single-page application that needs JavaScript.
- **Renderer.** An optional third-party service that fetches passports and builds a view, for example CIRPASS-2 dpp-renderer-be and dpp-renderer-fe.
- **Restricted tier.** An operator mechanism such as `Authorization: Bearer <token>` on the same URL or on a separate host.

#### End-to-end flow

1. A phone camera decodes the QR code and opens the HTTPS URL.
2. The browser sends GET with an HTML-first `Accept`, an `Accept-Language`, and no `Authorization`.
3. The server can redirect, for example with `303`, to a document URL.
4. The server selects `text/html` and a language, and lists `Accept, Accept-Language` in `Vary`.
5. The page shows the public tier with no login, consent wall, or third-party tracker.
6. The page can embed the same data in a `script` block of type `application/ld+json`.
7. A machine client sends GET to the same URL with `Accept: application/ld+json` or `application/json`.
8. The server answers `200` with the JSON or JSON-LD representation and the same `Vary` header.
9. The client validates the schema, the `@context` values, and the rules.
10. The client compares the identifier in the body with the URL that it dereferenced.
11. A registry stores a digest of the bytes that it fetched with a JSON `Accept` (CIRPASS-2 mock).

In the CIRPASS-2 portal path, the user logs in through OpenID Connect. Then dpp-renderer-be fetches the URL and converts RDF with Apache Jena.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | An HTTPS URL on the operator host. Uniqueness and persistence rest on domain ownership. | Carrier text, scheme, host, path shape; whether the body identifier equals the URL. |
| L02 data carriers | A QR code with the same URL for people and machines. The carrier sends no headers, so a bare GET must work. | Decoded QR text; the result of a browser `Accept` and a machine `Accept`. |
| L03 data exchange protocols | GET and HEAD over TLS. Proactive negotiation on `Accept` with q weights, and on `Accept-Language`. | Status, redirect chain, `Content-Type`, `Content-Language`, `Vary`, `Cache-Control`, `Link`, `Set-Cookie`. |
| L04 APIs for lifecycle and search | Public side is read-only. Create and update are internal. Search is operator-specific or absent. | GET and HEAD results; search results for a known serial; the answer for an unknown identifier. |
| L05 interoperability and data models | JSON, JSON-LD, or HTML. HTML can embed JSON-LD (JSON-LD 1.1 section 7). Language tags follow RFC 5646. | Parsed body, `@context`, embedded `script` blocks, `lang`, `title`, `alt`, table header markup. |
| L06 storage and persistence | Operator or service-provider hosting. URL persistence depends on domain, TLS certificate, and stable paths. | Repeated GETs: status, DNS and TLS errors, certificate dates, body digest changes. |
| L07 access rights and security | Anonymous GET gets the public tier. Restricted tiers use an operator token. HTML must filter like JSON. | Anonymous result per channel, `Set-Cookie`, third-party origins in HTML, login redirects, canaries. |
| L08 authentication and integrity | TLS only by default. Options: a separate JWS over the JSON, or a digest in a registry. | TLS chain; a JWS on a signed resource; equality of signed data, JSON, embedded JSON-LD, and HTML. |
| L09 registry and customs | The operator registers the URL. The CIRPASS-2 mock registry fetches it with a JSON `Accept`. | Mock registry record against the served URL and the identifier in the JSON. |
| L10 lifecycle and versions | The URL stays fixed; the content changes. Version fields are operator-defined. HTML can lag the JSON. | `version` and `updated_at` per representation; `ETag`, `Last-Modified`, `Cache-Control`; a history endpoint. |
| L11 roles and governance | The domain owner controls the identifier space. A renderer that proxies fetches is another party in the path. | Hosts in the redirect chain, TLS certificate subject, third-party origins in the HTML. |

The engine reference system differs from the main variant. It serves JSON at `/dpp/{id}` and HTML at `/dpp/{id}.html`, and it ignores `Accept`. It sends no `Vary`, `Cache-Control`, `Content-Language`, or `Link` header. Its handler defines only `do_GET`, so it does not implement HEAD.

#### Variants

- One URL with proactive negotiation on `Accept`, optionally also on `Accept-Language`.
- One URL per representation, with a suffix such as `.json` or `.html`, or a `?format=` parameter.
- HTML with a `Link` header of relation `alternate` and type `application/ld+json` (JSON-LD 1.1 section 6.2).
- HTML with embedded JSON-LD `script` blocks.
- A `303` redirect from the carrier URL to a document URL. The reference system does this from `/01/<gtin>/21/<serial>`.
- Reactive negotiation with `300`, or `406` with a list of alternatives.
- Static files on a CDN, with a media type per file extension and no negotiation.
- A single-page application shell that fetches JSON with JavaScript.
- A credential render template, which is a hybrid with the verifiable credentials family (section 5.5).

#### Specifications and versions (status on 2026-10-19)

No passport-specific open specification defines this family. It combines general web specifications with EU law.

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| RFC 9110 HTTP Semantics | June 2022, STD 97 | Internet Standard | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) |
| RFC 9111 HTTP Caching | June 2022, STD 98 | Internet Standard; obsoletes RFC 7234 | [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) |
| RFC 5646 language tags | September 2009, BCP 47 | Best Current Practice | [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646.html) |
| JSON-LD 1.1 | 16 July 2020 | W3C Recommendation (date from the independent check) | [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/) |
| WCAG 2.2 | 12 December 2024 | W3C Recommendation | [WCAG 2.2](https://www.w3.org/TR/WCAG22/) |
| ACT Rules Format 1.1 | 5 February 2026 | W3C Recommendation | [ACT Rules Format](https://www.w3.org/TR/act-rules-format-1.1/) |
| VC Rendering Methods v1.0 | Editor's copy, no date | Self-described experimental | [VC render method](https://w3c.github.io/vc-render-method/) |
| UNTP Verifiable Credentials | 0.7.0 pilot; WIP page | WIP text is not normative; `renderMethod` is a SHOULD there | [UNTP VC](https://untp.unece.org/docs/specification/VerifiableCredentials) |
| CIRPASS-2 D4.1 Reference Architecture | V1.1 (2026-06-16) | Project guidance; not normative | [D4.1 on Zenodo](https://zenodo.org/records/20720002) |
| CIRPASS-2 test environment description | 2026-06-16 | Project report | [Test environment](https://zenodo.org/records/20749604) |
| CIRPASS-2 dpp-renderer-fe | Release 1.1.0 (2026-09-23); `package.json` says 1.2.0 | Experimental | [dpp-renderer-fe](https://github.com/CIRPASS-2/dpp-renderer-fe) |
| CIRPASS-2 dpp-renderer-be | Releases `1.0.2-pgsql-oidc` and `1.0.2-mariadb-oidc` (2026-06-11) | Experimental | [dpp-renderer-be](https://github.com/CIRPASS-2/dpp-renderer-be) |
| axe-core | v4.14.0 (2026-10-05) | Active | [axe-core](https://github.com/dequelabs/axe-core) |
| Directive (EU) 2019/882 | OJ text of 7 June 2019 | Measures apply from 28 June 2025 (Art. 31) | Publications Office (Cellar) |
| Engine reference system | File state at commit `ed5779c` or later | Project example; synthetic; loopback only | `src/dppce/infrastructure/reference_server.py` |

For the reference system, the newest commit on this branch that touches the server file is `f743f5a`.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| Engine reference system (project example) | Server | Apache-2.0 | Commit `ed5779c` or later (2026-10-18) |
| [CIRPASS-2 dpp-renderer-be](https://github.com/CIRPASS-2/dpp-renderer-be) | Renderer back end | Apache-2.0 | Pushed 2026-06-11 |
| [CIRPASS-2 dpp-renderer-fe](https://github.com/CIRPASS-2/dpp-renderer-fe) | Renderer front end | Apache-2.0 | Pushed 2026-09-23 |
| [CIRPASS-2 mock-eu-registry](https://github.com/CIRPASS-2/mock-eu-registry) | Registry mock | Apache-2.0 | Pushed 2026-08-04 |
| [CIRPASS-2 dpp-data-extractor](https://github.com/CIRPASS-2/dpp-data-extractor) | Search key extractor | Apache-2.0 | Pushed 2026-08-04 |
| [transpareo-time-machine](https://github.com/transpareo/transpareo-time-machine) | Renderer | GPL-3.0 | Release v2.20.3, 2026-10-15 |
| [boebe-DPP-Viewer](https://github.com/boebe24/boebe-DPP-Viewer) | Android viewer (AAS source) | MIT | Pushed 2026-10-19; release v1.2.1 |
| [axe-core](https://github.com/dequelabs/axe-core) | Accessibility validator | MPL-2.0 | Pushed 2026-10-19 |
| [Pa11y](https://github.com/pa11y/pa11y) | Accessibility validator | LGPL-3.0 | Release 10.0.0, 2026-08-28 |
| [Coffee machine DPP prototype](https://doi.org/10.5281/zenodo.18433713) | Academic pilot | CC-BY-4.0 | Zenodo record 2026-01-30 |

The CIRPASS-2 renderers have 2 GitHub stars each. dpp-renderer-be sends one `Accept` header with 16 JSON-LD, JSON, and RDF media types and no q weights. It parses `text/plain` as N-Triples. dpp-renderer-fe needs an OpenID Connect login on every functional route, so it is a portal, not a consumer view.

The axe-core README claims that the tool finds 57% of WCAG issues on average. This is a vendor claim. axe-core and Pa11y run in a browser, but the engine never renders or executes HTML. So they can only support a separate manual step. The code of transpareo-time-machine, boebe-DPP-Viewer, and Pa11y was not read.

#### Difference from the legal baseline

- The law fixes outcomes, not a protocol. It names no HTTP method, header, or media type.
- The unique product identifier must enable a web link to the passport (Regulation (EU) 2024/1781, Art. 2(30)). Art. 2(29) defines the data carrier.
- Data must rest on open standards and be interoperable, machine-readable, structured, and searchable (Art. 10(1)(d)). The law prescribes no operator API.
- Customers and other actors get free and easy access according to their access rights (Art. 11(b)).
- Toy and detergent passports must be open to consumers without registration or a password (Regulation (EU) 2025/2509, Art. 20(4); Regulation (EU) 2026/405, Art. 22).
- Toys and detergents forbid tracking or analysis of use beyond what presentation strictly needs (Regulation (EU) 2025/2509, Art. 20(10); Regulation (EU) 2026/405, Arts 19 and 22).
- Which tracking is strictly necessary is a legal judgment. A black-box test cannot make it.
- The operator or a DPP service provider stores the passport (Art. 11(c)). A DPP service provider holds a back-up copy (Art. 10(4)).
- The passport stays available after insolvency or exit (Art. 11(e)). Toys require 10 years (Regulation (EU) 2025/2509, Art. 19(2)(g)); detergents require 10 years (Regulation (EU) 2026/405, Art. 21).
- The law sets no uptime figure and no rule for how a consumer reaches the back-up copy.
- Dealers and online marketplaces get a digital copy of the carrier or identifier within five working days (Art. 10(3)).
- Battery access tiers: the public gets Annex XIII point 1. Notified bodies and market surveillance authorities get point 3. The Commission gets points 1, 2, and 3.
- Persons with a legitimate interest get Annex XIII points 2 and 4. The act that defines them is not adopted (Regulation (EU) 2023/1542, Art. 77(9)).
- Batteries carry a QR code from 2027-02-18 (Regulation (EU) 2023/1542, Art. 13(6)). The independent check adds that only LMT, industrial over 2 kWh, and EV batteries link to a passport.
- The registry user guide is not law. It asks for an `https://` UPI of at most 2000 characters that resolves to the passport data.
- The guide rejects excessive redirects, protocol downgrades, and oversized responses. Its message is 'unable to process your request', not `NOT_RESOLVABLE_UPI`.
- Passport languages that the Member State requires: toys Art. 19(2)(e), detergents Art. 21(2)(e), and ESPR Art. 7(8) (family file; not in m01).
- Accessibility for persons with disabilities appears only for the detergent digital label (Regulation (EU) 2026/405, Art. 19(1)(e)) (family file; not in m01).
- The family file states that Directive (EU) 2019/882 does not list passports in its scope (family file; not verified).
- HTML and JSON parity, `Vary`, caching, and WCAG levels are engineering targets, not legal duties.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L03 | The server ignores `Accept` and always returns HTML. Registries and renderers get no machine data. | `identifier.resolve` with `application/ld+json` fails with `IDENTIFIER.RESPONSE.MEDIA_TYPE`. |
| L03 | The server negotiates but omits `Vary: Accept`. A CDN then serves JSON to browsers. | Negotiation matrix: bodies differ across `Accept` values, but `Vary` does not list `Accept`. |
| L03 | The server ignores q weights and returns JSON for `application/json;q=0`. | Negotiation matrix with weighted `Accept` vectors. |
| L03 | The server picks `text/plain` from the long dpp-renderer-be `Accept` list. The client then parses N-Triples. | Send the renderer-be `Accept` string; the `Content-Type` must be a declared machine type. |
| L03 | The server answers `406` to a browser `Accept`, because it does not treat `*/*` as a wildcard. | `identifier.resolve` with a browser `Accept` that expects `text/html`. |
| L03 | HEAD gives `501`, or other headers than GET. | HEAD probe in the negotiation matrix. |
| L05 | HTML and JSON come from different pipelines and drift. The HTML shows an older version. | Compare embedded JSON-LD and visible values with the JSON. |
| L05 | The HTML is a single-page application shell. Data appears only after JavaScript runs. | A static value search finds no data; the result is blocked or fail. |
| L05 | The `lang` attribute is absent or wrong, or `Content-Language` disagrees with the content. | Static `lang` check and an `Accept-Language` matrix. |
| L05 | Images carry hazard or recycling information without `alt` text. | Static parse: `img` without `alt` fails WCAG 2.2 SC 1.1.1. Adequate text stays manual. |
| L07 | A login or consent wall, or a redirect to an identity provider, guards the consumer view. | Anonymous `identifier.resolve`: the final host or status differs from the declared public view. |
| L07 | An analytics script, tracking pixel, third-party font, or first-visit `Set-Cookie`. | Static scan of response headers and HTML attributes. |
| L07 | The anonymous HTML shows restricted fields that the JSON hides. | `access.restricted_fields` with canaries on the HTML channel (reference fault `leak_html`). |
| L07 | A response to a request with `Authorization` carries `Cache-Control: public`. | Header rule on restricted responses (RFC 9111). |
| L06 | An unknown serial returns `200` with an HTML error page (soft 404). | `identifier.resolve` on an unknown identifier expects `404` or `410`. |
| L06 | The domain or certificate lapses after the operator exits. The carrier URL does not lead to the back-up. | Scheduled acquisition only; one run cannot detect it. |
| L11 | A renderer fetch proxy (`/fetch/v1?url=`) fetches internal addresses. | Not a passport test. For a renderer under test, send a private-address URL on loopback. |

#### What the engine can test

The x01 mapping (`x01-engine-mapping.json`, commit `b290791`) covers the files m01 to m10 only. It has no row for this family and no proposed capability merged from it. Where an m07 or m01 row has the same objective, the table gives that x01 verdict. Other rows give the g01 mapping and say whether the independent check confirmed it. See [Capabilities](../reference/capabilities.md).

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| A JSON `Accept` on the carrier URL gives machine data. | `identifier.resolve` (x01 m07 row: correct). | None | Negotiating reference-server variant; fault that always returns HTML. | loopback only |
| A browser `Accept` on the same URL gives `text/html`. | `identifier.resolve` with `accepted_media_types` `text/html` (x01 m07 row: correct). | None for one value | Negotiating layout; IXIT flag for single-URL negotiation. The reference server fails today. | loopback only |
| Every negotiated response lists the selecting fields in `Vary`. | None (not mapped by x01). | `identifier.negotiation_matrix` (g01 proposal) | Fault `negotiation_no_vary`. | loopback only |
| An unmatched `Accept` gives `406` or the declared default. | `identifier.resolve` sees the status only (not mapped by x01). | `identifier.negotiation_matrix` plus an IXIT field | Two server variants: `406` and default. | loopback only |
| q weights decide the representation. | `identifier.resolve` per value (not mapped by x01). | `identifier.negotiation_matrix` | `Accept` vectors, including both CIRPASS-2 renderer lists. | loopback only |
| HEAD returns the same status and headers as GET. | None (not mapped by x01). | HEAD probe in `identifier.negotiation_matrix` | Reference server needs `do_HEAD`; fault `head_501`. | loopback only |
| Embedded JSON-LD in the HTML equals the JSON-LD representation. | None (not mapped by x01). | `data.html_embedded_parity` (g01 proposal) | Stale, double-block, and `base` HTML; W3C JSON-LD 1.1 test suite (not retrieved). | loopback only |
| Each public field value appears in the HTML text. | `access.restricted_fields` reads HTML for leaks only (not mapped by x01). | `view.value_presence` (g01 proposal) | Reference HTML; stale HTML; single-page application shell. | loopback only |
| The anonymous consumer view needs no login or password. | `identifier.resolve` plus `access.restricted_fields` (the independent check confirmed the HTML channel). | An HTML entitlement rule in `access.restricted_fields` | Fault `html_login_redirect`. | loopback only |
| The consumer path sets no cookie and loads no third-party resource. | None (x01 m01 row: correct). | `privacy.tracking_probe` (x01, from m01) | HTML with a third-party analytics script; a `Set-Cookie` response; a clean page. | loopback only |
| Restricted responses are not shared-cacheable, and HTML leaks no withheld field. | `access.restricted_fields` (not mapped by x01; the independent check confirmed the HTML channel). | A `Cache-Control` rule on restricted responses | Fault `restricted_public_cache`. | loopback only |
| The HTML declares a valid BCP 47 language, and `Content-Language` agrees. | None (not mapped by x01). | `view.html_static_a11y` plus `identifier.negotiation_matrix` (g01 proposals) | Pinned IANA Language Subtag Registry file; bad `lang` variants. | loopback only |
| The HTML passes the WCAG 2.2 checks that a static parse can decide. | `manual.review` for the rest (not mapped by x01). | `view.html_static_a11y`, static subset only | Reference HTML without `title`, `alt`, or header cells; W3C ACT Rules (not retrieved). | sample artifact |
| The carrier URL and each hop use `https`. | `identifier.resolve` (x01 m07 row: correct; it does not judge downgrades). | A scheme assertion on `identifier.resolve` | Carrier fixture with an `http` URL; downgrade fault. | loopback only |
| The passport URL stays resolvable over time. | `identifier.resolve`, single run; `persistence.scheduled` is interface only (x01 m01 row: correct). | `persistence.scheduled` must become supported | Unknown-serial probe; soft-404 fault. | live system under test |
| `version` and `updated_at` agree across JSON, embedded JSON-LD, and HTML. | `persistence.versions`, JSON only (not mapped by x01). | `data.html_embedded_parity` for the HTML side | Stale-HTML fault with an older version. | loopback only |
| The registry URL equals the served URL and the identifier in the JSON. | `registry.consistency` (x01 m07 row: correct; two fixed field pairs). | None | Existing `registry_inconsistent` fault. | loopback only |

The engine never renders or executes HTML. So contrast (SC 1.4.3), reflow (SC 1.4.10), and script-driven requests stay manual. Whether a tokenizing HTML parser fits inside that rule is an owner decision. Record redaction replaces `Set-Cookie` values and some `Link` values today (x01). A cookie probe therefore needs a redaction change, which is a contract change.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/g01-plain-web-passport.json`. Law comes from `m01-law-baseline.json`; extra repositories come from `r01-repositories.json`.
- The independent check (`g01-plain-web-passport.verification.json`) checked 28 claims: 26 confirmed, 0 refuted, 2 not confirmed. It had no rule 5 findings.
- The check changed some facts. It added the JSON-LD 1.1 date and the battery QR target. It moved the axe-core push date to 2026-10-19, and it confirmed the toy and detergent article points.
- Two claims stay open. The reference-system "last change" commit is not confirmed. The word "searchable" in Battery Regulation Art. 77(5) is not confirmed, so we cite only ESPR Art. 10(1)(d).
- Open for the owner: a negotiating reference-server layout, the pinned `Accept` matrix, and an IXIT field for unmatched `Accept`. No field measurement of live passports was located.

### 5.2 GS1 web resolver family

The GS1 web resolver family makes the identifier on the product a web address. A GS1 Digital Link URI holds GS1 keys, for a passport usually a GTIN with optional batch and serial. A QR Code, a Data Matrix, or an RFID tag carries the URI. A GS1-Conformant Resolver at the URI host answers with a redirect or with a linkset that names the passport link. GS1 in Europe reports resolvers at brands, solution providers, and GS1 member organizations. Peer-reviewed prototypes (Made2Verify, a KAIST port pilot, R-Cycle) use the family for passports. The Battery Pass technical guidance names GS1 Digital Link as one option but does not mandate it. A code search found no GS1 Digital Link use in the CIRPASS-2 repositories.

#### Components

- **Data carrier.** A QR Code or Data Matrix holds the URI as text. An RFID tag holds an EPC binary string. NFC can hold the URI, but GS1 in Europe says NFC is not yet an approved GS1 carrier.
- **GS1 Digital Link URI.** The shape is `https://<host>[/<stem>]/<primary key AI>/<value>[/<qualifier AI>/<value>][?<AI>=<value>]`. For a GTIN, the qualifier order is `22`, `10`, `21`.
- **GS1-Conformant Resolver.** An HTTP service that redirects to one link or returns all links for the URI.
- **Linkset.** An RFC 9264 JSON document. Its relation keys are link types from the GS1 Web Vocabulary, for example `gs1:dpp` and `gs1:defaultLink`.
- **Resolver description file.** A JSON file at `/.well-known/gs1resolver` that names `resolverRoot` and `supportedPrimaryKeys`.
- **Passport host.** The target of the `gs1:dpp` link. GS1 does not define the passport format.
- **Global resolver.** `id.gs1.org` can hand a request to a brand resolver by GS1 Company Prefix pattern (`gs1:handledBy`).

#### End-to-end flow

1. A reader decodes the carrier and gets a GS1 Digital Link URI.
2. The client parses the URI into GS1 keys and pads the GTIN to 14 digits.
3. For an `eh` or `ex` path segment, the client or the resolver decompresses the EPC string.
4. The client sends a GET request with `Accept: application/linkset+json` or with `?linkType=linkset`.
5. The resolver checks the URI syntax and answers `400` for an invalid URI.
6. The resolver collects the links of the serial, batch, and GTIN levels.
7. The resolver returns `200` with the linkset, or `404` when it has no data.
8. The client validates the linkset against the pinned GS1 linkset schema.
9. The client selects the link with relation `gs1:dpp` or the IANA relation `dpp`.
10. The client fetches the passport and validates its schema, context, and signature.
11. The client checks that the passport identifier matches the parsed GS1 keys.

A phone camera sends no linkset request, so it gets a redirect to the `gs1:defaultLink` target, often a consumer page. A request with `?linkType=gs1:dpp` gets a redirect to the passport link, or `404`.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | GS1 primary key plus qualifiers in a URI path. Model is GTIN or GTIN+22, batch is GTIN+10, item is GTIN+21. | Path segments, AI codes, check digit, qualifier order, character set, percent-encoding, compressed segment. |
| L02 data carriers | QR Code or Data Matrix with the URI as text. RFID with EPC binary per TDS 2.3. | Decoded payload of an image sample, a hex EPC dump, or an NFC record. |
| L03 data exchange protocols | HTTPS with GET, HEAD, and OPTIONS, and CORS. Redirect to one link, or `200` with a linkset. | Status and `Location` of each hop, `Link`, `Content-Type`, `Vary`, and CORS headers. |
| L04 APIs for lifecycle and search | Read side only. Write APIs are specific to each implementation, for example a bearer-token API in GS1 Resolver CE. | The anonymous linkset before and after an update. Write APIs need an authorization scope. |
| L05 interoperability and data models | RFC 9264 linkset, GS1 linkset schema, JSON-LD context, Web Vocabulary link types. | Schema validity, relation keys, anchors, declared `type` against the served `Content-Type`. |
| L06 storage and persistence | The resolver stores links, not passports. The printed URI stays fixed while links change. | Status and target over repeated observations. A finite series proves no lifetime. |
| L07 access rights and security | Resolution is public by design. Access tiers sit at the target systems. | Restricted URLs in an anonymous linkset; anonymous answers of restricted targets. |
| L08 authentication and integrity | TLS only. Linksets and redirects carry no signature. `gs1:jws` can point to a JSON Web Signature. | TLS on the host; a `gs1:jws` target and its validity. |
| L09 registry and customs | No GS1 standard covers the EU registry. GS1 in Europe proposes to register parsed keys, not the URL. | Parsed carrier keys against the identifier in a mock registry record. |
| L10 lifecycle and versions | The resolver re-points links. A changed model needs a new GTIN. No link versions or end-of-life link type exist. | Target and linkset changes over time for one URI. |
| L11 roles and governance | GS1 issues company prefixes; brand owners allocate GTINs. Each resolver is sovereign over its own URI space. | `resolverRoot` and `contact` in the description file; the `gs1:handledBy` chain. |

#### Variants

- Granularity: GTIN only, GTIN+22, GTIN+10, GTIN+21, or all three qualifiers.
- Host: the reference host `id.gs1.org`, or a brand host with or without a custom path stem.
- Carrier: QR Code, Data Matrix, RFID (`SGTIN-96`, `SGTIN+`, `SGTIN++`), or NFC. A compressed URI holds an `eh` (hex) or `ex` (base64url) segment.
- Redirect code: the resolver standard fixes none. GS1 Resolver CE uses `307`.
- Linkset request: by `?linkType=linkset` or by `Accept`. Some resolvers serve an HTML page with the linkset in JSON-LD.
- Delegation: a direct brand resolver, or the global resolver with `gs1:handledBy`.
- DPP link type: `gs1:dpp`, the IANA relation `dpp`, or terms outside the vocabulary such as `gs1:productPassport`.
- Passport payload: HTML, JSON-LD, a UNTP credential (`application/vc+jwt` in UNTP examples), an AAS, or a battery data model.
- UNTP Identity Resolver profile (WIP text, not normative): public linksets, `Vary: Accept`, and no linkset filter by `Accept-Language`.
- Legacy `linkType=all`: a UNTP 0.7.0 example uses it. The UNTP WIP text makes it a deprecated alias that clients should not send.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified Aug 2026; current | [URI Syntax](https://ref.gs1.org/standards/digital-link/uri-syntax/) |
| GS1-Conformant Resolver | 1.2.1 | Ratified Aug 2026; current; fixes no redirect code | [Resolver standard](https://ref.gs1.org/standards/resolver/) |
| GS1 linkset JSON schema | No version field | Normative since resolver 1.2.0 | [Linkset schema](https://ref.gs1.org/standards/resolver/linkset-schema) |
| Resolver description file schema | `$id` names the 1.2.0 path | Normative since resolver 1.2.0 | [Description file schema](https://ref.gs1.org/standards/resolver/description-file-schema) |
| GS1 Web Vocabulary | 1.18.0 (2026-06-01) | Current; pin from ref.gs1.org. The GitHub mirror stops at v1.16. | [Vocabulary archive](https://ref.gs1.org/voc/data/archive) |
| Web Vocabulary link-type list | No version marker | `gs1:dpp` is stable. Store the digest of the fetched file. | [Link types](https://ref.gs1.org/voc/data/linktypes) |
| EPC Tag Data Standard | 2.3 | Ratified Oct 2025 (check saw search excerpts only) | [TDS](https://ref.gs1.org/standards/tds/) |
| Digital Link compression for EPC binary strings | 1.0.0 | Ratified Jul 2025 (check saw search excerpts only) | [Compression](https://ref.gs1.org/standards/digital-link/compression) |
| 2D Barcodes at Retail Point-of-Sale guideline | 1.1.0 | Ratified Dec 2025 | [2D retail guideline](https://ref.gs1.org/guidelines/2d-in-retail/) |
| UNTP Identity Resolver | 0.7.0 | Pilot release. The WIP text is not normative. No 0.8.0 or 1.0 found. | [UNTP IDR](https://untp.unece.org/docs/specification/IdentityResolver) |
| IANA link relation `dpp` | Registry update 2026-06-12 | Registered; reference is the UNTP Identity Resolver | [IANA link relations](https://www.iana.org/assignments/link-relations/link-relations.xhtml) |
| RFC 9264 Linkset | 2022 | Proposed Standard | [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html) |
| GS1 Resolver Test Suite | Commit `32597c10` (2026-08-07) | Work in progress; targets resolver 1.2.1 | [Test suite page](https://ref.gs1.org/test-suites/resolver/) |
| GS1 Resolver CE (Community Edition) | 3.0.0, March 2026 updates | Community code; GS1 does not maintain it | [Resolver CE](https://github.com/gs1/GS1_DigitalLink_Resolver_CE) |
| GS1 Barcode Syntax Engine | 1.4.1 (2026-05-28) | Active | [Syntax engine](https://github.com/gs1/gs1-syntax-engine) |

Two version gaps stay open. The resolver standard still cites URI Syntax 1.4.0. A GS1 page excerpt gives Tag Data Translation at 2.2, behind TDS 2.3.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [GS1 Resolver CE](https://github.com/gs1/GS1_DigitalLink_Resolver_CE) | Resolver | Apache-2.0 | Pushed 2026-10-13 |
| [GS1DL-resolver-testsuite](https://github.com/gs1/GS1DL-resolver-testsuite) | Test suite | Apache-2.0 | Commit 2026-08-07 |
| [gs1-syntax-engine](https://github.com/gs1/gs1-syntax-engine) | Validator | Apache-2.0 | Pushed 2026-10-08 |
| [gs1-syntax-dictionary](https://github.com/gs1/gs1-syntax-dictionary) | AI data file | Apache-2.0 | Pushed 2026-08-29 |
| [gs1/linkset](https://github.com/gs1/linkset) | Schema and example linksets | Apache-2.0 | Commit 2025-06-16 |
| [GS1DigitalLinkToolkit.js](https://github.com/gs1/GS1DigitalLinkToolkit.js) | SDK | Apache-2.0 | Pushed 2025-05-01 |
| [interpretGS1scan](https://github.com/gs1/interpretGS1scan) | SDK | Apache-2.0 | Pushed 2025-06-18 |
| [GS1DigitalLinkCompressionPrototype](https://github.com/gs1/GS1DigitalLinkCompressionPrototype) | SDK, experimental | Apache-2.0 | Pushed 2025-12-03 |
| [gs1/TDT](https://github.com/gs1/TDT) | EPC translation rules | Apache-2.0 | Pushed 2026-09-19 |
| [gs1/WebVoc](https://github.com/gs1/WebVoc) | Vocabulary | Apache-2.0 | Pushed 2026-01-29 |
| [2d-barcode-generator](https://github.com/gs1/2d-barcode-generator) | Symbol generator | Apache-2.0 | Pushed 2026-05-29 |
| [digital-link.js](https://github.com/gs1/digital-link.js) | SDK, stale | Apache-2.0 | Pushed 2023-01-31 |
| [OpenEPCIS EPC and Digital Link translator](https://github.com/openepcis/openepcis-epc-digitallink-translator) | SDK | Apache-2.0 | Pushed 2026-09-13 |
| [louisaxel-ambroise/gs1-digitallink-resolver](https://github.com/louisaxel-ambroise/gs1-digitallink-resolver) | Resolver | MIT | Pushed 2026-10-16 |
| [pyx-identity-resolver](https://github.com/pyx-industries/pyx-identity-resolver) | Resolver | Apache-2.0 | Pushed 2026-06-12 |
| [grigolatoe/gs1-digital-link-resolver](https://github.com/grigolatoe/gs1-digital-link-resolver) | Resolver | Apache-2.0 | Pushed 2026-09-07 |
| [Starfish-Network/gs1-digital-link-resolver](https://github.com/Starfish-Network/gs1-digital-link-resolver) | Parser and resolver | Apache-2.0 | Pushed 2026-10-07 |
| [odal-node/dpp-core](https://github.com/odal-node/dpp-core) | SDK | Apache-2.0 | Pushed 2026-10-16 |

The GS1 Resolver CE README says that GS1 does not maintain it and that it may not fully conform. Treat it as a realistic system under test and a fault source, not as an oracle. The UNTP Identity Resolver page states no license.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no GS1 Digital Link URI, resolver, linkset, or link type.
- The unique product identifier must be persistent, reached through a data carrier, and enable a web link to the passport (Regulation (EU) 2024/1781, Art. 2(30) and Art. 10(1)).
- Until harmonized-standard references appear in the OJ, identifier and carrier must comply with ISO/IEC 15459-1 to -6 or equivalents (Art. 10(1)(c), Art. 12(1), Annex III second paragraph). We name these by number only.
- Annex III lists a GTIN as a data item in point (c). GS1 in Europe argues that GS1 keys can serve as the identifier; that is a GS1 claim.
- The product-group act sets model, batch, or item granularity. Under Implementing Regulation (EU) 2026/1778, Art. 8, item registrations link to batch and model identifiers where these exist.
- Batteries carry a QR code from 2027-02-18 per Annex VI Part C (Regulation (EU) 2023/1542, Art. 13(6)). The battery identifier comes from Art. 77(3).
- Dealers get a digital copy of the carrier or identifier within five working days (Art. 10(3)). A DPP service provider holds a back-up copy (Art. 10(4)).
- GS1 specifies no back-up link or failover. The GS1 in Europe failover through the registry is a proposal.
- The registry user guide, which is not law, asks for an https UPI of at most 2,000 characters that resolves. A GS1 Digital Link URI fits that shape.
- The guide rejects excessive redirects, protocol downgrades, and oversized responses. Its message is 'unable to process your request', not `NOT_RESOLVABLE_UPI`.
- The law sets access rights per product-group act (Art. 9(2)(f)-(g), Art. 11(b)). GS1 resolution is public and adds no access control.
- The law asks for authenticity and integrity as outcomes (Art. 11(g)). GS1 resolvers add only TLS.
- Implementing Decision (EU) 2026/1736 cites six EN DPP standards; its legal basis is Regulation (EU) No 1025/2012, Art. 10(6). Their content was not read.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | Qualifiers out of order, or serial characters outside the 82-character set without percent-encoding. | Parse against the pinned URI grammar. |
| L01 | One place pads a 13-digit GTIN and another place refuses it. | Parse carrier, resolver anchor, and passport id; compare canonical forms. |
| L02 | QR, Data Matrix, or RFID on one product carry different keys. | Decode every carrier sample and compare the parsed keys. |
| L02 | A retail 2D code uses a placeholder or example domain. | Compare the decoded host with the declared resolver root. |
| L03 | An invalid or unknown URI gets `200` and an error page. | Send crafted URIs; expect `400` and `404`. |
| L03 | An absent link type falls back to the default link. | Request `?linkType=gs1:dpp` for an entity without a DPP link; expect `404`. |
| L03 | The `Accept` list is split on commas without trim or q-values (GS1 Resolver CE). | Send `Accept` variants with spaces and q-values; expect the linkset each time. |
| L03 | A second `?` goes onto a target that already has a query (GS1 Resolver CE). | Parse `Location` per RFC 3986 and compare the parameters. |
| L03 | `Link` uses `rel="application/linkset"`, or the context link has an unquoted `rel` and `type` `text/html` (GS1 Resolver CE). | Parse `Link` strictly per RFC 8288; fetch the context target. |
| L03 | Inheritance done as a redirect from `/01/<GTIN>/21/<serial>` to `/01/<GTIN>`. | The first `Location` must not be a less granular Digital Link URI. |
| L03 | No CORS on OPTIONS or on errors; a slash at the path end gives `404`; an `eh` or `ex` URI fails. | Compare each variant with the plain request. |
| L03 | A permanent redirect (`301` or `308`) keeps an old target in caches. | Record the code per hop. Report a risk, not a fail. |
| L05 | Relation keys use `http://gs1.org/voc/dpp`, and the client looks for `https://ref.gs1.org/voc/dpp`. | Normalize keys with a pinned equivalence table; report the form. |
| L05 | Link types outside the vocabulary, such as `gs1:productPassport`, replace `gs1:dpp`; or an anchor has two default links. | Check each `gs1:` relation against the pinned link-type list; count default links. |
| L05 | The schema regex rejects a valid `hreflang` such as `zh-Hant`, or a hyphenated relation URI. | Report these schema rejections as a separate finding. |
| L05 | A linkset at the carrier URL passes as a passport. | Classify the final body: a top-level `linkset` array is a linkset. |
| L05 | The DPP link declares one `type` and the host serves another. | Compare the served `Content-Type` with the declared `type`. |
| L05 | The description file uses `linkTypeDefaultCanBeAll`, or `resolverRoot` differs from the host. | Validate against the pinned schema; compare `resolverRoot` with the origin. |
| L06 | The brand domain lapses and no other path exists. | Scheduled observation reports a transport failure; check the ICS for a backup resolver. |
| L07 | An anonymous linkset lists restricted documents. | Put canary URLs in restricted links; scan the linkset and the HTML page. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json` at commit `b290791`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Parse every Digital Link form of URI Syntax 1.7.0. | `identifier.parse` (correct): it accepts only `/01/<GTIN>/21/<serial>`. | `identifier.gs1_grammar` | Vendored gs1-syntax-engine vectors; own valid and invalid URIs. | sample artifact |
| Decompress `eh` and `ex` URIs. | None (correct). | `identifier.gs1_grammar` | Own vectors from TDS 2.3 examples. | sample artifact |
| Identifier granularity matches the ICS. | None (correct). | `identifier.granularity` | One carrier URI per level. | sample artifact |
| Equivalent URIs give the same identifier. | `identifier.consistency` (correct): exact text only. | `identifier.equivalence` | Pairs of equivalent and different URIs. | sample artifact |
| A registry record matches the parsed carrier keys. | `registry.consistency` (correct): it never reads the carrier. | `identifier.equivalence` | Mock registry records with brand-host URIs. | loopback only |
| A QR image decodes to a valid URI. | `carrier.qr_decode` + `identifier.parse` (correct). | None after `identifier.gs1_grammar` | QR images per granularity. | sample artifact |
| Data Matrix and linear symbols carry the same keys as the QR. | None, and `carrier.qr_decode` + `identifier.parse` (both correct): QR only. | `carrier.symbols` | Paired images, one with a seeded mismatch. | sample artifact |
| An RFID EPC dump gives the declared URI. | None (correct). | `carrier.epc_decode` | `TEST-ONLY` EPC dumps; gs1/TDT rules. | sample artifact |
| HTTPS, GET, HEAD, OPTIONS, and CORS. | None (correct). | `resolver.conformance`, plus a transport contract change for OPTIONS | Loopback resolver with seeded faults; port the test-suite logic. | loopback only |
| Status `400`, `404`, `300`, and never `200` for an error. | None (correct): `identifier.resolve` judges an expected `404` as a fail. | `resolver.conformance` | Crafted invalid and unknown URIs. | loopback only |
| Default redirect, and `linkType=gs1:dpp` redirect or `404`. | `identifier.resolve` (correct): it does not assert the target. | `resolver.conformance` | Fixture with and without `gs1:dpp`. | loopback only |
| Linkset with `200` and no redirect, by query and by `Accept`. | `identifier.resolve` (overstated): it does not judge "no redirect". | `resolver.conformance` | `Accept` variants with spaces and q-values. | loopback only |
| `Link` header, query pass-through, path-end slash, inheritance, compressed requests, delegation. | None (correct). | `resolver.conformance` | Seeded faults; two loopback resolvers for delegation. | loopback only |
| The linkset validates against the pinned schema and vocabulary. | `data.jsonschema` (correct): it validates the passport, not a linkset. | `resolver.linkset` | gs1/linkset valid and invalid examples. | loopback only |
| The DPP link appears in every equivalent relation form. | None (correct). | `resolver.linkset` | Linksets with each form; a `gs1:productPassport` fault. | loopback only |
| The engine classifies the final body as linkset, HTML, or passport. | `identifier.resolve` (correct): a linkset gives `IDENTIFIER.RESOLVED`. | `resolver.linkset` guard; new reason code (owner decision) | Resolver that returns a linkset with `200`. | loopback only |
| The description file validates and matches the host. | None (correct). | `resolver.well_known` | Valid file; faulty root and keys. | loopback only |
| The carrier URI keeps its passport identity over time. | `persistence.versions` (wrong): it neither resolves the carrier nor repeats. | `persistence.scheduled` | Recordings from a loopback resolver whose target changes. | loopback only |
| After an update, the URI gives the new version. | `persistence.versions` (overstated): it never fetches an older version. | Resolved URL tied to the version target | Two-version loopback fixture. | loopback only |
| An anonymous linkset hides restricted resources. | `access.restricted_fields` (correct). | `access.channel_extensions` (linkset channel) | Linkset with canary URLs. | loopback only |
| A `gs1:jws` target verifies over the passport. | `integrity.jws` (overstated): it accepts only ES256, `typ` `dpp+jws`, and `x5c`. | `resolver.linkset` target selection; `integrity.jose_profiles` | Linkset with a `gs1:jws` link. | loopback only |
| The same resolver checks against a live resolver. | None (correct). | `resolver.conformance`, live mode | Signed authorization; GS1 hosted suite as an owner cross-check. | live system under test |

The transport records redirect targets but not per-hop status codes. The redaction removes CORS headers, and `Link` values whose relation is not on a fixed list, from records. These are contract changes in [the architecture](../explanation/architecture.md), not adapter changes alone. The legal-baseline check also notes that `identifier.parse` accepts `http://` URIs, which the registry refuses.

For a redirect, the oracle accepts any 3xx with a `Location` header and records the observed code. A real persistence campaign needs a live system under test.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m02-gs1-web-resolver.json`. The engine verdicts are in `x01-engine-mapping.json`; the extra repositories are in `r01-repositories.json`.
- The independent check (`m02-gs1-web-resolver.verification.json`) checked 30 claims: 27 confirmed, 0 refuted, 3 not confirmed. It had no rule 5 findings.
- The check changed three points. The UNTP page states no license. The transport records redirect targets. The law citations in the family file stay unverified, so this section uses `m01-law-baseline.json`.
- The claim that resolver 1.2.0 removed the `Link` header duty on redirects is not confirmed by the independent check, so we leave it out. The test suite has no compression test id; its README does not state this gap.
- Open for the owner: the namespace equivalence table, a linkset with `200` at the carrier URL, and OPTIONS in the transport. The vocabulary release that added `gs1:dpp` (1.12 to 1.16) is unknown.

### 5.3 Asset Administration Shell family

In the Asset Administration Shell (AAS) family, a passport is not a document type of its own. An AAS represents the product and references submodels. A client composes the passport from a DppMetadata submodel and content submodels.

IDTA publishes the specifications as Release 26-01 and maintains the submodel templates. Industrial servers and SDKs are mature, and peer-reviewed prototypes cover circular economy, end of life, Gaia-X, and battery use. The ZVEI DPP4.0 proposal (2023, date from the file name) gives a reference architecture for the family.

#### Components

- **AAS.** It holds `assetInformation` (`globalAssetId`, optional `specificAssetIds`) and references to submodels.
- **Submodel.** It holds typed elements. A `semanticId` reference fixes the meaning of the submodel and of each element.
- **DppMetadata submodel (IDTA 02099-1).** Its Value-Only form is the passport header. Its `contentSpecificationIds` list names the `semanticId` of each content submodel.
- **Content submodels.** For batteries, seven IDTA 02035 templates. Their `semanticId` values mix https IRIs, an ECLASS IRDI, and versioned SAMM URNs.
- **Infrastructure services (IDTA-01002).** AAS Repository, Submodel Repository, Concept Description Repository, AAS Registry, Submodel Registry, Discovery, and AASX File Server.
- **Service profiles.** A server lists its profile identifiers at `GET /description`.
- **ID Link (v3.2).** The `globalAssetId` is a resolvable URL that returns an RFC 9264 linkset.
- **AASX package (IDTA-01005).** A file container with media type `application/aas+zip` since v3.2.
- **Access rule model (IDTA-01004 v3.1).** Attribute-based rules over JWT claims, with default deny.

#### End-to-end flow

1. A reader decodes the carrier and gets the ID Link URL or another product identifier.
2. With an ID Link, the client sends `GET` with `Accept: application/linkset+json, application/json;q=0.9`.
3. The ID Link host returns `200` and a linkset with relations such as `aas` and `dpp`.
4. A client that is not linkset-aware may get `302` to the AAS and a `Link` header.
5. Without an ID Link, the client posts the identifier to `POST /lookup/shellsByAssetLink`.
6. Discovery returns the AAS ids that match all pairs. Several AASs can match.
7. The client reads the AAS descriptor at `GET /shell-descriptors/{id}` for the endpoints.
8. The client fetches the AAS and each referenced submodel, in Normal or `$value` form.
9. The client selects DppMetadata by `semanticId` `https://admin-shell.io/idta/cds/dppMetadata/1`.
10. The client keys each content submodel by its `semanticId` and merges all parts into one passport.
11. Optionally, the client gets `$signed` and verifies the JWS against a root from out of band.

Path ids are base64url without `=` padding. A `$history?date=` request gives the passport valid at a past date. The operator registers in the EU registry by a call outside AAS.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | AAS and submodel ids are strings. `globalAssetId` identifies the asset. DppMetadata `uniqueProductIdentifier` shall correspond to it. | `globalAssetId`, `specificAssetIds`, `uniqueProductIdentifier`, `digitalProductPassportId`; padded and unpadded base64url. |
| L02 data carriers | No AAS carrier rules. In the ID Link pattern, the carrier holds the `globalAssetId` URL. | Decoded payload; whether it is an absolute http(s) URL equal to `globalAssetId`. |
| L03 data exchange protocols | HTTP and JSON. XML and AASX by `/serialization` and `/packages`. Linkset at the ID Link. | Status, `Content-Type`, `Link`; linkset anchor and relations; `Result` error bodies. |
| L04 APIs for lifecycle and search | Profiles per service. Create, read, update, delete, query, cursor pagination, and serialization modifiers. | `/description` profiles; answers per profile; pagination; modifier errors (`400`). |
| L05 interoperability and data models | Metamodel 3.2 with JSON Schema, XSD, RDF, and SHACL. Templates fix `semanticId`, cardinality, and value types. | Schema and constraint results; template conformance; Normal against Value-Only. |
| L06 storage and persistence | The operator's repository. v3.2 adds `$history?date=` and `createdAt` and `updatedAt`. | History profiles; `$history` before and after an update; timestamp order. |
| L07 access rights and security | IDTA-01004 rules over JWT claims, default deny. Anonymous rules can be defined for public data. | Status and body per role; leaks across `/query`, `$value`, `/serialization`, `/packages`. |
| L08 authentication and integrity | `$signed` gives a compact JWS, RS256 only, with `x5c`, `sigT`, `sid`. AASX can carry package signatures. | JWS header, chain, signature, and payload against the unsigned answer. |
| L09 registry and customs | The AAS Registry is an endpoint directory. IDTA says it is not necessarily the EU registry. | Descriptor ids and endpoints against the AAS. Nothing about the EU registry. |
| L10 lifecycle and versions | `version`, `revision`, `updatedAt`, DppMetadata `lastUpdate` and free-text `dppStatus`. No link to an original passport. | Timestamps before and after an update; `DELETE` behavior; id stability. |
| L11 roles and governance | IDTA maintains specifications and templates. The operator or a service provider hosts services. | Token `iss`, `x5c` issuers, and endpoint hosts. |

IDTA-01001 v3.2 maps the DppMetadata `granularity` string to `AssetKind` `Instance`, `Type`, or `Batch`. `Batch` is new in 3.2. This page does not record the permitted granularity strings.

IDTA-01004 notes that the binding from the AAS to the asset is itself unprotected. The ID Link relation tokens are IDTA examples. IANA registers `dpp` with a UNTP reference and does not register `aas`, `aas-service-endpoints`, or `dpp-service-endpoints`.

#### Variants

- Entry point: direct repository, Discovery plus Registry, or ID Link plus linkset.
- Asset identity: a resolvable ID Link, a non-resolvable IRI or URN, or `specificAssetIds` only.
- A GS1 Digital Link URI as `globalAssetId` is possible because the field is a free string. No IDTA source prescribes it.
- Composition: a facade service that composes on request, or client-side composition.
- Access control: IDTA-01004 rules, role-based Keycloak roles (BaSyx), no authorization (FA3ST), or dataspace usage policies.
- Integrity: `$signed` with RS256, AASX package signatures, or none (most deployments).
- Hosts: self-hosted, a service provider, a shared resolver, or a dataspace such as Catena-X.
- Carrier: QR Code or Data Matrix with the ID Link. ZVEI also names RFID or NFC. A research prototype packs compressed AAS JSON in a QR Code.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| IDTA-01001 Part 1 Metamodel | 3.2 (tag `v3.2.0`, 2026-07-21) | Published, Release 26-01 | [aas-specs-metamodel](https://github.com/admin-shell-io/aas-specs-metamodel/tree/v3.2.0) |
| IDTA-01002 Part 2 API | 3.2 (tag `v3.2.0`, 2026-07-21) | Published; 3.1.3 is the last 3.1 release | [aas-specs-api](https://github.com/admin-shell-io/aas-specs-api/tree/v3.2.0) |
| IDTA-01003-a Part 3a | 3.1.1 (2025-08-01) | Published; content not read | [aas-specs-iec61360](https://github.com/admin-shell-io/aas-specs-iec61360) |
| IDTA-01003-b Part 3b | 3.0.0 (2026-07-21) | Published; content not read | [aas-specs-measurement-units](https://github.com/admin-shell-io/aas-specs-measurement-units) |
| IDTA-01004 Part 4 Security | 3.1 (tag `v3.1.0`, 2026-07-21) | Published; DPP annex is a placeholder | [aas-specs-security](https://github.com/admin-shell-io/aas-specs-security/tree/v3.1.0) |
| IDTA-01005 Part 5 AASX | 3.2 (tag `v3.2.0`, 2026-07-21) | Published | [aas-specs-aasx](https://github.com/admin-shell-io/aas-specs-aasx/tree/v3.2.0) |
| IDTA 02099-1 DPP Part 1 Metadata | Hub 1.0; docs 1.0.1; folder `1/0/2` | Published. The 1.0.1 JSON equals the 1.0 JSON. Pin `1/0/2` by folder and SHA-256 digest. | [Template folder](https://github.com/admin-shell-io/submodel-templates/tree/main/published/Digital%20Product%20Passport/Digital%20Product%20Passport%20Part-1) |
| IDTA 02035-1 to -7 Digital Battery Passport | Hub 1.0 | Published. Parts 1 to 3 pin `1/1`; parts 4, 5, 7 pin `1/0/2`; part 6 JSON pins `1/0/1`. | [Battery templates](https://github.com/admin-shell-io/submodel-templates/tree/main/published/Digital%20Battery%20Passport) |
| IDTA 02023 Carbon Footprint | Hub 1.0; folder `1/0/2` | Published | [Template folder](https://github.com/admin-shell-io/submodel-templates/tree/main/published/Carbon%20Footprint) |
| IDTA 02078-2, 02078-3, 02088 | 1.0 | In development or "coming soon" | [Content hub](https://industrialdigitaltwin.org/en/content-hub/submodels) |
| aas-test-engines | 1.0.3 (2025-08-05) | Checks metamodel 3.0.1 and API 3.0.3 only | [aas-test-engines](https://github.com/admin-shell-io/aas-test-engines) |
| `application/aas+zip` | IANA, 2026-02-20 | Registered; change controller IDTA | [IANA media type](https://www.iana.org/assignments/media-types/application/aas+zip) |
| RFC 9264 Linkset | 2022 | Used by the ID Link | [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html) |

For 02035 part 6, folder `1/0/2` holds an AASX only. IDTA defines no DPP profile identifier, and the v3.2 DPP features have no reusable conformance suite.

The IDTA texts cite EN 18219, 18221, 18222, 18223, 18239, and 18246, IEC 61406-1, IEC 63278-1, and DIN DKE SPEC 99100. This research did not read them.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [Eclipse BaSyx Java Server SDK](https://github.com/eclipse-basyx/basyx-java-server-sdk) | Server | MIT | Pushed 2026-10-19; 2.0.0-milestone-15 (2026-07-30) |
| [Eclipse BaSyx Python SDK](https://github.com/eclipse-basyx/basyx-python-sdk) | SDK, server, compliance tool | MIT | 2.2.0 (2026-10-02) |
| [Eclipse BaSyx AAS Web UI](https://github.com/eclipse-basyx/basyx-aas-web-ui) | Viewer | MIT | Pushed 2026-10-16 |
| [Eclipse FA3ST Service](https://github.com/FraunhoferIOSB/FAAAST-Service) | Server | Apache-2.0 | 1.3.0 (2025-10-28); pushed 2026-10-16 |
| [Eclipse AASX Server](https://github.com/eclipse-aaspe/server) | Server | Apache-2.0 (license file; GitHub says NOASSERTION) | Pre-release 2026-10-14 |
| [Eclipse AASX Package Explorer](https://github.com/eclipse-aaspe/package-explorer) | Editor | Apache-2.0 (license file; GitHub says NOASSERTION) | v2025-10-21; pushed 2026-09-10 |
| [Eclipse AAS4J](https://github.com/eclipse-aas4j/aas4j) | SDK | Apache-2.0 | 2.0.2 (2026-05-13) |
| [aas-core libraries](https://github.com/eclipse-aascw) | SDK (3.0, 3.1 rc; 3.2 holds only a license) | MIT (Python license files; other languages not read) | 3.0-python v1.1.4 (2026-02-06) |
| [aas-core-testdatagen](https://github.com/eclipse-aascw/aas-core-testdatagen) | Test data generator | MIT | v0.0.4 (2026-03-12) |
| [aas-smt-lint](https://github.com/eclipse-aascw/aas-smt-lint) | Template linter | MIT | Pushed 2025-11-06 |
| [aas-test-engines](https://github.com/admin-shell-io/aas-test-engines) | Test suite | Apache-2.0 | Last commit 2025-08-05 |
| [submodel-templates](https://github.com/admin-shell-io/submodel-templates) | Templates | CC-BY-4.0 | Pushed 2026-10-15 |
| [aas-specs-api](https://github.com/admin-shell-io/aas-specs-api) | OpenAPI profile files | CC-BY-4.0 | Branches pushed 2026-10-16 |
| [Eclipse Mnestix Browser](https://github.com/eclipse-mnestix/mnestix-browser) | Viewer with test data | MIT | Pushed 2026-10-15 |
| [Eclipse AASPortal](https://github.com/eclipse-aasportal/AASPortal) | Viewer | Apache-2.0 | Pushed 2026-10-18 |
| [shellsmith](https://github.com/SmartFactory-KL/shellsmith) | Client for BaSyx | MIT | Pushed 2026-10-08 |
| [open-dpp](https://github.com/open-dpp/open-dpp) | DPP platform | AGPL-3.0 | Pushed 2026-10-19 |
| [opendpp-interop](https://github.com/OpenDPP/opendpp-interop) | Vendor validator | Apache-2.0 | Pushed 2026-10-14 |

No server README that we read claims Part 2 at 3.2; BaSyx Python and FA3ST name 3.1 releases. BaSyx Java supports only role-based access, and FA3ST states that it has no security. Use open-dpp and opendpp-interop as comparators only.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no AAS, submodel, or service profile.
- The unique product identifier must be persistent, reached through a carrier, and enable a web link (Regulation (EU) 2024/1781, Art. 2(30) and Art. 10(1)). The AAS accepts any string as `globalAssetId`.
- Until harmonized-standard references appear in the OJ, identifier and carrier follow ISO/IEC 15459-1 to -6 or equivalents (Art. 10(1)(c), Art. 12(1)). IDTA enforces no scheme.
- Batteries carry a QR code from 2027-02-18 per Annex VI Part C (Regulation (EU) 2023/1542, Art. 13(6)). IDTA fixes no carrier.
- A DPP service provider holds a back-up copy (Art. 10(4)). The Batteries Regulation has no back-up duty. The AAS adds history but no back-up.
- The passport stays available after insolvency (Art. 11(e); Batteries Art. 78(e)). The AAS has no continuity mechanism.
- Product-group acts set who may read, create, and update which data (Art. 9(2)(f)-(g), Art. 11(b) and (f)). IDTA-01004 gives a rule language, not a policy.
- Battery access per Annex XIII: the public gets point 1. Notified bodies and market surveillance authorities get point 3.
- The Commission gets points 1, 2, and 3. Persons with a legitimate interest get points 2 and 4. The Art. 77(9) act is not adopted.
- The law asks for authentication, reliability, and integrity as outcomes (Art. 11(g); Batteries Art. 78(g)). AAS signatures are optional and name no revocation.
- A new passport links to the original one (Art. 11(d); Batteries Art. 77(7)). A battery passport ends after recycling (Art. 77(8)). The AAS has no construct for either.
- The operator uploads identifiers to the EU registry (Art. 13(4); Batteries Art. 77(10)). Implementing Regulation (EU) 2026/1778 offers a web interface and an API.
- The registry user guide, which is not law, asks for an https UPI of at most 2,000 characters that resolves. An https ID Link has that shape; a URN does not.
- Implementing Decision (EU) 2026/1736 cites six EN DPP standards. Its legal basis is Regulation (EU) No 1025/2012, Art. 10(6).

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | The server wants padded or standard base64, or raw IRIs. | Probe one resource with each encoding; compare status and returned id. |
| L01 | `uniqueProductIdentifier` differs from `globalAssetId`. | Fetch the AAS and DppMetadata `$value`; compare the two values. |
| L02 | The QR Code holds a bare id, its base64url form, or a URN. | Decode the sample; expect an absolute http(s) URL equal to `globalAssetId`. |
| L03 | The linkset comes as `application/json`, holds `//` comments from the IDTA example, or has a wrong anchor. | Check `Content-Type`, parse strict JSON, and compare the anchor. |
| L03 | Only the deprecated `GET /lookup/shells` exists. | Call both discovery operations; compare with `/description`. |
| L03 | AASX comes with the pre-3.2 media type. | Inspect `Content-Type` of `GET /packages/{id}`. |
| L04 | `/description` claims History or Signature, but the operations are absent. | Call one operation per claimed profile. |
| L04 | Pagination returns an empty cursor or repeats a cursor. | Page through a fixture; also send `limit=0` (prose default 100, schema minimum 1). |
| L05 | `contentSpecificationIds` names another patch version of a SAMM URN, so a section drops. | Match strings exactly; count sections. |
| L05 | Two submodels share a `semanticId` (02035-3 with 02023; 02035-2 with 02004), so keys collide. | Find duplicate `semanticId` values and duplicate keys. |
| L05 | List children keep an `idShort`, as the 02099-1 1.0.1 artifact did. | Check the list-child constraint; diff against folder `1/0/2`. |
| L05 | 02035-4 carries `templateId` `IDTA-02003-2-0`, the id of another template (found by the independent check). | Compare `templateId` with the expected template. |
| L06 | `$history` ignores the date. | Query a date before a controlled update; compare with the old snapshot. |
| L07 | Authorization is off or absent, so restricted battery data is public. | Send anonymous requests; scan for canary values. |
| L07 | Rules filter `GET /submodels/{id}` but not `/query`, `/serialization`, or AASX export. | Probe every channel with a low-privilege role. |
| L08 | `$signed` returns JSON, lacks `sigT` or `x5c`, or signs another payload. | Inspect the header, verify the JWS, and compare payloads. |
| L09 | A registry descriptor keeps old ids or old endpoints. | Resolve each endpoint; compare ids with the AAS. |
| L10 | `lastUpdate` or `updatedAt` stays the same after an update. | Update by script; compare timestamps. |
| L10 | `DELETE /shells/{id}` removes a passport that must stay. | Probe a disposable loopback fixture; otherwise manual review. |
| L11 | The system accepts a token or chain from an undeclared issuer. | Send a `TEST-ONLY` token from an undeclared issuer; expect refusal. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json` at commit `b290791`. Of 29 entries for this family, 20 are correct, 4 overstated, and 5 wrong. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| The carrier text equals `globalAssetId` or a `specificAssetIds` value. | `identifier.consistency`, `carrier.qr_decode` (correct): reads `id` only. | `identifier.subject_pointer` | QR images and AAS JSON samples. | loopback only |
| `uniqueProductIdentifier` corresponds to `globalAssetId`. | `data.rules` (overstated): it compares numbers only and cannot enter arrays. | `aas.dpp_compose`, `data.rule_kinds` | Consistent and inconsistent AAS pairs. | loopback only |
| The carrier text parses as an ID Link. | `identifier.parse` (correct): other schemes give unsupported. | `identifier.schemes` | Valid and invalid ID Links; GS1 URIs as `globalAssetId`. | sample artifact |
| The server accepts unpadded base64url ids. | `api.contract` (correct): decode-and-compare is new. | `aas.api_profile` | Ids with `/`, `+`, non-ASCII characters. | loopback only |
| The ID Link returns a linkset with an `aas` link. | `identifier.resolve` (correct): anchor and relation checks are new. | `resolver.linkset` | Loopback ID Link with faults; IXIT switch for unregistered tokens. | loopback only |
| A JSON-only client gets `302` and a `Link` header. | `identifier.resolve` (correct): no hop status; redaction removes a `linkset` `Link`. | `resolver.conformance`, redaction change | Loopback redirect fixture. | loopback only |
| Discovery uses AND semantics. | None (correct). | `aas.api_profile`, `api.write_ops` (POST) | Several AASs per asset. | loopback only |
| Errors use `Result` and the status mapping. | `api.contract` (overstated): it cannot provoke an error. | `aas.api_profile` | Single-file OpenAPI pin from the profile files. | loopback only |
| `/description` lists profiles, and each one works. | `api.contract` (wrong): `/description` is not a resource. | `api.resources`, `aas.api_profile` | Pinned `V3.2_SSP-xxx.yaml` set. | loopback only |
| Pagination, modifiers, query, and Value-Only behave as specified. | None (correct). | `aas.api_profile`, `api.write_ops` (query) | Nested and paged fixtures; IDTA corpus cases. | loopback only |
| A JSON sample is valid against the metamodel. | `aas.validate` (correct): 1.0.3 reports 3.0 only. | `aas.validate_formats` | 3.2 and 3.0 samples; BaSyx compliance tool. | sample artifact |
| An AASX sample has a valid package structure. | `aas.validate` (wrong): it gives `AAS.INVALID`, a false fail. | `aas.validate_formats` | Good and broken AASX samples. | sample artifact |
| DppMetadata conforms to IDTA 02099-1. | `data.jsonschema` (correct). | `aas.dpp_compose` | Schema derived from the `1/0/2` template; good and bad samples. | sample artifact |
| Each `contentSpecificationIds` value names one submodel. | `data.rules` (wrong): it cannot match strings across lists. | `aas.dpp_compose`, `data.rule_kinds` | AAS with 02035 and 02023 submodels. | loopback only |
| RDF validates against the IDTA SHACL shapes. | None (correct): `data.shacl` is interface only. | `data.shacl` | Pinned shapes and ontology; Turtle samples. | sample artifact |
| `$history` returns the version valid at the date. | `persistence.versions` (wrong): it reads the engine's own list only. | `aas.api_profile` | Loopback repository with scripted updates. | loopback only |
| The passport stays available, and a back-up exists. | `manual.review` (correct). | `persistence.scheduled` | Signed manual result for back-up evidence. | live system under test |
| Anonymous gets `401`, a wrong role gets `403`, public data is readable. | `access.restricted_fields` (overstated): it asserts no `401` or `403`. | Status assertions | `TEST-ONLY` JWTs per role; canary values. | loopback only |
| Withheld elements do not leak on any channel. | `access.restricted_fields` (overstated): five channel kinds, no POST. | `access.channel_extensions` | IXIT templates for `/query`, `/serialization`, `/packages`. | loopback only |
| `$signed` verifies and matches the unsigned answer. | `integrity.jws` (correct): ES256 only, so RS256 gives blocked. | `integrity.jose_profiles` | `TEST-ONLY` RSA root and leaf; signed and tampered JWS. | loopback only |
| AASX signatures cover all parts. | None (correct). | `integrity.opc_signature` | Signed and partly signed AASX with `TEST-ONLY` keys. | sample artifact |
| The descriptor agrees with the AAS and a mock registry. | `registry.consistency` (correct): the descriptor part is new. | `aas.api_profile` | Descriptors with old endpoints and wrong ids. | loopback only |
| An update changes `updatedAt` and `lastUpdate`. | `persistence.versions` (wrong): it cannot read them or start an update. | `api.write_ops` | Authorized write scope in the IXIT. | loopback only |
| A retained passport cannot be deleted. | `manual.review` (correct). | `api.write_ops` (signed destructive scope) | Disposable loopback fixture only. | loopback only |
| Record trust anchors and service providers. | `manual.review` (correct). | None | ICS fields for trusted issuers and roots. | live system under test |

The `aas.validate` result on an AASX or XML sample is a rule 7 concern. An input that the check cannot assess reads as a defect of the system under test. The x01 file reports this and does not fix it.

`aas.api_profile` depends on `api.resources`, which changes a protected model file. `integrity.jose_profiles` must not widen the algorithm list of the engine's own report signatures. A newer aas-test-engines release for 3.1 or 3.2 is a dependency change to report.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m03-aas-digital-twin.json`. The engine verdicts are in `x01-engine-mapping.json`; extra repositories are in `r01-repositories.json`.
- The independent check (`m03-aas-digital-twin.verification.json`) checked 34 claims: 29 confirmed, 0 refuted, 5 not confirmed. The law claims are among the 5, so this section uses `m01-law-baseline.json`.
- The check had one rule 5 finding: an enumeration of granularity values. We leave it out. It also found the 02035-4 `templateId` fault and the `limit=0` boundary case.
- Open: whether aas-test-engines 1.0.3 accepts 3.2 artifacts needs a local run. Server support for the 3.2 History and Signature profiles is not researched beyond READMEs.
- Open: IDTA certification criteria were not found. IDTA has not said whether it will register its linkset relation tokens.

### 5.4 Dataspace family

In the dataspace family, a passport is not a public web document. It is a data asset that the economic operator keeps behind its own dataspace connector. Catena-X, the automotive dataspace, uses this family with the Eclipse Tractus-X open-source reference stack. Peer-reviewed work uses Eclipse Dataspace Components (EDC) and Catena-X for passports and digital twins (Hulea et al. 2025; Schmidt et al. 2025; Manoury et al. 2025; Mügge et al. 2023).

Production use is limited to onboarded Catena-X members, and the family file found no public deployment count. The Tractus-X Digital Product Pass consumer app is archived. The Industry Core Hub is its recommended successor. A Tractus-X EDC decision record names Factory-X, Construct-X and Semiconductor-X as further users of the same connector.

#### Components

- **Data carrier.** A QR code with the plain text `CX:<manufacturerPartId>:<partInstanceId>`. This is Tractus-X practice; no Catena-X standard that the family file read fixes a carrier.
- **Connector.** Each participant runs a connector. In Catena-X it is Tractus-X EDC, which speaks the Dataspace Protocol (DSP) 2025-1.
- **Participant identity.** The Decentralized Claims Protocol (DCP) gives a self-issued JWT bound to a DID. A credential service supplies verifiable presentations of dataspace credentials.
- **Central discovery services.** Discovery Finder, BPN Discovery and EDC Discovery map a part number to the owner's Business Partner Number (BPN) and connector address.
- **Digital Twin Registry (DTR).** Each provider runs its own DTR. It implements the AAS Part 2 registry and discovery profiles and is itself a DSP dataset.
- **Submodel server.** It serves the passport aspect as value-only JSON behind the provider data plane.
- **SAMM aspect models.** Models in RDF Turtle. The ESMF tools generate JSON Schema, OpenAPI, AAS submodel templates and sample payloads from them.
- **Policies.** ODRL access and usage policies in the connector. Passport offers need `FrameworkAgreement` and `UsagePurpose` `cx.circular.dpp:1`.
- **Test kits.** The Eclipse DSP TCK, DCP TCK and Dataplane Signaling (DPS) TCK.

#### End-to-end flow

The consumer is a Catena-X member with valid credentials.

1. The consumer app decodes the QR text and checks it against `^CX:[^:]+:[^:]+$`.
2. The Discovery Finder returns the BPN Discovery endpoint for the key type `manufacturerPartId`.
3. BPN Discovery returns the BPNL of the manufacturer for the part number.
4. EDC Discovery returns the connector endpoints for that BPNL. A `DataService` entry in the provider DID document is an alternative.
5. The consumer reads `/.well-known/dspace-version` without credentials and selects DSP 2025-1.
6. The consumer gets a self-issued ID token from its Secure Token Service (STS).
7. The provider calls the consumer credential service at `/presentations/query` and verifies the presentations.
8. The consumer requests the catalog and selects the dataset of type `taxonomy#DigitalTwinRegistry`.
9. The consumer negotiates the registry offer. The negotiation goes from `REQUESTED` to `FINALIZED`.
10. An `HttpData-PULL` transfer returns an Endpoint Data Reference (EDR): an endpoint, a token and `expiresIn`.
11. Through the provider data plane, the consumer sends `POST /lookup/shellsByAssetLink` with the part keys.
12. The provider connector adds the `Edc-Bpn` header. The DTR returns only twins that this BPN may see.
13. The consumer reads the shell descriptor and selects the submodel descriptor with the passport `semanticId`.
14. The `subprotocolBody` names the dataset id and the provider control plane.
15. The consumer negotiates a second contract for the passport dataset and receives a second EDR.
16. The consumer sends GET to the `href`, with `/$value` for `SUBMODEL-3.x`, and receives the aspect JSON.
17. The consumer validates the payload against the generated JSON Schema.

The payload carries no signature. Integrity rests on TLS and on the authentication of the provider connector. On the provider side, the operator stores the payload, creates the EDC asset and policies, and registers the twin and the part number.

A third flow is only a concept: CX-0160-3 section 5.2 (preview) bridges passports to an EU-facing system outside the dataspace.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Participants have a DID for the protocol and a BPN for discovery and policy. Products use twin ids and `specificAssetIds`. | Carrier text, `specificAssetIds`, `metadata.passportIdentifier`, and BPN syntax. Agreement between carrier, twin and payload. |
| L02 data carriers | Tractus-X apps use a text QR code with the CX triplet. The DPP aspect lists carriers in `identification.dataCarriers`. | Decoded text: a URL, a GS1 Digital Link, or a CX triplet. |
| L03 data exchange protocols | Central discovery over HTTPS JSON. DSP catalog, negotiation and transfer. CX-0018 4.2 adds `HttpData-PULL` with EDR tokens. | The version endpoint without credentials. DSP status codes, with `404` for unauthorized access. Message samples against the DSP JSON Schemas. |
| L04 APIs for lifecycle and search | The DTR offers profiles `SSP-005` and `SSP-002` (must) and `SSP-004` (should). Unsupported operations give `501`. Submodels use `SSP-003`. | Status codes, paging, base64url ids, lookup results and descriptors. A loopback DTR has the same API without a connector. |
| L05 interoperability and data models | SAMM aspect models and generated schemas. CX-0143 1.4.0 names generic DPP 6.1.0 with `idShort` `digitalProductPass`. | Payload against the pinned schema. `semanticId` against the mandated URN. `@context` values against an allowlist. |
| L06 storage and persistence | Each provider stores its own passport. No central copy, archive or escrow exists. `backupReference` has no mechanism behind it. | `backupReference`, `predecessor` and `lastModification` over time. The existence of a backup is not observable. |
| L07 access rights and security | DCP authentication, ODRL access and usage policies, short-lived EDR tokens, and BPN visibility in the DTR. | Refusals per credential, catalog content per BPN, DTR answers per `Edc-Bpn` value. No anonymous path. |
| L08 authentication and integrity | TLS, a DID-bound JWT, and verifiable credentials with status lists. The passport payload has no signature. | Token and credential samples offline against pinned DID documents. No passport signature to verify. |
| L09 registry and customs | None. DPP 7.0.0 has a `registrationIdentifier` field. CX-0160-3 (preview) gives registry upload to a system outside the dataspace. | Presence and format of `registrationIdentifier`. Agreement with a mock registry record. |
| L10 lifecycle and versions | DSP version negotiation. A new URN version for each model change. Payload `version`, `passportStatus` and `predecessor`. Updates are in place. | Payload sequences. `semanticId` version against `metadata.specVersion`. |
| L11 roles and governance | The Catena-X association publishes standards in release trains. Members sign a framework agreement. A private conformity assessment applies. | Credential types and DID documents. Conformity assessment records were not examined. |

#### Variants

- Participant id: a DID (`did:web` in examples) in the protocol, and the BPN for business logic. Older Catena-X releases used the BPN in the protocol.
- Twin level: an instance twin (`PartInstance`) or a type twin (`PartType`). Each can carry a different part of the passport.
- Protocol version: DSP 2025-1, or the legacy `v0.8` endpoints in parallel. Tractus-X promises no compatibility across DSP versions.
- Transfer: `HttpData-PULL` with an EDR token, or `AmazonS3-PUSH` and `AzureStorage-PUSH`.
- Data plane access: a direct call with the EDR token, or the consumer proxy `/aas/request` that refreshes tokens.
- DTR access control: BPN visibility by `externalSubjectId`, or granular access-control rule sets.
- Payload model: the generic DPP aspect (5.0.0 to 7.0.0), or a product passport. Examples are battery pass 6.x and transmission pass 3.x.
- Battery passports: the Catena-X battery pass 6.x, or seven joint IDTA and Catena-X models under CX-0160 (preview).
- DCP credential profile: `vc20-bssl/jwt` or `vc11-sl2021/jwt`.
- Other stacks: a battery passport study uses a trusted data space without EDC.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| Dataspace Protocol | 2025-1, tag `2025-1-err2` (2026-09-11) | Stable. The root page redirect text still says "Release Candidate". | [DSP 2025-1](https://eclipse-dataspace-protocol-base.github.io/DataspaceProtocol/2025-1-err2/) |
| Decentralized Claims Protocol | v1.0.1 (2025-11-13) | Stable. The GitHub "latest" endpoint still returns v1.0. | [DCP v1.0.1](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/v1.0.1/) |
| DSP TCK | v1.0.2 (2026-09-04) | Supports DSP 2025-1 | [dsp-tck](https://github.com/eclipse-dataspacetck/dsp-tck) |
| DCP TCK | v1.2.1 (2026-09-07) | Tests credential service, issuer service and verifier | [dcp-tck](https://github.com/eclipse-dataspacetck/dcp-tck) |
| DPS TCK | v1.3.0 (2026-08-27) | Targets Data Plane Signaling 1.0-RC4 | [dps-tck](https://github.com/eclipse-dataspacetck/dps-tck) |
| EDC Connector | v0.18.1 (2026-09-25); v1.0.0-RC4 | Stable; release candidate | [EDC Connector](https://github.com/eclipse-edc/Connector) |
| Tractus-X EDC | 0.13.0 (2026-08-27) | Removed the federated catalog and the v2 and v4alpha APIs | [Tractus-X EDC](https://github.com/eclipse-tractusx/tractusx-edc) |
| Tractus-X DTR | `digital-twin-registry-0.13.0` (2026-09-01) | OpenAPI title `V3.1.0_SSP-001` | [DTR](https://github.com/eclipse-tractusx/sldt-digital-twin-registry) |
| CX-0018 Dataspace Connectivity | 4.2 | CX-Titan, current | [CX-0018](https://catenax-ev.github.io/docs/standards/CX-0018-DataspaceConnectivity) |
| CX-0002 Digital Twins in Catena-X | 2.4.0 | CX-Titan, current; cites IDTA 01002 3.2 | [CX-0002](https://catenax-ev.github.io/docs/standards/CX-0002-DigitalTwinsInCatenaX) |
| CX-0143 Digital Product Passport | 1.4.0 | Current on CX-Titan. 1.5.0 is on GitHub main. The overview value 1.2.0 is stale. | [CX-0143](https://catenax-ev.github.io/docs/standards/CX-0143-UseCaseCircularEconomyDigitalProductPassportStandard/introduction) |
| CX-0160 Battery Passport | 1.1.0 | CX-Neptune preview, not eligible for certification. Stated go-live 24 November 2026. | [CX-0160](https://github.com/catenax-eV/catenax-ev.github.io/tree/main/docs/standards/CX-0160-BatteryPassport) |
| CX-0053, CX-0001, CX-0152, CX-0010, CX-0050 | 1.1.1, 1.2.1, 1.0.0, 3.0.1, 2.2.1 | CX-Titan, current | [CX-0152](https://catenax-ev.github.io/docs/standards/CX-0152-PolicyConstrainsForDataExchange) |
| Generic DPP aspect model | 6.1.0 named by CX-0143; 7.0.0 released | 7.0.0 is released, but no Catena-X standard was found that mandates it. | [Semantic models](https://github.com/eclipse-tractusx/sldt-semantic-models) |
| Tractus-X EcoPass KIT | 26.09 | Names DPP 5.0.0 and battery 6.0.0. The unreleased next KIT names DPP 6.1.0. | [EcoPass KIT](https://eclipse-tractusx.github.io/docs-kits/kits/eco-pass-kit/adoption-view) |
| IDTA 02099-1 DPP Metadata | Hub 1.0; docs 1.0.1; folder `1/0/2` | Pin folder `1/0/2` by folder and SHA-256 digest | [IDTA 02099-1](https://industrialdigitaltwin.io/idta-submodel-templates/IDTA-02099-1/1.0.1/index.html) |
| IDTA 02035 battery parts 1 to 7 | Parts 1 to 3: `1/1`; 4, 5, 7: `1/0/2`; 6: `1/0/1` | The hub still shows 1.0. | [IDTA 02035-1](https://industrialdigitaltwin.io/idta-submodel-templates/IDTA-02035-1/1.0/index.html) |
| AAS Part 2 API | 3.2 | Published. aas-test-engines 1.0.3 checks API 3.0.3 and metamodel 3.0.1 only. | [IDTA 01002](https://industrialdigitaltwin.io/aas-specifications/IDTA-01002/v3.2/specification/interfaces.html) |
| SAMM; ESMF samm-cli | 2.2.0; v2.16.1 | Catena-X models use the SAMM 2.1.0 namespaces | [SAMM](https://eclipse-esmf.github.io/samm-specification/snapshot/index.html) |

The Catena-X standard texts are all rights reserved. This page cites their version numbers and names terms from them, not their text.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [Eclipse EDC Connector](https://github.com/eclipse-edc/Connector) | Connector | Apache-2.0 | Push 2026-10-19 |
| [Tractus-X EDC](https://github.com/eclipse-tractusx/tractusx-edc) | Connector | Apache-2.0 | Push 2026-10-16 |
| [Tractus-X Digital Twin Registry](https://github.com/eclipse-tractusx/sldt-digital-twin-registry) | Registry | Apache-2.0 | Release 2026-09-01 |
| [Tractus-X Discovery Finder](https://github.com/eclipse-tractusx/sldt-discovery-finder) | Registry | Apache-2.0 | Push 2026-06-17; latest release 0.5.1; newer tags up to v0.6.1 |
| [Tractus-X BPN Discovery](https://github.com/eclipse-tractusx/sldt-bpn-discovery) | Registry | Apache-2.0 | Push 2026-06-17; latest release 0.6.0; newer tag v0.6.1 |
| [Tractus-X Digital Product Pass](https://github.com/eclipse-tractusx/digital-product-pass) | Renderer | Apache-2.0 code; CC-BY-4.0 docs | Archived; push 2025-09-18 |
| [Tractus-X Industry Core Hub](https://github.com/eclipse-tractusx/industry-core-hub) | Platform | Apache-2.0 | Push 2026-10-09; latest release v0.5.0; v0.6.0 as tags only |
| [Tractus-X semantic models](https://github.com/eclipse-tractusx/sldt-semantic-models) | Data model | CC-BY-4.0 | Push 2026-09-25 |
| [IDTA SMT semantic models](https://github.com/admin-shell-io/smt-semantic-models) | Data model | CC-BY-4.0 | Push 2026-10-16; release V1.1.3 (2026-10-15) |
| [ESMF SDK and samm-cli](https://github.com/eclipse-esmf/esmf-sdk) | SDK | MPL-2.0 | Release v2.16.1, 2026-10-19 |
| [Dataspace Protocol repository](https://github.com/eclipse-dataspace-protocol-base/DataspaceProtocol) | Specification and schemas | Apache-2.0 | Tag 2026-09-11 |
| [DCP repository](https://github.com/eclipse-dataspace-dcp/decentralized-claims-protocol) | Specification | Apache-2.0 | Push 2026-08-05 |
| [DSP TCK](https://github.com/eclipse-dataspacetck/dsp-tck) | Test suite | Apache-2.0 | Push 2026-10-19 |
| [DCP TCK](https://github.com/eclipse-dataspacetck/dcp-tck) | Test suite | Apache-2.0 | Push 2026-10-13 |
| [DPS TCK](https://github.com/eclipse-dataspacetck/dps-tck) | Test suite | Apache-2.0 in `NOTICE.md`; no `LICENSE` file | Push 2026-10-16 |
| [aas-test-engines](https://github.com/admin-shell-io/aas-test-engines) | Validator | Apache-2.0 | Push 2025-08-05 |
| [CIR4FUN java-dpp-sdk](https://github.com/CIR4FUN-EU/java-dpp-sdk) | SDK | Apache-2.0 | Push 2026-09-29 |

The repository inventory found no test suite for passports in a dataspace. The independent check names two Catena-X repositories that were not examined: [sig-cx-test-suite](https://github.com/catenax-eV/sig-cx-test-suite) and `cx-odrl-profile`.

#### Difference from the legal baseline

This list uses the legal baseline (section 4) only. The law statements in the family file were not independently verified.

- **Web link.** The unique product identifier also enables a web link to the passport (Regulation (EU) 2024/1781, Art. 2(30); Regulation (EU) 2023/1542, Art. 3(1)(66)). The CX triplet is not a web link. It needs a discovery chain and credentials.
- **Carrier.** From 2027-02-18, the battery QR code gives access to the passport for some battery categories (Regulation (EU) 2023/1542, Art. 13(6)). A CX triplet gives no access outside the dataspace.
- **Open network.** Passport data must be transferable through an open interoperable network without vendor lock-in (Regulation (EU) 2024/1781, Art. 10(1)(d); Regulation (EU) 2023/1542, Art. 77(5)). DSP is open, but Catena-X participation needs membership credentials.
- **Access tiers.** Regulation (EU) 2024/1781, Art. 11(b) asks for free and easy access for listed actors. The family has no public tier and no role for authorities outside the dataspace.
- **Battery tiers.** The public gets Annex XIII point 1. Notified bodies and market surveillance authorities get point 3. The Commission gets points 1, 2 and 3. Persons with a legitimate interest get points 2 and 4.
- **No login for some groups.** Toy and detergent passports must be open to consumers without registration or a password (Regulation (EU) 2025/2509, Art. 20(4); Regulation (EU) 2026/405, Art. 22). A pure dataspace system needs a bridge for these groups.
- **Backup and availability.** ESPR passports need a backup copy through a DPP service provider (Regulation (EU) 2024/1781, Art. 10(4)). Availability must outlast the operator (Art. 11(e); Regulation (EU) 2023/1542, Art. 78(e)). In this family, a passport exists only while the provider connector runs.
- **Integrity.** The law asks for authentication, reliability and integrity of data (Regulation (EU) 2024/1781, Art. 11(g); Regulation (EU) 2023/1542, Art. 78(g)). It names no mechanism. A downstream holder cannot verify a passport copy from this family.
- **Registry.** The operator uploads the identifiers and receives a registration identifier (Regulation (EU) 2024/1781, Art. 13(4) and (5); Regulation (EU) 2023/1542, Art. 77(10)). The family has no upload step.
- **Lifecycle.** A new passport must link to the original (Regulation (EU) 2024/1781, Art. 11(d)). Battery responsibility moves after repurposing or remanufacturing (Regulation (EU) 2023/1542, Art. 77(7)). The `predecessor` field is not enforced. No handover protocol was found.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | A `manufacturerPartId` that contains `:` splits the triplet wrongly. | Parse the decoded text and compare the fields with the twin `specificAssetIds`. |
| L01 | Two providers register the same part number at BPN Discovery. | A BPN Discovery sample returns more than one BPN; compare with the twin `manufacturerId`. |
| L03 | The version endpoint needs credentials, omits 2025-1, or uses `0.8` for `v0.8`. | GET `/.well-known/dspace-version` without credentials; apply schema and rule checks. |
| L03 | A `TransferStartMessage` lacks `expiresIn` or has another `endpointType`. | A rule pack on EDR samples. |
| L03 | JSON-LD prefixes in a policy expand to unintended IRIs. | An allowlist of contexts; compare the expanded IRIs with the expected ones. |
| L05 | The descriptor has an outdated `semanticId`, such as `urn:bamm` or an older DPP version. | A rule on the descriptor against the mandated URN list. |
| L05 | A tool validates the draft-04 schema with a newer validator and ignores boolean exclusive bounds. | Send payloads with a value equal to an exclusive bound; a system under test that accepts them has the defect. |
| L07 | `partInstanceId` is marked `PUBLIC_READABLE` and leaks to every DTR reader. | Probe with an unlisted BPN on a loopback DTR; use canary asset ids. |
| L07 | The DTR is reachable without the provider connector, so a caller can forge `Edc-Bpn`. | Send a forged header on a loopback test environment only. |
| L07 | No anonymous access to the public battery passport part. | Anonymous resolution from the carrier ends without a passport. |
| L08 | The provider accepts an EDR token after expiry or after transfer termination. | Replay a captured `TEST-ONLY` token on a loopback provider. |
| L08 | The verifier accepts a token with `iss` different from `sub`, or a reused `jti`. | Token mutation tests with the DCP TCK verifier group or sample checks. |
| L10 | An `expired` passport is still served, or `predecessor` points nowhere. | A rule pack over payload sequences; look up the predecessor in the same SUT. |
| L11 | A usage policy lacks `cx.circular.dpp:1` or does not chain constraints with `odrl:and`. | A rule pack on catalog offer samples. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json` at commit `b290791`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Classify the carrier text: GS1 Digital Link, other URL, or CX triplet. | `carrier.qr_decode`, `identifier.parse`, `identifier.consistency` (correct): a triplet gives `IDENTIFIER.SYNTAX.INVALID`. | `identifier.schemes` (Catena-X triplet; "not a web link" as a separate finding) | QR images with triplets, a `:` in the part id, and URLs. | sample artifact |
| The version endpoint is open and lists DSP 2025-1. | None (correct): the resource names are a closed set. | `api.resources`, `dataspace.protocol_probe` | Pinned `protocol-version-schema.json`; loopback mock connector; DSP TCK metadata tests. | live system under test |
| DSP message samples match the DSP JSON Schemas. | `data.jsonschema` (overstated): absolute `$ref` values give `DATA.SCHEMA.NOT_LOCAL`, and samples are not an input. | `schema.pinned_import`, `data.document_source` | DSP repository examples and mutated copies. | sample artifact |
| Only expected JSON-LD contexts appear in messages and policies. | `data.context` (overstated): it reads only the item or model document. | `data.document_source` | Allowlist of the DSP, DCP, EDC and Catena-X contexts. | sample artifact |
| An `HttpData-PULL` data address is usable. | `data.rules` (overstated): the message is not reachable as input. | `data.document_source`; rule pack `cx-0018-pull-dataaddress` | EDR samples with and without `expiresIn`; `TEST-ONLY` tokens. | sample artifact |
| The DTR offers the required profiles and answers `501`. | `api.contract` (correct): GET only, closed resource set. | `api.write_ops` (POST), `api.resources` | Pinned DTR OpenAPI; loopback DTR; aas-test-engines API tests. | loopback only |
| The payload validates against the schema of the mandated version. | `data.jsonschema` (correct): the draft-04 schema gives blocked `DATA.SCHEMA.MALFORMED`, never pass. | `schema.pinned_import` | DPP 6.1.0 and 7.0.0 schemas and generated samples; samm-cli. | sample artifact |
| The descriptor names the mandated aspect and points through DSP. | `data.rules` (overstated): a descriptor is not an input, and paths do not enter arrays. | `data.document_source`; rule pack `cx-0002-submodel-descriptor` | Correct, `urn:bamm`, and malformed descriptor samples. | sample artifact |
| Generated AAS templates are valid AAS. | `aas.validate` (overstated): XML or AASX gives `AAS.INVALID`, a false fail. | `aas.validate_formats` | Generated `.aasx` and `-aas.xml` files; aas-test-engines. | sample artifact |
| The DTR shows asset ids only to listed BPNs. | `access.restricted_fields` (correct): roles go only as a Bearer header. | `access.channel_extensions` (role by request header) | Access policy with `TEST-ONLY-BPNL...` roles; canary ids. | loopback only |
| Public passport data needs no dataspace credentials. | `identifier.resolve`, `access.restricted_fields` (correct). | None for a bridged SUT. A pure dataspace system under test is not resolvable, never pass. | Synthetic public field list; bridged loopback mock. | live system under test |
| DSP endpoints hide unauthorized resources with `404`. | None (correct): only `401` and `403` count as refusal. | `dataspace.protocol_probe` | Loopback issuer, credential service, DID documents and STS; DCP TCK verifier tests. | loopback only |
| Passport offers carry the Catena-X usage policy. | `data.rules` (overstated): offers are not an input, and constraints are lists. | `data.document_source`; optional `data.shacl` | Catena-X policy schema (all rights reserved; check reuse first); offer samples. | sample artifact |
| DCP self-issued tokens meet the claim rules. | `integrity.jws` (wrong): the token has no `typ` `dpp+jws` or `x5c`, so the check is blocked. | `integrity.jose_profiles` | `TEST-ONLY` DID documents and ES256 keys; valid and broken tokens. | sample artifact |
| Dataspace credentials are not revoked. | None (correct): `integrity.status_list` is interface only. | `integrity.status_list` | Status list credentials with set and unset bits. | loopback only |
| Passport metadata follows the lifecycle rules. | `data.rules`, `persistence.versions` (overstated): no lifecycle transitions. | None proposed in x01; the gap stays open. | Payload sequences with status changes and broken links. | sample artifact |
| A backup reference and a registration identifier are declared. | `data.rules`, `registry.consistency` (overstated): the registration identifier is not compared. | `registry.record_fields`, `persistence.scheduled` | Payloads with and without the fields; mock registry record. | sample artifact |
| A signed external DSP or DCP TCK run counts as evidence. | `manual.review` (correct). | None | Manual result signed with a `TEST-ONLY` key. | sample artifact |
| BPN syntax in twins, policies and payloads. | `data.rules` (wrong): no pattern rule kind exists. `data.jsonschema` with a `pattern` is a partial fit. | `data.rule_kinds` | `TEST-ONLY` BPN strings with wrong length or type letter. | sample artifact |

The checks `data.jsonschema`, `data.context` and `data.rules` read only the item or model document over HTTP. A "sample artifact" label for a message, offer or descriptor is therefore not enough today. Both `data.document_source` and `api.resources` need a change to the protected resource names; this is a contract change for [the architecture](../explanation/architecture.md). BPN check characters stay unchecked: their algorithm is only in a protected ISO/IEC document.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m04-dataspace-federated.json`. The engine verdicts are in `x01-engine-mapping.json`; the extra repositories are in `r01-repositories.json`.
- The independent check (`m04-dataspace-federated.verification.json`) checked 35 claims: 32 confirmed, 0 refuted, 3 not confirmed. It found no paraphrase of protected standards text. This section leaves out the two source details that it flagged under rule 5.
- The check changed some points. `digitalTwinType` is mandatory in CX-0143 1.4.0, but the start version is not confirmed. The Industry Core Hub and discovery service versions now show tags beyond the latest releases. Two of the four named Catena-X conformity assessment bodies are not confirmed, so this section names none.
- The family file records an engine probe of 2026-10-19: the DPP 6.1.0 and 7.0.0 schemas fail the 2020-12 metaschema check. The independent check reproduced this on 7.0.0. x01 confirmed the code path but did not re-run the probe.
- Open questions: which DPP aspect version to pin, a public URL form for the triplet, DSP `404` in the access model, and pinned schema conversions. A Tractus-X EDC decision record of 2026-08-10 may change EDR token refresh; it was not read.

### 5.5 Verifiable credential and decentralized identity family

In this family, each passport statement is a signed W3C Verifiable Credential. The manufacturer issues a passport credential. Conformity assessment bodies, facility operators, and registers issue linked credentials. The UN Transparency Protocol (UNTP) is the main passport profile of the family, and its 0.7.0 release is a pilot release.

The EBSI project TRACE4EU piloted EBSI credentials for battery supply-chain data, without public deliverables or code. Peer-reviewed evidence is mostly prototypes and simulations, and no production-scale study was located.

#### Components

- **Verifiable credential.** A VCDM 2.0 document. Its first `@context` entry is `https://www.w3.org/ns/credentials/v2`, and its `type` includes `VerifiableCredential`.
- **Proof format.** An enveloping proof (JOSE `vc+jwt`, SD-JWT `vc+sd-jwt`, or COSE `application/vc+cose`), or an embedded Data Integrity proof.
- **Issuer identifier.** A DID, usually `did:web` or `did:webvh`. The `kid` of the signature is a DID URL that leads to the key.
- **Status list.** A Bitstring Status List credential. One bit per credential shows revocation or suspension.
- **Identity resolver.** A GS1-conformant resolver pattern that UNTP extends. It redirects, or it returns an RFC 9264 linkset with typed links such as `dpp`, `dcc`, `dfr`, `dte`, and `idr`.
- **Digital Identity Anchor (DIA).** A credential from an authoritative register. It binds the issuer DID to a registered identifier.
- **Trust list.** The UN/CEFACT Global Registrar Information Directory (GRID) lists authoritative registers and their trusted issuer DIDs.
- **Storage service.** It holds public documents, or documents in an AES-256-GCM envelope. It returns a `digestMultibase` of the stored bytes.
- **Wallet and API protocols (context only).** OpenID4VCI for issuance, OpenID4VP for presentation, and VCALM (formerly VC API) for issuer and verifier services.

#### End-to-end flow

1. A reader decodes the 1D or 2D carrier and gets an HTTPS resolver URL.
2. The client asks for the linkset with `Accept: application/linkset+json` or `?linkType=linkset`.
3. Without a `linkType`, the resolver redirects to the default link instead.
4. The client selects the `dpp` link. It notes `encryptionMethod` and `accessRole` on encrypted targets.
5. The client fetches the credential. Under the UNTP profile, the response is `application/vc+jwt`.
6. The verifier reads the JOSE header (`typ`, `cty`, `alg`, `kid`) and refuses a payload with a `vc` or `vp` claim.
7. The verifier resolves the `kid` to a key that the DID document lists under `assertionMethod`.
8. For `did:web`, the DID maps to an HTTPS URL that ends in `did.json`.
9. For `did:webvh`, the verifier first checks the hash chain of the `did.jsonl` log.
10. The verifier checks the signature, `iss` against `issuer.id`, and the validity window.
11. The verifier checks the `@context` order and the UNTP JSON Schema of the declared version.
12. For each `credentialStatus` entry, the verifier fetches and verifies the list, then reads the bit.
13. The verifier follows the issuer DID to its DIA and checks the registrar against a trust list.
14. For each performance claim, the verifier follows evidence links to conformity credentials and verifies them too.

UNTP fixes no redirect status code for step 3. A test oracle accepts any 3xx with a `Location` header and records the observed code. A UNTP 0.7.0 example uses `linkType=all`. The UNTP WIP text makes it a deprecated alias, so a test client sends `linkType=linkset`.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Three identifiers: the product `credentialSubject.id`, the credential `id`, and the issuer DID. UNTP 0.7.0 requires `idScheme` and `idGranularity` on the product. | The carrier text against `credentialSubject.id`, not against the credential `id`. A new credential `id` for each version. |
| L02 data carriers | Any carrier that holds a URL. UNTP IDR-04 and IDR-05 (MUST) reuse the 1D and 2D carriers already in use. An optional `decryptionKey` query parameter carries a key. | The decoded payload: resolver URL, short link, or raw JWT. A `decryptionKey` parameter in the URL. |
| L03 data exchange protocols | HTTP GET on the resolver, the credential, the DID document, and the status list. | Status codes, `Location`, `Content-Type`, the `/.well-known/gs1resolver` or `/.well-known/resolver` file, and `did.json` reachability. |
| L04 APIs for lifecycle and search | UNTP defines no create, update, or search API. The VCALM v1.0 draft defines issue, verify, and exchange endpoints. | The result of a verifier endpoint for good and bad fixtures. Write calls need an authorization scope. |
| L05 interoperability and data models | VCDM 2.0 envelope. UNTP 0.7.0 JSON Schema 2020-12 pins the second context to `https://vocabulary.uncefact.org/untp/0.7.0/context/`. | `@context` list and order, `type` values, required properties, and terms that JSON-LD expansion drops. |
| L06 storage and persistence | Signed files at the issuer or at a storage service. Verification also needs the DID document, the status list, and the contexts. | The same signed bytes over time, and the old key still in the DID document. One run proves no lifetime. |
| L07 access rights and security | UNTP decentralized access control: public data, unguessable URLs, encrypted targets, shared secrets, OAuth, and DID authentication. | Restricted fields in a public credential, an unflagged encrypted target, and a key in the carrier URL. |
| L08 authentication and integrity | JOSE or COSE envelope, or a Data Integrity proof. Key lookup through the DID. Bitstring Status List with a base-10 string index; UNTP 0.7.0 types it as integer. | Header, payload, proof, DID document, and status bit. A verifier can replay each finding offline from captured bytes. |
| L09 registry and customs | UNTP has no product registry. GRID lists registers. The EU registry verifies operators with eIDAS means. | Only passive checks: the issuer DID in a supplied trust list snapshot. |
| L10 lifecycle and versions | An update is a new credential, and the old one gets a revocation or suspension bit. `did:web` keeps no key history. | Credential ids, `validFrom` order, the status bit of the old credential, and `did:webvh` history. |
| L11 roles and governance | The manufacturer issues the passport. Conformity bodies issue conformity credentials. Registers issue a DIA after a check of DID control. | The signer of each credential, the endorsement links of a conformity credential, and a DIA for the issuer DID. |

#### Variants

- Proof format: `vc+jwt` (UNTP default), `vc+sd-jwt`, `vc+cose`, or a Data Integrity proof such as `eddsa-jcs-2022` or `ecdsa-sd-2023`.
- The UNTP WIP text proposes that issuers produce JOSE or COSE and that verifiers verify both. This rule is proposed, not normative.
- Issuer DID: `did:web` without history, or `did:webvh` with a logged history.
- Access: a public credential, an unlisted URL, a key on the label, or a key after DID authentication or OpenID4VP.
- Discovery: a resolver linkset, DID document service endpoints, or a wallet push through OpenID4VCI or VCALM.
- Trust: UNTP registrars with GRID and DIA, EBSI trusted issuers, eIDAS trust service providers, or industry trust lists.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| Verifiable Credentials Data Model | v2.0 | W3C Recommendation 2025-05-15 | [VCDM 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| Securing VCs using JOSE and COSE | Recommendation 2026-10-13 | W3C Recommendation; republished to remove leftover CR text (commit log) | [VC JOSE COSE](https://www.w3.org/TR/vc-jose-cose/) |
| VC Data Integrity | 1.0 | W3C Recommendation 2025-05-15 | [Data Integrity](https://www.w3.org/TR/vc-data-integrity/) |
| Data Integrity ECDSA Cryptosuites | v1.0 | W3C Recommendation 2025-05-15 | [ECDSA suites](https://www.w3.org/TR/vc-di-ecdsa/) |
| Data Integrity EdDSA Cryptosuites | v1.0 | W3C Recommendation 2025-05-15 | [EdDSA suites](https://www.w3.org/TR/vc-di-eddsa/) |
| Bitstring Status List | v1.0 | W3C Recommendation 2025-05-15 | [Status list](https://www.w3.org/TR/vc-bitstring-status-list/) |
| Controlled Identifiers | v1.0 | W3C Recommendation 2025-05-15 | [CID 1.0](https://www.w3.org/TR/cid-1.0/) |
| Decentralized Identifiers | v1.1 | Candidate Recommendation Snapshot 2026-03-05; DID Resolution moved to v0.3 | [DID 1.1](https://www.w3.org/TR/did-1.1/) |
| `did:web` method | No version | CCG document; no status or date on the page | [did:web](https://w3c-ccg.github.io/did-method-web/) |
| `did:webvh` method | v1.0 | DIF specification; no date on the page | [did:webvh](https://identity.foundation/didwebvh/v1.0/) |
| UNTP specification | 0.7.0 | Pilot release; tag `v0.7.0` of 2026-05-04 | [UNTP versions](https://untp.unece.org/versions) |
| UNTP specification | WIP (v0.8.0 artifacts) | Testing; not normative; no 0.8.0 or 1.0 release found | [UNTP WIP](https://untp.unece.org/docs/specification/) |
| GS1-Conformant Resolver | 1.2.1 | Ratified Aug 2026; fixes no redirect code | [Resolver standard](https://ref.gs1.org/standards/resolver/) |
| OpenID4VCI | 1.0 | OpenID Final 2025-09-16 | [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| OpenID4VP | 1.0 | OpenID Final 2025-07-09 | [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| SD-JWT | RFC 9901 | Proposed Standard, 2025; month not confirmed by the independent check | [RFC 9901](https://www.rfc-editor.org/info/rfc9901) |
| SD-JWT VC (`dc+sd-jwt`) | draft-ietf-oauth-sd-jwt-vc-19 | Internet-Draft; waits for AD go-ahead; not an RFC | [SD-JWT VC draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) |
| VCALM (formerly VC API) | v1.0 draft | Active development; the text discourages production use | [VCALM](https://w3c.github.io/vcalm/) |
| EUDI Wallet ARF | v3.0.0 (2026-07-23) | Newest release object is `Topic_AA_rr_paper_v0.8` (2026-10-14); content not read | [ARF repository](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework) |
| ESPR Art. 11 credentials implementing act | None | Not adopted | Not applicable |
| ISO/IEC 18975:2024 | 2024 | Named by the UNTP resolver page; bibliographic only | [ISO page](https://www.iso.org/standard/85540.html) |

The authoritative UNTP tags are on the [UN/CEFACT GitLab](https://opensource.unicc.org/un/unece/uncefact/spec-untp/-/tags). The GitHub mirror stops at tag `v0.6.1`. The UNTP license is unresolved: the page footer says CC BY 4.0, and the repositories say GPL-3.0.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [tests-untp](https://github.com/uncefact/tests-untp) | Reference implementation, test suite, playground | GPL-3.0 | Pushed 2026-10-05; release 0.2.1 |
| [untp-test-suite](https://github.com/uncefact/tests-untp/tree/next/packages/untp-test-suite) | Validator (three tiers) | GPL-3.0 | In tests-untp |
| [UNTP Playground](https://github.com/uncefact/tests-untp/tree/next/packages/untp-playground) | Validator | GPL-3.0 | In tests-untp |
| [VCkit](https://github.com/uncefact/project-vckit) | Credential server | GPL-3.0 | Pushed 2026-09-10; release 1.2.1 |
| [project-storage-service](https://github.com/uncefact/project-storage-service) | Storage server | GPL-3.0 | Pushed 2026-06-12; tag `v4.0.0` |
| [Pyx Identity Resolver](https://github.com/pyx-industries/pyx-identity-resolver) | Resolver | Apache-2.0 | Pushed 2026-06-12; tag `v4.0.0` |
| [vc-data-model-2.0-test-suite](https://github.com/w3c/vc-data-model-2.0-test-suite) | Test suite | Not stated (NOASSERTION) | Pushed 2026-09-27 |
| [vc-jose-cose-test-suite](https://github.com/w3c/vc-jose-cose-test-suite) | Test suite | Not stated (NOASSERTION) | Pushed 2026-10-18 |
| [vc-di-ecdsa-test-suite](https://github.com/w3c/vc-di-ecdsa-test-suite) | Test suite | BSD-3-Clause | Pushed 2026-10-18 |
| [vc-di-eddsa-test-suite](https://github.com/w3c/vc-di-eddsa-test-suite) | Test suite | BSD-3-Clause | Pushed 2026-10-18 |
| [vc-bitstring-status-list-test-suite](https://github.com/w3c/vc-bitstring-status-list-test-suite) | Test suite | No license file found | Pushed 2026-10-18 |
| [vc-test-suite-implementations](https://github.com/w3c/vc-test-suite-implementations) | Registry of 23 implementer files | BSD-3-Clause | Pushed 2026-09-09 |
| [OpenDPP opendpp-interop](https://github.com/OpenDPP/opendpp-interop) | Vendor validator | Apache-2.0 | Pushed 2026-10-14 |
| [tracepass-dpp-vc](https://github.com/malinoto/tracepass-dpp-vc) | UNTP extension profile | Apache-2.0 | Pushed 2026-10-16 |
| [EBSI](https://ebsi.eu/) | Platform | EUPL (portal statement) | Not checked; full service stated for later in 2026 |

- The UNTP Playground verifies with the `credentialStatus` policy turned off. A revoked credential can show as verified there.
- The storage service needs an API key for `/public`, `/private`, and `DELETE`. A loopback fixture models `401` without the key.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no credential format, no DID method, and no status list.
- Regulation (EU) 2024/1781, Art. 11(g) and (h) set authentication, integrity, security, and privacy as outcomes. Signed credentials are one possible mechanism.
- Under Art. 11, fourth subparagraph, the Commission may adopt implementing acts on the issue and verification of digital credentials. None was located on 2026-10-19.
- Access is tiered by actor under Art. 9(2)(f)-(g), Art. 11(b), and Art. 11(f). UNTP `accessRole` URIs are not mapped to these EU actor groups.
- Art. 10(4) and Art. 11(c) and (e) set storage, a back-up copy, and availability after insolvency. DID documents and status lists add dependencies that the law does not name.
- Art. 11(d) links a new passport to the original passport. The UNTP 0.7.0 DPP schema requires no such link.
- Art. 10(1)(a)-(c) and Art. 12(1) set persistent identifiers and carriers. Until OJ references exist, they cite ISO/IEC 15459-1 to -6 or equivalents, named here by number only.
- Implementing Regulation (EU) 2026/1778, Art. 4: legal persons get verified status with a qualified electronic seal or a qualified electronic attestation of attributes.
- Identification at eID assurance level high is a route only for sole traders established in the Union. Verified status lasts at most three years.
- Art. 13(5) and Art. 15(1)-(2) make the registration identifier a customs check. UNTP has no counterpart to this registry function.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | `credentialSubject.id` differs from the carrier identifier, or a new version reuses the credential `id`. | Compare the carrier text with the subject id; compare credential ids across versions. |
| L02 | The label holds a vendor short link, an app deep link, or a raw JWT. | Decode the sample QR and classify the payload. Follow redirects on loopback fixtures only. |
| L02 | A public QR holds a `decryptionKey` for data meant for one role. | Flag the parameter and compare it with the access tier of the target. |
| L03 | The resolver answers `200` with HTML for every request, ignores `linkType=linkset`, or omits the `dpp` link. | Probe content negotiation and `linkType`; validate the linkset against the pinned schema. |
| L04 | A verifier endpoint returns `verified: true` for a revoked credential, or `200` with an error body. | POST a revoked and a tampered fixture to a loopback instance. Check the result and the HTTP status. |
| L05 | RDF canonicalization drops undefined terms, so a displayed property is not signed. | Expand with pinned contexts and report dropped terms before trust in an `rdfc` proof. |
| L06 | The verifier treats an unreachable status list as "not revoked". | Return `5xx` or a timeout from a mock status service. The correct outcome is unreachable, never pass. |
| L07 | A restricted credential is in clear text at an unguessable but open URL. | Fetch the target without credentials and inspect the linkset target attributes. |
| L08 | `statusListIndex` is a JSON number because the producer follows the UNTP 0.7.0 schema. | Type check against the W3C rule, and record the declared UNTP version. |
| L08 | The status list is too short, not GZIP, or lacks the `u` prefix. | Decode `encodedList` and check prefix, decompression, and length (`STATUS_LIST_LENGTH_ERROR`). |
| L08 | The status list is unsigned or signed by another issuer. | Verify the list proof and compare its issuer with the credential issuer. |
| L08 | A legacy VC 1.1 JWT shape (`vc` claim, `typ` `JWT`), or `iss`, `kid`, and `issuer.id` differ. | Inspect the header and payload keys; compare the three issuer values. |
| L08 | The `did:web` document uses plain HTTP, a wrong path, or an `id` that differs from the DID. | Apply the `did:web` transformation and compare the document `id`. |
| L10 | The issuer publishes an update but does not revoke the old credential. | In a recorded sequence, both credentials verify and neither status bit is set. |
| L11 | A non-registrar issues the DIA, or the DIA names another subject DID. | Check the DIA issuer against a trust list snapshot, the DIA-02 domain match, and subject equality. |
| L11 | A conformity credential claims accreditation, but the endorsement link fails or names another body. | Follow the endorsement evidence and compare the endorsed body with the issuer. |
| L09 | The DIA `registeredId` differs from the operator identifier in the EU registry. | Compare the DIA with a supplied registry extract. Make no live registry call. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json`, which checked the engine source at commit `b290791`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

Today `integrity.jws` cannot verify any credential of this family. It requires `typ` `dpp+jws`, an `x5c` chain, ES256, and only the headers `alg`, `kid`, `typ`, and `x5c`. Without `x5c`, it gives `INTEGRITY.KEY.UNSUPPORTED`.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| The carrier identifier equals `credentialSubject.id`. | `identifier.consistency` (correct): it reads the top-level `id`. | `identifier.subject_pointer` | QR image and `TEST-ONLY` signed `vc+jwt`; a credential-`id`-only variant. | loopback only |
| The resolver returns a valid linkset with a `dpp` link. | `identifier.resolve` (correct): it reaches a linkset by media type. | `resolver.linkset` | Good linkset, no `dpp` link, JSON only. UNTP Playground as a reference. | loopback only |
| Default redirect without `linkType`; `404` for an absent link type. | `identifier.resolve` (overstated): it judges `404` as a fail and never asserts the target. | `resolver.conformance` | Default link and an absent link type. | loopback only |
| The resolver publishes a description file. | None (correct). | `resolver.well_known` | With and without the file. The UNTP file is a SHOULD, so absence is no fail. | loopback only |
| A `vc+jwt` credential verifies with the key from its `kid`. | None (correct): `integrity.jws` accepts `dpp+jws` with `x5c` only. | `integrity.jose_profiles` | `TEST-ONLY` keys; `did.json`; bad `typ`, `vc` claim, `iss` mismatch. W3C JOSE COSE suite. | sample artifact |
| A Data Integrity proof verifies under its cryptosuite and purpose. | None (correct). | `integrity.data_integrity` | Specification vectors; tampered and wrong-purpose variants. W3C EdDSA and ECDSA suites. | sample artifact |
| The issuer DID resolves to a valid DID document. | None (correct). | `identity.did` | `did.json` at the root and at a path; wrong `id`; plain HTTP. | loopback only |
| A `did:webvh` log verifies end to end. | None (correct). | `identity.did` | Valid log; broken hash; unauthorized update key. | sample artifact |
| Each status entry is well formed and the bit is clear. | None (correct): `evidence.status_list` decodes report lists and fetches nothing. | `integrity.status_list` (leave interface only) | Mock status service: bit set, bit clear, short, unsigned. W3C status list suite. | loopback only |
| Report the `statusListIndex` type conflict per UNTP version. | `data.jsonschema` (overstated): it validates against one schema and compares no two schemas. | No x01 capability id; a two-oracle report | Credentials with integer and string indexes. | sample artifact |
| Envelope and `@context` conform to VCDM 2.0 and to the UNTP version. | `data.context` and `data.jsonschema` (overstated): both read only the HTTP document. | `data.document_source` | Maintainer VCDM schema; operator-supplied UNTP schemas. untp-test-suite tiers 1 and 2. | sample artifact |
| JSON-LD expansion with pinned contexts loses no term. | None (correct): `data.context` compares exact strings. | `data.jsonld` | Undefined term; redefined protected term. | sample artifact |
| A typed link leads to a credential of the same type. | None (correct). | `resolver.linkset` | Correct and swapped link types. | loopback only |
| A DIA from a trusted registrar anchors the issuer DID. | None (correct): the trust bundle holds X.509 anchors only. | `trust.identity_anchor` | `TEST-ONLY` registrar DID; unlisted registrar; other subject DID. untp-test-suite tier 3. | sample artifact |
| Each assessed claim has a conformity credential for the same product and criteria. | None (correct). | `graph.claim_attestation` | Synthetic credential sets. The GPL-3.0 examples are not bundled. | sample artifact |
| Encrypted targets carry a flag; restricted data stays unreadable without the key. | `access.restricted_fields` (correct): envelope recognition is new. | `access.encrypted_target` | AES-256-GCM envelope, unflagged target, clear restricted credential. | loopback only |
| A restricted target needs a valid role presentation. | None (correct): credentials are static Bearer tokens. | `access.credential_acquisition` | `TEST-ONLY` holder DID and DIA with a correct and a wrong scope. | loopback only |
| A verifier endpoint refuses tampered, revoked, and expired credentials. | None (correct): `api.contract` supports GET only. | `api.write_ops` | Good, tampered, revoked, and expired fixtures. | loopback only |
| An update is a new linked credential, and the old one is revoked. | `persistence.versions` (overstated): it checks no link and no revocation state. | `integrity.status_list` and `lifecycle.links` | Two credentials and two status list states. | loopback only |
| Status lists and issuer keys stay available for older credentials. | None (correct): `persistence.scheduled` is interface only. | `persistence.scheduled` | Recordings at intervals; evidence, not proof. | live system under test |
| A render template or a linked document matches its `digestMultibase`. | None (correct, two entries). | `integrity.digest_binding` | Correct digest, wrong digest, unsupported multihash code. | loopback only |
| The carrier holds a resolver URL, no raw credential, and a flagged key. | `carrier.qr_decode` and `identifier.parse` (correct): parse accepts only one GS1 form. | `identifier.schemes`; `access.encrypted_target` for the key flag | QR images: GS1 item and batch URLs, other schemes, `decryptionKey`, raw JWT. | sample artifact |
| EU registry operator verification. | `manual.review` (correct): no black-box check. | None in this family | None | live system under test |

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m05-verifiable-credentials.json`. The engine verdicts are in `x01-engine-mapping.json`, and the extra repositories are in `r01-repositories.json`.
- The independent check (`m05-verifiable-credentials.verification.json`) checked 32 claims: 27 confirmed, 3 refuted, and 2 not confirmed. It had no rule 5 findings.
- Refuted and corrected: the UNTP WIP JOSE-or-COSE rule is a proposal, not a MUST. The DIA schema names are `idScheme` and `registrationScope`; the access control prose says `registrationScopeList`.
- Also changed: eID level high applies only to sole traders, and the storage service needs an API key. The `did:webvh` term `newDomain` was not found, so this section omits it.
- Not confirmed and left out: the month of RFC 9901 and the Commission slide dates for the Art. 11 credentials act. Open: the `vc+jwt` algorithm allowlist, the `statusListIndex` oracle, the UNTP license, and wallet input to the EU registry.

### 5.6 Event-based traceability family (EPCIS)

In this family, a passport does not hold supply-chain events. It links to them. GS1 EPCIS records visibility events: what happened to which identified objects, when, where, why, and, since release 2.0, how (sensor data). The GS1 Core Business Vocabulary (CBV) supplies the standard values and the rules for event identifiers.

A consumer resolves the passport identifier, reads a `gs1:epcis` or `gs1:traceability` link, and queries an EPCIS repository for events about the product. The family is mature in supply chains, with several open-source servers, validators, and generators. GS1 publishes no conformance test suite for EPCIS 2.0, and the UNTP Digital Traceability Events (DTE) specification profiles EPCIS events as credential subjects.

#### Components

- **EPCIS event.** One of five types: `ObjectEvent`, `AggregationEvent`, `TransactionEvent`, `TransformationEvent`, and `AssociationEvent` (new in 2.0).
- **Event fields.** `eventTime`, `eventTimeZoneOffset`, `recordTime`, an optional `eventID`, and an optional `errorDeclaration` for corrections.
- **CBV 2.0.** Standard values for business steps, dispositions, transaction types, and source and destination types. It also defines the EPCIS Event Hash ID.
- **JSON and JSON-LD binding.** A draft-07 JSON Schema, a JSON-LD 1.1 context, and SHACL shapes (`epcis-shacl.ttl`).
- **REST interface.** An OpenAPI 3.0.3 description with `/capture`, `/events`, top-level resources such as `/epcs/{epc}/events`, and named queries under `/queries`.
- **EPCIS repository.** A server that stores captured events and answers queries. Examples are OpenEPCIS, Oliot, and FasTnT.
- **Resolver link.** The GS1 Web Vocabulary link types `gs1:epcis` and `gs1:traceability` in the linkset of the passport identifier (see section 5.2).
- **UNTP DTE (optional).** A verifiable credential whose `credentialSubject` is an EPCIS event (see section 5.5).

#### End-to-end flow

1. The manufacturer captures events with `POST /capture` and an `EPCISDocument` in JSON-LD.
2. The repository answers `202` with a `captureID`.
3. The manufacturer polls `GET /capture/{captureID}` until `running` is false and `success` is true.
4. The manufacturer registers a `gs1:dpp` link and a `gs1:epcis` link in its resolver linkset.
5. A consumer scans the GS1 Digital Link carrier and asks the resolver with `linkType=gs1:epcis`.
6. The consumer authenticates and calls `GET /epcs/{epc}/events`, or `/events` with `MATCH_anyEPC`.
7. The consumer follows `Link` headers with `rel="next"` until the last page.
8. For each `TransformationEvent`, the consumer reads the input identifiers and resolves their passports in turn.
9. A subscriber platform can instead receive pushed events through a webhook, check `GS1-Signature`, and validate each event.

GS1 Web Vocabulary does not say which EPCIS URL the `gs1:epcis` link targets. It can be the server root, `/epcs/{epc}/events`, or a named query. The GS1-Conformant Resolver standard fixes no redirect status code, so a test oracle records the observed code.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Objects are EPC URNs or, since CBV 2.0, constrained GS1 Digital Link URIs. `eventID` is a UUID URN or an `ni:` Event Hash ID. | Identifier forms in returned events, translation per `GS1-EPC-Format`, and the `eventID` grammar. |
| L02 data carriers | Does not apply. EPCIS defines no carrier; `readPoint` records where a carrier was read. | Nothing specific; carrier tests belong to section 5.9. |
| L03 data exchange protocols | HTTP REST with JSON and JSON-LD; XML, SOAP, AS2, and message queues as other bindings. Custom `GS1-*` headers negotiate versions and formats. | Media type per `Accept`, `406`, `OPTIONS` answers, `GS1-*` headers, problem documents, and webhook calls. |
| L04 APIs for lifecycle and search | Asynchronous `/capture` with capture jobs, `/events` queries, top-level resources, and named queries with subscriptions. Events are append-only. | Capture job states, query results by identifier and vocabulary value, pagination, and status codes. |
| L05 interoperability and data models | Five event types with what, when, where, why, and how dimensions. JSON must pass the JSON Schema; JSON-LD must pass the SHACL shapes. | Offline validation of captured and returned documents, `@context` entries, and CBV values. |
| L06 storage and persistence | Partial. The repository keeps events with `recordTime` but EPCIS sets no retention, back-up, or availability rule. | The same event body and `recordTime` over time, and reachability of the `gs1:epcis` target. |
| L07 access rights and security | Every call needs authentication. Authorization rules are left to the implementation, which may withhold events, coarsen locations, or hide fields. | `401` and `403` problem documents, per-role event sets, and schema validity of redacted events. |
| L08 authentication and integrity | Partial. No event signature. The CBV Event Hash ID is a fingerprint over a canonical pre-hash string. Webhooks carry `GS1-Signature`. | A recomputed hash against `eventID`, XML and JSON hash parity, and webhook signatures. |
| L09 registry and customs | Does not apply. EPCIS has no link to the EU registry or to customs. The resolver link replaces older discovery services. | Nothing. |
| L10 lifecycle and versions | Product lifecycle is a sequence of events with business steps and dispositions. A correction is an error declaration, not an update. | Ordered event history, correction events, and version headers in responses. |
| L11 roles and governance | GS1 develops EPCIS and CBV under its IP Policy. Roles are capturing applications, repository operators, accessing applications, and resolvers. | The operator of the repository behind a `gs1:epcis` link, from host name and TLS certificate subject. |

Further details per layer:

- **L01.** The `GS1-EPC-Format` header takes `No_Preference`, `Always_GS1_Digital_Link` (the default), `Always_EPC_URN`, or `Never_Translates`. The independent check confirmed these four values.
- **L03.** The OpenAPI also defines `GS1-CBV-Min` and `GS1-CBV-Max`. The conformance list in section 14.8 of EPCIS names `GS1-CBV-Format`, but the OpenAPI names `GS1-CBV-XML-Format`. A probe must handle both names.
- **L03.** Errors are RFC 7807 problem documents typed `epcisException:<Name>`. For example, `QueryParameterException` gives `400`, `URITooLongException` gives `414`, and `ImplementationException` gives `500` or `501`.
- **L04.** A server must support `/epcs`, `/events`, and named queries. The other top-level resources are optional. The page size defaults to 30, and events are never split across pages.
- **L04.** A query URL has at most 2000 characters, and a longer one gives `414`. A WebSocket upgrade on `GET /queries/{queryName}/events` gives status `101`.
- **L05.** The JSON Schema rejects legacy `urn:epcglobal:cbv` values. It accepts a full CBV Web URI as an "other" URI, so the bare-string form is not forced.
- **L08.** The hash rules convert EPC URNs to canonical Digital Link URIs on `https://id.gs1.org` and sort lists. XML and JSON forms of one event must give the same hash.
- **L08.** CBV states limits: an error declaration reuses the original `eventID`, a redacted event does not reproduce the hash, and a hash alone does not prove authorship.

#### Variants

- Binding: REST with JSON or JSON-LD (EPCIS 2.0), REST with XML, SOAP query interface, AS2, or message-queue capture.
- Capture: asynchronous bulk capture at `/capture`, or synchronous capture of one event with `POST /events` (`201`).
- Push: webhook subscriptions (mandatory) or WebSocket subscriptions (optional).
- Identifiers: EPC URNs, GS1 Digital Link URIs, or other HTTP URIs in CBV-Compatible documents.
- Event identity: a UUID URN, an `ni:` Event Hash ID, or no `eventID`.
- CBV level: CBV-Compliant (standard values) or CBV-Compatible (other URIs that meet EPCIS rules).
- Integrity: plain events, a hash as `eventID`, a hash anchored on a ledger (section 5.7), or an event inside a signed credential.
- Access: API keys, HTTP Basic, OAuth 2.0 bearer tokens, partitioning by capturing client, field redaction, or location coarsening.
- UNTP DTE: UNTP-native events, or the EPCIS profile with an EPCIS event as the credential subject.
- Vendor subsets: FasTnT supports only `rollback` capture, only `Never_Translates`, and synchronous capture.

UNTP DTE 0.7.0 maps `MakeEvent` to `TransformationEvent` (and `AggregationEvent` for aggregation). It maps `MoveEvent` to `ObjectEvent` with `OBSERVE`, and `ModifyEvent` to `ObjectEvent`. For repair, `ModifyEvent` can use `ADD`. Requirements TEV-01 and TEV-02 ask for links to component and input passports.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| EPCIS Standard | 2.0.1 (2025-07-01); the PDF cover still says Release 2.0, Jun 2022 | Ratified; latest in the GS1 release list | [EPCIS](https://ref.gs1.org/standards/epcis/) |
| EPCIS release list | 2.0.1, 2.0.0, 1.2.0, 1.1.0, 1.0.1, 1.0.0 | 2.0.0 (2022-06-22) is archived | [EPCIS archive](https://ref.gs1.org/standards/epcis/archive) |
| CBV Standard | 2.0.0 (2022-06-22) | Ratified; latest | [CBV](https://ref.gs1.org/standards/cbv/) |
| EPCIS REST OpenAPI (ref.gs1.org) | OpenAPI 3.0.3; `info.version` 2.0.1 | Published artifact; license label "Apache2" | [openapi.json](https://ref.gs1.org/standards/epcis/openapi.json) |
| EPCIS REST OpenAPI (GitHub) | OpenAPI 3.0.3; `info.version` 2.0.0; 29 paths; no `securitySchemes` | Development copy | [gs1/EPCIS](https://github.com/gs1/EPCIS) |
| EPCIS JSON Schema | draft-07; `$id` under `/2.0.1/` | Normative; the standard text cites the `/2.0.0/` path | [JSON Schema](https://ref.gs1.org/standards/epcis/epcis-json-schema.json) |
| EPCIS JSON-LD context | JSON-LD 1.1, `@protected` | Published artifact | [Context](https://ref.gs1.org/standards/epcis/epcis-context.jsonld) |
| EPCIS SHACL shapes | Not opened | Normative for JSON-LD | [SHACL file](https://ref.gs1.org/standards/epcis/epcis-shacl.ttl) |
| EPCIS 2.1 draft context | Folder `public_review_2_1`, 2026-09-04 | Public review draft | [gs1/EPCIS](https://github.com/gs1/EPCIS) |
| EPCIS and CBV Implementation Guideline | Release 1.0, Oct 2015 | Ratified; predates EPCIS 2.0 | [Guideline](https://ref.gs1.org/guidelines/epcis-cbv/1.0.0/) |
| GS1 Web Vocabulary | 1.18.0 on ref.gs1.org (2026-06-01) | Current; `gs1:epcis` and `gs1:traceability` are stable | Shared sheet; terms read from [gs1/WebVoc](https://github.com/gs1/WebVoc) v1.16 |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified Aug 2026 | Shared sheet |
| GS1-Conformant Resolver | 1.2.1 | Ratified Aug 2026; fixes no redirect code | Shared sheet |
| UNTP Digital Traceability Events | 0.7.0 | Pilot release; WIP text not normative; no 0.8.0 or 1.0 found | [UNTP DTE 0.7.0](https://untp.unece.org/docs/0.7.0/specification/DigitalTraceabilityEvents) |
| ISO/IEC 19987:2024 "EPC Information services" | 2024 | Bibliographic only; not confirmed by the independent check | [ISO page](https://www.iso.org/standard/85557.html) |
| ISO/IEC 19988:2024 "Core business vocabulary" | Third edition, 2024-03 | Bibliographic only | [SCC catalogue](https://scc-ccn.ca/standardsdb/standards/8185963) |

The GitHub mirror of GS1 Web Vocabulary stops at v1.16 and is not current. The ref.gs1.org link-type file has no version marker, so an engine stores the digest of the fetched file. No change log for EPCIS 2.0.1 was found, so it is open whether 2.0.1 changed normative text or only artifacts.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [OpenEPCIS Repository CE](https://github.com/openepcis/epcis-repository-ce) | Server (Quarkus, Kafka, OpenSearch) | Apache-2.0 | Pushed 2026-01-10 |
| [Oliot EPCIS](https://github.com/JaewookByun/epcis) | Server (Vert.x, MongoDB) | Apache-2.0 | Pushed 2026-01-15 |
| [FasTnT EPCIS](https://github.com/louisaxel-ambroise/epcis) | Server (.NET 10, EPCIS 1.2 and 2.0) | Apache-2.0 per README; GitHub reports NOASSERTION | Pushed 2026-10-19 |
| [OpenEPCIS document validation service](https://github.com/openepcis/openepcis-document-validation-service) | Validator | Apache-2.0 | Pushed 2026-10-17 |
| [OpenEPCIS event sentry](https://github.com/openepcis/openepcis-event-sentry) | Validator (event profiles) | Apache-2.0 | Pushed 2026-09-09 |
| [OpenEPCIS test data generator](https://github.com/openepcis/epcis-testdata-generator) | Test data generator | Apache-2.0 | Pushed 2026-09-04 |
| [OpenEPCIS test resources](https://github.com/openepcis/openepcis-test-resources) | Valid and invalid documents | Apache-2.0 | Pushed 2026-10-16 |
| [EPCIS Event Hash Generator](https://github.com/RalphTro/epcis-event-hash-generator) | Reference hash implementation (Python) | MIT | Pushed 2026-09-25 |
| [OpenEPCIS event hash generator](https://github.com/openepcis/openepcis-event-hash-generator) | Hash library (Java) | Apache-2.0 | Pushed 2026-09-07 |
| [OpenEPCIS document converter](https://github.com/openepcis/openepcis-document-converter) | SDK (XML and JSON) | Apache-2.0 | Pushed 2026-09-09 |
| [OpenEPCIS Digital Link toolkit](https://github.com/openepcis/openepcis-epc-digitallink-translator) | SDK (EPC URN and Digital Link) | Apache-2.0 | Pushed 2026-09-13 |
| [OpenEPCIS DPP-ready](https://github.com/openepcis/openepcis-dpp-ready) | Ontology (preview 0.9.9) | Apache-2.0 | Pushed 2026-10-11 |
| [OpenDPP interop kit](https://github.com/OpenDPP/opendpp-interop) | Vendor validator with an EPCIS endpoint | Apache-2.0 | Pushed 2026-10-14 |
| [gs1/EPCIS](https://github.com/gs1/EPCIS) | Artifacts, samples, draft conformance requirements | Not stated (NOASSERTION; GS1 disclaimer) | Pushed 2026-09-04 |
| [epcis-signing](https://github.com/COPPA-CCP/epcis-signing) | SDK (event signatures) | Apache-2.0 | Pushed 2026-01-12 |
| [tracepass-open](https://github.com/malinoto/tracepass-open) | Validator and EPCIS 2.0 event mapper | Apache-2.0 | Pushed 2026-10-13 |

- The FasTnT README badge links refer to `FasTnT/epcis-ef-core`. The older `FasTnT/epcis` repository supports EPCIS 1.2 only, and its README publishes a default credential.
- The reference hash generator calls itself prototypical demo software. It supports CBV 2.0 by default and the draft CBV 2.1 as an option.
- The `gs1/EPCIS` conformance matrix is a draft. Rows M1, M121, and M122 have text, M123 is a placeholder, and the other rows are empty.
- OpenDPP validates EPCIS output against a vendored copy of the 2.0.1 JSON Schema. Its `ecdsa-jcs-2019` rule applies to credential ingest at `POST /api/v1/events`, not to the EPCIS endpoint.
- The last two rows come from the repository inventory. Treat vendor validators as comparators, not as authorities.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no protocol, HTTP method, header, or media type, and it does not name EPCIS.
- Regulation (EU) 2024/1781, Art. 10(1)(a) asks for a persistent unique product identifier, linked through the carrier. EPCIS adds identifiers for events, locations, and transactions.
- Art. 10(1)(d) asks for open, interoperable, machine-readable, structured, and searchable data without vendor lock-in. EPCIS adds a full query protocol and push subscriptions that the law does not require.
- Under Art. 9(2)(f)-(g), the delegated act decides who may access which data and who may create or update it. EPCIS offers mechanisms but no role model.
- Art. 11(b) gives free and easy access to listed actors according to their access rights. EPCIS requires authentication on every call, so a public tier needs a separate view.
- The toy and detergent regulations forbid registration or a password for consumers (Regulation (EU) 2025/2509, Art. 20(4); Regulation (EU) 2026/405, Art. 22).
- Art. 10(4) asks for a back-up copy through a DPP service provider. Art. 9(2)(i) and Art. 11(e) set availability, also after insolvency.
- EPCIS sets no retention rule. Events that a passport links to are outside the passport back-up unless the passport copies them.
- Art. 11(g) asks for data authentication, reliability, and integrity, with no mechanism. The Event Hash ID is a fingerprint, so authenticity needs a separate signature layer.
- Art. 11(d) asks that a new passport link to the original passport. EPCIS transformation events link inputs to outputs, but no law or GS1 text relates event histories to passport versions.
- The registry under Art. 13 stores identifiers and links, not events. EPCIS has no registry duty.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L05 | The server emits legacy `urn:epcglobal:cbv` URNs in JSON instead of bare CBV strings. | Validate returned documents against the pinned JSON Schema. |
| L05 | A document embeds a context URL that is not the GS1 context document, for example the namespace `https://ref.gs1.org/epcis/`. | Compare `@context` with an allowlist; expand with pinned contexts only. |
| L05 | A validator does not assert format `uri`, so a misspelled key such as `bizstep` passes as an extension. | Validate with format assertion on, or with SHACL after expansion. |
| L08 | An `ni:` `eventID` is computed from the JSON text, not from the canonical pre-hash string. | Recompute the hash and compare with two reference generators. |
| L04 | Capture with `rollback` stores the valid events of a partly invalid document. | After a failed capture job, a query returns none of its events. |
| L04 | `/capture` answers `200` or `201` without a `captureID`, or `/capture/{captureID}` is missing. | A REST probe against the pinned OpenAPI (`epcis.rest_probe`, proposed). |
| L03 | The server ignores `Accept`, or answers `200` with HTML instead of `406`. | Content negotiation cases with supported and unsupported media types. |
| L03 | `OPTIONS` is missing or returns no `GS1-EPCIS-Version` and `GS1-CBV-Version` defaults. | Assert the `OPTIONS` status, `Allow`, and the `GS1-*` headers. |
| L04 | Pagination splits an event, repeats events, or sends a malformed `Link` header. | Walk all pages and compare event identifiers across pages. |
| L07 | The query endpoint answers without authentication, or returns `200` with an empty list instead of `401` or `403`. | Probe without credentials and with a wrong role; check status and problem type. |
| L07 | Redaction removes a required field, such as `parentID` of an `AggregationEvent` with `ADD`. | Validate each role-specific response against the JSON Schema. |
| L07 | Partitioning by capturing client leaks events of another client. | Seed events from two clients; query as each client. |
| L07 | A deployment keeps a default credential from the project README. | Not testable black-box. Record a `manual.review` item; the engine never tries guessed passwords. |
| L03 | A webhook subscription accepts any `dest`, so the server calls internal addresses. | Request a `dest` outside the IXIT allowlist; expect the refusal that the declared policy names. |
| L03 | Webhook pushes carry no `GS1-Signature`, or a signature that does not depend on the payload. | A loopback listener verifies signatures over two different payloads. |
| L03 | The resolver advertises `gs1:traceability` for an EPCIS repository, so a `linkType=gs1:epcis` request finds nothing. | Assert the link relation in the linkset. |
| L01 | The server translates EPCs although the client sent `Never_Translates`. | Capture EPC URNs, query with each `GS1-EPC-Format` value, and compare identifiers. |
| L10 | An error declaration gets a new `eventID`, which breaks the link to the original. | `/events/{eventID}` must return the original and its declaration. |
| L06 | The repository behind the `gs1:epcis` link is retired while the passport must stay available. | Repeat checks of the link target over time. |

#### What the engine can test

`x01-engine-mapping.json` has no rows for this family, and none of its proposed capabilities merge an entry from this family. The verdicts below therefore come from the independent check of the family file, which read the engine source. "Not checked" means that the independent check did not test that mapping.

The capability ids `epcis.*`, `identifier.links`, and `evidence.untp_dte` are proposals of the family file. They are not registered, and x01 did not consolidate them. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| An EPCIS JSON document passes the pinned GS1 JSON Schema. | `data.jsonschema` (refuted): it asserts `uri` but not `date-time`, and it always applies 2020-12 rules. | A `date-time` format checker and draft-07 handling (contract change) | [openepcis-test-resources](https://github.com/openepcis/openepcis-test-resources); `gs1/EPCIS` samples; own negative cases | sample artifact |
| A JSON-LD document conforms to the GS1 SHACL shapes. | None (confirmed): `data.shacl` is interface only. | `data.shacl` with pinned `epcis-shacl.ttl` and offline contexts | Pinned shapes and context; JSON-LD samples. No SHACL suite found. | sample artifact |
| Each `@context` entry is an allowed EPCIS context URL. | `data.context` (confirmed): it compares exact URLs and fetches nothing. | None; allowlist entries | Documents with the `/2.0.0/` URL, the unversioned URL, the namespace URL, and a foreign context | sample artifact |
| An `ni:` `eventID` equals the recomputed Event Hash ID; XML and JSON give one hash. | None (not checked) | `epcis.event_hash` | [Reference generator](https://github.com/RalphTro/epcis-event-hash-generator) examples; XML and JSON pairs from test resources | sample artifact |
| `eventID` values use a UUID v1 or v4 URN, or `ni:` with `?ver=CBV`. | None: the independent check refuted `data.rules`, which has no pattern kind. | `epcis.event_id` | Valid UUID v1 and v4; invalid v3; `ni:` with an unknown algorithm; `ni:` without `ver` | sample artifact |
| Endpoints negotiate JSON and JSON-LD, return `406`, and answer `OPTIONS` with `GS1-*` defaults. | `api.contract` (refuted): GET only, an OpenAPI 3.1 subset, one passport resource. | `epcis.rest_probe` | Pinned `openapi.json` 2.0.1 with external `$ref` targets vendored; OpenEPCIS CE or FasTnT on loopback | loopback only |
| Capture with `rollback` stores all events or none. | None (not checked) | `epcis.capture_probe` | All-valid document, one invalid event, a document over the capture limit | loopback only |
| Pages hold 30 events by default, and the `rel="next"` chain ends. | None (not checked) | `epcis.rest_probe` | Repository seeded with 75 events for one EPC | loopback only |
| A repeated query parameter gives `400`; a URL over 2000 characters gives `414`. | None (not checked); `api.fuzz` is interface only. | `epcis.rest_probe` negative cases | Request templates | loopback only |
| `401` and `403` come as problem documents; each role sees only its events and fields. | `access.restricted_fields` (confirmed): field-based, so withheld events and coarsened locations stay uncovered. | Event-level policy in `access.restricted_fields` | Two `TEST-ONLY-` role tokens; events from two clients; a declared policy | loopback only |
| Webhook pushes carry a valid `GS1-Signature`; a disallowed `dest` is refused. | None (not checked) | `epcis.subscription_probe` | Loopback listener; test `signatureToken`; algorithm and `dest` allowlist from the IXIT | loopback only |
| The linkset has a `gs1:epcis` link whose target answers as an EPCIS endpoint. | `identifier.resolve` (confirmed): `accepted_media_types` must list `application/linkset+json`. | `identifier.links` and `epcis.rest_probe` | Loopback resolver with `gs1:epcis`, `gs1:traceability`, and a wrong relation; GS1 resolver test suite (section 5.2) | loopback only |
| A UNTP DTE holds a valid EPCIS event and links inputs and outputs to identifiers. | `data.jsonschema` and `integrity.jws` (not checked) | `evidence.untp_dte` | Own DTE samples until the UNTP license is resolved | sample artifact |
| An error declaration keeps the original `eventID`; `correctiveEventIDs` resolve. | `persistence.versions`, partial (not checked) | `epcis.capture_probe` correction scenario | Test resources documents with `errorDeclaration` | loopback only |
| CBV values are standard values or URIs outside CBV, as the ICS declares. | `data.rules` (not checked); rules cannot iterate `eventList` entries. | A rule pack for CBV value lists | CBV 2.0 value lists from the pinned schema enums | sample artifact |
| The repository behind the `gs1:epcis` link stays reachable. | None; `persistence.scheduled` is interface only. | `persistence.scheduled` | Recorded acquisitions at intervals | live system under test |

The engine supports an OpenAPI 3.1 subset with GET operations only. The GS1 contract is OpenAPI 3.0.3 with POST and `OPTIONS` operations. `api.contract` could judge GET query responses only after a conversion to 3.1, so a separate probe is the shorter route.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/f01-epcis-event-traceability.json`. The extra repositories are in `r01-repositories.json`. `x01-engine-mapping.json` has no rows for this family.
- The independent check (`f01-epcis-event-traceability.verification.json`) checked 34 claims: 26 confirmed, 5 refuted, and 3 not confirmed. It found no rule 5 violation except one sentence on ISO/IEC 19987 and 19988, which this section omits.
- Corrections applied: the GitHub OpenAPI has 29 paths, not 30. Three mappings to `data.jsonschema`, `data.rules`, and `api.contract` overstated the engine, and the matrix and OpenDPP notes were fixed.
- Not confirmed: the ESPR citations of the family file, which this section replaces with the legal baseline, and ISO/IEC 19987:2024. A local test with format `uri` on the key `bizstep` was not repeated with the engine checker.
- Open: the target URL of a `gs1:epcis` link, the `@context` URL in fielded documents, the `GS1-Signature` algorithm (an IXIT entry), and whether CBV 2.1 changes the hash.

### 5.7 Linked data and semantic web family

In this family, a passport is a set of RDF statements about a product and its passport record. The usual serialization is JSON-LD 1.1, and HTTP(S) IRIs name the nodes. A JSON-LD `@context` maps each JSON key to an IRI in a shared vocabulary or ontology. SHACL shapes state the constraints, and a validator checks them on the RDF graph, not on the JSON tree.

Public artifacts of this family come mainly from EU research projects: CIRPASS-2 ontologies and shapes, CE-RISE LinkML models, and the Battery Pass SAMM models. No production passport system that publishes linked data with SHACL validation was located. No Solid pod passport prototype was located either.

#### Components

- **Product and passport IRIs.** Absolute HTTP(S) IRIs in `@id`, often aliased to `id`. A GS1 Digital Link URI can serve as the product IRI.
- **JSON-LD document and contexts.** A JSON-LD 1.1 document with `@context` references. Contexts can declare `@protected`, `@vocab`, `@import`, and scoped contexts.
- **Vocabularies and ontologies.** The CIRPASS-2 EU DPP CORE ontology with sector modules, the GS1 Web Vocabulary, schema.org, the UNTP context, QUDT units, and SKOS code lists.
- **SHACL shapes.** Constraint shapes for a product group. CIRPASS-2 also writes view shapes for each access tier.
- **SAMM aspect models (variant).** Eclipse SAMM keeps the meaning in a Turtle model. `samm-cli` generates JSON Schema, OpenAPI, and sample payloads from it.
- **LinkML models (variant).** CE-RISE generates JSON Schema, OWL, and SHACL from one YAML source and keeps a versioned catalog.
- **Processors and validators.** JSON-LD processors (PyLD, jsonld.js, Titanium) and SHACL validators (pySHACL, Apache Jena SHACL, TopBraid, the EC ITB validator).
- **Storage.** Document stores that serve JSON-LD, triplestores with SPARQL, or LDP and Solid pods.

#### End-to-end flow

1. The operator mints a product IRI, for example a GS1 Digital Link URI, and prints it in a QR code.
2. The operator publishes a JSON-LD document. Its `@id` is that IRI, and its `@context` names versioned contexts.
3. The client decodes the QR code and sends GET with `Accept: application/ld+json`.
4. Or a GS1-conformant resolver returns a linkset, and the client follows the `gs1:dpp` or default link.
5. The server answers `200` with JSON-LD, or `303` to a data document, or JSON with a context `Link` header.
6. The client loads each context through a document loader, ideally from a local pinned copy.
7. The client expands the document and converts it to RDF.
8. A validator checks the graph against pinned SHACL shapes and records each result and focus node count.
9. If a Data Integrity proof is present, the verifier checks it with pinned contexts and RDFC-1.0 canonical N-Quads.
10. A person who asks for `text/html` at the same IRI gets a web page.

For a deterministic run, the engine pins shapes, ontologies, context files, processor versions, and the inference mode. A frozen document loader serves only pinned contexts and refuses all others.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Each node has an absolute IRI or is a blank node. CIRPASS-2 links a product node to a separate passport node. SAMM elements use URNs. | `@id` values, absolute or relative, subject against carrier URI, blank node count after expansion. |
| L02 data carriers | The family defines no carrier. The QR code holds an HTTP(S) URI. No source put RDF in the carrier. | The decoded payload and whether it equals the graph subject. |
| L03 data exchange protocols | HTTP GET with content negotiation (`application/ld+json`, `text/turtle`, `text/html`). A JSON response can carry its context in a `Link` header. | Status codes, the redirect chain with `303`, `Content-Type` with profile, `Link` and `Vary` headers, linkset entries. |
| L04 APIs for lifecycle and search | Read is GET. LDP 1.0 and Solid define POST, PUT, and PATCH with `ETag` and `If-Match`. Project services use plain REST APIs. | `Allow`, `Accept-Post`, `Accept-Patch`, `ETag`, `412` and `428` on write. Write tests need separate authorization. |
| L05 interoperability and data models | JSON-LD expansion to RDF, then SHACL Core validation. Keys without an IRI mapping produce no triple and no error. | The expanded graph, the SHACL report, focus nodes per shape, literal datatypes, and dropped keys. |
| L06 storage and persistence | Document stores, triplestores with named graphs, or pods. Contexts and vocabularies must stay resolvable for the passport lifetime. | Whether the passport and each context stay retrievable; `ETag` stability; old version IRIs. |
| L07 access rights and security | Solid uses Solid-OIDC with WAC or ACP. CIRPASS-2 view shapes set `sh:maxCount 0` on withheld paths for each tier. | The graph for each role, restricted predicates on any path, and the view report for each role. |
| L08 authentication and integrity | Integrity attaches to the graph. RDFC-1.0 gives canonical N-Quads. VC Data Integrity suites use RDFC-1.0 or JCS. | Proof type and cryptosuite, the verification result with pinned contexts, a hash of canonical N-Quads. |
| L09 registry and customs | The EU registry checks semantic conformity at registration. The act names no serialization. | Only the registry interface. A tester can pre-check against repository models once they exist. |
| L10 lifecycle and versions | Versions of vocabularies, contexts, and passports. CIRPASS-2 uses `dpp:dppSchemaVersion`, `dpp:dppStatus`, and a previous passport link. | The schema version, the context URL version, the status value, and the previous passport link. |
| L11 roles and governance | The owner of a vocabulary or context controls its meaning. Licenses differ per vocabulary. | Hosts of referenced contexts, version policy, and license statements in vocabulary files. |

#### Variants

- Product IRI equals the GS1 Digital Link URI, or the operator domain holds the IRI and the carrier holds the GS1 URI.
- Product node and passport node are separate (CIRPASS-2 pattern), or a blank-node passport holds identifier literals only.
- JSON-LD with a project ontology, with the GS1 Web Vocabulary and schema.org, or a UNTP credential subject with a protected context.
- Turtle-native knowledge graph with a SPARQL endpoint.
- SAMM model with plain JSON payloads. The payload links to the model only by a URN such as `x-samm-aspect-model-urn`.
- LinkML single source that generates JSON Schema, OWL, and SHACL.
- OWL with reasoning, or SHACL closed-world checks without inference.
- Transport: direct JSON-LD, `303` to a data document, a resolver linkset, embedded JSON-LD in HTML, or a Solid pod resource.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| JSON-LD 1.1 | REC 2020-07-16 | W3C Recommendation | [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/) |
| JSON-LD 1.1 Processing Algorithms and API | REC 2020-07-16 | W3C Recommendation | [JSON-LD API](https://www.w3.org/TR/json-ld11-api/) |
| RDF Dataset Canonicalization | RDFC-1.0, REC 2024-05-21 | W3C Recommendation | [RDF canon](https://www.w3.org/TR/rdf-canon/) |
| RDF 1.2 Concepts | CR 2026-04-07 | Candidate Recommendation Snapshot; RDF 1.1 stays the latest Recommendation | [RDF 1.2](https://www.w3.org/TR/rdf12-concepts/) |
| SHACL | REC 2017-07-20 | W3C Recommendation | [SHACL](https://www.w3.org/TR/shacl/) |
| SHACL 1.2 Core | WD 2026-10-14 | Working Draft | [SHACL 1.2](https://www.w3.org/TR/shacl12-core/) |
| OWL 2 (Second Edition) | REC 2012-12-11 | W3C Recommendation | [OWL 2](https://www.w3.org/TR/owl2-overview/) |
| Linked Data Platform | 1.0, REC 2015-02-26 | W3C Recommendation | [LDP](https://www.w3.org/TR/ldp/) |
| DCAT | Version 3, REC 2024-08-22 | W3C Recommendation | [DCAT 3](https://www.w3.org/TR/vocab-dcat-3/) |
| Content Negotiation by Profile | WD 2026-09-21 | Working Draft | [Profile negotiation](https://www.w3.org/TR/dx-prof-conneg/) |
| Linked Web Storage Protocol | 1.0, WD 2026-10-16 | Working Draft | [LWS](https://www.w3.org/TR/lws10-core/) |
| Solid Protocol | 0.11.0 | Draft Community Group Report; not on the W3C standards track | [Solid](https://solidproject.org/TR/protocol) |
| VC Data Integrity | 1.0, REC 2025-05-15 | W3C Recommendation | [Data Integrity](https://www.w3.org/TR/vc-data-integrity/) |
| CIRPASS-2 EU DPP CORE ontology | 2.0.7 (nine modules) | Project draft; documentation generated 2026-10-12 | [ontologies-docs](https://github.com/CIRPASS-2/ontologies-docs) |
| CIRPASS-2 battery ontology | 0.4.0 DRAFT | Draft; README says it is not an official ontology | [ontologies-battery](https://github.com/CIRPASS-2/ontologies-battery) |
| GS1 Web Vocabulary | 1.18.0 (`ref.gs1.org`, 2026-06-01) | Current; pin 1.18.0. The GitHub mirror stops at 1.16 and is not current. | [WebVoc mirror](https://github.com/gs1/WebVoc) |
| GS1-Conformant Resolver | 1.2.1 | Ratified Aug 2026; fixes no redirect status code | [Resolver standard](https://ref.gs1.org/standards/resolver/) |
| schema.org | 30.1 (2026-09-16) | Released | [Releases](https://schema.org/docs/releases.html) |
| UNTP vocabulary and context | 0.7.0 | Pilot release; WIP text is not normative | [UNTP context](https://vocabulary.uncefact.org/untp/0.7.0/context/) |
| Eclipse SAMM meta model | 2.2.0 (2025-03-11) | Released; 2.3.0 folders on main are unreleased | [SAMM](https://github.com/eclipse-esmf/esmf-semantic-aspect-meta-model) |
| Eclipse ESMF SDK (`samm-cli`) | 2.16.1 (2026-10-19) | Released | [ESMF SDK](https://github.com/eclipse-esmf/esmf-sdk) |
| Battery Pass Data Model | 1.2.0 (SAMM 2.1.0) | Draft per its authors; no maintenance since April 2025 | [BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel) |
| DCAT-AP | 3.0.1 (2026-06-04) | Released; ships SHACL shapes and a JSON-LD context | [DCAT-AP](https://github.com/SEMICeu/DCAT-AP) |
| CE-RISE product-profile model | 0.2.0 (2026-08-31) | Project model in LinkML | [CE-RISE](https://github.com/CE-RISE-software) |

The `ref.gs1.org` link-type file has no version marker. An engine must therefore store the digest of the file that it fetched. `gs1:dpp` is a stable link type.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [CIRPASS-2 ontologies-docs](https://github.com/CIRPASS-2/ontologies-docs) | Ontology | Apache-2.0 | Pushed 2026-10-15 |
| [CIRPASS-2 ontologies-battery](https://github.com/CIRPASS-2/ontologies-battery) | Ontology, shapes, tests | Apache-2.0 | Pushed 2026-10-06 |
| [CIRPASS-2 ontologies-tyre](https://github.com/CIRPASS-2/ontologies-tyre) | Ontology | Apache-2.0 | Pushed 2026-10-13 |
| [CIRPASS-2 ontologie-textiles](https://github.com/CIRPASS-2/ontologie-textiles) | Ontology | No license detected | Pushed 2026-09-28 |
| [CIRPASS-2 dpp-validator](https://github.com/CIRPASS-2/dpp-validator) | Validator | Apache-2.0 | Pushed 2026-08-04 |
| [CIRPASS-2 dpp-data-extractor](https://github.com/CIRPASS-2/dpp-data-extractor) | Search key extractor | Apache-2.0 | Pushed 2026-08-04 |
| [GS1 Web Vocabulary](https://github.com/gs1/WebVoc) | Ontology | Apache-2.0 | Pushed 2026-01-29 |
| [Battery Pass Data Model](https://github.com/batterypass/BatteryPassDataModel) | Data model (SAMM) | CC-BY-4.0 per README; none detected by the GitHub API | Pushed 2026-09-14 |
| [Eclipse SAMM](https://github.com/eclipse-esmf/esmf-semantic-aspect-meta-model) | Meta model | MPL-2.0 | Pushed 2026-10-09 |
| [Eclipse ESMF SDK](https://github.com/eclipse-esmf/esmf-sdk) | SDK | MPL-2.0 | Release 2.16.1, 2026-10-19 |
| [Tractus-X semantic models](https://github.com/eclipse-tractusx/sldt-semantic-models) | Data model (SAMM) | CC-BY-4.0 | Pushed 2026-09-25 |
| [pySHACL](https://github.com/RDFLib/pySHACL) | Validator | Apache-2.0 | Release 0.40.1, 2026-07-28 |
| [rdflib](https://github.com/RDFLib/rdflib) | SDK | BSD-3-Clause | Pushed 2026-10-16; release 7.6.0 |
| [PyLD](https://github.com/digitalbazaar/pyld) | SDK | BSD-3-Clause | Release 3.3.0, 2026-09-02 |
| [jsonld.js](https://github.com/digitalbazaar/jsonld.js) | SDK | BSD-3-Clause per npm; NOASSERTION per GitHub | Pushed 2026-03-04; npm 9.0.0 |
| [Titanium JSON-LD](https://github.com/filip26/titanium-json-ld) | SDK | Apache-2.0 | Release 1.7.0, 2025-10-05; pushed 2026-07-27 |
| [Apache Jena SHACL](https://jena.apache.org/documentation/shacl/) | Validator | Apache-2.0 | Repository pushed 2026-10-19 |
| [TopBraid SHACL API](https://github.com/TopQuadrant/shacl) | Validator | Apache-2.0 | Release 1.5.0, 2026-03-23; pushed 2026-06-30 |
| [EC ITB SHACL validator](https://github.com/ISAITB/shacl-validator) | Validator | EUPL-1.2 | Release 1.13.0, 2026-09-25 |
| [CE-RISE hex-core-service](https://github.com/CE-RISE-software/hex-core-service) | Server | NOASSERTION; models CC BY-NC 4.0 | Pushed 2026-03-27 |
| [CE-RISE dp-assessment-workbench](https://github.com/CE-RISE-software/dp-assessment-workbench) | Model validator | EUPL-1.2 | Pushed 2026-04-27 |
| [DCAT-AP](https://github.com/SEMICeu/DCAT-AP) | Data model | CC-BY-4.0 | Release 3.0.1, 2026-06-04 |
| [LiUSemWeb DPPO](https://github.com/LiUSemWeb/DPPO) | Ontology with shapes | No license detected | Pushed 2026-06-30 |
| [openepcis-dpp-ready](https://github.com/openepcis/openepcis-dpp-ready) | Vocabulary (preview) | Apache-2.0 | Pushed 2026-10-11 |
| [tests-untp](https://github.com/uncefact/tests-untp) | Test suite | GPL-3.0 | Pushed 2026-10-05 |

- The CIRPASS-2 test script calls pySHACL with `inference='none'` and `advanced=True`. The engine can reuse this pattern.
- `tests-untp` is GPL-3.0. The engine can use it as an external oracle, but it must not copy its code.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no RDF, JSON-LD, OWL, SHACL, protocol, or media type.
- Regulation (EU) 2024/1781, Art. 10(1)(d) requires open standards and machine-readable, structured, searchable data without vendor lock-in. Linked data is one way to meet these properties.
- Art. 11(a) and Regulation (EU) 2023/1542, Art. 78(a) require technical, semantic, and organizational interoperability. They name no ontology.
- Implementing Regulation (EU) 2026/1778, Art. 11 requires common, versioned data models in the Commission semantic repository. Art. 12 adds DCAT-AP metadata and typed, resolvable links.
- Art. 2(12) defines semantic conformity as completeness, structure, format, value type, vocabulary, and interpretation through the repository. Art. 8(7) makes the registry check it.
- The repository models were not located. A project ontology can conform to its own shapes and still fail the repository model.
- The registry user guide says passport data follows pre-defined XML or JSON schemas. This guide is non-binding.
- Art. 11(d) links a new passport to the original. The CIRPASS-2 previous passport link is one graph form of this link.
- Battery access tiers come from Annex XIII. The public gets point 1, and notified bodies and market surveillance authorities get point 3.
- The Commission gets points 1, 2, and 3. Persons with a legitimate interest get points 2 and 4. SHACL view shapes are a project choice.
- Context hosts, vocabulary versions, and vocabulary licenses are extra dependencies of this family. The law does not address them.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L05 | An unversioned remote context changes, so the same JSON now gives another graph. | Allow only exact versioned context URLs, and compare with digest-pinned local copies. |
| L05 | A key is misspelled or not in the context. Expansion drops it, but JSON Schema still passes. | Compare JSON keys with expanded properties. A SHACL `sh:minCount` fails on the absent path. |
| L05 | A fractional value is a JSON number, so it becomes `xsd:double` and fails a decimal shape. | Report datatypes after RDF conversion; SHACL `sh:datatype` violations. |
| L05 | A namespace variant (`gs1.org/voc` for `ref.gs1.org/voc`) means no focus node, so the report conforms. | Count focus nodes for each mandatory shape; check terms against pinned vocabularies. |
| L05 | A document redefines a protected term, and a lax consumer accepts another meaning. | A conformant processor reports `protected term redefinition`. |
| L05 | Results differ between runs because inference, `owl:imports`, or processor versions differ. | Pin versions and options in the evidence record, and compare the canonical report on replay. |
| L03 | The server ignores `Accept` and returns HTML, or returns JSON without a context `Link` header. | Check `Content-Type` and `Link` headers on recorded responses for each `Accept` value. |
| L03 | JSON-LD and Turtle forms of the same IRI drift apart. | Compare the two graphs as RDFC-1.0 canonical N-Quads. |
| L01 | The passport uses a relative `@id` or a blank node, so the subject differs from the carrier URI. | Check that subjects are absolute after expansion, and compare them with the carrier. |
| L07 | A restricted attribute leaks into the public view under a nested path or an equivalent property. | Validate the public graph against public view shapes with `sh:maxCount 0` on restricted paths. |
| L08 | A context host changes a context, so a Data Integrity proof fails, or passes on the changed context. | Verify with pinned contexts only, and record the context digests. |
| L08 | Producer and verifier use different canonicalization algorithms, so a hash fails on unchanged data. | Recompute with RDFC-1.0 named explicitly. PyLD 3.3.0 defaults to the legacy URGNA2012. |
| L10 | The schema version label, the context URL version, and the shape version disagree. | Compare the three values across the recorded passport versions. |
| L09 | The passport conforms to a project ontology but not to the applicable repository model. | Pre-check against a pinned snapshot of the repository model once it exists. |
| L06 | A vocabulary or context host disappears during the passport lifetime. | Acquire referenced contexts on a schedule and record status codes. |
| L05 | A SPARQL endpoint uses another graph scope than the published document. | Validate the published document, and compare its canonical N-Quads with a recorded endpoint result. |
| L11 | The passport embeds licensed dictionary content beyond its license terms. | Manual review only; no automatic decision. |

#### What the engine can test

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Each `@context` reference is on a pinned allowlist, with no inline context. | `data.context` (correct): nested contexts count; inline contexts fail. | `data.context_sources` for `@import` | Allowed, unknown, inline, scoped, and `@import` contexts; [JSON-LD API tests](https://github.com/w3c/json-ld-api/tree/main/tests) | sample artifact |
| A JSON response names one allowlisted context in a `Link` header. | None (correct): redaction removes the context `Link` value from the record. | `data.context_sources` | Recorded responses with zero, one, and two context headers | loopback only |
| The document expands with pinned contexts only, without errors. | None (correct): no JSON-LD processor exists. | `data.jsonld` | Pinned contexts with digests; W3C expand and toRdf manifests | sample artifact |
| No JSON key drops out during expansion. | None (correct) | `data.jsonld` | Key typos, keys outside the context, with and without `@vocab` | sample artifact |
| The graph conforms to the pinned shapes of the product group. | None (correct): `data.shacl` is interface only. | `data.shacl` | CIRPASS-2 battery examples and mutations, after an owner decision on rule 5 (section 9.4); [W3C SHACL tests](https://github.com/w3c/data-shapes) | sample artifact |
| Each mandatory shape selects at least one focus node. | None (correct) | `data.shacl` (focus node coverage) | Namespace variant document; document with no type | sample artifact |
| Numbers keep the expected datatype (decimal, double, integer). | `data.rules` (wrong): no type rule. `data.jsonschema` gives a partial JSON-side check. | `data.shacl` (datatype fidelity) | One value as number, typed string, and coerced term | sample artifact |
| Each class and property is defined in pinned vocabularies. | None (correct) | `data.jsonld` (vocabulary terms) | Pinned vocabulary snapshots with digests; invented terms | sample artifact |
| Units come from a pinned unit list. | `data.rules` (correct): a unit rule; fields in arrays are not addressable. | None (rule pack) | Pinned unit list; symbol-only and wrong units | sample artifact |
| JSON-LD, Turtle, and HTML forms describe the same graph. | `identifier.resolve` (correct): `Accept` parameter only. | `data.jsonld` (RDFC-1.0 with a work limit) | Equal and unequal pairs; [RDF canon tests](https://github.com/w3c/rdf-canon/tree/main/tests) | loopback only |
| The subject IRI is absolute and equals the carrier identifier. | `identifier.consistency` (correct): reads the key `id` only. | `identifier.subject_pointer` | Passports with `id`, `@id`, relative `@id`, and a blank node | loopback only |
| The resolver linkset holds a passport link of the expected type. | `identifier.resolve` (correct): partial, media type only. | `resolver.linkset` | Recorded linksets with and without `gs1:dpp` | loopback only |
| Each role view carries its data and none of the withheld data. | `access.restricted_fields` (correct): JSON paths per role only. | `data.shacl` (view mode) | Canary graphs per tier; CIRPASS-2 `tests/run_tests.py` pattern | loopback only |
| A Data Integrity proof verifies with pinned contexts. | None (correct): JOSE with ES256 only. | `integrity.data_integrity` | `TEST-ONLY` keys; signed samples; one sample after a context change | sample artifact |
| Schema, context, and shape versions agree across passport versions. | `persistence.versions` (wrong): reads none of these versions. | Not named in x01; a version cross-check is needed | Version histories with a silent context change | loopback only |
| The passport conforms to the Commission repository model. | `registry.consistency` (wrong): compares identifier fields only. | `data.repository_model` | Repository model snapshot once published | sample artifact |
| SHACL and JSON Schema results agree on shared fixtures. | `data.jsonschema` (correct) | `data.shacl` (differential runner) | Agreeing and diverging fixtures; [EC ITB validator](https://github.com/ISAITB/shacl-validator) | sample artifact |
| Contexts and vocabularies have persistent, versioned hosts and a license. | `data.context` (correct): allowlist only. | None; a `manual.review` step | Allowlist entries with host, version, and license | sample artifact |
| Each version graph conforms to its declared model, and the previous link resolves. | `persistence.versions` (overstated): fetches no earlier version. | `data.shacl` (per-version mode); `lifecycle.links` | Two-version history with a model change and a broken link | loopback only |

The engine today covers only the context allowlist. `data.jsonld` and `data.shacl` need a JSON-LD processor and an RDF library, and neither is installed. Rule 10 requires a report before the engine adds them. The parser must not fetch contexts from the network.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m08-linked-data-semantic.json`. Engine verdicts are in `x01-engine-mapping.json`, and extra repositories are in `r01-repositories.json`.
- The independent check (`m08-linked-data-semantic.verification.json`) checked 32 claims: 30 confirmed, 0 refuted, and 2 not confirmed. It had no rule 5 findings.
- Corrections: the textiles repository is `CIRPASS-2/ontologie-textiles`, and TopBraid had release 1.5.0 on 2026-03-23 and a push on 2026-06-30.
- The check also found that GS1 resolver 1.2.1 returns `404` for an absent link type. Law statements here come from the legal baseline file, not from the family file.
- Open: the format and location of the Commission semantic repository, the UNTP license, and vocabulary reuse terms. No processor or validator was run, so no behavior statement is a test result.

### 5.8 Distributed-ledger family

In this family, a distributed ledger holds a small trust anchor for a passport. The anchor is a digest, a pointer, or both. In almost all designs, the passport document itself stays off chain at the operator or at a storage service. The ledger adds an order, a block time, and tamper evidence for the anchor.

Designs use permissioned ledgers (Hyperledger Fabric, Besu), public chains (Ethereum and other EVM chains), IOTA, and the EBSI Timestamp and Track and Trace services. The evidence is mostly prototypes, pilots, and vendor statements. The family file located no production ledger passport for a product group that an ESPR delegated act regulates.

#### Components

- **Anchor.** A hash of the passport in a ledger transaction or in contract state. Examples: an EBSI timestamp, an Arianee `bytes32` imprint, a Fabric private-data hash.
- **Off-chain passport.** A JSON or JSON-LD document at an HTTPS host, or bytes that an IPFS content identifier (CID) addresses.
- **Token per product.** An ERC-721 or ERC-1155 token. Its `tokenURI` or `uri(id)` points to metadata JSON.
- **Smart contract or service API.** It runs the lifecycle: create, update, transfer, and destroy or deactivate.
- **Ledger identifiers.** CAIP-2 chain ids, contract addresses, token ids, DIDs such as `did:iota` and `did:ebsi`, and CIDs.
- **On-ledger permission model.** Issuer-only updates, allow-listed creator DIDs, per-document write and delegate rights, or authority hierarchies.
- **Portable inclusion proof.** An OpenTimestamps `.ots` receipt, an IOTA Proof of Inclusion, or an EIP-1186 Merkle proof.
- **Trust root.** Pinned block headers, a state root, or a committee from a trusted genesis blob.

#### End-to-end flow

This flow shows a hash-anchored passport. The token and CID variants follow the same verification logic.

1. A reader decodes the carrier and gets an HTTPS URL, often a GS1 Digital Link.
2. The URL resolves to the passport, or to a page that names the ledger reference.
3. The client fetches the passport bytes from the operator host or from an IPFS gateway.
4. The passport or its metadata names the anchor: chain id, transaction or record id, and algorithm.
5. The verifier recomputes the digest under the declared algorithm and canonicalization.
6. The verifier compares the digest with the anchored value.
7. For a CID, the verifier checks that each received block hashes to the CID multihash.
8. The verifier checks that the anchor is in a block or checkpoint of the declared chain.
9. Offline, it walks an inclusion proof to a trust root that the test pack pins.
10. Online, it reads the receipt status and compares the block with the `finalized` tag.
11. The verifier checks that the anchor author is the declared operator or an allow-listed DID.
12. The verifier reports digest match, path validity, and root trust as separate findings.

Current state, such as the latest `tokenURI`, the owner, or a revocation flag, needs a live ledger read. An offline check reports such items as not run.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Ledger identifiers add to the product identifier and do not replace it. Kinds: CAIP-2 chain id plus contract plus token id, DIDs, CIDs, and hash-derived EBSI ids. | Syntax of each reference without a node. Agreement of the carrier id, the passport id, and the ledger reference. |
| L02 data carriers | The ledger does not change the carrier. Most carriers hold an HTTPS URL. Some prototypes put a token id, a DID, or a wallet link in the QR code. | The decoded payload: an HTTPS URL or a bare ledger reference. |
| L03 data exchange protocols | Ethereum JSON-RPC 2.0 over HTTP POST, EBSI REST reads, IPFS trustless gateway reads, IOTA gRPC, and Fabric Gateway. | Operator API answers. JSON-RPC receipts and logs. Whether gateway bytes hash to the CID. Each direct ledger read is a live call. |
| L04 APIs for lifecycle and search | Lifecycle maps to contract or service calls: mint, `hydrateToken`, `updateTokenURI`, burn, and EBSI record versions. Search is event-log filters. | Operator API answers. Live only: events, view results, and `supportsInterface` answers. |
| L05 interoperability and data models | On-chain state is minimal. Off-chain metadata follows the ERC-721 or ERC-1155 metadata JSON. Passport content is free-form JSON in most prototypes. | Schema validity of the off-chain JSON. On-chain record shape against a contract ABI or a captured response. |
| L06 storage and persistence | Full data on chain, a hash on chain with an off-chain document, CID storage, Fabric private data, or a hybrid. The ledger keeps the anchor durable, not the document. | Whether the document is retrievable now and matches the anchor. One run proves no lifetime. |
| L07 access rights and security | Restricted data off chain, permissioned channels, private collections, on-ledger permissions, and zero-knowledge proofs. | Restricted fields or personal data in calldata, events, or public metadata. Unsalted hashes of low-entropy fields. |
| L08 authentication and integrity | Digest of the passport, anchor in a block, author key, and optional portable inclusion proof to a pinned root. | Offline: digest match, Merkle path, and root trust. Live only: inclusion on the current chain and finality. |
| L09 registry and customs | A ledger does not replace the EU registry of unique identifiers. No source read links EBSI to that registry. | Agreement between the registry record and the passport id. The engine compares against a mock registry only. |
| L10 lifecycle and versions | Append-only versions in EBSI records and IOTA audit trails. A mutable `tokenURI` in ERC-721. Burn, destroy, revocation, or DID deactivation at end of life. | Version order, a hash per version, update events, and passport availability after deactivation. |
| L11 roles and governance | Consortium ledgers, public chains, EBSI with Proof of Authority, and IOTA authority hierarchies. | Chain id in use, and issuer DIDs against a pinned registry snapshot. Governance shows in documents and ICS answers. |

Notes on the mechanisms:

- IPFS trustless gateway: support of `application/vnd.ipld.raw` is mandatory. The specification recommends support of `application/vnd.ipld.car`.
- The `format` query parameter SHOULD take precedence over `Accept`. A test oracle must not fail a gateway that honors `Accept` first.
- EBSI Timestamp: the `timestampId` is the multibase base64url (prefix `u`) form of a multihash of the SHA-256 of the anchored hash.
- The EBSI guide shows the stored `hash` field with prefix `m` in its response example. The multihash header bytes `0x12 0x20` are an inference, not a page statement.
- ERC-4906: a contract MUST emit `MetadataUpdate` or `BatchMetadataUpdate` when the JSON metadata changes. A new URI with the same JSON needs no event.
- Fabric private data: a non-member can read the hash through `GetPrivateDataHash`. The Fabric private data page says that purged data leaves a hash as evidence.
- EBSI Track and Trace: `HEAD /v1/track-and-trace/accesses?creator={did}` returns `204` when the DID may create documents and `404` when it may not.

#### Variants

- Storage: full data on chain (rare, costly), hash imprint with an off-chain document, CID with a pin service, private data collections, or a hybrid.
- Item identity: a chain-qualified token reference, a product DID, or a GS1 or vendor serial mapped to a token id.
- Anchor form: one hash per document, a Merkle root over a batch, a token imprint, or a CID as pointer and check.
- Inclusion evidence: a live node read, an OpenTimestamps receipt to a Bitcoin block header, or an IOTA Proof of Inclusion.
- One IOTA proof covers targets from one transaction only, so it does not serve batch anchors.
- Lifecycle: token transfer as custody handover, append-only record versions, documents with events, or chaincode records.
- Governance: consortium, public permissionless, public permissioned (EBSI), or a federated hierarchy on IOTA.
- Credentials: verifiable credentials with issuer DIDs on EBSI, as in the TRACE4EU battery pilot. Section 5.5 covers the credential mechanics.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| ERC-721 Non-Fungible Token Standard | EIP-721, created 2018-01-24 | Final | [ERC-721](https://eips.ethereum.org/EIPS/eip-721) |
| ERC-1155 Multi Token Standard | EIP-1155, created 2018-06-17 | Final | [ERC-1155](https://eips.ethereum.org/EIPS/eip-1155) |
| ERC-4906 Metadata Update Extension | EIP-4906, created 2022-03-13 | Final | [ERC-4906](https://eips.ethereum.org/EIPS/eip-4906) |
| EIP-1186 `eth_getProof` | Created 2018-06-24 | Stagnant | [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) |
| Ethereum execution-apis (JSON-RPC) | v1.0.0-beta.7 (2026-06-10) | Beta; it still defines `eth_getProof` | [execution-apis](https://github.com/ethereum/execution-apis) |
| CAIP-2 Blockchain ID | Created 2019-12-05 | Final | [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md) |
| IPFS CID specification | Page of 2026-06-26 | Permanent | [CID spec](https://specs.ipfs.tech/cid/) |
| IPFS Trustless Gateway | Updated 2026-03-05 | Status badge "reliable" | [Trustless gateway](https://specs.ipfs.tech/http-gateways/trustless-gateway/) |
| W3C Decentralized Identifiers | v1.1 | Candidate Recommendation Snapshot 2026-03-05 | [DID 1.1](https://www.w3.org/TR/did-1.1/) |
| IOTA DID Method | v2.0 (page of 2024-08-23) | Published in IOTA documentation | [did:iota](https://docs.iota.org/developer/iota-identity/references/iota-did-method-spec) |
| IOTA Notarization Toolkit | v0.1.27; `poi-v0.1.0` (2026-09-24) | Pre-1.0 | [notarization](https://github.com/iotaledger/notarization) |
| EBSI Timestamp documentation | Pages of 2026-09-30; paths under `/v1/timestamp/` | Version labels conflict (pilot v3, test v5) | [EBSI Timestamp](https://hub.ebsi.eu/docs/use-cases/anchoring/timestamp/timestamp-introduction) |
| EBSI Track and Trace documentation | Guide of 2026-10-01; paths under `/v1/track-and-trace/` | Labels and scopes conflict with a pilot excerpt | [EBSI Track and Trace](https://hub.ebsi.eu/docs/use-cases/anchoring/track-and-trace/create-tnt-doc) |
| `did:ebsi` method | Page of 2026-09-30 | No version on the page | [did:ebsi](https://hub.ebsi.eu/vc-framework/did/legal-entities) |
| EDPB Guidelines 02/2025 on blockchain | v2 (2026-07-07) | Final after consultation | [EDPB 02/2025](https://www.edpb.europa.eu/documents/guideline/guidelines-022025-on-processing-of-personal-data-through-blockchain_en) |
| Implementing Regulation (EU) 2025/2531 | Adopted 2025-12-16 | OJ of 2025-12-17; qualified electronic ledgers | [OJ text](https://publications.europa.eu/resource/cellar/cbd048d0-daeb-11f0-8da2-01aa75ed71a1.0006.03/DOC_1) |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified Aug 2026 | [GS1 Digital Link](https://ref.gs1.org/standards/digital-link/uri-syntax/) |

Annex point 3(b) of Implementing Regulation (EU) 2025/2531 names ISO 23257:2022 and ISO/TS 23635:2022. Annex point 3(a) names ETSI EN 319 401 V3.1.1. This page names these documents by number only. No DPP-specific ledger specification exists in EU law or in an open specification that the family file read.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [IOTA Notarization Toolkit](https://github.com/iotaledger/notarization) | SDK; offline Proof of Inclusion verifier | Apache-2.0 | Pushed 2026-09-24; release `poi-v0.1.0` |
| [IOTA DPP demonstrator](https://github.com/iotaledger/dpp-demonstrator) | Pilot; its README says it is not a regulation-compliant DPP | Apache-2.0 | Pushed 2026-03-10 |
| [IOTA Identity](https://github.com/iotaledger/identity) | SDK (`did:iota`) | Apache-2.0 | Pushed 2026-09-30 |
| [IOTA Hierarchies](https://github.com/iotaledger/hierarchies) | SDK (authority hierarchy) | Apache-2.0 | Pushed 2026-08-20 |
| [arianee-contracts](https://github.com/Arianee/arianee-contracts) | ERC-721 passport contracts | MIT | Pushed 2026-06-17 |
| [arianee-sdk](https://github.com/Arianee/arianee-sdk) | SDK | Not stated | Pushed 2026-10-17 |
| [opentimestamps-client](https://github.com/opentimestamps/opentimestamps-client) | Validator | Not stated (NOASSERTION) | Pushed 2026-02-07 |
| [python-opentimestamps](https://github.com/opentimestamps/python-opentimestamps) | Library | LGPL-3.0-or-later | Pushed 2025-03-18; tag v0.4.5 |
| [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver) | DID resolver | Apache-2.0 | Pushed 2026-10-19 |
| [execution-apis](https://github.com/ethereum/execution-apis) | JSON-RPC specification | CC0-1.0 | Pushed 2026-10-17 |
| [Hyperledger Fabric](https://github.com/hyperledger/fabric) | Permissioned ledger | Apache-2.0 | Pushed 2026-10-14; release v3.1.5 |
| [Hyperledger Besu](https://github.com/besu-eth/besu) | Ethereum client | Apache-2.0 | Pushed 2026-10-19; release 26.10.0 |
| [bsv-blockchain/dpp](https://github.com/bsv-blockchain/dpp) | Pre-1.0 draft, fixtures, conformance folder | Apache-2.0 | Pushed 2026-10-16 |
| [DigitalProductPassport/SmartContracts](https://github.com/DigitalProductPassport/SmartContracts) | Solidity passport contracts | MIT | Pushed 2026-10-16 |
| [NIGHTPASS](https://github.com/ODATANO/NIGHTPASS) | Demo battery passport app | None detected | Pushed 2026-09-20 |
| [eu-digital-product-passport](https://github.com/lambdasistemi/eu-digital-product-passport) | Cardano feasibility study | Not stated (NOASSERTION) | Pushed 2026-04-02 |
| [object-digital-passport/specifications](https://github.com/object-digital-passport/specifications) | Data model for art objects; outside DPP law | MIT | Pushed 2026-10-18 |

- The EBSI Timestamp and Track and Trace services are platforms with documentation only. The family file found no license and called no endpoint.
- Circularise and Minespider describe ledger passports in vendor or third-party text only. The family file treats these claims as secondary.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. It names no ledger, chain, or storage technology.
- Regulation (EU) 2024/1781, Art. 11(c), puts storage at the economic operator or at DPP service providers that act for it.
- Art. 10(4) adds a back-up copy through a DPP service provider. Whether ledger replication can serve as that copy is open.
- Ledger replication keeps the anchor, not the document. The passport stays available for the period of Art. 9(2)(i) and Art. 11(e).
- Art. 10(1)(a)-(c) asks for a persistent unique product identifier through the carrier. A token id, a contract address, or a DID is not that identifier.
- Art. 10(1)(d) asks for open standards and transfer without vendor lock-in. A passport that only a proprietary chain client can read is in tension with this.
- Art. 11(g) sets data authentication, reliability, and integrity as outcomes. A ledger anchor is one possible mechanism.
- An anchor proves that data did not change. It does not prove that the data were true when written.
- Art. 10(1)(e) bars customer personal data without explicit consent. Immutable public ledger data adds an erasure problem.
- Art. 11(d) links a new passport to the original one.
- A token burn or a DID deletion must not make the passport unavailable before the retention period ends.
- Art. 13 and Implementing Regulation (EU) 2026/1778 set the central registry. A ledger anchor does not replace the registration duty.
- The registry proof of registration carries a Commission time stamp, a hash, and a qualified electronic seal. The act names no hash algorithm.
- Implementing Regulation (EU) 2026/1778, Art. 4: legal persons get verified status with a qualified electronic seal or a qualified attestation.
- Identification at eID assurance level high is a route only for sole traders established in the Union.
- Regulation (EU) 2023/1542 has no back-up duty and no DPP service provider concept.
- Battery access tiers (Annex XIII): public gets point 1, notified bodies and market surveillance authorities point 3, and the Commission points 1, 2, and 3.
- Persons with a legitimate interest get points 2 and 4. Clear text on a public chain would expose data of points 2 to 4 to everyone.
- Outside the m01 baseline (family file; not verified against m01): eIDAS 2 gives qualified electronic ledgers a presumption of order and integrity.
- The independent check of the family file confirmed the eIDAS references Art. 45k and Art. 45l. An ordinary chain anchor gets no such presumption.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L08 | The anchor hash covers a non-canonical JSON form, so a re-served document no longer matches. | Recompute the digest on a reordered-key fixture under the declared canonicalization. |
| L08 | The receipt names no algorithm, or the multihash code does not match the digest length. | Parse the receipt and check the multihash code and length. |
| L08 | The receipt gives raw hex where the ledger stores a multibase multihash, or the reverse. | Decode the declared encoding. Report an encoding mismatch apart from a digest mismatch. |
| L08 | The receipt points to a reverted transaction (status `0x0`) or a re-orged block. | Read the receipt from a mock or live node and compare with the `finalized` tag. |
| L08 | An inclusion proof verifies against a root that the verifier never authenticated. | Require a pinned trust root. Report root trust as a separate finding. |
| L08 | A key that is not bound to the declared operator wrote the anchor. | Compare the sender key with a pinned DID document. |
| L08 | A deleted or deactivated issuer DID still shows as a live issuer. | Check a pinned DID document for the `deleted_did` flag or deactivation. |
| L01 | A CID fails decoding: wrong multibase, extra bytes at the end, or a reserved version. | Apply the IPFS CID decoding rules to the sample string. |
| L01 | The receipt gives a bare chain number or name, so the anchor is ambiguous. | Check the chain id against the CAIP-2 syntax. |
| L03 | Only a proprietary chain client or wallet can read the passport. | Resolve the carrier payload and look for a JSON passport over HTTPS. |
| L06 | No host or pin keeps the off-chain document (link rot). | Retrieval fails. Repeated checks over time need scheduled persistence checks. |
| L06 | A gateway returns bytes that do not hash to the requested CID. | Hash each block and compare with the CID multihash. |
| L07 | Restricted or personal data is in clear text in calldata, events, or public metadata. | Search captured payloads for canary values. |
| L07 | An unsalted hash of a low-entropy personal field sits on a public chain. | Run a dictionary test over the declared low-entropy fields. |
| L07 | After an erasure request, the off-chain endpoint still returns the record. | Probe a loopback system under test before and after the request. |
| L10 | Metadata changes without `MetadataUpdate`, although the contract claims ERC-4906. | Check captured logs and `supportsInterface(0x49064906)`. Remember that a URI change alone needs no event. |
| L10 | A burn or destroy makes the resolver drop the passport early, or show no status marker. | Resolve the passport after the deactivation on a loopback system under test. |
| L10 | A version is silently replaced, not appended. | Compare successive captures and the hash of each version. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json`, which checked the engine source at commit `b290791`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

The table uses the merged capability ids from x01. The family file used other names: `integrity.anchor_hash` and `storage.cid_verify` merge into `integrity.digest_binding`. `integrity.inclusion_proof` becomes `integrity.ledger_proof`. `ledger.events` and `ledger.contract_interface` merge into `ledger.read`.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| The anchored digest equals the digest of the passport bytes. | None (correct). | `integrity.digest_binding` | Match, one byte changed, reordered JSON, unknown algorithm, length mismatch. | sample artifact |
| The anchor is in a block or checkpoint that chains to a pinned trust root. | None (correct). | `integrity.ledger_proof` | Valid and tampered `.ots` files, IOTA proofs, EIP-1186 proofs, an unpinned root. poi-rs and python-opentimestamps as references. | sample artifact |
| The anchor transaction succeeded and is final. | None (correct): no ledger transport exists. | `ledger.read` | Loopback JSON-RPC mock: success, `0x0`, unknown, re-orged. | live system under test |
| Token metadata is valid against the token and passport schemas. | `data.jsonschema` (overstated): it reads only the HTTP item or model document. | `data.document_source` | Pinned ERC-721 and ERC-1155 metadata schemas; valid and invalid samples. | sample artifact |
| Bytes for a CID hash to that CID. | None (correct). | `integrity.digest_binding` | Raw blocks and CAR files for CIDv0 and CIDv1; truncated CAR; wrong block. | sample artifact |
| Ledger references are syntactically valid. | None (correct): a JSON Schema `pattern` gives partial cover. | `identifier.schemes` | Valid and malformed CIDs, CAIP-2 ids, `did:iota` and `did:ebsi` strings. | sample artifact |
| The carrier identifier and the ledger reference point to the same product. | `identifier.resolve`, `identifier.consistency` (overstated): neither reads a ledger reference. | `ledger.read` for the ledger side | Loopback resolver and passport host with a token reference. | loopback only |
| Versions are append-only and each version hash matches its document. | `persistence.versions` (correct): order within one observation only. | `integrity.digest_binding` for version hashes | Captured record with three versions; reordered and rewritten variants. | loopback only |
| A contract that claims ERC-4906 signals each metadata change. | None (correct). | `ledger.read` | Captured logs with and without the event. | sample artifact |
| After deactivation, the passport stays available with a clear status. | `identifier.resolve` (correct): availability only. | `lifecycle.status` | Loopback system under test that burns a token and keeps or drops the passport. | loopback only |
| No restricted field or personal data is in public on-chain payloads. | `access.restricted_fields` (correct): HTTP channels only. | `access.public_payload_leak` | Captured payloads with canaries; an unsalted low-entropy hash. | sample artifact |
| Off-chain restricted data obeys the access policy per role. | `access.restricted_fields` (correct). | None | Existing access fixtures plus a passport with a ledger reference. | loopback only |
| The passport names a back-up DPP service provider where the profile asks for it. | `data.rules` (correct): presence check. | None | Passport with and without the reference. | loopback only |
| The anchor author is the declared operator or its service provider. | None (correct). | `integrity.issuer_binding` | Pinned DID documents; keys that match and keys that do not; a deleted DID. | sample artifact |
| A qualified-ledger claim names a provider on an EU trusted list. | None (correct). | `trust.eu_trusted_list` | Pinned trusted-list snapshot with and without the service. | sample artifact |
| The mock registry identifier matches the passport identifier. | `registry.consistency` (correct). | None | Mock registry entries for ledger-anchored passports. | loopback only |
| A token contract declares the interfaces that it claims. | None (correct). | `ledger.read` | Captured `eth_call` answers from a local development chain. | live system under test |
| After erasure, off-chain personal data is gone and the anchor links to no person. | None (correct). | `persistence.erasure` | Loopback system under test with an erasure endpoint. | loopback only |
| An EBSI Track and Trace creator DID is allow-listed. | None (correct). | `integrity.issuer_binding` | Recorded `204` and `404` answers; a passport that names the creator DID. | loopback only |

- `identifier.consistency` can compare the document behind `tokenURI` only when the IXIT item template points to that document. It does not read a ledger.
- `persistence.versions` is experimental in [Capabilities](../reference/capabilities.md), not supported.
- `ledger.read` needs a transport-policy contract change. JSON-RPC uses POST, which needs an active scope today.
- Ethereum proofs and ABI selectors need keccak-256 and RLP. The standard library has neither, so a dependency needs a report first.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m06-dlt-anchored.json`. The engine verdicts are in `x01-engine-mapping.json`, and the extra repositories are in `r01-repositories.json`.
- The independent check (`m06-dlt-anchored.verification.json`) checked 32 claims: 26 confirmed, 2 refuted, and 4 not confirmed. It re-checked only 7 of 40 literature DOIs.
- Corrected here: the IPFS `format` precedence is SHOULD, the EBSI `u` prefix applies to `timestampId` only, and Annex point 3(b) names two ISO documents.
- Not confirmed and left out: the Data Act Art. 36 requirement list. The Fabric purge text now cites the private data page only.
- Open: ledger replication as the ESPR back-up copy, EBSI version labels, and ICS and IXIT fields for a chain-qualified anchor. The sources disagree on a Battery Pass ledger, so this page claims none.

### 5.9 Platforms, DPP service providers, and sector programs

In this family, a hosted or self-hosted platform stores passport data for an economic operator. The platform issues identifiers and data carriers and serves different views to different audiences. Data comes from ERP, PLM or PIM systems, supplier questionnaires, or lifecycle events, often as EPCIS 2.0. The family also covers the DPP service provider role in EU law and sector programs for batteries, textiles, electronics, tires, construction, toys and furniture.

Most platform facts in this section come from vendor pages. They are secondary sources: the family file did not test any platform, and this section does not rank vendors or recommend one. Vendor adoption figures are vendor claims, and the family file found no independent confirmation of them. A review of 225 studies finds most published work conceptual, with limited empirical validation (`10.1007/s43615-026-00927-x`, 2026).

#### Components

- **Passport store.** A database behind a REST API, in a vendor cloud or on customer premises.
- **Identifier and carrier service.** It builds GS1 Digital Link URLs or other identifiers and generates QR codes, sometimes in batches.
- **Resolver or redirect service.** It sends a scan of the printed URL to the passport view. Some platforms let the operator change the redirect after the label is printed.
- **Role-based views.** A public view and restricted views per audience, controlled by tokens, credentials or contract policies.
- **Integration layer.** Connectors to ERP, PLM and PIM systems, webhooks, bulk files, EPCIS 2.0 capture, and a registry client.
- **Optional trust layer.** W3C verifiable credentials with `did:web`, hash anchors on a ledger, or NFT tokens.
- **Optional dataspace connector.** In Catena-X, an Eclipse Dataspace Connector and a Digital Twin Registry carry the data.
- **Back-up provider.** An independent DPP service provider that holds the back-up copy that EU law requires for ESPR products.

The platforms below publish a technical approach. "Not stated" means that the vendor pages that the family file read give no such fact.

| Platform | Stated mechanisms (vendor pages) | Integrity mechanism |
| --- | --- | --- |
| Arianee Enterprise and Arianee Protocol | REST v2 with OpenAPI 3.0; GS1 Digital Link QR batches; EPCIS 2.0; OIDC and API keys | NFT tokens on EVM chains; token id format not stated |
| Circularise | GS1 Digital Link with GTIN and serial; field permissions per disclosure group; SAML single sign-on | Public chain and zero-knowledge proofs claimed; not stated on the pages read |
| Spherity VERA | `did:web` identifiers and verifiable credentials; registry and back-up services offered | Credential proofs with a `did:web` issuer key |
| EON Product Cloud | REST, webhooks, OAuth 2.0, JSON-LD; GS1 Digital Link plus its own format for non-GTIN products | Not stated |
| Digimarc | Beta EPCIS 2.0 API; GS1 Digital Link redirect | Hash of each event anchored to IOTA |
| Circulor | REST APIs; role-based visibility; QR carrier; Catena-X offer | Hyperledger Fabric; channel and data split not stated |
| Siemens, SAP | AAS-based models, Catena-X connectors, QR access | Not stated |
| Kezzler, atma.io, TrusTrace, Scantrust | GS1 identifiers, QR, EPCIS; RFID plus QR (atma.io); dynamic serialized QR (Scantrust) | Not stated |
| Cofinity-X | EDC-based dataspace service for Catena-X with a passport exchange module | Not stated |
| Minespider, Tilkal, Madaster, Protokol, iPoint | Few technical facts on the pages read | Not stated |

#### End-to-end flow

This flow combines vendor statements and law. No single platform documents every step.

1. The operator loads product data at model, batch or item level from ERP, PLM, PIM or supplier inputs.
2. The platform builds an identifier, for example `https://<domain>/01/<GTIN>[/10/<lot>][/21/<serial>]`.
3. The platform generates QR codes. A label supplier prints or encodes the carrier.
4. The operator makes a back-up copy available through an independent DPP service provider.
5. The operator registers the passport in the EU registry and receives a registration identifier.
6. A scan sends an HTTPS request to the printed URL. The resolver redirects or negotiates content.
7. The platform serves the public view. Restricted fields need a role token, a credential or a contract.
8. Authorized actors add events such as repair, resale or recycling.
9. A remanufactured product gets a new passport that links to the original.
10. If the operator stops, clients reach the back-up copy. The family file found no law that fixes the redirect design.

Variants of the flow replace steps 6 and 7. In Catena-X, the consumer negotiates a contract through its connector and pulls the passport submodel. In the Spherity write-up, a verifier resolves a `did:web` DID and checks the credential signature. In the Digimarc blueprint, a verifier app compares platform data with hashes on the IOTA ledger.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | GS1 Digital Link at model, batch or item level. Alternatives: `did:web` DIDs, Catena-X part ids, NFT token ids, EPC URNs, RFID memory ids. | Decoded carrier text, its scheme, and whether each granularity resolves to the expected passport. |
| L02 data carriers | QR codes on every platform read. Some use dynamic QR, RFID plus QR, NFC, or woven labels. | QR image and decoded text; the redirect chain behind the URL. RFID and NFC need a tag dump. |
| L03 data exchange protocols | GS1-conformant resolution, vendor REST with OAuth 2.0, EPCIS 2.0 capture and query, or dataspace contract negotiation. | Status code, `Location`, `Link` and `Content-Type` per `Accept` value; redirect hop count. |
| L04 APIs for lifecycle and search | Vendor REST with create, read, update, delete and event operations. BaSyx Go adds an AAS-based DPP API. | Public OpenAPI file, methods and status codes per path, pagination, and `DELETE` behavior. |
| L05 interoperability and data models | IDTA submodel templates, Catena-X SAMM aspect models, BatteryPass-Ready schemas, CIRPASS-2 ontologies, UNTP vocabularies, vendor schemas. | Media type, `@context` values, schema identifiers and versions, field names and units. |
| L06 storage and persistence | Vendor cloud, self-hosted open source, or data kept at the manufacturer with hashes on a ledger. | Declared back-up location, version history, archive status, and the stated retention period. |
| L07 access rights and security | Field permissions per audience, OAuth 2.0 or OIDC scopes, credential-gated fields, or connector policies. | Fields per role on each channel; `401` or `403` behavior; whether the consumer view needs a login. |
| L08 authentication and integrity | Signed credentials, ledger hash anchors, permissioned chains, NFTs, or audit logs only. Many vendor pages state no mechanism. | Proof type, issuer key location, verification result, status check, and changes without a new signature. |
| L09 registry and customs | Registration through the registry website or API by the verified operator. | Registration identifier and back-up link in the passport; agreement with a mock registry record. |
| L10 lifecycle and versions | Event logs, signed version manifests, links to previous passports, and ownership transfer. | Version list, previous and next links, status values, and reads after deactivation. |
| L11 roles and governance | Operator, primary host and back-up provider; dataspace operating companies with private certification. | Provider reference in the passport. Provider certificates and contracts need manual review. |

#### Variants

- **Operator self-hosts** and uses a provider only for the back-up copy.
- **Provider hosts** and serves the passport for the operator.
- **One-stop provider** subcontracts carriers, identifiers and the back-up.
- **Dataspace variant.** A Catena-X operating company onboards members, and certified apps exchange passports through connectors.
- **Sector data service.** A sector organization acts as provider, as the tire industry proposes (search excerpt).

Sector programs show which variants appear where. The CIRPASS-2 project runs 13 lighthouse pilots in textiles, electronics, tires and construction. Textile and construction pilots use QR codes with GS1 identifiers. The tire pilot page cites an ISO tire identification standard for RFID tags, but it does not give the number.

The independent check confirmed that the Trace4Value textile pilot put garments with a passport on the market in January 2024. Electronics pilots use federated platforms or a blockchain; most of their technical details are "not stated". Battery programs use AAS submodels or Catena-X aspect models. The Cir4Fun furniture program plans a furniture dataspace, but its home page states no data model.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified August 2026; current | [GS1 Digital Link](https://ref.gs1.org/standards/digital-link/uri-syntax/) |
| GS1-Conformant Resolver | 1.2.1 | Ratified August 2026; current. The day of ratification is unsettled. | [GS1 Resolver](https://ref.gs1.org/standards/resolver/) |
| UNTP | 0.7.0 | Pilot release. The work-in-progress text is not normative. | [UNTP versions](https://untp.unece.org/versions) |
| IDTA 02099-1 DPP Part 1 Metadata | Folder `1/0/2` | Hub shows 1.0; docs site 1.0.1. Pin `1/0/2` by folder and SHA-256 digest. | [IDTA submodel templates](https://github.com/admin-shell-io/submodel-templates) |
| AAS Part 2 API | 3.2 | Current. `aas-test-engines` covers API 3.0.3 only. | [AAS Part 2](https://industrialdigitaltwin.org/en/content-hub/aasspecifications/specification-of-the-asset-administration-shell-part-2-application-programming-interfaces-idta-number-01002) |
| Catena-X CX-0143 | 1.4.0 published; 1.5.0 on GitHub `main` | The family file's "next" KIT page shows 1.3 (optional). | [EcoPass KIT](https://eclipse-tractusx.github.io/docs-kits/next/kits/eco-pass-kit/adoption-view) |
| Catena-X CX-0160 battery passport | 1.0; 1.1.0 preview | The KIT page marks 1.0 mandatory. 1.1.0 is a preview, not eligible for certification. | [EcoPass KIT](https://eclipse-tractusx.github.io/docs-kits/next/kits/eco-pass-kit/adoption-view) |
| Catena-X generic DPP aspect model | 5.0.0 or 6.1.0 | Released KIT 26.09 names 5.0.0; unreleased "next" KIT and CX-0143 name 6.1.0. | [EcoPass KIT](https://eclipse-tractusx.github.io/docs-kits/next/kits/eco-pass-kit/adoption-view) |
| BatteryPass-Ready data model and longlist | Longlist 2.0 | Longlist dated August 2026. The data model date is not confirmed. | [BatteryPass-Ready resources](https://thebatterypass.eu/battery-pass-ready/resources/) |
| Battery Pass Data Model | 1.2.0 (SAMM 2.1.0) | No releases or tags; superseded by BatteryPass-Ready | [Battery Pass Data Model](https://github.com/batterypass/BatteryPassDataModel) |
| CIRPASS-2 battery ontology | 0.4.0 DRAFT | Development resource. The README disclaims official status. | [ontologies-battery](https://github.com/CIRPASS-2/ontologies-battery) |
| CIRPASS-2 back-up redirect options | Zenodo record v2 | December 2024, CC BY 4.0 | [Redirect options](https://zenodo.org/records/15040842) |
| W3C Bitstring Status List | 1.0 | W3C Recommendation | [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/) |

The Battery Pass Technical Guidance states CC BY-NC 4.0 in the PDF itself. Treat it as link only, and derive no fixtures from it.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [open-dpp](https://github.com/open-dpp/open-dpp) | Platform | AGPL-3.0 | Push 2026-10-19; per-package tag `@open-dpp/dto@6.2.1` (2026-10-12) |
| [Eclipse BaSyx Go components](https://github.com/eclipse-basyx/basyx-go-components) | Server with DPP API | MIT | v1.1.2 (2026-10-16) |
| [Tractus-X Industry Core Hub](https://github.com/eclipse-tractusx/industry-core-hub) | Connector middleware | Apache-2.0 | Stable v0.5.0 (2026-03-17); v0.6.0 pre-release tags only |
| [Tractus-X Digital Product Pass](https://github.com/eclipse-tractusx/digital-product-pass) | Renderer | Apache-2.0 | Archived; release 4.0.2 (2024-09-13) |
| [Transpareo Time Machine](https://github.com/transpareo/transpareo-time-machine) | Renderer and verifier | GPL-3.0-or-later | v2.20.3 (2026-10-15) |
| [OpenEPCIS Digital Link translator](https://github.com/openepcis/openepcis-epc-digitallink-translator) | SDK | Apache-2.0 | Tag v0.9.3; push 2026-09-13 |
| [CIRPASS-2 mock EU registry](https://github.com/CIRPASS-2/mock-eu-registry) | Test environment | Apache-2.0 | Push 2026-08-04 |
| [CIRPASS-2 DPP validator](https://github.com/CIRPASS-2/dpp-validator) | Validator | Apache-2.0 | Push 2026-08-04 |
| [CIRPASS-2 ontologies](https://github.com/CIRPASS-2/ontologies-battery) | Ontology | Apache-2.0; textile repository has none | Push 2026-09-28 to 2026-10-13 |
| [Cir4Fun SDKs](https://github.com/CIR4FUN-EU/java-dpp-sdk) | SDK | Apache-2.0 | Java push 2026-09-29; Python push 2026-09-03 |
| [Arianee Protocol](https://docs.arianee.org/v2.2/docs) | Smart contracts and SDKs | Mixed per repository | Push 2026-10-18 |
| [odal-node dpp-engine](https://github.com/odal-node/dpp-engine) | Server | README names BSL-1.1 | Push 2026-10-16 |
| [open-dpp passport-templates](https://github.com/open-dpp/passport-templates) | Data model | MIT | Push 2026-10-01 |
| [OpenDPP SDK](https://github.com/OpenDPP/opendpp-sdk) | SDK from a private contract | Apache-2.0 | Push 2026-10-13 |
| [mini-dpp-platform](https://github.com/hadijannat/mini-dpp-platform) | AAS-based server | MIT | Push 2026-05-28 |

The last three rows come only from the repository inventory. It classified some of them from the GitHub description only.

#### Difference from the legal baseline

This list uses the legal baseline (section 4) only.

- EU law prescribes no platform architecture. It prescribes properties, roles and one central component, the DPP registry.
- A DPP service provider is an independent third party that the operator authorizes (Regulation (EU) 2024/1781, Art. 2(32)). It is not an economic operator (Art. 2(46)).
- The operator or authorized providers store the passport (Art. 11(c)). A provider must also hold a back-up copy (Art. 10(4)).
- A provider may not sell, re-use or process passport data beyond the service, unless the parties agree otherwise (Art. 11, second subparagraph).
- The delegated act on provider requirements and a possible certification scheme is not adopted. The Commission timeline lists Q2 2027 and Q3 2027.
- A vendor "DPP provider certification" is therefore a private scheme. The Commission FAQ says that no general third-party certification of passport content exists.
- The registry keeps a list of verified service providers (Implementing Regulation (EU) 2026/1778, Art. 3(f)). It checks the back-up link where relevant (Art. 8(7)).
- Legal persons prove their identity to the registry with a qualified electronic seal or a qualified attestation. Identification at eID level high is only for Union sole traders.
- The Batteries Regulation has no back-up duty and no service provider concept. The battery passport applies from 2027-02-18.
- Battery Annex XIII access: the public gets point 1, and notified bodies and market surveillance authorities get point 3. The Commission gets points 1 to 3.
- Persons with a legitimate interest get points 2 and 4. The implementing act that defines legitimate interest is not adopted.
- Toys copy the back-up duty (Regulation (EU) 2025/2509, Art. 19(13)). For construction products, Regulation (EU) 2024/3110, Art. 75(2)(f) covers availability and back-up.
- No ESPR product delegated act exists. The timeline lists iron and steel for Q4 2026, and textiles, aluminum and tires for Q3 to Q4 2027.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | A batch or model URL is printed, but the platform resolves only the item form. | Resolve each granularity of one GTIN and compare the status codes. |
| L01 | Serial comes before lot, or a GTIN-12 is not padded to 14 digits. | Parse the URL against the GS1 grammar. |
| L02 | A dynamic QR redirect goes through a vendor domain that the operator does not control. | Follow the redirect chain and compare the domain of each hop with the operator domain. |
| L03 | A valid identifier with no data returns `200` with an empty page. | Request an unused valid identifier. Expect `404`. |
| L03 | A redirect loop or a long chain between resolver, platform and back-up host. | Follow redirects with a hop limit. |
| L04 | `DELETE` removes a passport with no archive state. | On a sandbox, create, delete, then read the versions and the archive state. |
| L05 | The document cites a demo or unreachable `@context`. | Compare `@context` entries with a pinned allowlist. |
| L06 | The primary host and the back-up host are the same provider. | Compare the host domains and the provider reference. Confirm the contract by manual review. |
| L07 | Restricted fields leak through search, export, errors or HTML. | Put canary values in restricted fields and probe each channel per role. |
| L08 | A "verified" badge comes from a server flag, not from a proof check. | Tamper with a sample document and see whether the badge changes. |
| L09 | The registration identifier or back-up link in the passport differs from the registry record. | Compare passport fields with a mock registry record. |
| L10 | A remanufactured product gets a new passport with no link to the original. | Check the link fields between the two passports. |
| L11 | A provider re-uses passport data or usage metadata. | Not testable as a black box. Use signed manual review of the terms. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. Capability names follow the merged proposals in x01. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Accept every valid GS1 Digital Link granularity; reject wrong qualifier order. | `identifier.parse` (correct): one path form only. | `identifier.gs1_grammar` | Valid and invalid URLs per granularity; OpenEPCIS translator as a cross-check. | sample artifact |
| Report a DID, token id or EPC URN as an unsupported scheme, not a syntax failure. | `identifier.parse` (correct): an undeclared scheme gives `IDENTIFIER.SCHEME.UNSUPPORTED`. | `identifier.schemes`, only for several schemes in one ICS | Carrier strings for each L01 variant. | sample artifact |
| Decode dynamic and dual-carrier labels and compare them with the declared identifier. | `carrier.qr_decode` (correct), with `identifier.consistency`. | `carrier.rfid` (interface only) | QR label images; recorded tag dumps. | sample artifact |
| Judge resolver status codes, `linkType`, linkset and the description file. | `identifier.resolve` (correct): it can require the linkset media type. | `resolver.conformance` | Loopback resolver with GTIN, lot and serial linksets. | loopback only |
| The declared back-up delivers the passport when the primary is down. | None (correct). | `persistence.backup` | Two loopback servers and a mock registry record. | loopback only |
| Create, update, delete and event calls match a pinned OpenAPI contract. | `api.contract` (correct): GET only. | `api.write_ops` | Pinned OpenAPI file; sandbox with test items; signed authorization. | live system under test |
| An AAS-based DPP service conforms to the AAS API. | `aas.validate` (wrong): it reads one file, not an API. | `aas.api_profile`; can wrap `aas-test-engines` (API 3.0.x only) | Loopback BaSyx Go with a sample passport submodel. | loopback only |
| A passport validates against a pinned sector schema or shapes. | `data.jsonschema` (correct). | `data.shacl` for ontology shapes | Pinned schemas; CIRPASS-2 dpp-validator as a cross-check. | sample artifact |
| Every `@context` entry is on an approved list. | `data.context` (correct). | None | Documents with allowed and demo contexts. | sample artifact |
| Older versions stay readable, and the retention period is stated. | `persistence.versions` (overstated): it fetches no older version. | `persistence.scheduled`; a `data.rules` presence rule for retention | Three versions and an archived state. | live system under test |
| Each role gets only its fields on every channel. | `access.restricted_fields` (correct). | `access.credential_acquisition` for OAuth 2.0 or OIDC tokens | Canary fields per tier; tokens per role. | live system under test |
| Data Integrity proofs and JWS verify with a `did:web` issuer key. | `integrity.jws` (overstated): keys only from `x5c`; no Data Integrity. | `integrity.data_integrity` | `TEST-ONLY` keys, a `did.json` file, tampered copies. | sample artifact |
| Ledger anchor receipts verify offline. | `manual.review` (correct). | `integrity.ledger_proof` | Anchor proof samples and tampered copies. | sample artifact |
| Credential status comes from a status list. | None (correct): `integrity.status_list` is interface only. | `integrity.status_list` | Status lists with revoked and valid indexes. | loopback only |
| Registration identifier, back-up link and granularity agree with the registry. | `registry.consistency` (overstated): it compares two identifier fields only. | `registry.record_fields` | Mock records with equal and different back-up links. | loopback only |
| A toy registration identifier and commodity code agree with the registry. | None (correct). | `registry.record_fields` | Mock registry with commodity codes. | loopback only |
| A new passport for a remanufactured product links to the original. | `persistence.versions` (wrong): it reads no links between passports. | `lifecycle.links` | Linked and unlinked passport pairs. | sample artifact |
| Record signed evidence about a service provider without a compliance claim. | `manual.review` (correct). | `evidence.provider_attestation`, after a delegated act | Signed manual results with `TEST-ONLY` keys. | sample artifact |
| Probe a Catena-X style catalog, negotiation and submodel pull. | None (correct): DSP needs POST. | `dataspace.protocol_probe` | Local Industry Core Hub deployment with test credentials. | loopback only |
| A toy passport holds the Annex VI Part I data (family file; not verified). | `data.rules` (correct). | None; a rule pack needs Annex VI first. | Sample toy passports. | sample artifact |

The resolver oracle must encode the strength of each rule. In GS1-Conformant Resolver 1.2.1, `application/linkset+json`, `400`, `404`, no `200` on error and the description file are SHALL. A `300` for tied links and the `application/ld+json` and HTML responses are SHOULD.

A resolver must not fail a test when it omits `300`. The resolver standard fixes no redirect status code, so the oracle accepts any 3xx with a `Location` header. The check records the observed code.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m10-platforms-sectors.json`. The engine verdicts are in `x01-engine-mapping.json`, and three extra repositories are in `r01-repositories.json`.
- The independent check (`m10-platforms-sectors.verification.json`) checked 30 claims: 20 confirmed, 5 refuted, 5 not confirmed. It found no clear rule 5 violation. This section follows its two low-severity rule 5 fixes.
- The check corrected these points: Industry Core Hub has no stable v0.6.0, and IDTA 02099-1 has a later folder. The redirect report is record v2. Resolver `300` and media types other than linkset are SHOULD.
- The check could not confirm EU article text in the family file, because EUR-Lex returned empty pages. This section states law from the legal baseline only.
- Open: the CIRPASS-2 reference architecture was not read; no vendor OpenAPI contract was retrieved; the list of verified providers is not public.

### 5.10 Hybrid stacks

A hybrid stack is not a separate technology. It is a per-layer assignment: different families supply different layers and pass control to each other at a few hand-over points. Every stack in the research record follows the same outer frame from EU law: carrier, unique identifier, operator storage, and registry upload. The research record examines five cases. The cases are Battery Pass, the Catena-X bridge, the IDTA ID Link, GS1 with UNTP, and an operator API with a ledger anchor.

The faults of a hybrid sit mainly at the seams. Typical seams are relation names, identifier equality across layers, and the byte form that is signed or hashed.

#### Components

- **Law frame.** A carrier on the product links to a unique identifier. The operator or a service provider stores the passport, and the identifier goes to the EU registry.
- **Identification and discovery.** A GS1 Digital Link URI, an IDTA ID Link URL, a URN, or a DID, with a resolver or a linkset endpoint.
- **Linkset.** An RFC 9264 linkset is the common wire format of the GS1-conformant resolver and of the IDTA ID Link. The two differ in relation names.
- **Passport host.** An operator repository (AAS, NGSI-LD, or SQL in the Battery Pass demonstrator), an AAS service, a dataspace twin, or a credential host.
- **Translator.** In the Battery Pass proposal, a translator service maps generic CRUD calls onto each platform API.
- **Dataspace layer.** In Catena-X: the Digital Twin Registry, AAS descriptors with a DSP subprotocol, and EDC contract negotiation.
- **Integrity layer.** A W3C verifiable credential with a status list, or a digest on a ledger. Some stacks have no integrity layer.
- **Back-up and registry services.** A third-party back-up copy and a registry record, often from a separate proxy.

#### Composition per stack

The task named five stacks. The research record does not contain a separate CIRPASS-2 case, so the CIRPASS-2 row uses only the repository inventory. "AAS over a dataspace" is the Catena-X case.

| Stack | Families and the layers they supply | Main seam |
| --- | --- | --- |
| Battery Pass (Technical Guidance v1.0 and BatteryPass-Ready) | Law baseline: L02, L09. URN and DID proposal: L01. Linked data, then JSON Schema and XSD: L05. Central resolver service and translator: L03. | Registry resolver to operator repository (L03, L09). Canonical API to platform API through the translator (L04, L05). |
| Catena-X CX-0160 (AAS over a dataspace) | Dataspace: L01 (`urn:uuid` and BPN-based asset ids), L03, L07. AAS: L04, L05. A proxy outside Catena-X supplies L02, L06, L09, and the public part of L07. | Dataspace to the EU-facing proxy. CX-0160-3 gives no technical profile for this proxy. |
| CIRPASS-2 | Not researched as a case. The inventory lists a mock EU registry (L09), a renderer back end, and a data extractor that reads JSON, JSON-LD, RDF, or AAS passports. | Not researched. |
| UNTP over GS1 | GS1 resolver: L01, L02, L03. Verifiable credentials: L05 (with the UNTP context), L08 (signature, status list, issuer DID), L10 (re-issue and revoke). | Resolver to credential host (L03). Credential to DID document and status list (L08). |
| IDTA ID Link (AAS over the web) | AAS: L01 (ID Link URL as `globalAssetId`), L03 (linkset), L04 (AAS Part 2 profiles), L05. Linkset hints: L07. No L08. | Linkset relation `aas` or `dpp` to the AAS or DPP service. |
| Operator API with a ledger anchor | Platform: L01, L03, L04, L06. Ledger: a second identifier and L08 (digest only). EBSI Timestamp is the worked example. | Served bytes to digest to ledger record. The canonical byte form is the critical agreement. |

#### End-to-end flow

1. The client decodes the carrier and gets a URL or an identifier.
2. If the payload is a URL, the client sends GET with `Accept: application/linkset+json`.
3. A resolver or ID Link landing service answers with a linkset, or redirects to a default link.
4. The client selects the passport relation (`dpp`, `gs1:dpp`, or `aas`) from the linkset.
5. In a dataspace, the client looks up the twin, negotiates a contract, and reads submodels from the data plane.
6. A proxy outside the dataspace serves the public tier without a contract.
7. The client reads the passport: an AAS, a JSON document, or a credential.
8. The verifier checks a signature and a status bit, or recomputes a digest and compares it with a ledger record.
9. The tester compares the identifier on the carrier with the identifier in the passport and in the integrity artifact.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Each case takes L01 from a different family: URN or DID, `urn:uuid` with BPN-based asset ids, ID Link URL, or GS1 Digital Link URI. | The identifier on the carrier, in the passport, and in any anchor or signature, as exact strings. |
| L02 data carriers | A QR code with a URL is the common case. The Battery Pass guidance also describes an identifier plus offline data, which needs an app. | Decoded payload: absolute HTTPS URL, URN, DID, or bare identifier. |
| L03 data exchange protocols | The main hand-over layer: GS1 linkset or redirect, ID Link linkset, DTR lookup with DSP, central resolver with translator, or REST plus ledger read. | Status codes, `Location` and `Link` headers, `Content-Type`, linkset relations and anchors, authentication demands. |
| L04 APIs for lifecycle and search | Battery Pass core services; seven BatteryPass-Ready modules; AAS Part 2 through CX-0002; linkset-advertised operations; credential issue and revoke. | Public read behavior, version-by-date reads, and advertised operations against operations that answer. |
| L05 interoperability and data models | RDF and SAMM; JSON Schema 2020-12 and XSD per battery category; IDTA-02035 submodels with IDTA-02099-1 metadata; UNTP credential. | Media type, `@context`, `semanticId` values, schema validity, Annex XIII fields per tier. |
| L06 storage and persistence | Operator repository with third-party back-up; dataspace twin plus a proxy copy; off-chain document with an on-chain digest. | Back-up reference, if exposed. Equality of live and back-up copies when both URLs are known. |
| L07 access rights and security | Operator access control; dataspace contract policy with usage purpose `cx.circular.dpp:1`; OIDC and OAuth2 hints in a linkset; DID presentation. | Public tier reachable without credentials; restricted fields absent from the anonymous view; `401` or `403` on restricted endpoints. |
| L08 authentication and integrity | VC signature and status list (UNTP); ledger digest (anchor). Catena-X and ID Link show no integrity mechanism. The Battery Pass verification service is unspecified. | Signature validity, status bit, digest over the served bytes, issuer identity against the named operator. |
| L09 registry and customs | Law registry. Battery Pass proposes the registry as a resolver. The Catena-X proxy registers. IDTA, GS1, and UNTP define no registry step. | Only against a mock registry: record fields and identifier equality with the carrier. |
| L10 lifecycle and versions | A stable URL that the operator re-points; version-by-date operations; credential re-issue with revocation; one anchor per version. | Carrier URL after a simulated operator change; date semantics; predecessor link after repurposing. |
| L11 roles and governance | Commission, operators, and back-up provider (Battery Pass); Catena-X e.V. and assessment bodies; IDTA; GS1; UN/CEFACT; ledger operator. | Mostly not observable. Partly visible through issuer identities, BPNs, resolver domains, and provider references. |

#### How a tester recognizes the seams

- **Change of relation vocabulary.** The linkset uses `aas`, `aas-service-endpoints`, `dpp-service-endpoints`, or `gs1:dpp`. Of the IDTA tokens, only `dpp` is in the IANA registry.
- **Change of identifier.** The carrier holds a GS1 URI, the AAS holds a `urn:uuid`, and the passport holds a `partInstanceId`. Nothing ties them together.
- **Change of access regime.** A dataspace contract, a wallet, or a login appears where the public tier should be free.
- **Change of byte form.** A signature or digest covers a different serialization than the bytes that the client receives.
- **Change of host.** The redirect target, back-up host, or proxy domain differs from the domain that the carrier names.

#### Variants

- A central resolver service in front of distributed repositories, with translators (Battery Pass Technical Guidance).
- A module chain: authenticate, create, register, back up, read, update, delete (BatteryPass-Ready user stories v1.0).
- An ID Link landing service with a linkset. The IDTA text says a linkset-unaware client may get `302` with a `Link` header.
- A GS1 Digital Link URI used as the ID Link. Neither specification states or forbids this. It is an inference in the research record.

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| Battery Passport Technical Guidance | 1.0 (March 2024) | Final deliverable; project ended April 2025. The PDF states CC BY-NC 4.0; link only, no fixtures. | [Battery Pass deliverables](https://github.com/batterypass/BatteryPassDataModel/tree/main/docs/Battery%20Pass%20Deliverables/WP3%20Battery%20Passport%20Technical%20Guidance) |
| Battery Pass Data Model | 1.2.0, SAMM 2.1.0 | Shared sheet: no maintenance since April 2025. Independent check: last push 2026-09-14. | [BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel) |
| BatteryPass-Ready Data Model | 2.0, release folder `v2.0.1` | Work in progress per README; JSON Schema 2020-12 and XSD per category | [BatteryPass-Ready README](https://git.gefeg.com/bp/BatteryPassDataModel/-/raw/main/README.md?ref_type=heads) |
| BatteryPass-Ready user stories | 1.0 | Published June 2026 | [User stories PDF](https://thebatterypass.eu/wp-content/uploads/BatteryPass-Ready_User-Stories_v1.0.cleaned.pdf) |
| CX-0160 Battery Passport base | 1.1.0 | CX-Neptune preview; not yet eligible for certification. Use Case 2 (CX-0160-2) goes live on 24 November 2026. | [CX-0160 folder](https://github.com/catenax-eV/catenax-ev.github.io/tree/main/docs/standards/CX-0160-BatteryPassport) |
| CX-0160-3 exchange to service providers | 1.0.0 | Preview, as the base | [CX-0160 folder](https://github.com/catenax-eV/catenax-ev.github.io/tree/main/docs/standards/CX-0160-BatteryPassport) |
| IDTA-01002 AAS Part 2 API | 3.2.0 | GitHub release 2026-07-21. Shared sheet: AAS Part 1 and Part 2 at 3.2 (Release 26-01). | [aas-specs-api](https://github.com/admin-shell-io/aas-specs-api) |
| IDTA 02099-1 DPP metadata | Folder `1/0/2` | Pin by folder and SHA-256 digest; hub shows 1.0, docs site 1.0.1 | Shared sheet |
| GS1-Conformant Resolver | 1.2.1 | Ratified August 2026; no redirect status code fixed | [GS1 resolver standard](https://ref.gs1.org/standards/resolver/) |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified August 2026 | Shared sheet |
| UN Transparency Protocol | 0.7.0 | Pilot release; work-in-progress text not normative; no 1.0 located | [UNTP versions](https://untp.unece.org/versions) |
| IANA link relation types | Updated 2026-06-12 | `dpp` and `linkset` registered; the other IDTA tokens are absent | [IANA registry](https://www.iana.org/assignments/link-relations/link-relations.xhtml) |
| RFC 9264 linkset | RFC | Anchors are optional; explicit anchors recommended | [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html) |
| EBSI Timestamp | Page of 2026-09-30 | Stores only a hash; write scope `timestamp:write` | [EBSI Timestamp](https://hub.ebsi.eu/docs/use-cases/anchoring/timestamp/timestamp-introduction) |

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [Battery Pass demonstrator](https://github.com/batterypass/BatteryPassDataModel/tree/main/docs/Battery%20Pass%20Deliverables/WP4%20Battery%20Passport%20Demonstrator) | Pilot, known from slides only; no code located | Not stated | Slides of 2024-05-22 and 2025-02-25 |
| [Battery Pass Data Model](https://github.com/batterypass/BatteryPassDataModel) | Data model | GitHub shows no license; README CC-BY-4.0 (not confirmed by the independent check) | Pushed 2026-09-14 |
| [BatteryPass-Ready Data Model](https://git.gefeg.com/bp/BatteryPassDataModel/-/raw/main/README.md?ref_type=heads) | Data model; raw schema files returned 404 | CC-BY-4.0 (README) | Not checked |
| [BatteryPass-Ready test environment](https://thebatterypass.eu/battery-pass-ready/) | Test environment, not contacted | Not stated | Not checked |
| [CX-0160 standard files](https://github.com/catenax-eV/catenax-ev.github.io/tree/main/docs/standards/CX-0160-BatteryPassport) | Standard with assessment criteria files | Repository `NOASSERTION` | Folder commit 2026-09-18 |
| [aas-specs-api](https://github.com/admin-shell-io/aas-specs-api) | Specification source of the ID Link pattern | CC-BY-4.0 | Pushed 2026-10-16 |
| [EBSI Timestamp](https://hub.ebsi.eu/docs/use-cases/anchoring/timestamp/timestamp-introduction) | Ledger service, not called | Not stated | Page of 2026-09-30 |
| [CIRPASS-2 mock-eu-registry](https://github.com/CIRPASS-2/mock-eu-registry) | Mock EU registry; README disclaims normative status | Apache-2.0 | Pushed 2026-08-04 |
| [CIRPASS-2 dpp-renderer-be](https://github.com/CIRPASS-2/dpp-renderer-be) | Renderer back end for JSON and JSON-LD passports | Apache-2.0 | Pushed 2026-06-11 |
| [CIRPASS-2 dpp-data-extractor](https://github.com/CIRPASS-2/dpp-data-extractor) | Search-key extractor for JSON, JSON-LD, RDF, and AAS passports | Apache-2.0 | Pushed 2026-08-04 |

A GS1 Germany news item is the only source found that links BatteryPass-Ready and GS1 Digital Link. It is a vendor statement, so it is secondary evidence only.

#### Difference from the legal baseline

- Law prescribes properties, roles, and one central component, the registry. It names no resolver protocol, AAS, dataspace, credential format, or ledger.
- The registry user guide asks for a unique product identifier that is an HTTPS URL. A `urn:uuid`, a URN, or a DID alone does not meet that non-binding request.
- Law makes the registry a store of identifiers and registration data. Use of the registry as a resolver is a project proposal, not a legal function.
- The Batteries Regulation has no back-up duty and no service-provider concept. The Battery Pass back-up service is therefore a design choice for batteries. ESPR products need a back-up.
- Battery access tiers: the public gets Annex XIII point 1. Notified bodies and market surveillance authorities get point 3.
- The Commission gets points 1, 2, and 3. Persons with a legitimate interest get points 2 and 4. The Art. 77(9) act is not adopted.
- Law requires free access to the public tier. The family record states that CX-0160-3 agrees a pure dataspace cannot give it.
- Implementing Regulation (EU) 2026/1778 verifies legal persons with a qualified electronic seal or a qualified attestation. Identification at eID level high is a route for Union sole traders only.
- The battery passport applies from 18 February 2027. The registry user guide says that battery registration is not yet possible.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | Carrier, AAS, and passport hold three different identifiers with no link between them. | Exact-string comparison across layers; report a consistency failure. |
| L01 | Identifier case differs between systems, for example in a URN namespace. | Exact-string comparison with a note on case. |
| L03 | The landing service returns the linkset as `application/json`, or HTML to a linkset-aware client. | Accept negotiation with `application/linkset+json`; `Content-Type` check. |
| L03 | The linkset uses only an unregistered relation, so a GS1-only client cannot reach the passport. | Relation inventory against the relation that the ICS declares; warn on tokens absent from IANA. |
| L03 | The linkset anchor differs from the requested URL. | Anchor equality check. A missing anchor is "not stated", not a mismatch. |
| L03 | Published JSON contains comments or a misspelled relation key. The IDTA 3.2 example has both `dpp-service-endpoint` and `dpp-service-endpoints`. | Strict JSON parse and schema check of the linkset. |
| L04 | The linkset advertises operations that the server does not implement. | Call each advertised operation on a loopback fixture. |
| L05 | The proxy republishes submodels with other semantic ids or omits DPP metadata. | `semanticId` inventory and schema validation of the public payload. |
| L06 | The back-up copy is in a system-specific format or is stale. | Fetch both copies; compare normalized content and version stamp. |
| L07 | The public tier sits behind a dataspace contract, wallet presentation, or login. | Anonymous fetch of Annex XIII point 1 fields fails. |
| L08 | The anchor covers a different serialization than the served bytes. | Recompute the digest over the served bytes and the declared canonical form; report which one matches. |
| L09 | Registration uses the dataspace identifier, but the carrier holds another identifier. | Compare the mock registry record with the carrier identifier. |
| L10 | After an operator change, the QR target still points to the old operator. | Two-phase loopback scenario with re-pointing; observe target and version. |

#### What the engine can test

The engine mapping file `x01-engine-mapping.json` covers the files m01 to m10 only and has no row for this family. The verdicts below come from `f02-hybrid-stack-composition.verification.json` and from the x01 observations about the same checks.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Carrier, linkset anchor, passport, and signature subject hold the same identifier. | `identifier.consistency` (not mapped by x01). x01 notes that it reads the top-level key `id` only. | `identifier.subject_pointer`; `identifier.cross_layer` (proposal in this family) | QR image, recorded linkset, passport, signed credential, with and without matching ids | sample artifact |
| Parse URN, DID, and ID Link identifiers. | `identifier.parse` (independent check confirmed): GS1 Digital Link only; other schemes give unsupported. | `identifier.schemes` | Valid and invalid URN, DID, and URL samples | sample artifact |
| The QR holds an absolute HTTPS URL. | `carrier.qr_decode` (independent check confirmed that it exists) | None | QR images with a URL, a bare URN, and a DID | sample artifact |
| The URL answers a linkset request with `200`, the linkset media type, and the right anchor. | `identifier.resolve` (not mapped by x01). x01 notes that any non-200 status other than `404` or `410` is a fail. | `resolver.linkset`; `resolver.conformance` | Loopback resolver with GS1-style and IDTA-style linksets and a redirect variant; [GS1 resolver test suite](https://github.com/gs1/GS1DL-resolver-testsuite) | loopback only |
| The passport relation is present under the name that the ICS declares. | None | `resolver.linkset` with a relation map in the IXIT | Linksets in each relation style | loopback only |
| The `aas` relation reaches an AAS whose `globalAssetId` equals the ID Link. | `aas.validate` (not mapped by x01): structure only. aas-test-engines 1.0.3 checks metamodel 3.0.1 only. | `aas.idlink_roundtrip` (proposal in this family) | Loopback ID Link landing service and AAS repository fixture | loopback only |
| Operations advertised in a linkset answer. | `api.contract` (refuted by the independent check): five passport resources and GET only, OpenAPI 3.1 subset. | `aas.api_profile`; `api.resources` | Pinned AAS Part 2 OpenAPI subset; loopback server | loopback only |
| Payload validates against the BatteryPass-Ready schema, or submodels carry the IDTA semantic ids. | `data.jsonschema`, `aas.validate`, `data.rules` (not mapped by x01). x01 notes that these read only the served item or model document. | `data.document_source`; a `data.rules` pack for Annex XIII tiers | Pinned schema files (retrieval failed); sample passports per category | sample artifact |
| The back-up copy equals the live copy. | None (independent check refuted `registry.consistency` here: it has no back-up field). | `persistence.backup` | Loopback live and back-up hosts with equal and diverging copies | loopback only |
| The public tier is reachable without credentials across the hand-over. | `access.restricted_fields` (independent check confirmed that it exists). x01 notes that it requires `401` or `403` nowhere. | None stated | Role views: anonymous, legitimate interest, authority | loopback only |
| Authentication hints in a linkset are well formed. | None | `resolver.linkset` hint lint | Linksets with valid and broken hints | sample artifact |
| A UNTP `vc+jwt` signature covers the served credential. | `integrity.jws` (refuted by the independent check): it finds the key only in an `x5c` header, so a DID `kid` is out of reach. | `integrity.jose_profiles`; `identity.did` | Signed credential with a DID key | sample artifact |
| A ledger anchor covers the exact served bytes. | None | `integrity.digest_binding`; `integrity.ledger_proof` | Anchor receipt bundle with matching and mismatching digests | sample artifact |
| A stack with no integrity layer is reported honestly. | `integrity.jws` (refuted by the independent check): it returns `INTEGRITY.TOKEN.MALFORMED`, a fail. Applicability must handle this case. | None in the check; applicability profile | Unsigned passport | sample artifact |
| The registry record matches the carrier identifier and the resolver targets. | `registry.consistency` (refuted in part): it compares the identifier and operator identifier only. | `registry.record_fields` | Mock registry records; CIRPASS-2 mock-eu-registry | loopback only |
| After a simulated operator change, the printed URL reaches the current passport. | `persistence.versions` (experimental; not mapped by x01) | `lifecycle.links`; `lifecycle.handover` (proposal in this family) | Loopback resolver with two back ends and a switch | loopback only |

#### Evidence and limits

- The evidence is in `docs/research/raw/implementation-methods/f02-hybrid-stack-composition.json`. The independent check confirmed 30 of 37 claims, refuted 5, and could not confirm 2.
- The independent check refuted four engine mappings, as the table shows. It also moved the 24 November 2026 date from the whole standard to Use Case 2.
- Blockchain: the Battery Pass Technical Guidance names distributed ledger technology once, as an optional feature of upstream supply-chain systems. Its architecture has no ledger.
- A May 2024 EU Blockchain Observatory report says that the Battery Pass platform relies on a private permissioned ledger. It cites no Battery Pass document, and the independent check confirmed this gap.
- Open: the operator and profile of the Catena-X EU-facing proxy, the relation name for the passport hand-over, the BatteryPass-Ready schema fields, and all CIRPASS-2 layers. Claims taken from sibling records were not re-verified.

### 5.11 Reference implementations, pilots, and the EU registry

This family covers the central Commission DPP registry and the EU-funded reference work on decentralized operator systems. The registry has been operational since 2026-07-20, and Implementing Regulation (EU) 2026/1778 has applied since 2026-08-06. CIRPASS, CIRPASS-2, Battery Pass, BatteryPass-Ready, and Cir4Fun publish architectures, mock services, data models, and SDKs; TRACE4EU, DaCapo, and the commercial OpenDPP kit are adjacent items. Section 7.2 of the [gap assessment](gap-assessment-2026-10-15.md) holds the earlier status rows; this section adds dates and mechanisms and does not repeat those rows.

#### Components

- **EU DPP registry.** A Commission service with a web form, a JSON or XML file upload, and an API. It returns a unique registration identifier.
- **Registry acceptance test site.** It needs a separate EU Login account, and its data is cleaned at intervals. The user guide prints its address with `http://`.
- **CIRPASS D3.2 DPP System Architecture (v1.9, 2024).** It proposes an HTTP URI design with an operator resolver, and a DID and VC design.
- **CIRPASS-2 D4.1 Reference Architecture (V1.1, 2026).** Non-normative recommendations: JSON-LD default, VC-JOSE, hash-chained updates, and an EU fallback redirect.
- **CIRPASS-2 test environment.** `mock-eu-registry`, `dpp-validator`, `dpp-data-extractor`, `dpp-renderer-be`, and `dpp-renderer-fe`, behind Keycloak OIDC. The READMEs call the tools experimental.
- **CIRPASS-2 battery ontology.** OWL modules, a SHACL profile, three access-tier views, and a test runner. The umbrella version is 0.4.0 DRAFT.
- **Battery Pass.** Technical Guidance v1.0 and data model v1.2.0 in SAMM 2.1.0. The project ended in April 2025.
- **BatteryPass-Ready.** JSON Schema 2020-12 and XSD per battery category, user stories v1.0, and a hosted test environment.
- **Cir4Fun SDKs.** Java and Python clients for project-defined repository and registry routes.
- **Eclipse OSS4DPP.** A pre-launch initiative. It has no code and no formal Eclipse project.

#### End-to-end flow

1. The operator assigns an https UPI and encodes it in the data carrier, for example a QR code.
2. The operator hosts the passport and a back-up copy at a DPP service provider.
3. A registry user signs in through EU Login with multi-factor authentication.
4. A legal representative signs or seals the EC-sealed PDF declaration with a qualified signature or seal.
5. The operator registers one UPI by web form, or up to 100 UPIs by JSON or XML file.
6. The registry dereferences each UPI and checks schema, duplicates, URL syntax, and semantics.
7. One bad record rejects the whole file. The request ends as `SUCCESS` or `FAILURE`.
8. On success, the registry returns a unique registration identifier per passport.
9. The operator downloads a sealed, timestamped proof of registration within 90 days.
10. At import, the declarant gives customs the registration identifier. Customs verifies it with the commodity code.
11. A user scans the carrier. The UPI URL returns HTML to a browser and data under content negotiation.
12. The client validates the data and checks role-based access to restricted fields.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | Registry: the UPI is a mandatory https URL of at most 2,000 characters (user guide). Mock: free-string `upi` of 1 to 200 characters, UUID `registryId`. | Decoded UPI; scheme and length; the registration identifier; agreement of `upi`, `modelUpi`, and `batchUpi`. |
| L02 data carriers | The carrier holds the UPI only (D3.2). Battery carriers are QR codes. D4.1 adds a model-level link for online sales. | Decoded payload of a QR sample; equality with the registered UPI. |
| L03 data exchange protocols | One URL with `Accept` negotiation: HTML for a browser, JSON or JSON-LD for machines. D4.1 adds `application/vc+jwt`. D3.2 uses redirects and typed links. | Status, `Content-Type`, `Vary`, and `Location` per `Accept` value; redirect count; scheme changes. |
| L04 APIs for lifecycle and search | Mock: `POST /metadata/v1` and a proof `GET`; no record search. The registry user guide documents the web form and file upload only. Cir4Fun: CRUD and history routes. | Status codes and bodies; batch result (all records or none); request status changes. |
| L05 interoperability and data models | CIRPASS-2 OWL and SHACL; Battery Pass SAMM; BatteryPass-Ready JSON Schema and XSD; registry semantic repository (2026/1778, Art. 11-12). | Validity against pinned schemas and shapes; `@context` URLs; AAS `modelType` and `semanticId`. |
| L06 storage and persistence | The operator or a provider stores the passport. The mock stores `liveURL` and `backupURL`. The registry keeps registration data for 10 years. | Back-up URL resolves; its content equals the live content; it withholds the same fields. |
| L07 access rights and security | Registry: EU Login and eIDAS-verified organizations. Mock: Keycloak roles `admin`, `eo`, and `eu`. Battery access groups come from the law. | `401` without a token, `403` for a wrong role, and the field set per role. |
| L08 authentication and integrity | Mock: optional detached RS256 JWS; RS256 proof JWT with `dppHash`. Registry: sealed proof with a Commission timestamp. D4.1: VC-JOSE, ES256 first. | `alg`, `kid`, and `cty`; signature against a pinned key; `dppHash` recomputed over the fetched bytes. |
| L09 registry and customs | Registry checks and stores identifiers, commodity code, and back-up link. Mock: `commodityCode` pattern and `granularityLevel` rules. Customs link through EU CSW-CERTEX later. | Official registry: no observation without authorization. Mock or recorded records: fields, granularity rules, registration identifier. |
| L10 lifecycle and versions | Mock duplicate rules: `MODIFY` (default), `APPEND_WITH_NEW_ID`, `APPEND_WITH_SAME_ID`, `NONE`. Registry versions carry Commission timestamps. D4.1 recommends hash-chained updates. | History, timestamps, previous-version links and hashes; result of a duplicate registration. |
| L11 roles and governance | The Commission runs the registry. Member States name national administrators by 2027-02-18. Operators control the data they submit. | Issuer in signatures; hosts of the live and back-up URLs; issuer of the registry proof. |

The mock schema sets three granularity rules. An `ITEM` record needs `deactivated` and `modelUpi`; `batchUpi` is optional. A `BATCH` record needs `modelUpi` and forbids `batchUpi`, and a `MODEL` record forbids both.

#### Variants

- Registration channel: web form, file upload of up to 100 records, or API (EU registry). JSON metadata `POST` (mock).
- UPI form: an https URL (EU registry) or an EPC URN (mock examples).
- Other UPI forms: GS1 Digital Link (OpenDPP, D3.2 example) or a DID with a UUID query (D3.2).
- Exchange: one URL with `Accept` negotiation (CIRPASS-2, D4.1), or resolver redirects with typed links and a linkset (D3.2).
- Data model: OWL plus SHACL (CIRPASS-2), SAMM (Battery Pass v1.2.0), or JSON Schema plus XSD per category (BatteryPass-Ready v2.x).
- Proof of registration: RS256 JWT plus JWKS (mock), or a sealed document with a Commission timestamp (EU registry).
- Updates: overwrite in place (mock `MODIFY`), append a record, hash-chained VC updates (D4.1), or soft deletion with a registry notice (BatteryPass-Ready).
- Access: OIDC with RBAC (CIRPASS-2), EU Login plus eIDAS (EU registry), VCs in eIDAS wallets (D4.1), or `did:ebsi` token scopes (TRACE4EU).

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| Implementing Regulation (EU) 2026/1778 | OJ L of 17.7.2026 | Applies since 2026-08-06 | [Cellar text](https://publications.europa.eu/resource/cellar/56aaf918-8178-11f1-bf5e-01aa75ed71a1.0006.03/DOC_1) |
| ESPR consolidated text | `02024R1781-20240628`, corrigenda C1 and C2 | In force | [Cellar text](https://publications.europa.eu/resource/cellar/78530460-7228-11f0-bf4e-01aa75ed71a1.0006.03/DOC_1) |
| Batteries Regulation consolidated text | `02023R1542` of 13.08.2026 | In force; battery passport from 2027-02-18 | [Cellar text](https://publications.europa.eu/resource/cellar/d86c4599-ac88-11f1-b9e5-01aa75ed71a1.0007.02/DOC_1) |
| DPP Registry user guide for economic operators | PDF v1.03, 2026-09-16 | Published; battery registration cannot succeed yet | [User guide](https://single-market-economy.ec.europa.eu/document/download/a71b5d30-ed8b-4c27-809d-757cf5e6030f_en?filename=dpp_registry_user_guide_for_economic_operators.pdf) |
| CIRPASS D3.2 DPP System Architecture | v1.9 (2024-05); V1.8 dated 2024-03-26 | Final; project ended 2024-03-31 | [Zenodo 12206138](https://zenodo.org/records/12206138) |
| CIRPASS-2 D4.1 Reference Architecture | V1.1 (2026-06-16) | Non-normative; PDF still has a draft watermark | [Zenodo 20720002](https://zenodo.org/records/20720002) |
| CIRPASS-2 test environment description | 1.0 (2026-06-16) | Published; CC BY 4.0 | [Zenodo 20749604](https://zenodo.org/records/20749604) |
| `mock-eu-registry` | 1.1.1-pgsql-oidc and 1.1.1-mariadb-oidc (2026-07-01) | Experimental example | [mock-eu-registry](https://github.com/CIRPASS-2/mock-eu-registry) |
| EU DPP Battery Ontology | 0.4.0 DRAFT; CORE P_DPP 2.1.0, MAT 1.1.0 | Draft; changelog 2026-10-06 | [ontologies-battery](https://github.com/CIRPASS-2/ontologies-battery) |
| Battery Passport Technical Guidance | 1.0 (March 2024) | Final; the PDF states CC BY-NC 4.0; link only | [Guidance folder](https://github.com/batterypass/BatteryPassDataModel/tree/main/docs/Battery%20Pass%20Deliverables/WP3%20Battery%20Passport%20Technical%20Guidance) |
| Battery Pass Data Model | 1.2.0 (SAMM 2.1.0) | No maintenance since April 2025 | [BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel) |
| BatteryPass-Ready Data Model | README 2.0 (work in progress); tree labels 2.0.1 current | Work in progress | [README](https://git.gefeg.com/bp/BatteryPassDataModel/-/raw/main/README.md?ref_type=heads) |
| BatteryPass-Ready user stories | 1.0 (June 2026) | Published | [User stories PDF](https://thebatterypass.eu/wp-content/uploads/BatteryPass-Ready_User-Stories_v1.0.cleaned.pdf) |
| Cir4Fun `java-dpp-sdk` | README 0.5.1 | Pre-1.0; no GitHub release; only tag `v0.3.0` | [java-dpp-sdk](https://github.com/CIR4FUN-EU/java-dpp-sdk) |
| Cir4Fun `dpp-sdk` (Python) | 0.4.0 (2026-08-11) | Pre-1.0 | [PyPI dpp-sdk](https://pypi.org/project/dpp-sdk/) |
| OpenDPP interop kit | v1.18.0 (2026-10-13) | Vendor kit, not an EU project | [opendpp-interop](https://github.com/OpenDPP/opendpp-interop) |
| Eclipse OSS4DPP | Page "Sources checked 24 July 2026" | Pre-launch; no deliverable | [OSS4DPP](https://dpp.eclipse.org/) |

The Battery Pass and BatteryPass-Ready data models carry different formats. Version 1.2.0 is SAMM with generated JSON Schema and JSON-LD. Version 2.x is JSON Schema 2020-12 plus XSD, with no SAMM, JSON-LD, or SHACL.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [mock-eu-registry](https://github.com/CIRPASS-2/mock-eu-registry) | Registry mock | Apache-2.0 | Pushed 2026-08-04 |
| [dpp-validator](https://github.com/CIRPASS-2/dpp-validator) | Validator (JSON Schema, SHACL) | Apache-2.0 | Pushed 2026-08-04 |
| [dpp-data-extractor](https://github.com/CIRPASS-2/dpp-data-extractor) | Search-key indexer | Apache-2.0 | Pushed 2026-08-04 |
| [dpp-renderer-fe](https://github.com/CIRPASS-2/dpp-renderer-fe) | Renderer (with `dpp-renderer-be`) | Apache-2.0 | Pushed 2026-09-23; back end 2026-06-11 |
| [deploy-resources](https://github.com/CIRPASS-2/deploy-resources) | Docker Compose stack | Apache-2.0 | Pushed 2026-06-10 |
| [ontologies-battery](https://github.com/CIRPASS-2/ontologies-battery) | Ontology and SHACL | Apache-2.0 | Pushed 2026-10-06 |
| [BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel) | Data model | CC BY 4.0 by README; GitHub API: none | Pushed 2026-09-14 |
| [BatteryPass-Ready data model](https://git.gefeg.com/bp/BatteryPassDataModel/-/tree/main/BatteryPass-Ready?ref_type=heads) | Data model | CC BY 4.0 | Not checked |
| [java-dpp-sdk](https://github.com/CIR4FUN-EU/java-dpp-sdk) | SDK | Apache-2.0 | Pushed 2026-09-29 |
| [python-dpp-sdk](https://github.com/CIR4FUN-EU/python-dpp-sdk) | SDK | Apache-2.0 | Pushed 2026-09-03 |
| [opendpp-interop](https://github.com/OpenDPP/opendpp-interop) | Offline validator kit | Apache-2.0 | Pushed 2026-10-14 |
| [battery-passport-kit](https://github.com/Jwrede/battery-passport-kit) | Validator for BatteryPass-Ready JSON | MIT | Pushed 2026-10-18 |
| [trace4eu](https://github.com/trace4eu) | EBSI services and VC issuer | EUPL-1.2 (seven repositories) | 2024-11-21 to 2025-07-10 |

The CIRPASS-2 READMEs disclaim completeness and normative status. The core ontology repository `ontologies-core` returns `404`, so the CORE files for pinned SHACL fixtures are not available. The OpenDPP kit vendors two schemas that its authors built from a protected EN; the engine must not use them as an oracle.

#### Difference from the legal baseline

- EU law prescribes no DPP technology. JSON-LD as default, VC-JOSE, receipts, hash chains, a fallback resolver, and a `/.well-known` endpoint are project choices.
- ESPR Art. 13(1) requires the registry to store at least unique identifiers, commodity codes, and battery identifiers. The mock stores more fields.
- The registration identifier is returned automatically and does not prove that the product meets the law (ESPR Art. 13(5)).
- Implementing Regulation (EU) 2026/1778, Art. 8 lists automatic checks: semantic conformity, mandatory-data consistency, granularity, commodity code, and back-up link.
- Under Art. 4, eID at assurance level high is a route only for sole traders established in the Union. Legal persons use a qualified electronic seal or a qualified attestation.
- Art. 9 defines a sealed proof of registration with a Commission timestamp and a passport-version hash. The mock RS256 JWT is a different artifact.
- Battery access (Annex XIII): the public gets point 1, notified bodies and market surveillance authorities point 3, and the Commission points 1, 2, and 3.
- Persons with a legitimate interest get points 2 and 4. The Art. 77(9) act that defines them is not adopted.
- ESPR Art. 10(4) requires a back-up copy through a DPP service provider. The Batteries Regulation has no back-up duty.
- Customs verify the registration identifier and commodity code (ESPR Art. 15). The EU CSW-CERTEX link is due within four years of 2026-08-06.
- The user guide is not law. It asks for an https UPI of at most 2,000 characters that resolves.
- The guide answers excessive redirects, protocol downgrades, and oversized responses with 'unable to process your request', not `NOT_RESOLVABLE_UPI`.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | The UPI is an EPC URN or a plain GTIN, which the EU registry rejects as an invalid URL. | Parse with an https URL scheme and a 2,000-character bound. |
| L03 | The live URL ignores `Accept` and always returns HTML, so a registry cannot hash or validate the data. | Request with `Accept: application/ld+json`; a `text/html` final answer fails. |
| L03 | The server negotiates but omits `Vary: Accept`, so caches serve the wrong representation. | Inspect `Vary` on each negotiated response. |
| L03 | A redirect chain downgrades from https to http, or it loops. | Record each hop with a bound; flag every downgrade. |
| L03 | `Content-Type` is `application/json+ld` instead of `application/ld+json` (a mock README example). | Exact media type match. |
| L03 | The renderer fetch proxy `GET /fetch/v1?url=` fetches any URL, also internal addresses. | Loopback probe with an internal address; expect a refusal. |
| L05 | Conditional battery attributes are absent because the consortium schemas make them optional. | A rules pack per battery category. |
| L05 | The search-key cache truncates UPIs longer than 36 characters (`VARCHAR(36)`), while the mock allows 200. | Register a long UPI in a loopback stack and search for it. |
| L06 | `backupURL` points at the same host or at the GS1 URL of the `upi` (OpenDPP sample). | Compare hosts and content of `liveURL` and `backupURL`. |
| L07 | Role `eu` can change registry and validator schemas under the observed path policies. | Write probes with an `eu` token; expect `403`. |
| L08 | `dppHash` covers a different representation or a different format, so it never matches. | Recompute SHA-256 per media type and compare. |
| L08 | The proof JWT verifies only through a JWKS on the same server. | Verify against a pinned trust bundle; report an issuer-trust failure. |
| L08 | The detached JWS key comes from a `jwksUri` claim that the caller controls. | Sign with a key at a loopback JWKS and observe acceptance. |
| L09 | An `ITEM` record has no `modelUpi` or no `deactivated`, or a `BATCH` record carries `batchUpi`. | Validate the record against the pinned mock schema. |
| L09 | One bad record rejects a whole file, and the operator reads it as partial success. | Not testable on the official registry; replay a recorded outcome in a mock. |
| L10 | A duplicate registration overwrites the earlier record (`MODIFY` default) and loses history. | Register the same UPI twice; inspect history and `registryId`. |

#### What the engine can test

The verdicts come from `x01-engine-mapping.json`. "Correct" means that the entry states the gap accurately, not that the check gives a verdict today. See [Capabilities](../reference/capabilities.md) for the registered capabilities.

| Test objective | Existing check (verdict from x01) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| The live URL serves JSON-LD or JSON under negotiation. | `identifier.resolve` (correct): set `accept` and `accepted_media_types`. | None | Loopback host with JSON-LD and JSON; `deploy-resources` stack. | loopback only |
| A bare browser request gets HTML. | `identifier.resolve` (correct): the default needs a JSON object and fails. | `resolver.conformance` (negotiation matrix, `Vary`) | Loopback host with HTML and JSON-LD. | loopback only |
| An enveloped VC is offered and verifies. | `integrity.jws` (wrong): it refuses `typ` `vc+jwt` and `cty`. | `integrity.jose_profiles` | `TEST-ONLY` ES256 key; signed and tampered samples. | sample artifact |
| The UPI has the form the registry accepts. | `identifier.parse` (correct). | `identifier.schemes` (`https-url-upi`, `epc-urn`) | Valid and invalid UPI strings. | sample artifact |
| The UPI passes the registry pre-checks. | `identifier.resolve` (correct): it does not judge downgrades. | `resolver.conformance` (registry preflight) | Loopback redirect chains with a downgrade. | loopback only |
| A registry record is well formed for its granularity. | `data.jsonschema` (wrong): it reads only item or model documents. | `data.document_source` | Vendored mock schema; positive and negative records. | sample artifact |
| The registry record agrees with its passport. | `registry.consistency` (correct): two fixed field pairs. | `registry.record_fields` | Loopback mock registry and passport host. | loopback only |
| The registry hash binds the exact representation. | None (correct). | `integrity.digest_binding` | Two representations; correct and wrong hashes. | loopback only |
| The proof of registration verifies. | `integrity.jws` (wrong): `x5c` keys only, `typ` `dpp+jws`. | `integrity.jose_profiles`; `trust.eu_trusted_list` for the official proof | `TEST-ONLY` RSA key; recorded proof JWTs. | sample artifact |
| The back-up copy is reachable and equivalent. | `identifier.consistency` (overstated): no back-up notion. | `persistence.backup` | Two loopback hosts, one with drift. | loopback only |
| Each battery access group gets its fields. | `access.restricted_fields` (correct). | None; needs a declared policy | Policy from the battery views; `TEST-ONLY` role tokens. | loopback only |
| A JSON-LD battery passport meets the SHACL profile. | None (correct): `data.shacl` is interface only. | `data.shacl` | Pinned shapes and repository fixtures, unchanged. The owner decides on rule 5 first (section 9.4). | sample artifact |
| JSON-LD contexts are known. | `data.context` (correct). | None; `persistence.scheduled` for availability over time | Allowlist of pinned context URLs. | sample artifact |
| Battery JSON validates against consortium schemas. | `data.jsonschema` (correct): not yet run on these schemas. | A `data.rules` pack for conditional elements | BatteryPass-Ready 2.0.1 schemas with attribution. | sample artifact |
| An AAS battery passport is valid. | `aas.validate` (correct): AAS 3.0 JSON only. | None | Battery Pass AASX samples. | sample artifact |
| Repository reads match a pinned contract. | `api.contract` (correct): `GET` only. | `api.write_ops` | Maintainer OpenAPI; Cir4Fun mock services. | loopback only |
| Updates are append-only and linked. | `persistence.versions` (overstated): no link between versions. | `integrity.digest_binding` (hash chain) | Version series with a broken link. | loopback only |
| Status and deactivation agree. | None (correct); a `data.rules` unit rule covers allowed values. | `lifecycle.status` | Samples before and after deactivation. | loopback only |
| Write and admin calls refuse wrong roles. | None (correct). | `api.write_ops` | `TEST-ONLY` Keycloak realm with three roles. | loopback only |
| A model-level discovery endpoint exists. | None (correct). | `resolver.well_known` (informative) | Loopback host with and without it. | loopback only |

No row needs a live system under test. The engine must not contact the official registry or its test site without a signed authorization.

#### Evidence and limits

- The family evidence is in `docs/research/raw/implementation-methods/m07-eu-reference-pilots.json`. The extra repositories come from `r01-repositories.json`, and the law from `m01-law-baseline.json`.
- The independent check (`m07-eu-reference-pilots.verification.json`) checked 39 units: 32 confirmed, 4 refuted, 3 not confirmed. This section applies its corrections.
- The check corrected the mock `ITEM` rule, the `java-dpp-sdk` tag, and the `data.jsonschema` mapping. It found four rule 5 risks; this section omits those passages.
- The Battery Pass 1.2.0 schemas are not fixtures here. Their descriptions refer to a protected document, so the owner must decide first.
- Open: the registry API, its hash input, its dereference thresholds, the meaning of mock role `eu`, and the BatteryPass-Ready license for fixtures.

### 5.12 Other twin and data-sharing stacks

This family groups twin and IoT data-sharing stacks other than the AAS. The stacks are NGSI-LD with FIWARE brokers, DTDL with Azure Digital Twins, W3C Web of Things (WoT), OPC UA, oneM2M, and BIM material passports. None of these stacks is a DPP standard. Each can supply the data model and the API of a passport host. Only OPC UA has a DPP-specific artifact, the companion specification OPC 30450-1.

Evidence of DPP use is weak and uneven. The family file found no NGSI-LD passport implementation. DTDL and WoT reach a passport through published bridges to the AAS. BIM material passports exist mostly as research prototypes.

#### Components

- **NGSI-LD context broker.** It stores entities with Property and Relationship attributes and exchanges them as JSON-LD over HTTP.
- **DTDL model and twin graph.** DTDL interfaces carry DTMI identifiers. Azure Digital Twins builds a twin graph from them.
- **WoT Thing Description (TD) and TD Directory.** A JSON-LD description of a device, served at `/.well-known/wot` or through `/things`.
- **OPC UA server.** An address space with ObjectTypes and DataTypes, optionally with an OPC 30450-1 model.
- **Bridge or gateway.** A tool that maps DTDL or TD to the AAS, or exposes OPC UA data as JSON.
- **BIM link.** A BIM element that refers to a passport record, with buildingSMART IDS and bSDD as requirement and dictionary layers.

#### End-to-end flow

This flow shows an NGSI-LD broker as the passport host. No stack in this family defines the carrier or the resolver step.

1. A reader decodes the carrier and gets a URL, for example a GS1 Digital Link.
2. A gateway maps the identifier to an entity id. No stack defines this step.
3. The operator publishes a JSON-LD context that maps passport terms to IRIs.
4. The operator sends `POST /ngsi-ld/v1/entities/` with the context in a `Link` header.
5. The broker answers `201` with a `Location` header.
6. A client calls `GET /ngsi-ld/v1/entities/{id}` and receives the passport entity.
7. The client expands the JSON-LD and checks the passport fields.
8. Integrity needs an envelope that the host adds, because the stack defines none.

#### How each layer works

| Layer | Mechanism | What a tester can observe |
| --- | --- | --- |
| L01 unique identifiers | NGSI-LD entity ids are URIs, for example `urn:ngsi-ld:...`. DTDL uses DTMIs for models. WoT TD has an optional `id`. | Entity id in the path and payload, and its match with the carrier identifier. |
| L03 data exchange protocols | NGSI-LD HTTP binding under `/ngsi-ld/v1/`. WoT Discovery uses `/.well-known/wot` and DNS-SD. OPC UA DPP access goes through REST interfaces. | Status codes, `Content-Type`, `Link` headers for context and `next`, and `Location` on create. |
| L04 APIs for lifecycle and search | NGSI-LD create, query, batch, and temporal operations. WoT TD Directory under `/things`. Azure Digital Twins query API. | CRUD behavior, pagination, filters, and error bodies. |
| L05 interoperability and data models | NGSI-LD entities, DTDL v4 interfaces, TD 1.1 documents, and OPC UA NodeSets. | `@context` values, expanded IRIs, schema validity, and passport fields. |
| L06 storage and persistence | Brokers keep current state. Some add history in PostgreSQL or TimescaleDB. | Earlier values through the temporal endpoint after an update. |
| L07 access rights and security | WoT TD lists security schemes such as `bearer` and `oauth2`. NGSI-LD core states no API authentication. | `401` and `403` behavior per role, and absent restricted attributes. |
| L10 lifecycle and versions | NGSI-LD history is a time series. DTDL versions models through the `;N` suffix of the DTMI. | Earlier states through the temporal API, and the model version in the DTMI. |

Notes on the mechanisms:

- NGSI-LD carries the context in a `Link` header with rel `http://www.w3.org/ns/json-ld#context`, or as `@context` in an `application/ld+json` body.
- In WoT Discovery, only the listing under `/things` is mandatory. CRUD, `/events`, and the `/search/*` endpoints are optional, so a test must probe first.
- The `/things` listing prefers `application/ld+json`. A TD uses `application/td+json`.
- A DTDL document must have an Interface at top level. The other element kinds occur only inside its contents.
- NGSI-LD "context source registration" is broker federation. It is not the EU registry.

#### Variants

- NGSI-LD normalized or simplified representation, and context in a header or in the body.
- DTDL v2 and v3 in Azure Digital Twins, and v4 in Azure IoT Operations.
- OPC UA binary sessions or a REST gateway with JSON in transit.
- TD Directory search through JSONPath, XPath, or SPARQL.
- BIM passport linked by QR code to a GS1 Digital Link (vendor report only).

#### Specifications and versions (status on 2026-10-19)

| Artifact | Version | Status | Source |
| --- | --- | --- | --- |
| ETSI GS CIM 009 NGSI-LD API | V1.9.1 (2025-07) | Group specification | [ETSI GS CIM 009](https://www.etsi.org/deliver/etsi_gs/CIM/001_099/009/01.09.01_60/gs_cim009v010901p.pdf) |
| W3C WoT Thing Description | 1.1 | Recommendation, 2023-12-05 | [WoT TD 1.1](https://www.w3.org/TR/wot-thing-description11/) |
| W3C WoT Discovery | Recommendation | Recommendation, 2023-12-05 | [WoT Discovery](https://www.w3.org/TR/wot-discovery/) |
| DTDL | v4 | Microsoft specification; no releases | [DTDL v4](https://github.com/Azure/opendigitaltwins-dtdl/blob/master/DTDL/v4/DTDL.Specification.v4.md) |
| OPC 30450-1 DPP Information Model | V1.0.0 (listing date 2026-10-17) | Status field blank; login to download | [OPC 30450-1](https://opcfoundation.org/developer-tools/documents/view/406) |
| oneM2M | Release 5 | Latest release with published features | [oneM2M specifications](https://www.onem2m.org/technical/published-specifications) |
| buildingSMART IDS | 1.0 | Approved 2024-06-01; announced 2024-06-04 | [IDS](https://www.buildingsmart.org/standards/bsi-standards/information-delivery-specification-ids/) |

- A search summary gave OPC 30450-1 as a Release Candidate of 2026-07-08. The independent check did not reproduce it, so the status stays open.
- The OPC 30450-1 listing cites EN 18223:2026, "Digital Product Passport - System interoperability" (CEN/CLC/JTC 24). This page records the citation only.
- ISO 16739-1, "Industry Foundation Classes (IFC)", is named here by number and title only.
- Brokers lag the NGSI-LD specification. Orion-LD states near-compliance with 1.6.1. Stellio states checks against 1.9.1.

#### Open-source implementations

| Name | Kind | License | Last activity |
| --- | --- | --- | --- |
| [Orion-LD](https://github.com/FIWARE/context.Orion-LD) | NGSI-LD broker | AGPL-3.0 | Pushed 2026-09-25; release 1.12.0 |
| [Scorpio Broker](https://github.com/ScorpioBroker/ScorpioBroker) | NGSI-LD broker | BSD-3-Clause | Pushed 2026-07-29; release 6.0.1-java-kafka |
| [Stellio](https://github.com/stellio-hub/stellio-context-broker) | NGSI-LD broker | Apache-2.0 | Pushed 2026-10-19 at re-check; release 2.38.0 |
| [opendigitaltwins-dtdl](https://github.com/Azure/opendigitaltwins-dtdl) | DTDL specification | CC-BY-4.0 and MIT | Pushed 2025-03-26; no releases |
| [node-wot](https://github.com/eclipse-thingweb/node-wot) | WoT SDK | EPL-2.0 or W3C Software Notice | Pushed 2026-10-16; release v0.9.2 |
| [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) | OPC UA SDK | Not stated (NOASSERTION) | Pushed 2026-10-19; release 2.0.1 |
| [open62541](https://github.com/open62541/open62541) | OPC UA SDK | MPL-2.0 | Pushed 2026-10-19; release v1.5.9 |
| [IfcOpenShell](https://github.com/IfcOpenShell/IfcOpenShell) | IFC toolkit | LGPL-3.0 | Pushed 2026-10-19 |
| [bSDD](https://github.com/buildingSMART/bSDD) | Dictionary service | MIT | Pushed 2026-10-07 |
| [lignum-dpp-bsdd](https://github.com/louistrue/lignum-dpp-bsdd) | Construction DPP demo with bSDD, QR, and IFC | None detected | Pushed 2026-03-31 |

#### Difference from the legal baseline

The law is protocol-neutral. The rows below use only the legal baseline in section 4.

- Regulation (EU) 2024/1781, Art. 2(30) needs an identifier that enables a web link. These stacks give only generic URIs or model ids.
- Art. 10(1)(b) needs a carrier. No stack defines one.
- Art. 10(1)(d) needs an open interoperable network and searchable data. The stacks give generic CRUD, not issue, supersede, or deactivate.
- Art. 10(4) needs a back-up copy through a DPP service provider. No stack supplies it.
- Art. 11(b) needs access by actor class. The stacks give authentication primitives only, not field-level tiers.
- Art. 11(g) needs authentication, reliability, and integrity. The stacks leave all of it to the implementer.
- Art. 11(d) needs a new passport to link to the original. No stack models that link.
- Art. 13 needs registry upload. No stack provides it.

#### Typical faults

| Layer | Fault | How a black-box test detects it |
| --- | --- | --- |
| L01 | Entity id does not match the carrier identifier. | Compare the carrier URL with the identifier attribute. |
| L03 | Server ignores the context `Link` header, or mixes JSON with `@context`. | Retrieve with both `Accept` types and compare headers and expanded terms. |
| L03 | Pagination `Link` with rel `next` is missing or wrong. | Query with a small `limit` and follow `next` to the end. |
| L04 | A second create with the same id returns `201` or overwrites. | Post the same id twice and expect the `AlreadyExists` error type. |
| L05 | The `@context` URL is outside the allowlist. | `data.context` flags it. Context drift needs a new pinned-digest check. |
| L05 | A TD is served as `application/json` only. | Request `/.well-known/wot` with `Accept: application/td+json`. |
| L07 | Notifications carry restricted attributes. | Subscribe as a low-privilege client and inspect the payload. |
| L10 | History is lost after a broker migration. | Compare temporal query output before and after a controlled update. |

#### What the engine can test

The engine mapping file `docs/research/raw/implementation-methods/x01-engine-mapping.json` has no rows for this family. The verdicts below come from the independent check of the family file.

| Test objective | Existing check (verdict) | New capability needed | Fixture or reusable suite | Network need |
| --- | --- | --- | --- | --- |
| Context signal in header or body | `data.context` (confirmed, allowlist only) | `api.header_contract` | Loopback NGSI-LD mock; no suite found | loopback only |
| Create then retrieve round trip | `api.contract` (not mapped; needs a pinned OpenAPI) | None if pinned | Pinned NGSI-LD OpenAPI, not located | loopback only |
| Passport fields in an entity | `data.context`, `data.jsonschema`, `data.rules` (not mapped) | `data.shacl` | Valid and invalid entity samples | sample artifact |
| DTDL model validity | None | `data.dtdl_validate` (new dependency) | Valid and invalid DTDL v3 and v4 | sample artifact |
| TD validity and media type | `data.jsonschema` (not mapped; TD schema not pinned) | `api.contract` for `/things` | Loopback TD Directory | loopback only |
| Restricted attributes per role | `access.restricted_fields` on `access.policy` (corrected) | Notification channel adapter | Mock broker with role filters | loopback only |
| Signed JSON-LD export | `integrity.jws` (confirmed) | None for JWS | `TEST-ONLY` key, tampered export | sample artifact |
| Entity id equals carrier id | `identifier.consistency` (confirmed) | `identifier.parse_urn` | URN and Digital Link pairs | sample artifact |
| Temporal history after update | `persistence.versions` (confirmed, experimental) | `persistence.temporal_adapter` | Mock broker with history | loopback only |
| OPC 30450-1 instance | None | `protocol.opcua_client` (new dependency) | Licensed specification not read | loopback only |
| IFC export against an IDS | None (`manual.review`) | `data.ids_check` (new dependency) | Project-written IFC and IDS samples | sample artifact |

#### Evidence and limits

- The evidence is in `docs/research/raw/implementation-methods/g03-other-twin-stacks.json` and its verification file. The independent check confirmed 22 of 26 claims.
- The independent check refuted two engine mappings. `data.context` fetches no context, and the access check runs on `access.policy` without a notification channel.
- The ESPR article numbers in the family file were not confirmed by the independent check. This section takes law from the legal baseline only.
- Open: the true status of OPC 30450-1, a pinned NGSI-LD OpenAPI, normative schemas for TD and DTDL, and any NGSI-LD passport profile.
- Not researched: oneM2M protocol detail, the OPC UA specification text, and the Azure Digital Twins API reference.

## 6. Cross-cutting topics

The topics below cut across the families. Each subsection compares the families on one group of layers.

### 6.1 Identifiers, granularity, and data carriers across families

This section compares layer L01 (unique identifiers) and layer L02 (data carriers) across the families. The status is on 2026-10-19. The "Engine support today" columns use the verdicts of the engine mapping in `docs/research/raw/implementation-methods/x01-engine-mapping.json`, not the raw `existing_check` values of the family files.

The engine mapping covers the family files m01 to m10 only. It has no rows for `docs/research/raw/implementation-methods/g02-carrier-embedded-data.json`. Engine statements that come only from that file rest on its independent check against the code, not on a mapping verdict.

#### What the law asks for

The law defines roles, not syntax. ESPR Art. 2(30) defines the unique product identifier as a unique string that also enables a web link to the passport. Art. 2(31) and Art. 2(33) define the unique operator identifier and the unique facility identifier.

The product identifier must be persistent and linked to the passport through the data carrier (ESPR Art. 10(1)(a)). Art. 10(1)(c) and Annex III name the ISO/IEC 15459 series or equivalent standards until harmonized standards are cited. This page names that series only by number.

ESPR Art. 2(29) defines a data carrier as a linear bar code symbol, a two-dimensional symbol, or another device-readable capture medium. It must be physically present on the product, its packaging, or its documents (Art. 10(1)(b)). Each delegated act sets the carrier type, layout, and position (Art. 9(2)(b)-(c)) and the model, batch, or item level (Art. 9(2)(d)).

The operator gives dealers and online marketplaces a free digital copy of the carrier or identifier within five working days of a request (Art. 10(3)). The delegated act on issuing agencies and self-created identifiers under Art. 12(4) was not located.

For batteries, every battery bears a QR code from 18 February 2027 (Batteries Art. 13(6)). The QR code gives access to the passport only for LMT, industrial above 2 kWh, and EV batteries.

The battery QR code is printed or engraved visibly, legibly, and indelibly (Art. 13(7)). Annex VI Part C asks only for high contrast and a size that common hand-held readers decode. It names no symbology. Art. 77(3) has the operator attribute the unique identifier.

The registry adds a fourth identifier: a persistent registration identifier that it returns after a successful registration (ESPR Art. 13(5); Implementing Regulation (EU) 2026/1778, Art. 8(8) and (10)). Item-level registrations link to batch and model identifiers where these exist (Art. 8(1)-(5)).

The registry user guide v1.03 is not binding. It requires the unique product identifier to be an `https://` URL of at most 2000 characters. Implementing Decision (EU) 2026/1736 cites EN 18219:2026 *Digital product passport - Unique identifiers* and EN 18220:2026 *Digital product passport - Data carriers*. Their content is protected and is not used here.

#### Identifier schemes and granularity

Table 1 shows which identifier form each family uses and how it expresses model, batch, and item level. Law sets the three levels; the scheme comes from the family.

| Family | Identifier form | Model, batch, item | Operator and facility identifiers | Engine support today |
| --- | --- | --- | --- | --- |
| Plain web passport | An HTTPS URL on an operator host. The URL is the passport address, or a GS1 Digital Link shape without a conformant resolver. | Separate model and item URLs occur. The method adds no granularity syntax. | Not researched. | `identifier.parse` knows one GS1 path form only. An opaque URL fails that form. A generic `https-url` scheme is a gap. |
| GS1 web resolver | GS1 Digital Link URI: `/01/{GTIN-14}` with qualifiers in the fixed order 22, 10, 21. Shorter GTINs are padded to 14 digits. | Model: GTIN, or GTIN plus AI 22. Batch: GTIN plus AI 10. Item: GTIN plus AI 21. | Party GLN (AI 417) for the operator. GLN (AI 414) for a facility. | `identifier.parse` accepts only `/01/{gtin}/21/{serial}`. It checks the GTIN check digit only. Proposed: `identifier.gs1_grammar`. |
| AAS digital twin | `globalAssetId`, as an HTTP(S) ID Link or an IRI or URN, plus `specificAssetIds`. IDTA 02099-1 adds `uniqueProductIdentifier`. | IDTA-01001 3.2 maps the 02099-1 granularity string to AssetKind Type, Instance, or Batch. Batch is new in 3.2. | `economicOperatorId` and `facilityId` are plain strings without IDTA syntax. | `identifier.consistency` reads the top-level key `id` only. `aas.validate` reports metamodel validity only. Proposed: `identifier.subject_pointer`. |
| Dataspace (Catena-X) | Twin id as `urn:uuid`. Specific asset ids `manufacturerPartId` and `partInstanceId`. | Type twin: part number only. Instance twin: part number plus `partInstanceId`. Batch: not researched. | BPNL, BPNS, BPNA: 16 characters with two check characters. DIDs identify participants in the protocol. | No BPN scheme in `identifier.parse`. A JSON Schema `pattern` in `data.jsonschema` can check BPN structure in the passport. |
| Verifiable credentials (UNTP) | Product `id` URI with `idScheme` and `idGranularity` in UNTP 0.7.0. The credential has its own `id`. | `idGranularity` takes model, batch, or item in the UNTP 0.7.0 schema. | Issuer DIDs (`did:web`, `did:webvh`). An identity anchor credential binds a DID to a registered id. | No DID handling. `identifier.consistency` reads the credential `id`, not the product `id`. Proposed: `identity.did`. |
| EPCIS events | EPC URNs or a constrained set of GS1 Digital Link URIs. Event ids are UUID URNs or `ni:` hash ids. | `urn:epc:id:sgtin` names an item. Class URNs such as `urn:epc:class:lgtin` also occur. | SGLN for locations and PGLN for parties. | No EPC URN scheme today. Proposed in `identifier.schemes`. |
| Linked data | The product IRI, often equal to the Digital Link URI. A separate passport node is common. | Model nodes typed by a vocabulary module occur in CIRPASS-2 examples. | Not researched. | `identifier.consistency` reads the key `id` only. |
| Ledger-anchored | The legal identifier stays a URL. The ledger adds token references, DIDs, and content ids. | Prototypes map a serial to a `tokenId`. | DIDs such as `did:ebsi` for legal entities. | No ledger reference parser. A JSON Schema `pattern` gives partial syntax coverage. |
| Platforms and sectors | GS1 Digital Link at all three levels, `did:web`, BPN, NFT token ids, and RFID ids. | All three levels occur on GS1 platforms. | Not researched per platform. | A declared non-GS1 scheme gives `unsupported`, not a syntax failure. |
| Hybrid stacks | One identity across layers, from several families. Examples: `urn:uuid` twin ids, ID Link URLs, Digital Link URIs. | Depends on the family that supplies layer L01. | BPNL and BPNS in Catena-X battery data. | Same limits as the source families. |
| EU reference pilots | Registry: an `https` URL. Mock registry: a free string `upi` of 1 to 200 characters. | Mock registry: an ITEM record requires `deactivated` and `modelUpi`; `batchUpi` is optional. | Mock registry `reoId` and `facilitiesId` are free strings. | `registry.consistency` compares the identifier. Granularity links are new: proposed `registry.record_fields`. |
| Other twin stacks | NGSI-LD entity URIs, DTDL model ids, service-scoped twin ids. No form matches GS1 Digital Link. | Not defined. The passport must carry the unique product identifier as an attribute. | Not researched. | No scheme today. |

Table 1 notes:

- The GS1 serial (AI 21) allows 1 to 20 characters from a set of 82. The engine serial set `[A-Za-z0-9._-]` is narrower, so the engine can reject valid GS1 serials.
- The LEI has 20 characters: a prefix, two reserved zeros, an entity part, and two check digits. LEIs issued before 30 November 2012 do not follow the prefix rule. An LEI can move to another issuer without a code change.
- The EORI number is a two-letter country code plus up to 15 characters. One valid EORI exists per person, and numbers do not expire.
- UNTP proposes the form `uuid:{UUID}`, not the RFC 9562 form `urn:uuid:{UUID}`.
- UNTP suggests UUIDs where hard-to-guess values help limit item-data visibility. RFC 9562 warns against reliance on UUID unguessability for security.
- Catena-X makes `digitalTwinType` (PartInstance or PartType) mandatory in CX-0143 1.4.0. Version 1.4.0 is current on CX-Titan. Version 1.5.0 is on GitHub main.
- IDTA 02099-1 shows 1.0 on the content hub and 1.0.1 on the docs site. The repository folder is `1/0/2`. Pin by folder and SHA-256 digest.

Granularity is testable only as a comparison. The ICS already has a granularity field, but no check reads it against the carrier. The proposed `identifier.granularity` compares the carrier qualifiers and the AAS `assetKind` with `ICS.granularity`.

Global uniqueness and issuance authority are not observable from outside. A test can see a collision within one sample set or one registry answer, not more.

#### Physical carriers

Table 2 lists the carriers that the family files name. "Capacity" holds only the limits that the input files state. Other limits were not researched.

| Carrier | Payload | Capacity | Reader | Engine support today |
| --- | --- | --- | --- | --- |
| QR Code with a URL | Digital Link URI, ID Link URL, operator URL, DID, or `CX:<part id>:<instance id>` text in Catena-X reference apps. | GS1 guidance says URI length drives symbol size. Numeric limits not researched. | Phone camera. Battery law fixes this carrier. | `carrier.qr_decode` (capability `carrier.qr`, extra `qr`) requires exactly one readable QR symbol with text. A second symbol beside it fails the decode. |
| Data Matrix or GS1 DataMatrix | A Digital Link URI, or element strings marked by FNC1 with no web link. | Smaller than QR and rectangular-capable, per GS1 in Europe. Numeric limits not researched. | Not read natively by consumer phone cameras, per GS1 in Europe. Scanners read it. | No check. zxing-cpp 3.1.1 exposes Data Matrix and `symbology_identifier`. Proposed: `carrier.symbols`. |
| Data Matrix by direct part marking | Marked on the part by laser, dot peen, or casting. | Not researched. | Industrial reader. One study reports 89.36 percent readability on low-contrast polymer parts after a re-encoding network. | No check. Same proposal as Data Matrix. |
| Linear EAN/UPC | GTIN only: model level, not web-resolvable. | Not researched. | Retail scanner. | No check. Proposed: `carrier.symbols`. |
| NFC tag, static NDEF | A URI record (type `U`). Byte 0 is a prefix code, for example `0x04` for `https://`. | Tag memory not researched. | Phones read it natively. GS1 in Europe says NFC is not yet an approved GS1 carrier. | `carrier.nfc` is `interface_only` and needs a reader. Proposed: `carrier.ndef_sample` for offline dumps. |
| NFC secure dynamic message (NXP NTAG 424 DNA) | The tag writes encrypted UID and tap counter data and a truncated CMAC into the URL on each read. | Vendor-specific (NXP application note AN12196 Rev. 2.0). | Phone, plus a brand backend that holds the key. | No check. The installed `cryptography` package provides CMAC. Proposed: `carrier.nfc_sun`. |
| UHF RFID, EPC bank | EPC binary: header, filter, partition, company prefix, item reference, serial. TDS 2.3 adds `+` and `++` schemes. | The SGTIN-96 serial is a 38-bit integer up to 274,877,906,943, with no leading zeros. | Gen2 reader, not a phone. | `carrier.rfid` is `interface_only`. Proposed: `carrier.epc_decode` for offline hex samples. |
| Hybrid UHF/NFC tag, compressed URI | `{stem}/eh{hex}` or `{stem}/ex{base64url}` that holds an EPC binary string. | GS1 limits compressed URIs to closed systems. | NFC phone, then software decodes. | No check. Proposed in `identifier.gs1_grammar`. |
| Digital watermark | A GS1 key repeated invisibly across the artwork. | GS1 says the payload is limited. | Image, IR, or UV capture. Some technologies need a license. | No check today. |
| Signed payload in a 2D code | Precedents outside DPP: EU DCC, ICAO visible digital seals, SMART Health Cards. | SMART Health Cards use QR versions up to 22. | App with pinned trust material. | `integrity.cose` is `interface_only`. `integrity.jws` has no numeric-QR handling. No seal check. |

Table 2 notes:

- GS1 marks GS1 content by FNC1 in GS1-128, GS1 QR Code, and GS1 DataMatrix. GS1 DotCode marks it by the absence of FNC1. A Digital Link URI marks itself by its pattern.
- The SGTIN-96 serial cannot hold an alphanumeric or a leading-zero serial. The RFID serial and the QR serial of one product can then differ.
- The TDS 2.3 `++` schemes add a lossless binary encoding of the brand domain. A reader can then rebuild a non-canonical Digital Link URI.
- For the free digital copy of ESPR Art. 10(3), the engine mapping marks the claimed check pair as overstated. `identifier.consistency` compares the QR text with the declared sample identifier only after a JSON passport returns `200`.
- Otherwise `identifier.consistency` gives `blocked`. The check reads one image, so it does not compare two carriers directly.
- Physical presence, placement, contrast, and durability need an inspector. They go to `manual.review`, and the engine does not grade print quality.

Several families put more than one carrier on a product. Examples are linear plus 2D codes in retail, QR plus NFC, and label plus RFID. The proposed `carrier.symbols` and `identifier.equivalence` would compare the keys of all carriers on one sample.

#### Data on the carrier itself

In most families the carrier holds only a pointer. The carrier-embedded data file describes three places where data travels with the product instead.

The first place is the URI query string. GS1 Digital Link puts data attributes in the query as `AI=value` pairs, while the identity stays in the path. In the GS1 AI dataset 1.2, AI 17 (expiry date) is valid as a data attribute, and AI 21 is not.

AI 8030 carries a digital signature of up to 90 characters. It requires a serialized key, such as GTIN plus serial. Extension keys must not be all-numeric. The keys `linkType` and `context` are reserved for resolvers.

The second place is an NFC message with several records. Android dispatches on the first record only. Apple's page says that iOS background reading uses the first URI record found and states no position rule.

A URI record at position 0 therefore satisfies both platforms. No DPP rule on this was located, so a multi-record profile would be engine-defined. A data record placed first fails on Android only.

The third place is RFID memory. TDS 2.3 defines `+AIDC data` after the EPC and attributes in user memory, with a slot for an AI 8030 signature. This page omits their layouts under the rule 5 fence.

The signature scheme behind AI 8030 is ISO/IEC 20248, named here by number only. A cryptographic check of it is therefore "not run".

Signed payloads in 2D codes have precedents outside the DPP domain. The EU Digital COVID Certificate (HCERT 1.0.8) chains CBOR, COSE_Sign1, zlib, and Base45 behind the prefix `HC1:`. ICAO visible digital seals carry a raw signature, usually in a Data Matrix, with ECDSA recommended.

No EU binding text asks for offline data, an embedded hash, or a signed carrier payload. The 2024 draft standardization request listed optional control data and six optional offline basic data elements. The adopted request text was not read.

The only binding passport hash is in the registry's proof of registration (Implementing Regulation (EU) 2026/1778, Art. 2(16) and Art. 9(2)). No algorithm or canonical form is published. A carrier control hash therefore cannot be compared deterministically with it today.

Embedded data adds failure modes. Offline data can go stale after a passport update. A public NFC record can leak restricted fields. A tag can hold a different serial than the label.

#### Carrier-to-passport binding and its limits

The binding between a carrier and a passport is digital. The family files show three patterns, each with a different strength.

| Pattern | Example | What a check can show | Engine support today |
| --- | --- | --- | --- |
| Identifier equality | Carrier text equals the passport `id`, the registry record, and the resolver linkset. | The digital records agree. | `identifier.consistency` compares exact text. Proposed: `identifier.equivalence` for canonical forms. |
| Signed target or payload | JWS or credential targets; signed 2D payloads. | The key holder signed the data. | `integrity.jws` covers one ES256 profile. Other profiles give `blocked`. |
| Dynamic tag | NFC secure dynamic messages with a per-tap CMAC over UID and counter. | A tag with the key made a fresh message. A replayed URL fails the counter test. | No check. Proposed: `carrier.nfc_sun` with TEST-ONLY keys. |

None of these patterns proves physical authenticity. A valid signature on a static code proves the origin of the data, not that the code is on the genuine item.

Static QR, NDEF, and EPC data can be copied, and a copied signed code verifies everywhere. GS1 states that any optical carrier can be copied, so the carrier itself cannot be authenticated.

A genuine tag can also be moved to a counterfeit product. The SUN CMAC is symmetric, so only the key holder can verify it. An issuer key leak lets forged payloads verify, as a dark-web study of forged EU DCC payloads shows.

Research directions exist but are not digitally testable from a file. Examples are copy-detection QR patterns and RF fingerprints of NFC tags.

A conformance test report must therefore state the limit. Digital consistency between carrier, passport, registry, and linkset is not evidence that the item is genuine.

The engine can test most of the digital chain offline from sample artifacts. It can decode an image, parse a dump, check syntax and check digits, and compare identifiers and granularity.

Today it covers QR decoding, one GS1 Digital Link form, and exact-text comparison. See [the capability reference](../reference/capabilities.md) for the current states.

### 6.2 Integrity, trust, and access control across families

This section compares layer L08 (authentication, reliability, and integrity) and layer L07 (access rights, security, and confidentiality) across the families. The status is on 2026-10-19. The "Engine support today" column uses the verdicts of the engine mapping in `docs/research/raw/implementation-methods/x01-engine-mapping.json`, not the raw `existing_check` values of the family files.

#### What the law asks for

The law states outcomes, not mechanisms. Data authentication, reliability, and integrity must be ensured (ESPR Art. 11(g); Batteries Art. 78(g)). ESPR Art. 11, fourth subparagraph, lets the Commission adopt implementing acts on digital credentials of actors with access rights. The legal baseline located no such act.

Concrete cryptographic means exist only at the registry. Implementing Regulation (EU) 2026/1778 Art. 9 gives a proof of registration with a hash of the passport version. A qualified electronic seal guarantees the proof, and a Commission time stamp validates the registration time. Art. 2(16) defines the hash but names no algorithm.

Registry users are verified under Art. 4 of the same regulation. Legal persons use a qualified electronic seal or a qualified attestation of attributes. Identification at eID assurance level high is a route only for sole traders established in the Union.

Access is tiered by actor. ESPR Art. 11(b) gives free and easy access to listed actors according to access rights that delegated acts set.

For batteries, Annex XIII gives point 1 to the public and point 3 to notified bodies and market surveillance authorities. The Commission gets points 1, 2, and 3, and persons with a legitimate interest get points 2 and 4. The Art. 77(9) implementing act that defines persons with a legitimate interest was not located.

For toys and detergents, consumers need no registration or password, and tracking beyond strict need is not allowed.

#### Integrity and trust options

| Option | Families | What it proves | What it does not prove | Engine support today |
| --- | --- | --- | --- | --- |
| TLS only | Plain web, GS1 resolver, dataspace, AAS (most deployments), other twin stacks | The client talks to the host that holds the certificate. | Integrity after download. A copy at a back-up or a cache cannot be checked. | No check produces an integrity finding from TLS alone. |
| Separate JWS over the passport JSON | Plain web (reference system `/dpp/{id}/signed`), back-up and failover, GS1 resolver (`gs1:jws` link) | The holder of the signer key signed these exact bytes. | That the signed attributes are true. That the HTML view equals the signed data, without a parity check. | `integrity.jws` verifies one profile: ES256, `typ` `dpp+jws`, key from an `x5c` chain. Any other profile gives blocked. |
| AAS signed endpoints (`$signed`) | AAS digital twin (v3.2 service profiles) | The signer certificate in `x5c` signed the AAS, submodel, or concept description payload. | Revocation status; none is specified. The binding of the AAS to the physical asset. | Blocked: the profile uses RS256 and `sigT` and `sid` headers, which `integrity.jws` refuses. |
| AASX package signatures | AAS digital twin | The signer covered the listed package parts and relationships. | The content of parts outside the signature. | No check today. Proposed: `integrity.opc_signature`. |
| VC-JOSE-COSE, enveloped (`vc+jwt`, `vc+cose`) | Verifiable credentials (UNTP default), EU pilots (CIRPASS-2 D4.1, OpenDPP), hybrid stacks, dataspace (DCP credentials) | The issuer key, found through `kid`, `iss`, or `cnf`, signed the credential. | That the claims are true or complete. That the issuer is the operator named in the passport. | Blocked: `typ` `vc+jwt` and `cty` are refused, and keys come from `x5c` only. Proposed: `integrity.jose_profiles` and `identity.did`. |
| VC Data Integrity (`DataIntegrityProof`) | Verifiable credentials, linked data, platforms (Transpareo), EPCIS (OpenDPP event ingest) | The verification method of the issuer signed the canonical form, under the expected proof purpose. | Stability when a remote JSON-LD context changes; the proof then breaks. Truth of the claims. | No check reads Data Integrity proofs. Proposed: `integrity.data_integrity`, JCS suites first, RDFC suites later with pinned contexts. |
| SD-JWT (`vc+sd-jwt`) | Verifiable credentials, EU pilots (D4.1, OpenDPP validator) | The issuer signed the disclosed claims; the holder chose which claims to show. | Anything about claims that the holder did not disclose. | No check. No proposed capability in the engine mapping names SD-JWT. |
| COSE_Sign1 in a carrier | Carrier-embedded data (no independent check of this file), verifiable credentials (proposal) | The signer key signed the embedded payload, readable offline. | That the code sits on the genuine item. Copied codes verify everywhere. | `integrity.cose` is `interface_only`. The engine mapping does not cover the carrier family file. |
| Bitstring Status List | Verifiable credentials, dataspace (DCP profiles), platforms | The issuer has or has not set a revocation or suspension bit. | Anything when the list cannot be retrieved. EU law does not require status lists. | `evidence.status_list` verifies a signed list file that the operator supplies. `integrity.status_list` is `interface_only`. |
| JAdES or qualified seals on passport data | EU pilots (D4.1 names optional JAdES profiles, bibliographic only) | A qualified seal links the data to an identified legal person. | That law requires it. The law names a qualified seal only for the registry proof. | No check. Proposed: `trust.eu_trusted_list` with a pinned EU trusted list snapshot. |
| Registry proof of registration | Law baseline, EU pilots, back-up and failover, carrier-embedded data | The registry recorded a hash of a passport version at a sealed, time-stamped moment. | Which bytes were hashed, or how. Art. 2(16) names no algorithm and no canonical form. | `registry.consistency` compares two field pairs only. The CIRPASS-2 mock proof, an RS256 JWT with a JWKS key, gives blocked under `integrity.jws`. |
| Ledger anchor (digest, Merkle root, token imprint) | Ledger-anchored, EPCIS (event hash anchors), platforms, other twin stacks (research) | A digest existed at a ledger time, and a sender account or DID wrote it. | That the data were true when written. The legal baseline shows no legal presumption for an ordinary ledger anchor. | No check. Proposed: `integrity.digest_binding`, `integrity.ledger_proof`, `integrity.issuer_binding`, and `ledger.read`. |
| EPCIS Event Hash ID | EPCIS event traceability | The served event matches a canonical fingerprint in its `eventID`. | Authorship. CBV states that a signature must be added against tampering. | Not in the engine mapping. The capability reference lists no matching check. |
| NFC SUN message | Identification carriers | A tag with the shared AES key produced this tap, with a fresh counter. | Anything to a party without the key. That the tag is attached to the genuine product. | No check. Proposed: `carrier.nfc_sun`. |

Some rows need notes. The DCP self-issued ID token of the dataspace family is party authentication, not document integrity. The engine mapping marks it as blocked under `integrity.jws`, so no partial signature finding results. In the Catena-X aspect models that the dataspace file read, the passport payload carries no signature.

The verifiable credentials file records the UNTP 0.7.0 profile. It requires the JOSE enveloping proof, `did:web`, and the Bitstring Status List. The work-in-progress rule that issuers produce JOSE or COSE and verifiers verify both is marked Proposed, not normative. The independent check refuted the earlier "MUST" wording of that rule.

For the ledger family, the eIDAS 2 presumption for qualified electronic ledgers comes from the ledger family file. The legal baseline does not cover it, so treat it as "(family file; not verified)". The independent check of the ledger file did not confirm the EBSI timestamp encoding details. Do not build fixtures on them yet.

#### Access-control options

| Option | Families | What it proves | What it does not prove | Engine support today |
| --- | --- | --- | --- | --- |
| Open web, anonymous public tier | Plain web, GS1 resolver, verifiable credentials (UNTP linkset), identification carriers | Anyone can read the public data with no login. | That restricted data stay hidden on every channel. That tracking is "strictly necessary"; that is a legal judgment. | `access.restricted_fields` (capability `access.policy`) probes five channel kinds for leaks of withheld paths. For a role with no entitled path, it asserts no `401` or `403`. |
| Role-based tokens (OAuth 2.0, OIDC, API keys) | Plain web, EPCIS, AAS (BaSyx RBAC), EU pilots (CIRPASS-2 Keycloak roles), platforms, other twin stacks, back-up and failover | The server binds a token to a role and filters the response for that role. | How the token was issued. Whether the role matches a legal actor group. | Supported for static test tokens sent as `Authorization: Bearer`. A refusal fails only for a role with entitled paths. Token flows are proposed as `access.credential_acquisition`. |
| AAS attribute-based rules (IDTA-01004 Access Rule Model) | AAS digital twin | The server allows an action only when a rule matches token claims, global attributes, or AAS values. | That the rules express the legal tiers. IDTA gives a rule language, not a policy for those tiers. | Partial. One template per channel kind, and no POST, so `/query` is not probed. Proposed: `access.channel_extensions`. |
| ODRL and dataspace contracts | Dataspace (Catena-X, Eclipse DSP and DCP), hybrid stacks, EU pilots (CIRPASS D3.2 proposal), linked data (research) | Only onboarded members with the right credentials and an agreed usage purpose reach the data. | Free public access. A pure dataspace stack has no public tier and no role for authorities outside the dataspace. | No check judges policies. A pure dataspace system under test gives no resolvable URL, never pass. Proposed: `dataspace.protocol_probe` on a loopback dataspace. |
| Credential presentations (DID-Auth, OpenID4VP, DIA in a presentation) | Verifiable credentials (UNTP decentralized access control), EU pilots (D4.1), hybrid stacks (Battery Pass guidance) | The requester controls a DID and holds an anchor credential that carries the required role scope. | That the UNTP role URIs map to EU actor groups. They are not mapped. | No check. Proposed: `access.credential_acquisition` with a holder simulator on loopback. |
| Encrypted targets and keys on the label | Verifiable credentials (UNTP) | Only a holder of the symmetric key can read the target. | Confidentiality when the key travels in the carrier URL, server logs, or `Referer` headers. | No check. Proposed: `access.encrypted_target` with `TEST-ONLY` keys. |
| Unguessable identifiers | Verifiable credentials, identification carriers | Item data are harder to list in bulk. | Security. RFC 9562 warns against reliance on UUID unguessability. | No check. A tester can flag sequential identifiers in a sample set. |
| Ledger permission models and private collections | Ledger-anchored, platforms (Circulor) | Only members or allow-listed identities can write or read the private data. | That public calldata, events, or token metadata hold no restricted data or personal data. | No check. Proposed: `access.public_payload_leak` and `persistence.erasure`. |

The engine sends role credentials only as a Bearer header. Roles that a request header asserts, such as `Edc-Bpn` in the dataspace family, need a transport change.

Two details matter for test design. First, the independent check of the verifiable credentials file refuted one field name in it. The schema names are `idScheme` and `registrationScope`, while the access-control page says `registrationScopeList`. A tester should record that mismatch as a finding.

Second, the identification carriers file says UNTP uses UUIDs as a shared secret. The independent check did not confirm that wording. The safe statement is narrower: UNTP suggests hard-to-guess UUIDs to limit item-data visibility, and RFC 9562 warns against that reliance.

#### What the engine can verify black-box

The engine can verify these items from the outside, with pinned trust material and no manual step:

1. A compact JWS of the `dpp+jws` profile, with ES256 and an `x5c` chain, through `integrity.jws`.
2. Signature validity, issuer trust, and certificate validity, as separate findings of that check.
3. A signed status list file that the operator supplies, through `evidence.status_list`.
4. Leaks of withheld paths for each declared role, on five channel kinds, through `access.restricted_fields`.
5. Refusal of a role that has entitled paths, which fails with `ACCESS.ENTITLEMENT.REFUSED`.
6. Equality of two field pairs between a registry record and the passport, through `registry.consistency`.

The proposed capabilities would extend black-box coverage. Most need only a sample artifact or a loopback fixture. Examples are other JOSE profiles, Data Integrity with JCS suites, DID key resolution, digest binding, offline ledger inclusion proofs, and NFC SUN messages. The engine mapping gives sizes as estimates from code review, not measurements.

#### What needs a manual step or a declaration

These items need a manual step, an IXIT declaration, or live access that the engine does not have:

1. The access policy. Until the Art. 77(9) act and delegated acts exist, use the policy that the system declares.
2. Test credentials for each role, issued by the operator. The engine sends static tokens only.
3. The hash input and algorithm of the registry proof. The law names neither, so a comparison needs a declaration.
4. Validation of qualified seals and time stamps. This needs a pinned EU trusted list snapshot and a new capability.
5. Root certificates that partners exchange out of band, as in AAS `$signed`. The IXIT must supply them.
6. Ledger finality and current contract state. These need live, allow-listed ledger access.
7. Whether tracking is strictly necessary on the consumer view. That is a legal judgment.
8. Physical authenticity of the item and the tag. No digital check can prove it.
9. Truth of signed claims. A valid signature proves who signed the bytes, not that the claims are true.

The engine records an unexecuted check as "not run" and an unavailable adapter as `unsupported`, never as pass. A JWS of an unsupported profile gives blocked, not a partial finding. A conformance test report states these results as such.

Two engine limits affect access tests directly. The transport redaction removes `Set-Cookie` values and most other response header values. A tracking probe therefore needs an infrastructure change, not only adapter code. The resource names are a closed list in a protected model file, so new endpoints for back-up copies or linksets need a contract change.

### 6.3 Persistence, back-up, lifecycle, and registry interaction

This section compares layers L06 (storage and persistence), L10 (lifecycle and updates), and L09 (registry and customs) across the families. The status is on 2026-10-19. The engine columns use the verdicts in `docs/research/raw/implementation-methods/x01-engine-mapping.json`, which cover the files m01 to m10 only.

#### What the law asks for

The law fixes duties and goals, but no interface. The economic operator or an authorized DPP service provider stores the passport (ESPR Art. 11(c); Batteries Art. 78(c)).

The ESPR adds a back-up copy through a DPP service provider at the time of placement on the market (Art. 10(4)). Manufacturers and importers ensure that the back-up holds the most up-to-date version (Art. 27(1)(c), Art. 29(2)(c)). Annex III point (l) lets the passport carry the reference of the provider that hosts the back-up.

Toys and detergents copy the back-up duty (Regulation (EU) 2025/2509 Art. 19(13); Regulation (EU) 2026/405 Art. 21). The Batteries Regulation has no back-up-copy duty in Art. 77 or Art. 78, only the continuity rule of Art. 78(e).

Passports stay available for the period that delegated acts set, also after insolvency, liquidation, or cessation of activity in the Union (ESPR Art. 11(e); Batteries Art. 78(e)). Toys and detergents set 10 years. For construction products, Regulation (EU) 2024/3110 Art. 75(2) sets 25 years for the system and at least 10 years per passport. A battery passport ends after recycling (Batteries Art. 77(8)).

A new passport for a product that already has one links to the original (ESPR Art. 11(d); Batteries Art. 77(7)). The law sets no version format, no hash chain, and no synchronization interval for the back-up.

Implementing Regulation (EU) 2026/1778 adds registry rules:

- Art. 8(7)(e): the Commission checks, where relevant, that the back-up link is valid. The act gives no method.
- Art. 8(9)(c): the registry stores a service-provider reference, where relevant.
- Art. 10: the registry logs and versions every change with a Commission time stamp.
- Art. 10(3): the registry deletes registration data 10 years after registration, unless Union law sets another period.
- Art. 6a: a registered passport can move to another verified operator, also after cessation.
- Art. 15(2) and Art. 15(3): the registry is available at all times except maintenance; Art. 15(3) allows unannounced suspension.

The registry has been operational since 2026-07-20. The user guide v1.03 (last published 2026-09-16) shows Batteries pre-selected at item level. It also states that successful registration of battery passports is not yet possible, because the semantic catalogue is not yet defined.

The form and its error list show no back-up input, so nobody can observe the Art. 8(7)(e) check yet. The delegated act on DPP service providers is not adopted, and the Commission has published no draft. The call for evidence planned it for Q1 to Q2 2026. The Have Your Say API says Q4 2026, and the Commission timeline says Q2 or Q3 2027.

#### Storage, back-up, and failover by family

| Family | Where the passport lives | Back-up copy | Route when the primary host fails |
| --- | --- | --- | --- |
| Law baseline | Operator or DPP service provider. | Required by the ESPR, toys, and detergents. Not required for batteries. | Not fixed by law. |
| Back-up and failover | Primary at the operator or a provider; copy at a provider. | Catena-X `backupReference`, CIRPASS-2 mock `backupURL`, BatteryPass-Ready Backup module after each write. | Proposals only; see the next table. |
| Plain web | Static files, a CDN, or an application server. | The method does not say how a client reaches it. | None. A 404, a DNS failure, or an expired certificate ends access. |
| GS1 resolver | The resolver stores links, not passports. | No back-up, archive, or mirror link type among the 60 link types read. | Host substitution or a registry of last resort (GS1 in Europe proposals). |
| AAS digital twin | Operator AAS and Submodel Repository. | No IDTA mechanism. An AASX package is a portable copy. | None specified. |
| Dataspace | Provider submodel server behind its own connector. | DPP aspect 7.0.0 has a required free-text `backupReference`. No Catena-X standard was found that mandates 7.0.0. | No protocol. The CX-0160 preview puts a synchronized copy in a separate EU-side system. |
| Verifiable credentials | Issuer files or the UN/CEFACT storage service. | Any copy stays verifiable while the issuer key and the status list stay reachable. | None. A `did:web` document keeps no history. |
| Ledger-anchored | From full data on chain to a hash only. | The ledger replicates the anchor, not the off-chain document. | None. IPFS availability depends on a pin service. |
| EU pilots | Operator repository; the mock registry holds `liveURL` and `backupURL`. | BatteryPass-Ready Backup and Deletion modules. | CIRPASS D3.2 default EU resolver (proposal). |
| Linked data | Document stores, triplestores, or Solid pods. | No back-up rule. Contexts and vocabularies must also stay resolvable. | None. |
| EPCIS event traceability | An event repository that acts as an append-only log. | EPCIS sets no retention, back-up, or availability rule. | None. |
| Hybrid stacks | Operator repository plus a third-party back-up. | Battery Pass guidance asks for the back-up in the platform-independent semantic format. | The CX-0160 preview gives back-up management to an EU-side proxy. |
| Platforms | Vendor SaaS, self-hosted open source, or hashes on a ledger. | The CIRPASS-2 service-provider response names back-up operators as a separate provider type. | Not described. |
| Carrier-embedded data (family file; no independent check) | The carrier holds a copy of the embedded data. | Offline basic data act as a fallback. | Offline read. The data go stale after an update. |

The failover routes are proposals. No adopted law or open standard fixes the route, the trigger, or the response format.

| Route | Source | Notes |
| --- | --- | --- |
| Registry of primary and back-up links, plus a fallback app | CIRPASS-2 option 1 | Most contributors favored it. A generic browser still sees a dead link. |
| EU domain with a subdomain per operator, re-pointed by DNS | CIRPASS-2 option 2 | Longer carrier string. Failover lags DNS propagation. |
| Central EU redirect for every UPI | CIRPASS-2 option 3 | Longer carrier string. The service must learn of a cessation, or crawl. |
| EU agency takes over lapsed domains; or a second, derived EU URL for machines | CIRPASS-2 options 4 and 5 | No change to the label text in option 4. |
| Default EU resolver after "host not found" or a 404; or a `backup` service in a DID document | CIRPASS D3.2 (not confirmed by the independent check) | A registry-fed resolver returns the archive or back-up location. |
| Host substitution on a GS1 Digital Link URI | GS1 in Europe, Release 2.2, January 2025 | The app keeps the GS1 keys and tries a known alternative host. |
| Fallback redirection service of last resort | CIRPASS-2 D4.1 V1.1, recommendation 3.17 (not confirmed by the independent check) | D4.1 asks the Commission to define infrastructure, governance, and APIs. |

D4.1 recommendation 3.15 asks the back-up provider to hold all data and stay current. It also asks for the same access rules (not confirmed by the independent check). Every D4.1 page carries a "Draft" watermark.

In the service-provider consultation, most respondents chose 99 % yearly availability as the minimum level. This is a stakeholder preference, not law and not a test oracle.

#### Versions and updates by family

| Family | Update model | History access | Handover and end of life |
| --- | --- | --- | --- |
| Law baseline | Data stay accurate and up to date. Delegated acts set update rights. | The registry versions each change with a Commission time stamp. | New linked passport; Art. 6a transfer. |
| Plain web | Overwrite in place under the same URL. | Operator-defined. The reference system serves `/dpp/{id}/versions` with a `content_digest` per version. | Caches can serve an old variant without validators and `Cache-Control`. |
| GS1 resolver | The resolver re-points links. The printed URI stays fixed. | GS1 standards define no link versions. | No deactivation status and no end-of-life link type. |
| AAS digital twin | `PUT` and `PATCH`; `updatedAt` and `lastUpdate` change. | v3.2 `$history?date=` operations return the version valid at a date. | No handover construct. The IDTA DPP annex asks servers to enforce deletion limits. |
| Dataspace | In place, with `version`, `lastModification`, `passportStatus`, and `predecessor`. | Each aspect model change gets a new URN version. | No standard handover protocol between operators. |
| Verifiable credentials | A signed credential is immutable. A change is a new credential plus a revocation or suspension bit. | A series of credentials; `did:webvh` keeps a key log. | UNTP work-in-progress text asks that status lists stay resolvable; it is not normative. |
| Ledger-anchored | Append-only by construction. | EBSI records hold an ordered list of version hashes. | Token transfer, record revocation, or burn. |
| EU pilots | The mock registry overwrites by default (`MODIFY`). `APPEND_WITH_NEW_ID` and `APPEND_WITH_SAME_ID` keep records. | `createdAt` and `modifiedAt` on mock records. | D4.1 proposes append-only records with a signed hash of the previous version. |
| Linked data | New graph versions or new documents. | `owl:versionIRI`, a schema-version property, and previous-passport links. | A passport status property, separate from the battery status. |
| EPCIS event traceability | Append-only events. An `errorDeclaration` records a correction. | Ordered event history for an identifier. | Ownership moves through source and destination types. |
| Hybrid stacks | A Battery Pass redirect service follows the current operator, so the QR code stays valid. | IDTA version-by-date operations in the linkset. | The CX-0160 preview asks for system-neutral data transfer. |
| Platforms | Event logs, or snapshot versions with a signed manifest. | Date queries on some platforms. | Support for a switch of provider. |
| Carrier-embedded data (family file; no independent check) | Embedded data and hashes pin one version. | None on the carrier. | A battery status change needs new markings (Batteries Art. 13(9)). |

The independent check did not confirm the D4.1 succession details in the back-up file. These details are a statement signed by the operator that leaves, or an attestation by the back-up provider after insolvency. Use them as design input, not as an oracle.

#### Registry interaction by family

| Family | Interaction with the EU registry | Back-up data on the registry path |
| --- | --- | --- |
| Law baseline | The operator uploads identifiers. The registration identifier is not proof of compliance (ESPR Art. 13). | A provider reference where relevant (Art. 8(9)(c)). |
| Back-up and failover | Proposals: the registry holds back-up links, or acts as lookup of last resort. | Not in any adopted act. |
| EU pilots | Mock registry: `POST /metadata/v1` with `liveURL` and `backupURL`. A signed proof JWT carries `dppHash`. | `backupURL` is required, but the mock never fetches it. A dead back-up passes. |
| Plain web | The registry dereferences the UPI. The CIRPASS-2 mock asks for JSON or JSON-LD. | An HTML-only answer fails the mock fetch. |
| Dataspace | No Catena-X component uploads to the EU registry. The CX-0160 preview gives this task to an EU-side system. | `registrationIdentifier` can hold the registration identifier. |
| Linked data | The Art. 8(7) semantic conformity check reads the passport against the semantic repository. | None. |
| Identification carriers | Item records link to batch and model identifiers where they exist (Art. 8). | None. |
| Hybrid stacks | The BatteryPass-Ready registration module returns a registration ID. Deletion notifies the registry. | Not described. |
| Carrier-embedded data (family file; no independent check) | The draft standardization request defines a carrier control hash over the registered passport. | The research located no registry API for hash lookup. |
| GS1 resolver, AAS, verifiable credentials, ledger, EPCIS, other twin stacks | No defined interaction. AAS registries and NGSI-LD registrations are directories, not the EU registry. | None. |

The registry guide v1.03 limits the UPI to an `https` URL of at most 2000 characters. A bad format, protocol, domain, or port gives the error "The UPI URL is invalid". Excessive redirects, protocol downgrades, and oversized responses give the message "unable to process your request", not the error `NOT_RESOLVABLE_UPI`.

#### What the engine can test

The engine record of the mock registry holds `identifier`, `operator_identifier`, `passport_url`, and `registered_at`. It has no back-up field. `persistence.versions` reads one `versions` list and the item once.

| Test objective | Check today | Engine mapping verdict | Capability that closes the gap |
| --- | --- | --- | --- |
| Integer versions ascend, update times do not go back, and the last `content_digest` equals the current item. | `persistence.versions` | Correct for the order rule (ledger file). Overstated for "accurate and up to date" (law baseline file). | None for the order rule. |
| Updates are append-only and linked. | `persistence.versions` | Overstated. One observation cannot show append-only behavior. | `persistence.scheduled`; proposed `integrity.digest_binding`. |
| An old version stays readable after an update. | `persistence.versions` | Overstated. The check fetches no older version. | `persistence.scheduled`. |
| An AAS `$history` answer is right for a date. | `persistence.versions` | Wrong. The check reads only the engine's own list format. | Proposed `aas.api_profile`. |
| Registry identifier equals passport identifier. | `registry.consistency` on `registry.mock` | Correct (GS1 resolver, ledger, EU pilots, identification carriers). | Parsed-key comparison is new. |
| Registration identifier, commodity code, batch and model links, and back-up link agree with the passport. | `registry.consistency` | Overstated. The check compares two field pairs only. | Proposed `registry.record_fields`. |
| A registry record is well formed for its granularity. | `data.jsonschema` | Wrong. The check reads only item or model documents. | Proposed `data.document_source`. |
| The passport declares a back-up provider. | `data.rules` (`required_fields`) | Correct (ledger file). | None. |
| The back-up is reachable and equals the primary. | `identifier.consistency` | Correct as a stated partial fit (law baseline). Overstated (EU pilots). | Proposed `persistence.backup`. |
| The passport stays available over time; the back-up follows updates. | None | Correct: no check repeats acquisitions. | `persistence.scheduled`. |
| A predecessor link resolves to the original passport. | None | Correct. | Proposed `lifecycle.links`. |

The engine mapping does not cover the back-up and failover file. The independent check of that file confirmed two engine facts: `persistence.scheduled` is `interface_only`, and `persistence.backup` is not yet a capability.

**Testable now.** `persistence.versions` judges version order, update-time order, and the current digest in one list on one host. With `registry.mock`, `registry.consistency` compares the record identifier with the passport `id`, and `operator_identifier` with `operator.identifier`. A `data.rules` presence rule can flag an absent back-up reference. `identifier.resolve` records the redirect count; a rule for scheme downgrade would be new.

**Needs `persistence.scheduled`.** Availability over a window, drift between primary and back-up, and the lag after a primary update need repeated, recorded acquisitions. So do older versions that must stay readable, and verification material such as status lists and issuer keys. A finite campaign gives evidence, never proof of availability for the legal period or after a real cessation.

**Needs `registry.official`.** The Art. 8(7)(e) back-up link check and the real registration outcome need a separately authorized official environment. The engine does not contact the official registry or its acceptance test site. Until then, a tester can only compare operator-supplied artifacts, such as a proof of registration, with the passport.

The family files name faults that fit loopback fixtures:

- The back-up URL equals the live URL. The OpenDPP registry sample sets `backupURL` to the GS1 URL of the UPI.
- The back-up holds an older version, or the provider re-signs it so the issuer signature fails under `integrity.jws`.
- The mock registry accepts a back-up link that answers 404.
- The fallback starts on a 404 but not on a DNS failure, a refused connection, a 410, or a 5xx.
- A duplicate registration overwrites the earlier mock record (`MODIFY`), and the history is lost.
- `backupReference` holds a placeholder such as `https://dummy.link`.

Open points remain. The research did not read the official upload templates, and the sources differ on the trigger for cessation.

## 7. What the engine can test, by family and layer

This section maps the test objectives of all evidence files to the engine at commit `b290791`. It is a research view, not a plan, and it is not normative for the code.

The source of each verdict is the engine mapping file `x01-engine-mapping.json`. That file covers the files `m01` to `m10` only. For the files `f01` to `f04` and `g01` to `g03`, only their own verifiers checked the mappings.

### 7.1 How to read the matrix

Each column of the compact table joins layers into one group:

- Identifier and carrier: L01 and L02.
- Resolution and exchange: L03 and L04.
- Data model: L05.
- Access: L07.
- Integrity: L08 and the trust part of L11.
- Persistence and registry: L06, L09, and L10.

Governance items of L11 have no technical observable. Section 7.7 gives them to `manual.review`.

A cell of the compact table has one of four values:

- **supported**: a registered check gives a verdict on the objective today.
- **partial**: a registered check covers a part. The cell names the gap.
- **new**: the objective needs a proposed capability. The cell gives its identifier.
- **not testable**: no black-box observable exists. A signed manual result is the only evidence.

The x01 verdict is not a coverage grade. It says whether a family file described its check honestly. So a `correct` entry can still need a new capability.

New capability identifiers are the 51 merged identifiers of x01. Proposals of the `f` and `g` files keep their own names.
A reference such as `m02#9` names item 9, counted from 0, in the list `conformance_implications` of the file `m02`.

### 7.2 Compact matrix

Capability states are the states on 2026-10-19 in the [capability manifest](../reference/capabilities.md).

| Family | Identifier and carrier | Resolution and exchange | Data model | Access | Integrity | Persistence and registry |
| --- | --- | --- | --- | --- | --- | --- |
| Legal baseline (section 4) | partial: `identifier.parse` (no `https` URL scheme; accepts `http`) | partial: `identifier.resolve` (bounds enforced, not judged); new: `resolver.conformance` | partial: `data.rules` (no date fact, no absence rule); new: `data.rule_kinds` | supported: `access.restricted_fields` (public tier); new: `privacy.tracking_probe` | partial: `integrity.jws` (one profile); new: `trust.eu_trusted_list` | new: `persistence.scheduled`, `persistence.backup`, `lifecycle.links` |
| 5.1 Plain web | partial: `identifier.parse` (one GS1 form; accepts `http`) | partial: `identifier.resolve` (one `Accept` value per step); new: `resolver.conformance` | new: `data.html_embedded_parity`, `view.html_static_a11y` | partial: `access.restricted_fields` (HTML read for leaks only) | not researched | partial: `registry.consistency` (identifier and operator only); new: `persistence.scheduled` |
| 5.2 GS1 resolver | partial: `identifier.parse` (one path form); new: `identifier.gs1_grammar`, `carrier.symbols` | partial: `identifier.resolve` (final answer only); new: `resolver.conformance` | new: `resolver.linkset`, `resolver.well_known` | partial: `access.restricted_fields` (no linkset channel) | partial: `integrity.jws` (no target from the linkset) | partial: `registry.consistency` (exact text); new: `identifier.equivalence` |
| 5.3 Asset Administration Shell | partial: `identifier.consistency` (reads key `id` only); new: `identifier.subject_pointer` | partial: `api.contract` (`GET` only); new: `aas.api_profile` | partial: `aas.validate` (JSON only); new: `aas.validate_formats`, `aas.dpp_compose` | partial: `access.restricted_fields` (401 and 403 not asserted) | new: `integrity.jose_profiles` (RS256), `integrity.opc_signature` | new: `aas.api_profile` (history), `api.write_ops` |
| 5.4 Dataspace | new: `identifier.schemes` (Catena-X triplet) | new: `dataspace.protocol_probe`; supported: `manual.review` for TCK results | partial: `data.jsonschema` (draft-04, remote `$ref`); new: `schema.pinned_import` | partial: `access.restricted_fields` (no `404` refusal) | new: `integrity.jose_profiles`, `integrity.status_list` | partial: `registry.consistency` (two field pairs); new: `registry.record_fields` |
| 5.5 Verifiable credentials | partial: `identifier.consistency` (not `credentialSubject.id`); new: `identifier.subject_pointer` | partial: `identifier.resolve`; new: `resolver.linkset`, `resolver.well_known` | partial: `data.context`, `data.jsonschema` (no decoded `vc+jwt`); new: `data.jsonld` | new: `access.encrypted_target`, `access.credential_acquisition` | new: `integrity.jose_profiles`, `integrity.data_integrity` | new: `lifecycle.links`; not testable: eIDAS checks of the registry |
| 5.6 EPCIS events | new: `epcis.event_id` | partial: `api.contract` (`GET` only); new: `epcis.rest_probe`, `epcis.capture_probe` | supported: `data.context`; partial: `data.jsonschema` (no `date-time`); new: `data.shacl` | partial: `access.restricted_fields` (no event-level policy) | new: `epcis.event_hash` | partial: `persistence.versions`; new: `epcis.capture_probe` |
| 5.7 Linked data | partial: `identifier.consistency` (no `@id`); new: `identifier.subject_pointer` | partial: `identifier.resolve`; new: `data.context_sources` | supported: `data.context` (body contexts); new: `data.jsonld`, `data.shacl` | supported: `access.restricted_fields`; new: `data.shacl` view mode | new: `integrity.data_integrity` | new: `data.shacl` per version, `lifecycle.links` |
| 5.8 Distributed ledger | new: `identifier.schemes` (ledger references) | partial: `identifier.consistency` (no ledger reference); new: `ledger.read` | partial: `data.jsonschema` (HTTP copy of token metadata only) | supported: `access.restricted_fields`; new: `access.public_payload_leak` | new: `integrity.digest_binding`, `integrity.ledger_proof` | supported: `registry.consistency`, `persistence.versions` (order rule); new: `lifecycle.status` |
| 5.9 Platforms | partial: `identifier.parse` (other schemes give `unsupported`); new: `identifier.gs1_grammar` | partial: `api.contract` (`GET` only); new: `api.write_ops`, `aas.api_profile` | supported: `data.jsonschema`, `data.context`; new: `data.shacl` | supported: `access.restricted_fields`; new: `access.credential_acquisition` | partial: `integrity.jws` (`x5c` only); new: `integrity.data_integrity` | partial: `registry.consistency`; new: `persistence.backup`, `persistence.scheduled` |
| 5.10 Hybrid stacks | partial: `identifier.consistency` (one carrier); new: `identifier.cross_layer` (f02) | partial: `identifier.resolve`; new: `resolver.linkset` | supported: `data.jsonschema`; partial: `aas.validate` | supported: `access.restricted_fields` (anonymous public tier) | partial: `integrity.jws` (`x5c` only); new: `integrity.digest_binding` | partial: `registry.consistency`; new: `persistence.backup` |
| 5.11 Reference implementations and registry | partial: `identifier.parse`; new: `identifier.schemes` | supported: `identifier.resolve` (one `Accept` value); new: `resolver.conformance` | supported: `data.context`, `data.jsonschema`, `aas.validate`; new: `data.shacl` | supported: `access.restricted_fields`; new: `api.write_ops` | new: `integrity.jose_profiles`, `integrity.digest_binding` | partial: `registry.consistency`; new: `registry.record_fields` |
| 5.12 Other stacks | partial: `identifier.consistency`; new: `identifier.schemes` (URN) | partial: `api.contract` (pinned OpenAPI needed); new: `api.header_contract` (g03) | partial: `data.context`; new: `data.shacl`; not testable: OPC UA and IFC models | supported: `access.restricted_fields` (no notification channel) | partial: `integrity.jws` (`x5c` only) | partial: `persistence.versions`; new: `persistence.temporal_adapter` (g03) |

### 7.3 Identifier and carrier (L01, L02)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5.2, 5.9, carriers | Parse every GS1 Digital Link form: keys, qualifiers in order, path prefix, query attributes, `eh` and `ex` compression. | Carrier payload | GS1 Digital Link URI Syntax 1.7.0; GS1 DL Compression 1.0.0; GS1 AI dataset | `identifier.parse` (correct) | `identifier.gs1_grammar` | Vendored vectors in `tests/vectors/` | sample-artifact |
| Legal baseline, 5.11 | The UPI is an absolute `https` URL of at most 2000 characters. | Payload or declared UPI | Registry user guide v1.03 (guidance only) | `identifier.parse` (correct); accepts `http`, refuses other `https` URLs | `identifier.schemes` | Bad URL strings | sample-artifact |
| 5.3, 5.4, 5.5, 5.8, 5.10, 5.12 | Parse other schemes: AAS ID Link, Catena-X triplet, EPC URN, UUID URN, `did:web`, ledger references, LEI, BPN. | Declared identifier | IDTA-01002 v3.2; RFC 9562; W3C DID 1.1; CAIP-2 | `identifier.parse` (correct); `data.rules` (wrong, `m04#18`) | `identifier.schemes`; a JSON Schema `pattern` covers syntax in part | Synthetic strings | sample-artifact |
| All | The carrier identifier equals the passport identifier under GS1 canonical equivalence. | Carrier text; passport `id` | GS1 Digital Link URI Syntax 1.7.0 | `identifier.consistency` (correct); exact text only | `identifier.equivalence` (g02: `identifier.cross_carrier`) | Equal and unequal pairs | sample-artifact |
| 5.3, 5.5, 5.7, 5.10 | Read the identifier at `globalAssetId`, `credentialSubject.id`, or `@id`. | Passport JSON | IDTA-01001; W3C VCDM 2.0; JSON-LD 1.1 | `identifier.consistency` (correct); `data.rules` (overstated, `m03#1`) | `identifier.subject_pointer`; f02: `identifier.cross_layer` | Equal and unequal documents | loopback-only |
| 5.2, carriers | Carrier granularity matches the passport level. | Qualifiers; `ICS.granularity` | GS1 Digital Link URI Syntax 1.7.0 | none (correct) | `identifier.granularity` | One carrier per level | sample-artifact |
| All | A QR sample decodes to one symbol with text. | Payload; symbol count | zxing-cpp | `carrier.qr_decode` (correct; overstated, `m01#3`) | none | Damaged, two-symbol images | sample-artifact |
| 5.2, carriers | Data Matrix and EAN or UPC give the same keys as the QR. | Payloads of one sample | GS1 2D Barcodes at Retail POS Guideline 1.1.0 | none (correct; overstated, `m09#19`) | `carrier.symbols` | Seeded mismatch | sample-artifact |
| 5.2, 5.9, carriers | Offline EPC and NDEF dumps give the declared identifier. | Dump file | GS1 TDS 2.3; ndeflib | none (correct) | `carrier.epc_decode`, `carrier.ndef_sample` | GS1 TDT artefacts | sample-artifact |
| 5.6 | Event identifiers use a CBV form. | `eventID` strings | CBV 2.0 section 8.9 | `data.rules` (not in x01; refuted: no pattern rule) | `epcis.event_id` | Valid and invalid identifiers | sample-artifact |
| Legal baseline, carriers | The carrier is legible and of high contrast; dealers get a digital copy. | Product; request evidence | Batteries Annex VI Part C; ESPR Art. 10(3)(b) | `manual.review` (correct) | not testable black-box | Signed manual result | sample-artifact |

Per the independent check of `g02`, `identifier.parse` accepts a query string of URI characters and does not interpret it.

### 7.4 Resolution and exchange (L03, L04)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5.1, 5.11 | A machine `Accept` gets JSON or JSON-LD; a browser `Accept` gets HTML. | Final status, `Content-Type` | RFC 9110 section 12 | `identifier.resolve` with `accept` and `accepted_media_types` (correct) | none for one value per step | Loopback server with negotiation | loopback-only |
| 5.1, 5.7 | Negotiation matrix: `Vary`, q weights, `406` or a declared default, `HEAD` equal to `GET`, graph isomorphism. | Headers per `Accept` value | RFC 9110; RDFC-1.0 | none (not in x01; correct, `m08#9`) | `resolver.conformance` (g01: `identifier.negotiation_matrix`), `data.jsonld` | Faults `negotiation_no_vary`, `head_501` | loopback-only |
| 5.2, 5.5, 5.9, 5.11, carriers | GS1 resolver: status table, default and `linkType` redirects, query pass-through, walk-up, CORS, delegation. | First-hop status and headers | GS1-Conformant Resolver 1.2.1; RFC 8288 | none (correct); `identifier.resolve` (overstated, `m02#11`, `m05#2`) | `resolver.conformance`; an absent `300` is no failure | GS1DL resolver test suite logic | loopback-only; live-sut under authorization |
| 5.5, 5.11 | A redirect has any 3xx code with a `Location`; `linkType=linkset` gets the full linkset. | Status class; `Location` | UNTP 0.7.0 Identity Resolver | `identifier.resolve` (not in x01; refuted for `f04#3`, `f04#4`) | `resolver.conformance`: record the code; refusal of `linkType=all` is no failure | Fixtures for `301`, `302`, `307`, `308` | loopback-only |
| Legal baseline, 5.1, 5.11 | Bounded redirects, no scheme downgrade, a size limit, and `http` to `https`. | Hops, schemes, size | Registry user guide v1.03 (guidance only) | `identifier.resolve` (overstated, `m01#1`; correct, `m07#4`) | `resolver.conformance` | Downgrade and long-chain fixtures | loopback-only |
| 5.2, 5.3, 5.5, 5.7, 5.10 | The linkset comes with `200`, no redirect, `application/linkset+json`, and the right anchor. | Status, media type, anchor | GS1-Conformant Resolver 1.2.1; RFC 9264 | `identifier.resolve` (correct); media type only | `resolver.linkset` | Wrong-anchor linksets | loopback-only |
| 5.3, 5.9, 5.10 | AAS API profiles: `/description`, base64url ids, pages, modifiers, query, discovery. | AAS API answers | IDTA-01002 v3.2 | `api.contract` (wrong, `m03#8`; overstated, `m03#7`); `aas.validate` (wrong, `m10#6`) | `aas.api_profile`, `api.resources` | aas-test-engines 1.0.3 (API 3.0.3 only) | loopback-only |
| 5.4, 5.9 | Version metadata, catalog, negotiation, transfer; a hidden resource gives `404`. | DSP messages | DSP 2025-1; DCP v1.0.1 | none (correct); `manual.review` takes a signed TCK result (correct) | `dataspace.protocol_probe` | dsp-tck, dcp-tck | loopback-only |
| 5.3, 5.5, 5.9, 5.11 | Write operations and verifier calls obey the pinned contract. | Non-`GET` pairs | Pinned OpenAPI; VCALM v1.0 draft | `api.contract` `GET` only (correct) | `api.write_ops` with a signed scope | Sandbox with test items | loopback-only |
| 5.6 | EPCIS REST: `406`, `OPTIONS`, pages, all-or-none capture, `414`, subscriptions. | Status, headers, callbacks | EPCIS 2.0 sections 12 and 14.8 | `api.contract` (not in x01; refuted) | `epcis.rest_probe`, `epcis.capture_probe`, `epcis.subscription_probe` | openepcis-test-resources | loopback-only |
| 5.12 | NGSI-LD gives the right media type and `Link` pair. | Headers; entities | ETSI GS CIM 009 V1.9.1 | `data.context` (not in x01); partial | `api.header_contract` | NGSI-LD mock | loopback-only |
| Legal baseline | Full interoperability with other passports. | None from law alone | ESPR Art. 11(a) | none (correct) | not testable black-box | none | none |

The independent check of `f01` found `api.contract` partial only for `GET` query answers, after a conversion of OpenAPI 3.0.3 to 3.1.
The independent check of `f02` refuted a linkset-driven use of `api.contract`, which covers five passport resources only.

### 7.5 Data model (L05)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| All | The passport validates against a pinned schema. | Item or model document | BatteryPass-Ready v2.x JSON Schema 2020-12; sector schemas | `data.jsonschema` (correct) | none | Pinned schemas with digests | loopback-only |
| 5.4, 5.6 | Published schemas load: Catena-X draft-04 aspect schemas, DSP absolute `$ref`, EPCIS draft-07 with `date-time`. | Pinned schema files | CX-0143 1.4.0 names aspect 6.1.0; DSP 2025-1; EPCIS 2.0 | `data.jsonschema` (correct: it gives `blocked`); `f01#0` refuted | `schema.pinned_import`; a format checker change | ESMF samm-cli | sample-artifact |
| 5.4, 5.5, 5.8, 5.11, legal baseline | Validate other documents: messages, offers, descriptors, registry records, registration files, token metadata. | Sample or resource bytes | DSP 2025-1; CIRPASS-2 mock-eu-registry schema | `data.jsonschema`, `data.context`, `data.rules` (wrong or overstated) | `data.document_source` | Mutated examples | sample-artifact |
| 5.4, 5.5, 5.6, 5.7, 5.9, 5.11 | Every `@context` reference is on a pinned allowlist. | `@context` values | Pinned allowlist; VCDM 2.0 | `data.context` (correct; overstated, `m04#3`, `m05#10`) | `data.context_sources` for `Link` and `@import` | Unknown and inline contexts | sample-artifact |
| 5.5, 5.7 | Expansion with pinned contexts and no fetch drops no term; terms exist; datatypes hold. | Expanded JSON-LD | JSON-LD 1.1 API; GS1 Web Vocabulary 1.18.0 by digest | none (correct); `data.rules` (wrong, `m08#6`) | `data.jsonld` | W3C JSON-LD API manifests | sample-artifact |
| 5.3, 5.6, 5.7, 5.9, 5.11, 5.12 | The graph conforms to pinned shapes; no shape is vacuous; results agree with the JSON Schema path. | SHACL report | W3C SHACL; IDTA `shacl-schema.ttl`; CIRPASS-2 `battery-shapes.ttl` (draft; reuse needs an owner decision under rule 5, section 9.4) | none (correct); `data.shacl` is `interface_only` | `data.shacl` | W3C data-shapes tests | sample-artifact |
| Legal baseline | Annex XIII point 1 items exist by category and date; status values come from the allowed set. | Passport fields | Batteries Annex XIII | `data.rules` (correct; overstated, `m01#9`, `m01#13`) | `data.rule_kinds` | Category and date samples | sample-artifact |
| 5.3, 5.4, 5.11 | An AAS file is valid for its metamodel and format. | JSON, XML, or AASX | IDTA-01001; IDTA-01005 | `aas.validate` (correct; wrong, `m03#13`; overstated, `m04#8`) | `aas.validate_formats` | aas-test-engines 1.0.3 (version 3.0 only) | sample-artifact |
| 5.3 | DppMetadata and battery parts fit their IDTA templates; the composed passport has one section per id. | Shell and submodels | IDTA 02099-1 folder `1/0/2`; IDTA 02035 per part, by digest | `aas.validate` (not in x01; refuted); `data.rules` (wrong, `m03#15`) | `aas.dpp_compose`; f04: `oracle.pin_manifest` | Template samples | loopback-only |
| 5.2, 5.5, 5.7, carriers | Linkset valid; one default link; a DPP link in each relation form; typed links reach the right type. | Linkset and targets | GS1-Conformant Resolver 1.2.1; RFC 9264; GS1 Web Vocabulary 1.18.0 | none (correct); `data.context` (not in x01; refuted) | `resolver.linkset` | GS1DL resolver test `validLinkset` | loopback-only |
| 5.2, 5.5, 5.11 | The resolver description file is valid; `resolverRoot` matches the carrier host. | Description file | GS1-Conformant Resolver 1.2.1 section 3 | none (correct) | `resolver.well_known`; the UNTP file is optional | Faulty files | loopback-only |
| 5.1 | Embedded JSON-LD equals the JSON-LD view; public values appear in HTML; static WCAG 2.2 checks pass. | Static HTML | JSON-LD 1.1 section 7; WCAG 2.2 | none (not in x01); `manual.review` for rendered checks | `data.html_embedded_parity`, `view.value_presence`, `view.html_static_a11y` | Stale-HTML faults | loopback-only |
| 5.12 | DTDL, WoT, IDS, and OPC UA models are valid. | Model documents | DTDL v4; W3C WoT TD 1.1; buildingSMART IDS 1.0 | none (not in x01) | `data.dtdl_validate`, `data.ids_check`; OPC UA not testable without the licensed OPC 30450-1 | Project-written samples | sample-artifact |

### 7.6 Access (L07)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Legal baseline, 5.1, 5.4, 5.9, 5.10 | The public tier is readable without login or registration. | Anonymous fetch | ESPR Art. 11(b); Batteries Art. 77(2)(a) | `access.restricted_fields` (correct) | none; a pure dataspace system under test gives `blocked` | Canaries | loopback-only |
| Legal baseline, 5.7, 5.11 | Each battery group gets exactly its points of Annex XIII (section 4.2). | Field sets per role | Batteries Annex XIII | `access.restricted_fields` (correct; overstated, `m01#6`) | `data.shacl` view mode | TEST-ONLY tokens; no point 2 for authorities | loopback-only |
| 5.3, 5.6 | Anonymous gets `401`; a wrong role gets `403` without payload. | Status per role | IDTA-01004 v3.1; EPCIS 2.0 | `access.restricted_fields` (overstated, `m03#20`) | not proposed by x01 | TEST-ONLY JWT per role | loopback-only |
| 5.2, 5.3, 5.4, 5.6 | No leak through a linkset, AAS surfaces, `/query`, header roles, or events. | Channel answers | IDTA-01004 v3.1; Tractus-X DTR | `access.restricted_fields` (correct; overstated, `m03#21`) | `access.channel_extensions` | Canary URLs; TEST-ONLY BPN roles | loopback-only |
| 5.5 | Encrypted targets carry a flag; restricted data needs the key. | Linkset; target body | UNTP 0.7.0 | `access.restricted_fields` (correct) | `access.encrypted_target` | TEST-ONLY AES key | loopback-only |
| 5.5, 5.9 | A role credential comes from a token or presentation flow. | Token exchange | OpenID4VP 1.0; OpenID4VCI 1.0 | none (correct) | `access.credential_acquisition` | Holder simulator | loopback-only |
| 5.3, 5.11 | Write and admin operations refuse wrong roles. | Write status codes | Declared policy | none (correct) | `api.write_ops` | TEST-ONLY Keycloak realm | loopback-only |
| Legal baseline, 5.1 | The public view sets no cookie and loads no third-party resource. | `Set-Cookie`; static `src` | Regulation (EU) 2025/2509, Art. 20(10); Regulation (EU) 2026/405, Arts 19 and 22 | none (correct) | `privacy.tracking_probe` | Pages with analytics | loopback-only |
| Legal baseline | The passport holds no customer personal data without consent. | Passport fields | ESPR Art. 10(1)(e) | `data.rules` (wrong, `m01#7`) | `data.rule_kinds` (heuristic) with `manual.review` | Passports with personal fields | sample-artifact |
| 5.8 | Public ledger data holds no restricted field; erasure removes off-chain data. | Calldata; metadata | EDPB Guidelines 02/2025 v2 | `access.restricted_fields` (correct); HTTP only | `access.public_payload_leak`, `persistence.erasure` | Payloads with canaries | sample-artifact |
| 5.1, carriers | Shared caches keep no restricted answer; carrier data holds no restricted field. | `Cache-Control`; embedded records | RFC 9111 | `access.restricted_fields` (not in x01) | header rule (g01); `access.carrier_leak` (g02) | Fault `restricted_public_cache` | loopback-only |

Per the independent check of `g03`, `access.restricted_fields` belongs to `access.policy`, and it reads no notification payload.

### 7.7 Integrity and trust (L08, L11)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Legal baseline, all | A declared mechanism protects integrity; today one JWS profile. | Signed passport | ESPR Art. 11(g); RFC 7515 | `integrity.jws` (overstated, `m01#16`) | `integrity.cose` for a COSE profile | Tampered passports | sample-artifact |
| 5.2, 5.3, 5.4, 5.5, 5.10, 5.11 | Other JWS profiles: AAS RS256, `vc+jwt`, ID tokens, registry proofs. | Compact JWS | W3C VC-JOSE-COSE; IDTA-01002 v3.2; DCP v1.0.1 | `integrity.jws` (correct; wrong, `m04#13`, `m07#2`, `m07#8`) | `integrity.jose_profiles` | W3C test suite | sample-artifact |
| 5.5, 5.7, 5.9 | Data Integrity proofs verify, JCS suites first. | Embedded proof | VC Data Integrity 1.0 | none (correct; overstated, `m10#11`) | `integrity.data_integrity` | W3C vc-di test suites | sample-artifact |
| 5.4, 5.5, 5.9 | The credential is not revoked. | Status list bit | W3C Bitstring Status List v1.0 | none (correct) | `integrity.status_list` | Loopback status service | loopback-only |
| 5.5, carriers | The issuer DID resolves and lists the key; a `did:webvh` log verifies. | DID document | did:web; did:webvh v1.0 | none (correct) | `identity.did` | Loopback `did.json` | loopback-only |
| 5.5 | An identity anchor binds the issuer; claims have conformity credentials. | Credential set | UNTP 0.7.0 | none (correct) | `trust.identity_anchor`, `graph.claim_attestation` | untp-test-suite Tier 3 | sample-artifact |
| 5.5, 5.8, 5.10, 5.11 | A digest binds bytes: anchors, CIDs, `digestMultibase`, registry hashes. | Bytes; digest | VC Data Integrity 1.0; IPFS CID rules | none (correct) | `integrity.digest_binding` | Changed and reordered pairs | loopback-only |
| 5.8, 5.9 | Proofs chain to a pinned root; the transaction is final; the author is the operator. | Receipts; node answers | RFC 9162; EIP-1186 | none or `manual.review` (correct) | `integrity.ledger_proof`, `ledger.read`, `integrity.issuer_binding` | Local dev chain | sample-artifact; live-sut |
| Legal baseline, 5.8, 5.11 | A proof of registration carries a qualified seal and the version hash. | Sealed proof | Implementing Regulation (EU) 2026/1778, Art. 9 | none (correct) | `trust.eu_trusted_list` | TEST-ONLY sealed proofs | sample-artifact |
| Carriers | NFC SUN messages and signed carrier payloads verify offline. | Tap URLs; codes | NXP AN12196; HCERT 1.0.8 | none (correct, `m09#10`; `g02` not in x01) | `carrier.nfc_sun`; g02: `integrity.vds` | TEST-ONLY keys | sample-artifact |
| 5.6 | The EPCIS Event Hash ID recomputes. | Event | CBV 2.0 section 8.9.2 | none (not in x01) | `epcis.event_hash` | epcis-event-hash-generator | sample-artifact |
| 5.3 | AASX package signatures cover the right parts. | AASX | IDTA-01005 v3.2 | none (correct) | `integrity.opc_signature` | Signed AASX | sample-artifact |
| Legal baseline, 5.3, 5.9 | Provider conduct, trust choices, and back-up terms. | Operator documents | ESPR Art. 11 | `manual.review` (correct) | not testable black-box | Signed manual results | sample-artifact |

The independent check of `f02` refuted two claims. `integrity.jws` covers only `x5c`-based JWS, and an unsigned passport is a matter of applicability, not of this check.
The `g02` file records that a structural check of the AI 8030 signature field is possible. The signature scheme itself rests on a protected ISO/IEC document, so the engine cannot verify it.

### 7.8 Persistence and registry (L06, L09, L10)

| Family | Test objective | Observable | Oracle source | Existing check (x01 verdict) | New capability | Fixture or suite | Network need |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Legal baseline, 5.1, 5.2, 5.3, 5.5, 5.9 | The passport stays available under one identity; verification material stays reachable. | Recordings over time | ESPR Art. 11(e) | none (correct); `persistence.versions` (wrong, `m02#22`; overstated, `m10#9`) | `persistence.scheduled`; a finite campaign is never proof | Scheduler | live-sut |
| Legal baseline, 5.9, 5.10, 5.11 | The back-up is reachable, on another host, equal to the primary, and served on failover. | Primary and back-up answers | ESPR Art. 10(4) | `identifier.consistency` (correct, `m01#14`; overstated, `m07#9`) | `persistence.backup` | Switchable loopback primary | loopback-only |
| Legal baseline, 5.4, 5.8 | The passport declares a back-up reference where required. | Passport field | ESPR Annex III point (l) | `data.rules` (correct; overstated, `m04#16`) | none for presence | With and without the field | sample-artifact |
| Legal baseline, 5.8, 5.11 | Versions obey the declared rule; history is append-only. | Engine `versions` list | Declared update rule | `persistence.versions` (correct; overstated, `m01#21`, `m07#16`) | `integrity.digest_binding` for hash chains | Versioned passport | loopback-only |
| 5.3, 5.4, 5.5, 5.7, 5.12 | Stack versions: AAS history, `updatedAt`, superseded credentials, model versions, NGSI-LD history. | Stack answers | IDTA-01002 v3.2; Bitstring Status List v1.0 | `persistence.versions` (wrong, `m03#18`, `m03#25`, `m08#14`; overstated, `m04#15`, `m05#18`, `m08#18`) | `aas.api_profile`, `api.write_ops`, `data.shacl`; g03: `persistence.temporal_adapter` | Scripted updates | loopback-only |
| Legal baseline, 5.9, 5.10, carriers | Predecessor and successor links resolve, and both ends agree. | Two passports | ESPR Art. 11(d); Batteries Art. 77(7) | none (correct); `persistence.versions` (wrong, `m10#16`) | `lifecycle.links` | Original and successor | loopback-only |
| 5.8, 5.11 | After deactivation the passport stays available; flag, status, and HTTP status agree. | Status; registry flag | CIRPASS-2 status values (non-normative) | `identifier.resolve` (correct); none (correct) | `lifecycle.status` | Before and after samples | loopback-only |
| All | The registry identifier equals the carrier and passport identifier. | Mock record | ESPR Art. 13 | `registry.consistency` (correct; `g01#16` not in x01) | `identifier.equivalence` for parsed keys | Fault `registry_inconsistent` | loopback-only |
| Legal baseline, 5.3, 5.4, 5.9, 5.11 | Other fields agree: model and batch links, commodity code, registration identifier, back-up link, hash. | Record or CSV export | Implementing Regulation (EU) 2026/1778, Art. 8 | `registry.consistency` (overstated, `m01#18`, `m04#16`, `m10#14`) | `registry.record_fields` | CIRPASS-2 mock-eu-registry shape | loopback-only |
| Legal baseline, 5.7 | A registration file or passport fits the Commission templates or data model. | File; passport | Implementing Regulation (EU) 2026/1778 | `data.jsonschema` (wrong, `m01#19`); `registry.consistency` (wrong, `m08#15`) | `data.document_source`, `data.repository_model` | Templates, not yet published | sample-artifact |
| 5.5, 5.11 | Official registry checks and operator identification. | Official system | Implementing Regulation (EU) 2026/1778, Art. 4 | `manual.review` (correct) | `registry.official` stays `interface_only` | none | live-sut |

Art. 4 of Implementing Regulation (EU) 2026/1778 allows eID at assurance level high only for sole traders established in the Union. Legal persons use a qualified electronic seal or a qualified attestation.

The independent check of `f02` refuted two registry claims. `registry.consistency` does not cover a back-up link, and resolver targets need a new rule.

### 7.9 Engine mapping totals and the mappings that do not hold

x01 checked 226 entries against the source at commit `b290791`. It ran no test suite and retrieved no oracle source.

| Verdict | Entries |
| --- | --- |
| correct | 172 |
| overstated | 36 |
| wrong | 18 |
| `check_missing` | 0 |

x01 also found nine partial covers that the entries missed, such as a JSON Schema `pattern` for BPN or LEI syntax.

The table groups the 54 entries that do not hold by their reason.

| Check and reason | Wrong | Overstated |
| --- | --- | --- |
| `data.jsonschema`, `data.context`, `data.rules` read only the item or model document over HTTP. | `m01#19`, `m07#5` | `m04#2`, `m04#3`, `m04#4`, `m04#7`, `m04#12`, `m05#10`, `m06#3` |
| `data.rules` has five rule kinds: no pattern, absence, string equality, type, or list rule; no date fact. | `m01#7`, `m03#15`, `m04#18`, `m08#6` | `m01#9`, `m01#13`, `m03#1` |
| `persistence.versions` reads the engine's own list once; it fetches no older version and reads no link. | `m02#22`, `m03#18`, `m03#25`, `m08#14`, `m10#16` | `m01#21`, `m02#26`, `m04#15`, `m05#18`, `m07#16`, `m08#18`, `m10#9` |
| `integrity.jws` accepts ES256, `typ` `dpp+jws`, and an `x5c` chain only; other profiles give `blocked`. | `m04#13`, `m07#2`, `m07#8` | `m01#16`, `m02#24`, `m10#11` |
| `identifier.resolve` judges the final answer; a bound ends as inconclusive; `404` is a failure. | none | `m01#1`, `m02#11`, `m05#2` |
| `aas.validate` reads one JSON file; XML or AASX gives a false `AAS.INVALID`; it tests no API. | `m03#13`, `m10#6` | `m04#8` |
| `api.contract` targets five resources and one sampled id; it cannot provoke an error answer. | `m03#8` | `m03#7` |
| `access.restricted_fields` reads five channel kinds, sends no `POST`, and asserts no `401` or `403`. | none | `m01#6`, `m03#20`, `m03#21` |
| `registry.consistency` compares two field pairs; it does not judge a data model. | `m08#15` | `m01#18`, `m04#16`, `m10#14` |
| `identifier.consistency` reads no ledger reference and no back-up copy, and needs a JSON passport. | none | `m06#6`, `m07#9`, `m09#19` |
| `carrier.qr_decode` decodes only; resolution needs `identifier.resolve`. | none | `m01#3` |
| `data.jsonschema` validates one document against one schema; it does not compare schemas. | none | `m05#9` |

The verifiers of the `f` and `g` files refuted 11 more engine claims. Sections 7.3 to 7.8 apply their corrections.

### 7.10 Contract changes and engine findings

x01 reports these changes in protected files. This page does not make them.

- `ResourceName` in `src/dppce/models/declarations.py` is a closed set of five resources. `api.resources` needs it extended. `resolver.well_known` and `persistence.backup` need it or another route to their target.
- Per-hop status and headers, or a no-follow request, need a change in `src/dppce/infrastructure/interfaces.py`. Today `Record.redirects` holds hop URLs only.
- Redaction removes CORS headers, `Set-Cookie`, and `Link` values with a relation outside a fixed list. `resolver.conformance`, `data.context_sources`, and `privacy.tracking_probe` need an allowlist change.
- A date condition in a rule pack needs the evaluation date as a fact (`src/dppce/applicability.py`).
- `integrity.jose_profiles` must not widen the algorithm allowlist that the report signatures share.
- The trust bundle holds X.509 anchors only, so `trust.identity_anchor` needs a models change.

x01 also reports two engine findings that do not depend on the research. `aas.validate` gives `AAS.INVALID`, a completed failure, for an XML or AASX sample. This reads as a fault of the system under test, which conflicts with the project rule on honest states.

`identifier.resolve` judges `404` and `410` as `IDENTIFIER.UNRESOLVED`, and other statuses below 500 except `200` as failures. So it cannot be the oracle where `400` or `404` is the correct answer.

x01 gives sizes as estimates from reading the code, not measurements. Small: `data.document_source`, `api.resources`, `aas.validate_formats`, `identifier.subject_pointer`. Large: `resolver.conformance`, `data.jsonld`, `data.shacl`, `aas.api_profile`, `api.write_ops`, `persistence.scheduled`.

## 8. Recommendations for the engine

This section turns the engine mapping into an ordered work list.
The primary input is `proposed_capabilities` in `docs/research/raw/implementation-methods/x01-engine-mapping.json`: 51 capabilities from the method files m01 to m10.
Further inputs are the oracle reconciliation f04 with its independent check, the critic file x02, and the [gap assessment](gap-assessment-2026-10-15.md).

This page is research. It is not normative for the code, and no requirement becomes approved through it.
The sizes are x01 estimates from a code review, not measurements.

### 8.1 What the mapping found

The mapping compared 226 conformance implications with the engine source at commit `b290791`.
It judged 172 correct, 36 overstated, and 18 wrong.
These findings shape the list:

- `data.jsonschema`, `data.context`, and `data.rules` read only the item or model document. They cannot judge a message, a registry record, or a linkset.
- `data.rules` has no pattern, absence, string-equality, or list rule. Dotted paths do not enter arrays.
- `identifier.resolve` judges 404 and 410 as unresolved and any other non-200 status as a fail. It cannot judge expected error answers.
- The transport records hop URLs, but not the status and headers of each hop. Redaction removes CORS headers, `Set-Cookie`, and most `Link` values.
- `integrity.jws` verifies one profile (ES256, `dpp+jws`, `x5c`). Any other profile gives blocked.
- `aas.validate` gives `AAS.INVALID`, a completed fail, for an XML or AASX sample, not unsupported. This is a rule 7 concern that x01 reported.
- `registry.consistency` compares two hard-coded field pairs. `identifier.consistency` reads the top-level key `id` only.

The independent check of f04 refuted three of its engine mappings.
`aas.validate` gives generic AAS validity only, not conformance to a pinned IDTA template.
`identifier.resolve` cannot send a `linkType` query or assert a first-hop 3xx status.
`data.context` checks exact `@context` URLs only, not the link types of a linkset.

### 8.2 How to read the tables

Inside each group, the rows are in priority order. This page applies five criteria, in this order:

1. A change that removes a false verdict comes first (rule 7).
2. A capability that other proposals depend on comes next.
3. A gap of tier T1 comes before a gap of tier T2 or T3.
4. Size S comes before M, and M comes before L.
5. A capability with no new dependency comes before one that needs a dependency decision.

Column keys:

- Families: short names of the families in sections 4 and 5. Pilots are the EU reference pilots. Carriers are the cross-family topic of identifiers and data carriers.
- Oracle: the first source id that x01 gives. x01 did not retrieve the sources again and left out EN, ISO, IEC, and DIN ids (rule 5).
- Network: `sample-artifact` is an offline IXIT sample, and `loopback-only` is a local test server. `live-sut` needs a signed authorization.
- Gap: the gap that the capability closes or advances. This page made the match, because no gap record names these ids.

### 8.3 Group 1: extend a registered check

| Id | Purpose | Families | Oracle | Network | Size | Dependency or license question | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `aas.validate_formats` | Add format and version parameters. Give unsupported for an unsupported format, not `AAS.INVALID`. | AAS, dataspace, pilots | `idta-01001-metamodel` | `sample-artifact` | S | aas-test-engines 1.0.3 checks file version 3.0 only. A newer release is a dependency change. | D3-09 |
| `api.resources` | Add resource kinds: service description, version metadata, back-up, linkset, and discovery. | AAS, dataspace | `idta-01002-api` | `loopback-only` | S | Extends `ResourceName` in a protected model file. Several other proposals depend on it. | D3-01 (advances) |
| `identifier.gs1_grammar` | Parse the full GS1 Digital Link grammar, further check digits, and compressed URIs. | GS1, carriers, platforms | `gs1-digital-link-uri-syntax-1-7-0` | `sample-artifact` | M | No library if written from the GS1 AI dataset. The GMN check-character rule needs its GS1 source. | D4-06 |
| `integrity.jose_profiles` | Verify further JWS profiles with a separate algorithm allowlist. Keys come from `x5c`, a pinned JWKS, or a pinned DID document. | AAS, dataspace, VC, pilots, platforms, GS1 | `w3c-vc-jose-cose` | `sample-artifact` | M | joserfc is installed. Must not widen the report signature profile. New signature formats are a models change. | D3-10 |
| `data.rule_kinds` | Add pattern, forbidden-field, string-equality, and list rules, and the evaluation date as a fact. | law, AAS, dataspace, linked data, platforms | `reg-eu-2023-1542` | `loopback-only` | M | `dppce.rulepack/1` needs a new version. The date fact changes `src/dppce/applicability.py` (protected). | none |
| `identifier.schemes` | Add scheme parsers beyond the GS1 form, and allow several declared schemes. | law, AAS, dataspace, VC, ledger, pilots, carriers, platforms | `new-rfc-9562` | `sample-artifact` | M | Standard library. A list of schemes per ICS is a models change. | D4-08 (advances) |
| `access.channel_extensions` | Add a linkset channel, several templates per channel kind, and a role from a request header. | GS1, AAS, dataspace | `idta-01004-security` | `loopback-only` | M | `dppce.accesspolicy/1` needs a new version. A header role changes the transport, which sends Bearer only. | D5-04 |
| `data.document_source` | Let the three data checks judge a named sample or a further resource, not only the item or model. | law, dataspace, VC, ledger, pilots | `new-dsp-spec-2025-1` | `sample-artifact` | S | None. A resource other than item or model needs `ResourceName` (protected). | D3-02 (advances) |
| `identifier.equivalence` | Compare identifiers on parsed keys with a declared canonical form. | GS1, carriers | `gs1-digital-link-uri-syntax-1-7-0` | `loopback-only` | S | None. Depends on `identifier.gs1_grammar`. | D4-06 |
| `data.context_sources` | Extend `data.context` to contexts in a `Link` header and to `@import`. | linked data | `new-w3c-json-ld-11` | `loopback-only` | S | The context relation must join the `Link` allowlist of the redaction module. | D3-11 (advances) |
| `registry.record_fields` | Compare a declared set of field pairs. Read a registry export as a sample. | law, pilots, carriers, platforms, dataspace | `impl-reg-eu-2026-1778` | `loopback-only` | M | None. Live contact with a registry stays out of bounds. | D5-07 |
| `api.write_ops` | Probe non-GET operations against a pinned contract, with idempotency and rollback rules. | AAS, dataspace, VC, pilots, platforms | `idta-01002-api` | `loopback-only`; `live-sut` only with scope write or tamper | L | Schemathesis is not installed. The transport already gates non-GET methods on an active scope. | D5-10 |
| `identifier.subject_pointer` | Read the passport identifier at a declared location, not only at the key `id`. | AAS, VC, linked data, carriers | `idta-01001-metamodel` | `loopback-only` | S | None. A `vc+jwt` payload needs `integrity.jose_profiles` first. | none |
| `carrier.symbols` | Decode Data Matrix and EAN or UPC symbols as well as QR. Compare the keys of several carriers. | GS1, carriers | `pypi-zxing-cpp` | `sample-artifact` | S | None new. x01 probed zxing-cpp 3.1.1, which exposes these symbologies. | none |

### 8.4 Group 2: promote an `interface_only` capability

Each of these capabilities is `interface_only` today.
The [capability list](../reference/capabilities.md) states the acceptance criterion for each change of state.

| Id | Purpose | Families | Oracle | Network | Size | Dependency or license question | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `integrity.status_list` | Retrieve a status list through the transport, verify it, and decode the bit. A failed retrieval gives unreachable, never pass. | dataspace, VC, platforms | `w3c-bitstring-status-list-1-0` | `loopback-only` | M | None new. The decoder in `src/dppce/evidence/status.py` is reusable. The list signature needs a credential profile. | D3-10 (advances) |
| `data.shacl` | Validate the RDF graph with pinned shapes. Compare the result with the JSON Schema path. | AAS, pilots, linked data, platforms, dataspace | `new-w3c-shacl` | `loopback-only` | L | pySHACL is not installed. License not checked. Block network access of rdflib. Depends on `data.jsonld`. | D3-11 |
| `carrier.rfid` | Read RFID tags through a reader, tested against physical tags in a recorded campaign. | platforms, GS1 | `new-gs1-tds-2-3` | `sample-artifact` (hardware) | L | A reader driver and hardware. None chosen. The air-interface standard is protected. | D4-10 |
| `persistence.scheduled` | Acquire at declared intervals, keep each recording, and judge continued resolution. | law, GS1, AAS, dataspace, VC, pilots, platforms | `reg-eu-2024-1781` | `live-sut` | L | None. A scheduler runs outside the run. | D7-05 |
| `integrity.cose` | Verify a COSE signature under a profile with an algorithm allowlist and its own test vectors. | law, platforms | `w3c-vc-jose-cose` | `sample-artifact` | M | Needs a CBOR library. cbor2 and pycose are not installed. Licenses not checked. | none |

### 8.5 Group 3: new capability

| Id | Purpose | Families | Oracle | Network | Size | Dependency or license question | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `integrity.data_integrity` | Verify W3C Data Integrity proofs: JCS suites first, RDFC suites later. | VC, linked data, platforms | `w3c-vc-data-integrity-1-0` | `sample-artifact` | M | rfc8785 and cryptography are installed. Multibase is a few lines or a new dependency. RDFC needs `data.jsonld`. | D3-10 |
| `identity.did` | Resolve `did:web` through the transport, validate the DID document, and verify `did:webvh` logs. | VC, carriers | `new-w3c-did-1-1` | `loopback-only` | M | None for `did:web`. The `did:webvh` logs need `integrity.data_integrity`. | D3-10 |
| `data.jsonld` | Expand JSON-LD to RDF with pinned contexts and a frozen loader. Report dropped terms. | VC, linked data | `new-w3c-json-ld-11-api` | `loopback-only` | L | pyld and rdflib are not installed. Licenses not checked. RDFC-1.0 needs a work limit. | D3-11 |
| `access.public_payload_leak` | Search public on-chain payloads and token metadata for restricted fields and canaries. | ledger | `new-edpb-guidelines-02-2025` | `sample-artifact` | S | None. Reuses the canary search of the access adapter. | D5-04 (advances) |
| `resolver.linkset` | Validate a linkset, find the DPP link, and classify the final document. | GS1, AAS, VC, linked data, carriers | `new-gs1-resolver-linkset-schema` | `loopback-only` | M | The guard in `identifier.resolve` is a new reason code (owner decision). Licenses not checked. | D4-04, D4-07 |
| `resolver.well_known` | Validate well-known description documents. Compare `resolverRoot` with the carrier host. | GS1, VC, carriers, pilots, platforms | `new-gs1-resolver-description-file-schema` | `loopback-only` | S | Needs a target outside `ResourceName` (protected), or a fixed path from the carrier origin. | D4-07 |
| `identifier.granularity` | Compare the granularity of the carrier identifier and the AAS `assetKind` with `ICS.granularity`. | GS1, carriers | `gs1-digital-link-uri-syntax-1-7-0` | `sample-artifact` | S | None. Depends on `identifier.gs1_grammar`. | D4-12 |
| `carrier.ndef_sample` | Parse an offline NDEF dump. Compare its URI record with the declared identifier. | carriers | `new-nfc-forum-rtd-page` | `sample-artifact` | S | Standard library. Access terms of the NFC Forum specification not checked. | D4-10 |
| `aas.dpp_compose` | Compose a shell and its submodels into one view. Check conformance to the pinned template. | AAS | `idta-02099-1-dpp-metadata` | `loopback-only` | M | None. Depends on `data.rule_kinds` and `api.resources`. | D3-09 |
| `trust.identity_anchor` | Hold DID trust anchors in the trust bundle. Verify an identity anchor credential. | VC | `new-untp-0-7-0-dia` | `sample-artifact` | M | Trust bundle model change (protected). Anchors are X.509 only today. | D3-10 |
| `carrier.epc_decode` | Decode an offline EPC memory dump to a GTIN, a serial, and a Digital Link URI. | GS1, carriers | `new-gs1-tds-2-3` | `sample-artifact` | M | Standard library. Work from the GS1 TDS only. | D4-10 |
| `carrier.nfc_sun` | Verify NFC SUN messages: decrypt, check the truncated CMAC and the counter, and reject a replay. | carriers | `new-nxp-an12196` | `sample-artifact` | M | cryptography provides AES and CMAC. Keys are TEST-ONLY. Vendor terms not checked. | D4-10 |
| `resolver.conformance` | Judge resolver behavior: error status, redirects, query pass-through, HEAD, OPTIONS with CORS, and `Link` headers. | law, GS1, AAS, VC, pilots, carriers, platforms | `gs1-conformant-resolver-1-2-1` | `loopback-only`; `live-sut` under a signed authorization | L | Per-hop status needs a change of `Record` or `Request` (protected). Test-suite license not checked. | D4-07 |
| `access.credential_acquisition` | Get role credentials through OAuth 2.0, OIDC, or a holder simulator, not static Bearer secrets. | VC, platforms | `new-openid4vp-1-0` | `loopback-only` | L | TEST-ONLY keys. Token endpoints need POST under an active scope. | D5-05 |
| `dataspace.protocol_probe` | Act as a TEST-ONLY participant on a loopback dataspace: catalog, negotiation, and transfer. | dataspace, platforms | `new-dsp-spec-2025-1` | `loopback-only` | L | Needs POST, TEST-ONLY DID keys, `identity.did`, and `integrity.jose_profiles`. TCK licenses not checked. | D3-08 (advances) |
| `aas.api_profile` | Probe an AAS API against its declared service profiles. Wrap the API mode of aas-test-engines. | AAS, carriers, platforms | `idta-01002-api` | `loopback-only` | L | aas-test-engines 1.0.3 has four read profiles for 3.0. Newer profiles need a newer release. | D3-08 (advances) |
| `trust.eu_trusted_list` | Validate qualified seals and timestamps on operator documents against a pinned trusted list. | law, ledger, pilots | `impl-reg-eu-2026-1778` | `sample-artifact` | L | No advanced-signature library is installed. ETSI documents are a separate license question. | D5-09 |
| `persistence.backup` | Compare the back-up copy with the primary. Test a declared fallback on a fixture. | law, pilots, platforms | `reg-eu-2024-1781` | `loopback-only` | M | None. Needs a back-up resource kind from `api.resources`. | D7-05 |
| `access.encrypted_target` | Recognize encrypted link targets. Check that restricted data is unreadable without the key. | VC | `new-untp-0-7-0-architecture` | `loopback-only` | M | joserfc supports JWE. Decrypt with TEST-ONLY keys only. | none |
| `lifecycle.links` | Resolve predecessor, successor, and previous-version links. Compare both ends. | law, VC, linked data, carriers, platforms | `reg-eu-2024-1781` | `loopback-only` | M | None. Link resolution goes through the transport policy. | none |
| `lifecycle.status` | Judge status transitions. Registry flag, passport status, and HTTP status must agree. | ledger, pilots | `reg-eu-2023-1542` | `loopback-only` | M | None. | none |
| `integrity.issuer_binding` | Check that the author of an anchor is the declared operator or an allow-listed DID. | ledger | `new-ebsi-did-method` | `sample-artifact` | M | Depends on `identity.did` and `integrity.jose_profiles`. | none |
| `integrity.digest_binding` | Compare a resource with a declared digest or IPFS CID. | VC, ledger, pilots | `w3c-vc-data-integrity-1-0` | `loopback-only` | M | hashlib covers SHA-2. keccak-256 needs a dependency. | none |
| `integrity.ledger_proof` | Verify offline inclusion proofs against a trust root pinned in the test pack. | ledger, platforms | `rfc-9162` | `sample-artifact` | M | Reuse the Merkle code of the engine log. Ethereum proofs need RLP and keccak-256. | none |
| `integrity.opc_signature` | Verify the package signatures of an AASX file. | AAS | `idta-01005-aasx` | `sample-artifact` | M | Needs an XML signature library. lxml is not installed. | none |
| `graph.claim_attestation` | Each claim of independent assessment in a verified credential set needs a conformity credential. | VC | `untp-dcc-0-7-0` | `sample-artifact` | L | Depends on a credential profile. A credential that matches does not prove the claim true. | none |

The critic file x02 proposes five more capabilities. x01 did not map them, so the inputs give no size or oracle:

- An event lineage check over a recorded event set, and an EPCIS interface probe on loopback fixtures (section 5.6).
- An ICS profile for several families, and a cross-family mode of `identifier.consistency` (section 5.10).
- A content-negotiation probe: `Vary`, `406`, media type and profile parameters, and parity of HTML and JSON (section 5.1).
- A consistency check of the HTML view against the machine-readable passport, and a digest check of render templates.
- A comparison of the carrier payload with the online passport, and a control-hash check.

### 8.6 Group 4: data or profile only

This work is mainly pinned data, rule packs, or profiles. At most it needs a small loader or a maintainer tool.

| Item | Purpose | Source | Network | Size | Dependency or license question | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| `pattern` in a pinned schema | Check the structure of BPN, LEI, EORI, `urn:uuid`, and ledger references with `data.jsonschema`. | x01 | `sample-artifact` | not estimated | Check characters stay out. | none |
| `unit` and `required_fields` rules | Assert allowed status values, also after deactivation, and the presence of a predecessor reference. | x01 | `loopback-only` | not estimated | Transitions and link resolution stay new. | none |
| EPCIS oracles | Pin an EPCIS 2.0 schema, its context, and a query contract for the registered checks. | x02 | `sample-artifact` | not estimated | Licenses not researched in these inputs. | none |
| `oracle.pin_manifest` | Record artifact, folder, digest, retrieval date, and other locations. A read-only refresh script detects drift. | f04 | `sample-artifact` | not estimated | The refresh script stays outside the run. | none |
| `vocabulary.link_type_allowlist` | Load the pinned GS1 link types file for link-type checks. | f04 | `sample-artifact` | not estimated | A byte-level check of the file comes first. | D4-07 (advances) |
| Catena-X release profile | Map a declared Catena-X release to an aspect version set. | f04 | `sample-artifact` | not estimated | Cite version numbers only. | none |
| `schema.pinned_import` | Turn a published schema set into a reviewed, offline bundle with local `$ref` values. | x01 | `sample-artifact` | S | Maintainer tool with a review step. Record the license per bundle. | none |
| `data.repository_model` | Pin a snapshot of the Commission semantic repository and validate passports against it. | x01 | `sample-artifact` | M | Format unknown. If it is SHACL or OWL, it depends on `data.shacl`. | D3-03, D3-04 |

Two oracle choices need no code. Section 8.8 gives the pinned values.

- For the UNTP Identity Resolver, accept any 3xx with a `Location` header and record the observed code. The test purpose must declare the UNTP version, because the WIP text ends in a 404.
- Treat `linkType=all` as a legacy alias. Accept it if offered, never require it, and send `linkType=linkset` for the full linkset.

### 8.7 Group 5: out of scope for a black-box engine

These items stay manual, deferred, or out of reach for an engine that observes from outside:

- `ledger.read` (L, `live-sut`): it reads a ledger node or indexer, which can be outside the system under test. It needs POST and keccak-256.
- `persistence.erasure` (M): it needs an authorized write scope. The absence of data cannot be proven, only not observed.
- `privacy.tracking_probe` (M): the engine can record cookie names and third-party references. The judgment of "strictly necessary" stays manual. The engine never renders HTML, so script requests are out of reach.
- `evidence.provider_attestation` (S): `manual.review` covers it today. Defer it until the delegated act on DPP service providers exists.
- Proof of lifetime availability: a finite campaign is evidence, never proof.
- Absence of personal data: a pattern rule is a heuristic and proves no absence.
- The truth of a claim: a credential that matches a claim does not prove the claim.
- Check characters of LEI and BPN: they rest on a protected ISO/IEC document. The engine checks structure only, unless an open source turns up.
- Live contact with the official registry: `registry.official` waits for a separately authorized environment (gap D5-08).
- BIM-based construction product passports, the EU web portal and customs, and IoT twins other than AAS. x02 proposes no capability for them.

### 8.8 Oracle artifacts to pin

The table gives the values of f04, with the corrections of its independent check, status on 2026-10-19.
The SHA-256 digests and git blob ids are in `docs/research/raw/implementation-methods/f04-oracle-version-reconciliation.json`. This page does not repeat them.

| Artifact | Pin | Status and other values | License | Note |
| --- | --- | --- | --- | --- |
| IDTA 02099-1 DPP Part 1 Metadata, JSON | folder `1/0/2`, by folder and digest | Content hub shows 1.0, docs site 1.0.1. The 1.0.1 JSON equals the 1.0 JSON. | CC-BY-4.0 | The independent check confirmed the digest. |
| IDTA 02035 parts 1 to 3, JSON | folder `1/1` | Bugfix 1.1. The hub still shows 1.0. | CC-BY-4.0 | The independent check confirmed part 1. It did not re-check parts 2 to 4. |
| IDTA 02035 parts 4, 5, 7, JSON | folder `1/0/2` | Bugfix 1.0.2. Part 5 has a `_V1.0.2` file-name suffix. | CC-BY-4.0 | The independent check confirmed part 5. |
| IDTA 02035 part 6, JSON | folder `1/0/1` | Folder `1/0/2` holds an AASX only. | CC-BY-4.0 | Open question: is the absent 1.0.2 JSON intentional? The AASX size grew sharply. |
| AAS specifications Part 1 and Part 2 | 3.2 (Release 26-01) | aas-test-engines 1.0.3 checks metamodel 3.0.1 and API 3.0.3 only. | not researched | The 3.2 DPP features have no reusable conformance suite. |
| Catena-X CX-0143 | version number 1.4.0 | 1.4.0 is current on the CX-Titan site. 1.5.0 is on GitHub main (26.09 CX-Saturn). 1.2.0 is stale. | all rights reserved | Cite the version only. |
| Catena-X CX-0160 battery passport | 1.1.0 as preview only | CX-Neptune preview, not eligible for certification. Stated go-live: 24 November 2026. | all rights reserved | Not a certification oracle before go-live. |
| Catena-X generic DPP aspect model | 6.1.0 (f04 proposal) | Changelog 1.3.0 of CX-0143 set 6.1.0. The 1.5.0 page on main still names it. | CC-BY-4.0 | The released KIT 26.09 names 5.0.0 (battery 6.0.0). No standard found mandates 7.0.0. |
| GS1 Web Vocabulary | 1.18.0 from ref.gs1.org (2026-06-01) | The GitHub mirror stops at v1.16 and is not current. `gs1:dpp` is a stable link type. | Apache-2.0 (GitHub mirror), with the GS1 IP policy | Digest not computed. The link types file has no version marker, so store the digest of the fetched file. |
| GS1 Digital Link URI Syntax | 1.7.0 | Ratified August 2026, current. | not researched | Oracle of `identifier.gs1_grammar`. |
| GS1-Conformant Resolver | 1.2.1 | Ratified August 2026, current. No fixed redirect status code. | not researched | GS1 Resolver CE uses 307. |
| UNTP Identity Resolver | 0.7.0 pilot release, and WIP main as non-normative | 0.7.0: five 307 arrows, final fallback to the default link. WIP main: four 307 arrows, final 404. | CC BY 4.0 page footer, not read again | No numbered requirement fixes a code. Both flowcharts also show 400 and 200. |
| Battery Pass Technical Guidance v1.0 | link only | March 2024. The PDF states CC BY-NC 4.0. The acatech page states no license. | CC BY-NC 4.0 (in the PDF) | Derive no fixtures from it. The independent check did not extract the license sentence again. |
| Regulation (EU) 2024/1781 | source id `reg-eu-2024-1781` | Retire the alias `espr-reg-2024-1781`. | EU legal text | Digest not computed. |
| Implementing Decision (EU) 2026/1736 | source id `impl-dec-eu-2026-1736` | Retire the alias `cid-2026-1736-dpp-harmonised-standards`. | EU legal text | Digest not computed. |
| Implementing Regulation (EU) 2026/1778 | source id `impl-reg-eu-2026-1778` | Retire the alias `cir-2026-1778-dpp-registry`. | EU legal text | Digest not computed. |

f04 leaves two points open for a byte-level check: `gs1:epcis` in the ref.gs1.org link types file, and the UNTP 307 reading.

### 8.9 Decisions for the owner

Each change to a protected file needs an owner decision under CLAUDE.md rule 1.
No requirement becomes approved through this page. An agent reports the exact change and does not make it.

Rule 10 applies to each new dependency: report it, do not add it.
The gap assessment roadmap already carries several of these decisions in packages O1-4, O2-2, and O2-3.

| Protected file | Change | Capabilities that need it |
| --- | --- | --- |
| `src/dppce/models/declarations.py` | Extend `ResourceName`. | `api.resources`, `data.document_source`, `resolver.well_known`, and through them `persistence.backup` and `aas.dpp_compose` |
| `src/dppce/models/declarations.py` | Allow a list of identifier schemes per ICS. | `identifier.schemes` |
| `src/dppce/models/` | New values of `ICS.signature_format`. | `integrity.jose_profiles`, `integrity.data_integrity` |
| `src/dppce/models/` | DID trust anchors in the trust bundle. | `trust.identity_anchor` |
| `src/dppce/applicability.py` | The evaluation date as a fact for `when` conditions. | `data.rule_kinds` |
| `src/dppce/applicability.py` | An applicability rule for a system under test with several families. | x02 hybrid proposal |
| `src/dppce/infrastructure/interfaces.py` | Per-hop status and headers, or a request that does not follow redirects. | `resolver.conformance` |
| `pyproject.toml` | pyld, rdflib, pySHACL, a CBOR library, multiformats, an XML signature library, Schemathesis, a keccak-256 library, and a newer aas-test-engines. | `data.jsonld`, `data.shacl`, `integrity.cose`, `integrity.digest_binding`, `integrity.opc_signature`, `api.write_ops`, `aas.validate_formats` |

These changes touch no protected file, but change a contract. Report them too:

- A new allowlist entry in the redaction module for the JSON-LD context relation, CORS headers, and cookie names.
- OPTIONS as a read-only method, and extra request headers such as `Accept-Language`, in the transport.
- New versions of the schemas `dppce.rulepack/1` and `dppce.accesspolicy/1`.
- A new reason code for the guard of `resolver.linkset` in `identifier.resolve`.

## 9. Corrections and contradictions

### 9.1 Verification totals

| File | Claims checked | Confirmed | Refuted | Not confirmed | Rule 5 findings |
| --- | --- | --- | --- | --- | --- |
| `f01-epcis-event-traceability` | 34 | 26 | 5 | 3 | 3 |
| `f02-hybrid-stack-composition` | 37 | 30 | 5 | 2 | 3 |
| `f03-backup-failover-availability` | 29 | 24 | 2 | 3 | 3 |
| `f04-oracle-version-reconciliation` | 31 | 25 | 5 | 1 | 2 |
| `g01-plain-web-passport` | 29 | 27 | 0 | 2 | 0 |
| `g02-carrier-embedded-data` | 32 | 28 | 2 | 2 | 6 |
| `g03-other-twin-stacks` | 28 | 24 | 2 | 2 | 3 |
| `l01-reviews-taxonomies` | 33 | 29 | 1 | 3 | 2 |
| `l02-prototypes-pilots` | 28 | 21 | 3 | 4 | 0 |
| `l03-testing-conformance` | 37 | 31 | 1 | 5 | 3 |
| `m01-law-baseline` | 42 | 39 | 2 | 1 | 2 |
| `m02-gs1-web-resolver` | 30 | 27 | 0 | 3 | 0 |
| `m03-aas-digital-twin` | 34 | 29 | 0 | 5 | 2 |
| `m04-dataspace-federated` | 36 | 33 | 0 | 3 | 4 |
| `m05-verifiable-credentials` | 32 | 27 | 3 | 2 | 0 |
| `m06-dlt-anchored` | 32 | 26 | 2 | 4 | 2 |
| `m07-eu-reference-pilots` | 39 | 32 | 4 | 3 | 4 |
| `m08-linked-data-semantic` | 32 | 30 | 0 | 2 | 0 |
| `m09-identification-carriers` | 36 | 32 | 1 | 3 | 3 |
| `m10-platforms-sectors` | 30 | 20 | 5 | 5 | 3 |
| `r01-repositories` | 29 | 26 | 1 | 2 | 0 |
| Total | 690 | 586 | 44 | 60 | 45 |

The engine-mapping check (`x01-engine-mapping.json`) judged 226 mappings of the first round: 172 correct, 36 overstated, and 18 wrong.
The engine-mapping check did not cover the later files `f01` to `f04` and `g01` to `g03`. Their own verifiers judged 26 engine mappings of those files and refuted 12.
Sections 5 to 8 use the corrected mappings.

### 9.2 Corrections that matter for the engine

Most refuted claims are engine mappings. A research agent often claimed that an existing check covers more than its code does.
The sections of this page use the corrected statements. The table lists the corrections with the largest effect on engine design.

| File | Refuted claim, in short | Corrected statement |
| --- | --- | --- |
| `m01` | Authorities get Annex XIII points 2 and 3 of the battery passport. | Notified bodies and market surveillance authorities get point 3 only. The Commission gets points 1 to 3. An access fixture for authorities must not entitle point 2. |
| `m01` | The construction products act sets access levels in Art. 75(2)(b) to (c). | Access levels are in point (c). Create and update rules are in points (d) and (e). Availability and back-up are in point (f). |
| `f03` | The EU registry is live for battery registrations. | The registry has a form for batteries at item level. The user guide says that a successful battery registration is not yet possible. |
| `f04` | `identifier.resolve` covers redirect codes and the `linkType` probes. | These probes need a new resolver-behavior check. `identifier.resolve` judges only the final answer. |
| `f04` | `data.context` can check link types against the GS1 Web Vocabulary. | `data.context` only checks that the `@context` URL is on the allowlist. A link-type check is new. |
| `f04` | `aas.validate` checks a submodel against the pinned IDTA template. | `aas.validate` gives a generic AAS validity result. Template conformance is a new capability. |
| `f02` | `integrity.jws` covers a UNTP credential secured with JOSE. | `integrity.jws` covers JWS with an `x5c` chain only. A key found through a DID needs a new capability. |
| `f01` | `data.jsonschema` validates EPCIS JSON documents. | The check asserts `uri` but not `date-time`, and it validates under the 2020-12 rules only. It needs a change first. |
| `m07` | `data.jsonschema` validates a mock-registry record without change. | The check accepts only the document kinds `item` and `model`. A registry record needs a contract change. |
| `m07` | In the CIRPASS-2 mock registry, an item record needs `batchUpi`. | An item record needs `deactivated` and `modelUpi`. `batchUpi` is optional. |
| `m06` | An IPFS gateway must let the `format` parameter win over `Accept`. | The parameter should win. Only `raw` is mandatory. An oracle must not fail a gateway that honors `Accept` first. |
| `m10` | A GS1 resolver must answer `300` when links of one type tie. | The `300` answer is a recommendation. An oracle must not fail a resolver that omits it. |
| `m05` | UNTP work in progress requires JOSE or COSE from every issuer. | The rule is a proposal for the working group. It is not normative. |
| `m05` | The UNTP identity anchor uses the keys `schemeId` and `registrationScopeList`. | The 0.7.0 schema uses `idScheme` and `registrationScope`. The prose page and the schema disagree. |

The verification files hold every other correction, including DOIs, years, authors, and repository data.

### 9.3 Contradictions between files

The completeness critic found 11 contradictions between files (`x02-critic.json`).
The version file `f04` and the shared sheet of the writers resolved them as follows.

| Topic | Values found | Resolution on this page |
| --- | --- | --- |
| GS1 Web Vocabulary | 1.18.0 at ref.gs1.org; 1.16 on GitHub | Pin 1.18.0 and store the digest. The GitHub mirror is not current. |
| IDTA 02099-1 | 1.0 on the hub; 1.0.1 on the docs site; folder 1/0/2 in the repository | Pin folder 1/0/2 by digest. The 1.0.1 JSON equals the 1.0 JSON. |
| IDTA 02035 parts | 1.0 on the hub; 1.0.1, 1.0.2, or 1.1 by part | Pin by part and digest (section 8). |
| Catena-X CX-0143 | 1.2.0, 1.3, 1.4.0, 1.5.0 | 1.4.0 is current on the published site. 1.5.0 is on GitHub main. 1.2.0 is stale. |
| Catena-X DPP aspect model | 5.0.0, 6.1.0, 7.0.0 | CX-0143 set 6.1.0. The released kit names 5.0.0. No standard found mandates 7.0.0. |
| UNTP resolver redirect code | No code; 307 | No numbered requirement fixes a code. The flowchart uses 307. Accept any 3xx with a Location header. |
| UNTP `linkType=all` | In use; deprecated | Used in a 0.7.0 example. Deprecated in the work in progress. |
| Battery Pass Technical Guidance license | CC BY-NC 4.0; acatech copyright | The PDF states CC BY-NC 4.0. Treat it as link-only. |
| Battery Pass and a ledger | Ledger claimed; no ledger described | Unresolved. This page does not state that Battery Pass uses a ledger. |
| Access to the taxonomy paper `10.18420/inf2025_141` | Full text read; not reachable | The record with the full text is the stronger one. |
| Source identifiers for two EU acts | Several aliases | The canonical identifiers are the ones in `catalogue/sources.yaml`. |

### 9.4 Rule 5 findings

The verifiers recorded 45 rule 5 findings. Most are of low weight: a name next to a request text, or what an open source says about a standard.
The writers left those passages out. One finding concerned an enumeration that an IDTA annex labels with an EN number. This page does not repeat it.
In the second round, the carrier file came close to the content of ISO/IEC RFID and signature standards through GS1 texts that cite them. Section 6.1 names those standards by number only.
Two findings limit the reuse of open artifacts as engine fixtures:

- The README of the CIRPASS-2 battery ontology names a table of a draft EN standard as one input of its SHACL shapes.
- The data point descriptions of the Battery Pass Data Model v1.2.0 refer to chapters of DIN DKE SPEC 99100.

Before the engine vendors either artifact, the owner must decide how rule 5 applies. Section 8 repeats this condition.

## 10. Open questions

Every research file lists open questions. This section merges them into one list with the ids OQ-M01 to OQ-M39. The ids differ from the OQ-0xx ids of the project list of open questions. Status on 2026-10-19.

Each row merges duplicates. The source files are in `docs/research/raw/implementation-methods`. The independent check did not confirm every item. Questions on toy annexes and two consumer-law directives are not researched and stay out of this list.

### 10.1 Questions that other files answer

The engine team does not need to ask these again.

- Battery Pass blockchain (m06): f02 answers in part. The technical guidance describes central services without a ledger. One report claims a private ledger. This page does not state that Battery Pass uses a blockchain.
- Redirect status code (m02, m09): the shared version sheet answers. The GS1 standard fixes no code, GS1 Resolver CE uses `307`, and the oracle accepts any `3xx` response with a `Location` header.
- 02099-1 folder (f04, m03): pin folder `1/0/2` by folder and SHA-256 digest.
- AAS conformance suite (m10): `aas-test-engines` 1.0.3 checks metamodel 3.0.1 and API 3.0.3 only. No reusable suite covers v3.2.
- EU fallback service (m10): f03 located none.
- Vocabulary and Catena-X versions (m02, m08, m04): pin GS1 Web Vocabulary 1.18.0. CX-0143 1.4.0 is current. CX-0160 1.1.0 is a preview.

### 10.2 Registry and law

The law statements here follow the legal baseline check. Questions that come from family files are marked "(family file; not verified)".

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M01 | Which hash algorithm, input, and file format does the registry use for the hash of a passport version (Implementing Regulation (EU) 2026/1778, Arts 2(16), 9)? | A carrier control hash cannot be compared without them. | Commission |
| OQ-M02 | Should a carrier control hash cover the first registered version or the latest version? | The proof of registration covers the latest version only. | Owner, Commission |
| OQ-M03 | When will the registry API specification and the public APIs of the semantic repository appear, and at which URLs? The section is empty on 2026-10-19. | The L05 and L09 oracles cannot pin them today. | Commission |
| OQ-M04 | Which thresholds does the registry apply when it resolves a UPI: redirect count, response size, ports, domains, media types? | The user guide gives the message "unable to process your request" for excessive redirects, protocol downgrades, and oversized responses, but no values. | Commission |
| OQ-M05 | Which access rules apply to Annex XIII points 2 and 4 of Regulation (EU) 2023/1542 on 2027-02-18 if the Art. 77(9) act is not adopted? | Access-policy tests need the rule set for each role. | Commission |
| OQ-M06 | Does the back-up duty of Art. 10(4) apply to battery passports? Is registration a precondition for placing a battery on the market from 2027-02-18? | The applicability rules cannot decide if back-up checks apply to a battery. | Commission, reviewer |
| OQ-M07 | Do the OJ citations of EN 18219:2026 and EN 18220:2026 end the fallback to the ISO/IEC 15459 series, and from which date? | The identifier scheme list in the profile depends on it. | Commission, standards body |
| OQ-M08 | Which granularity, carrier, and identifier scheme will the product delegated acts and the Art. 12(4) issuing-agency act set? None was located. | The ICS values for identifier checks stay open. | Commission |
| OQ-M09 | Will the service provider act define a back-up interface, a synchronization interval, an availability level, and an activation procedure? Sources give adoption dates from Q1 2026 to Q3 2027. | Back-up checks have no oracle without it. | Commission |
| OQ-M10 | Will the Art. 11 act on credentials prescribe W3C credentials, eIDAS attestations, or another mechanism? Does the registry accept wallet-presented attestations? | The integrity layer needs a trust framework. | Commission |
| OQ-M11 | Does the registry store resolver URLs and a back-up link? How does the Commission check the back-up link? Do the upload templates carry the field? | The failover flow and the registry mock depend on it. | Commission |

### 10.3 Identification and carriers

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M12 | Which open oracle can check the check characters of LEI, BPN, and GMN (AI 8013)? ISO/IEC 7064 is protected, and the GS1 General Specifications file is too large to fetch. | The engine can only check structure. Cryptographic or check-digit results stay "not run". | Owner, GS1 |
| OQ-M13 | Does the zxing-cpp release in the `qr` extra expose the symbology identifier? (not confirmed by the independent check) | Carrier checks need it to tell GS1 mode from plain URLs. | Owner (local test) |
| OQ-M14 | Did the adopted request C(2024) 5423 keep the optional control data, the counterfeit link, and the six offline data elements? | The offline carrier profile depends on it. | Commission |
| OQ-M15 | Will GS1 approve compressed EPC Digital Link URIs, a DPP application standard, or hybrid UHF and NFC carriers? | Carrier profiles cannot be final. | GS1, Commission |
| OQ-M16 | Does a repurposed or remanufactured battery keep its identifier or get a new one, and which construct links the passports? | A linkage check needs one rule. | Commission, IDTA |

### 10.4 Resolution and link types

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M17 | Should the engine flag `301` and `308` as a risk? The oracle accepts any `3xx` response. | The reason codes and the fault catalogue need one policy. | Owner |
| OQ-M18 | Which namespace form is the oracle for gs1 link types: `https://ref.gs1.org/voc/`, `http://gs1.org/voc/`, or `https://gs1.org/voc/`? Which release introduced `gs1:dpp`? Does the link-type file contain `gs1:epcis`? | The engine needs a pinned equivalence table and a stored digest of the fetched file. | Owner, GS1 |
| OQ-M19 | Which relation name marks the passport hand-over: IANA `dpp`, `gs1:dpp`, or the IDTA token? IANA lists `dpp` from UNTP only. | A linkset oracle must decide if unregistered bare tokens pass. | IDTA, GS1, UNTP |
| OQ-M20 | Can one GS1 Digital Link URI act as an IDTA ID Link, with one linkset that carries both relations? | Hand-over between families has no test today. | IDTA, GS1 |
| OQ-M21 | Is a schema rejection of a valid BCP 47 tag or hyphenated relation URI a fail, a separate finding, or ignored? Does the `public` member carry a rule? | GS1 schema defects would give false fails. | Owner, GS1 |
| OQ-M22 | Does a `200` linkset answer at the carrier URL count as a conforming entry point? Should `identifier.resolve` report it as a distinct outcome? | The default path accepts any JSON object as a passport. | Owner |
| OQ-M23 | Which Accept vectors form the test matrix? Is `406` or a default representation the expected answer? The IXIT has no field for this. | Negotiation checks need a pinned baseline. | Owner |

### 10.5 Data models, twins, and dataspaces

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M24 | Does `aas-test-engines` 1.0.3 accept or reject v3.2 artifacts? Which IDTA profile covers a minimal DPP deployment? Do current servers implement the History and Signature profiles? | `aas.validate` could reject valid v3.2 passports. | Owner (local run), IDTA |
| OQ-M25 | Will IDTA add algorithms beyond RS256 or a revocation mechanism? What does the IDTA certification portal cover? | The integrity profile and the scope statement depend on it. | IDTA |
| OQ-M26 | How do `contentSpecificationIds` track patch versions? How does a passport tell the battery carbon footprint template from the generic template that shares its `semanticId`? | Version pins and semantic checks can pass the wrong template. | IDTA |
| OQ-M27 | Which Catena-X release certifies CX-0143 1.5.0? Does any standard mandate DPP aspect 7.0.0? Will the conformity criteria become machine-checkable? | The aspect pin is 6.1.0 or 5.0.0, depending on the source. | Upstream project |
| OQ-M28 | Who runs the "EU-facing DPP management system" of CX-0160-3, and with which resolver and API profile? Go-live is stated for 24 November 2026. | The bridge to the EU system has no test purpose. | Upstream project |
| OQ-M29 | Should a signed DSP or DCP TCK run count as evidence through `manual.review`? How does the access-policy model show a DSP `404` for unauthorized calls? | Both TCKs need a credentialed connection the engine does not make. | Owner |

### 10.6 Events, credentials, and ledgers

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M30 | Which URL should a `gs1:epcis` link target? Which `@context` URL do fielded EPCIS 2.0 documents embed? Did release 2.0.1 change normative text? | The `data.context` allowlist and the link oracle depend on it. | GS1 |
| OQ-M31 | How should a public tier expose traceability when EPCIS needs authentication on every call? Which signature algorithm does a system under test declare for GS1-Signature? | The IXIT must carry the answer. | GS1, owner |
| OQ-M32 | Which algorithms does the UNTP profile accept for `vc+jwt`? Should the engine accept `dc+sd-jwt` next to `vc+sd-jwt`? How should a test pack treat `statusListIndex`? | A conformance pack needs a maintainer-chosen allowlist. | UNTP, owner |
| OQ-M33 | Should the engine extend `integrity.jws` or add a separate JOSE credential capability? Which contract changes does the engine need for a linkset, a cross-layer identifier check, or ledger read access? | The architecture contract has no entry for them. | Owner |
| OQ-M34 | How should ICS and IXIT express a chain-qualified anchor? Which algorithm applies when a receipt names no canonical form? Would an EIP-1186 proof count as evidence? | Anchor checks need a pinned chain, a finality rule, and recorded responses. | Owner |
| OQ-M35 | Can a ledger copy satisfy the Art. 10(4) back-up duty? Does any act mention ledgers or qualified electronic ledgers? | A ledger family could claim back-up without a legal basis. | Commission |
| OQ-M36 | Which trigger marks cessation for a fallback client: DNS failure, `404`, `410`, or a signed tombstone? Must the back-up host differ from the primary host? | A fallback check needs one rule. | Commission, owner |

### 10.7 Licenses, semantics, and fixtures

| Id | Question | Why it matters for the engine | Who can answer |
| --- | --- | --- | --- |
| OQ-M37 | Under which license can the engine reuse UNTP schemas, contexts, and samples? The page footer and the repositories differ. Which CIRPASS-2 files and Battery Pass PDFs are reusable? | The Battery Pass guidance is link-only. The team cannot derive fixtures without a license. | Upstream project, owner |
| OQ-M38 | Which JSON-LD processor should `data.shacl` use? How does the engine detect drift of a context that the system under test hosts? How are expected disagreements with JSON Schema declared? | Network loading breaks the no-network rule. Graphs differ between processor versions. | Owner |
| OQ-M39 | Where and in which formats will the semantic repository publish its models? Is the CIRPASS-2 CORE ontology repository private, renamed, or moved? | The L05 and L09 oracles and SHACL fixtures depend on them. | Commission, upstream project |

## 11. Limits of this research

- No person reviewed this page or its evidence files. Agreement between agents is not a human review.
- The page is not normative for the code. The [architecture contract](../explanation/architecture.md) stays the engineering contract.
- The page makes no statement of legal compliance. It is not legal advice. The legal status date is 2026-10-19.
- The content of EN, ISO, IEC, and DIN documents was not used. For several layers, the harmonised standards may add rules that this page cannot show.
- The verifiers checked a sample of claims chosen by risk. The other claims rest on one agent and one reading of the source.
- Most papers were read as abstracts only. MDPI pages and several publisher pages were not reachable.
- The agents read long specifications in windows through a summarizing fetch tool. Wording in the evidence files is paraphrase, not a character-exact copy.
- No artifact was hashed, except the oracle files in `f04-oracle-version-reconciliation.json`.
- Vendor statements are secondary sources. The page does not rank vendors and makes no commercial recommendation.
- About 400 sources in the evidence files are not yet in `catalogue/sources.yaml`. A merge needs one canonical identifier for each source.
- Specifications change often. Several versions on this page were current only on 2026-10-19.

## 12. Evidence and references

### 12.1 Evidence files

Each file holds the full record of its topic: sources with verification levels, implementations, literature, test implications, faults, and open questions.
Each `*.verification.json` file next to it holds the independent check.

- `docs/research/raw/implementation-methods/f01-epcis-event-traceability.json`
- `docs/research/raw/implementation-methods/f02-hybrid-stack-composition.json`
- `docs/research/raw/implementation-methods/f03-backup-failover-availability.json`
- `docs/research/raw/implementation-methods/f04-oracle-version-reconciliation.json`
- `docs/research/raw/implementation-methods/g01-plain-web-passport.json`
- `docs/research/raw/implementation-methods/g02-carrier-embedded-data.json`
- `docs/research/raw/implementation-methods/g03-other-twin-stacks.json`
- `docs/research/raw/implementation-methods/l01-reviews-taxonomies.json`
- `docs/research/raw/implementation-methods/l02-prototypes-pilots.json`
- `docs/research/raw/implementation-methods/l03-testing-conformance.json`
- `docs/research/raw/implementation-methods/m01-law-baseline.json`
- `docs/research/raw/implementation-methods/m02-gs1-web-resolver.json`
- `docs/research/raw/implementation-methods/m03-aas-digital-twin.json`
- `docs/research/raw/implementation-methods/m04-dataspace-federated.json`
- `docs/research/raw/implementation-methods/m05-verifiable-credentials.json`
- `docs/research/raw/implementation-methods/m06-dlt-anchored.json`
- `docs/research/raw/implementation-methods/m07-eu-reference-pilots.json`
- `docs/research/raw/implementation-methods/m08-linked-data-semantic.json`
- `docs/research/raw/implementation-methods/m09-identification-carriers.json`
- `docs/research/raw/implementation-methods/m10-platforms-sectors.json`
- `docs/research/raw/implementation-methods/r01-repositories.json`

Two generated indexes list every source and paper once: `index-sources.json` (460 sources) and `index-literature.json` (273 papers).

### 12.2 Literature cited on this page

Titles are as the search tools returned them. Each DOI was checked at Crossref or OpenAlex, unless the evidence file says otherwise.

- A Reference Architecture for Digital Product Passports at Batch Level to Support Manufacturing Supply Chains (2024). [doi:10.1007/978-3-031-59465-6_19](https://doi.org/10.1007/978-3-031-59465-6_19)
- A Comprehensive Review of Digital Product Passports in Sustainable Manufacturing: Current State, Challenges, and Future Directions (2026). [doi:10.1007/s43615-026-00927-x](https://doi.org/10.1007/s43615-026-00927-x)
- A Comprehensive Review of Digital Product Passports in Sustainable Manufacturing: Current State, Challenges, and Future Directions (2026). [doi:10.1007/s43615-026-00927-x](https://doi.org/10.1007/s43615-026-00927-x)
- Current methodologies of creating Material Passports: A Systematic Literature Review (2025). [doi:10.1016/j.cscm.2025.e04267](https://doi.org/10.1016/j.cscm.2025.e04267)
- Digital Product Passport as a Digital Twin? Analyzing Conceptual Intersections and Deriving Design Elements (2026). [doi:10.1016/j.procir.2026.05.053](https://doi.org/10.1016/j.procir.2026.05.053)
- Bridging the Gaps Towards a Unified Architecture for Digital Product Passports: A Data Space Perspective on Existing Standards and Initiatives (2026). [doi:10.1016/j.procs.2026.02.274](https://doi.org/10.1016/j.procs.2026.02.274)
- Enabling a dynamic information flow in digital product passports during product use phase: A literature review and proposed framework (2025). [doi:10.1016/j.spc.2025.01.014](https://doi.org/10.1016/j.spc.2025.01.014)
- Towards a reference architecture for digital product passports in engineering (2026). [doi:10.1017/pds.2026.10518](https://doi.org/10.1017/pds.2026.10518)
- Digital Product Passports: Use Cases Framework and Technical Architecture Using DLT and Smart Contracts (2023). [doi:10.1109/dcoss-iot58021.2023.00067](https://doi.org/10.1109/dcoss-iot58021.2023.00067)
- From Static Records to Smart Passports: Evolving Digital Product Passports Toward Product-Service System Integration (2025). [doi:10.1109/dcoss-iot65416.2025.00163](https://doi.org/10.1109/dcoss-iot65416.2025.00163)
- From Product Data to Circular Infrastructure: A System-of-Systems Analysis of Digital Product Passports Ecosystem (2026). [doi:10.1109/sose69681.2026.11622330](https://doi.org/10.1109/sose69681.2026.11622330)
- Legal Challenges and Technical Solutions to Decentralised Digital Product Passports (2025). [doi:10.18420/inf2025_03](https://doi.org/10.18420/inf2025_03)
- Under The Industrial Hood: A Taxonomy for Digital Product Passports (2025). [doi:10.18420/inf2025_141](https://doi.org/10.18420/inf2025_141)
- Exploring the Design Space and Research Directions for Digital Product Passport Systems (2025). [doi:10.23919/cnsm67658.2025.11297523](https://doi.org/10.23919/cnsm67658.2025.11297523)
- Architecture for a Digital Product Passport System based on the Ecodesign for Sustainable Products Regulation and the corresponding Standardisation Request (2024). [doi:10.24406/publica-9335](https://doi.org/10.24406/publica-9335)
- Digital Product Passports: A Systematic Literature Review on Framework Design and Validation (2026). [doi:10.3390/digital6020043](https://doi.org/10.3390/digital6020043)
- Digital Product Passport Management with Decentralised Identifiers and Verifiable Credentials (2024). [doi:10.48550/arxiv.2410.15758](https://doi.org/10.48550/arxiv.2410.15758)
- Design and Implementation of a Digital Product Passport Prototype for a Coffee Machine in the Circular Economy (2026). [doi:10.5281/zenodo.18433713](https://doi.org/10.5281/zenodo.18433713)
- Product Digital Twin Ontology: A Pivot for Bridging Asset Administration Shell-based and Ontology-based Digital Product Passports. (2026). [doi:10.5381/jot.2026.25.3.a21](https://doi.org/10.5381/jot.2026.25.3.a21)
