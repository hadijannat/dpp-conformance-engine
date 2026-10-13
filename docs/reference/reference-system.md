# Reference DPP system and data formats

Audience: contributors who work on the reference system, the adapters, or the fixtures.
Purpose: define the synthetic reference system and the local data formats that the checks read.
Prerequisites: read the [architecture contract](../explanation/architecture.md).

The reference system is a minimal local example. It is not a normative authority, and no
field name here comes from a standard or from a law. All data are synthetic.

## 1. Server

Module: `dppce.infrastructure.reference_server`. Standard library only (`http.server`).
It binds to `127.0.0.1` on a port that the caller selects (port `0` means any free port).

```python
class ReferenceServer:
    def __init__(self, fixtures: Path, *, faults: frozenset[str] = frozenset(), port: int = 0) -> None: ...
    @property
    def origin(self) -> str: ...          # for example "http://127.0.0.1:49152"
    def start(self) -> None: ...          # serves in a daemon thread
    def stop(self) -> None: ...
    def __enter__(self) -> ReferenceServer: ...
    def __exit__(self, *exc: object) -> None: ...
```

`python -m dppce.infrastructure.reference_server --fixtures fixtures/reference --port 8080
[--fault NAME]...` runs it in the foreground. The server only reads. It has no write operation.

## 2. Identifiers and the origin override

Carriers hold the public identifier, for example
`https://id.example.test/01/09506000134352/21/EV0001`. The domain `example.test` is reserved
and never resolves. A test rig maps it to the local server:

- `IXIT.endpoints["public_origin"]` is `https://id.example.test`.
- `IXIT.endpoints["origin_override"]` is the local origin, for example `http://127.0.0.1:49152`.

A check sends a URL whose origin equals `public_origin` to `origin_override` in its place.
The helper `dppce.adapters.common.effective_url(ctx, url)` does this in one place. Each
observation that used it lists the transformation `origin_override`.
Identifier comparison always uses the public form.

Identifier scheme `gs1-digital-link` (the only scheme with a parser in this version): an HTTP
or HTTPS URL whose path has the form `/01/<14 digits>/21/<serial>`. The parser checks the GTIN
check digit. Every other declared scheme gives the reason code `IDENTIFIER.SCHEME.UNSUPPORTED`
with status `unsupported`.

Three synthetic items, one for each profile:

| Profile | Category | Serial | Capacity (Wh) |
| --- | --- | --- | --- |
| `battery/ev` | `ev` | `EV0001` | 75000 |
| `battery/lmt` | `lmt` | `LMT0001` | 500 |
| `battery/industrial` | `industrial` | `IND0001` | 5000 |

## 3. Endpoints

All are `GET`. `{id}` is `<gtin>-<serial>`, for example `09506000134352-EV0001`.

| Path | Answer |
| --- | --- |
| `/01/{gtin}/21/{serial}` | `303` with `Location: /dpp/{id}` |
| `/dpp/{id}` | `200 application/json`: the item-level passport for the role |
| `/dpp/{id}/model` | `200 application/json`: the shared model-level data |
| `/dpp/{id}/signed` | `200 application/jose`: compact JWS over the anonymous item-level passport |
| `/dpp/{id}/versions` | `200 application/json`: the version history |
| `/dpp/{id}/export` | `200 application/json`: export of the data for the role |
| `/dpp/{id}.html` | `200 text/html`: a human-readable view for the role |
| `/search?q={text}` | `200 application/json`: `{"results": [...]}` with data for the role |
| `/registry/{id}` | `200 application/json`: the mock registry record |
| any other path | `404 application/json`: `{"error": "not_found", "detail": "..."}` |

Roles: a request with no credential is `anonymous`. `Authorization: Bearer <token>` selects
the role whose token is in `fixtures/reference/roles.json`. The tokens are synthetic test
values and their names start with `TEST-ONLY-`.

## 4. Documents

### 4.1 Item-level passport (`/dpp/{id}`)

```json
{
  "@context": ["https://dppce.example.test/contexts/battery/v1"],
  "id": "https://id.example.test/01/09506000134352/21/EV0001",
  "type": "BatteryPassport",
  "granularity": "item",
  "model": "https://id.example.test/01/09506000134352",
  "category": "ev",
  "operator": {"name": "Example Battery Works (synthetic)", "identifier": "urn:example:operator:0001"},
  "manufactured": "2027-03-01",
  "rated_capacity": {"value": 75000, "unit": "Wh"},
  "remaining_capacity": {"value": 74000, "unit": "Wh"},
  "state_of_health_percent": 99,
  "status": "original",
  "version": 3,
  "updated_at": "2026-10-10T08:00:00Z"
}
```

Numbers are integers. A role that the access policy permits also gets the object `restricted`:

```json
{"restricted": {"dismantling_notes": "Synthetic note.", "supplier_reference": "CANARY-7f3a-supplier"}}
```

### 4.2 Model-level data (`/dpp/{id}/model`)

```json
{
  "@context": ["https://dppce.example.test/contexts/battery/v1"],
  "id": "https://id.example.test/01/09506000134352",
  "type": "BatteryModel",
  "granularity": "model",
  "category": "ev",
  "chemistry": "synthetic-chemistry-a",
  "nominal_voltage": {"value": 400, "unit": "V"},
  "mass": {"value": 450, "unit": "kg"}
}
```

Item-level data and model-level data are separate documents with separate schemas.

### 4.3 Version history (`/dpp/{id}/versions`)

```json
{"versions": [
  {"version": 1, "updated_at": "2026-09-01T08:00:00Z", "content_digest": "sha256:..."},
  {"version": 3, "updated_at": "2026-10-10T08:00:00Z", "content_digest": "sha256:..."}
]}
```

`content_digest` is `dppce.evidence.canonical.digest` of the anonymous item-level passport of
that version. Declared update rule of the reference system: a change of content needs a higher
version number and a later or equal `updated_at`. The last entry describes the current document.

### 4.4 Registry record (`/registry/{id}`)

```json
{"identifier": "https://id.example.test/01/09506000134352/21/EV0001",
 "operator_identifier": "urn:example:operator:0001",
 "passport_url": "https://id.example.test/01/09506000134352/21/EV0001",
 "registered_at": "2026-09-01T08:00:00Z"}
```

### 4.5 Signed passport (`/dpp/{id}/signed`)

Compact JWS, `alg: ES256`, `typ: "dpp+jws"`, `kid`, and `x5c` (leaf certificate first, DER,
standard base64). The payload is `canonical_bytes` of the anonymous item-level passport.
The fixture PKI lives in `fixtures/reference/pki/`. Each file name starts with `TEST-ONLY-`:

- a root certificate that the test trust bundle lists as an anchor, and a leaf that it signed;
- a second, untrusted root with its leaf (fault `sig_untrusted_issuer`);
- a leaf from the trusted root whose validity ended on 2025-12-31 (fault `cert_expired`).

## 5. Local data formats

All paths are relative to the data root. A profile names the files that it uses.

### 5.1 Rule pack (`profiles/battery/rules/*.yaml`)

```yaml
schema_version: dppce.rulepack/1
rulepack_id: battery/illustrative-rules
version: 0.1.0
rules:
  - id: BAT-RULE-001
    kind: required_fields          # completeness for a category and an access tier
    document: item                 # item | model
    when: {fact: ics.product_category, op: eq, value: ev}   # optional applicability expression
    fields: [id, operator.identifier, rated_capacity.value]
    basis: {class: illustrative}
  - {id: BAT-RULE-002, kind: unit, document: item, field: rated_capacity.unit, allowed: [Wh], basis: {class: illustrative}}
  - {id: BAT-RULE-003, kind: range, document: item, field: state_of_health_percent, min: 0, max: 100, basis: {class: illustrative}}
  - {id: BAT-RULE-004, kind: relationship, document: item, left: remaining_capacity.value, op: le, right: rated_capacity.value, basis: {class: illustrative}}
  - {id: BAT-RULE-005, kind: freshness, document: item, field: updated_at, max_age_days: 30, basis: {class: engineering, note: "Demonstration value."}}
```

`basis.class` is `normative`, `engineering`, or `illustrative`. A `normative` rule must give
`source_id` and `citation`. An `engineering` rule is a project threshold and is reported as such.
The freshness limit is inclusive: an age of exactly `max_age_days` passes.
Field paths are dotted. A rule whose `when` expression is `false` is skipped; `unknown` makes
the check inconclusive with the reason code `DATA.RULES.APPLICABILITY_UNKNOWN`.

Reason codes, in this order of precedence when more than one rule fails:
`DATA.COMPLETENESS.MISSING`, `DATA.UNIT.INVALID`, `DATA.RANGE.VIOLATED`,
`DATA.RELATIONSHIP.VIOLATED`, `DATA.FRESHNESS.STALE`. A pass gives `DATA.RULES.OK`.
The observation summary lists every failed rule id.

### 5.2 Access policy (`profiles/battery/access/*.yaml`)

```yaml
schema_version: dppce.accesspolicy/1
policy_id: battery/reference-policy
version: 0.1.0
basis: {class: illustrative}
restricted:                         # dotted paths in the item-level passport
  - {path: restricted.dismantling_notes, roles: [legitimate_interest, authority]}
  - {path: restricted.supplier_reference, roles: [authority]}
canaries:                           # synthetic values; sandboxes only
  - {path: restricted.supplier_reference, value: CANARY-7f3a-supplier}
channels:
  fetch: /dpp/{id}
  export: /dpp/{id}/export
  search: /search?q={serial}
  error: /dpp/{id}/does-not-exist
  html: /dpp/{id}.html
```

The policy states what the system owner declares. The check observes whether the system
enforces that declaration. It does not decide who has a legal entitlement.

For the role under test, the check reads each channel. A restricted path that the role may not
see, or a canary value in the body bytes, is a leak. Reason codes: `ACCESS.LEAK.FETCH`,
`ACCESS.LEAK.EXPORT`, `ACCESS.LEAK.SEARCH`, `ACCESS.LEAK.ERROR`, `ACCESS.LEAK.HTML`; the first
leaking channel in that order names the code. A pass gives `ACCESS.POLICY.ENFORCED`.
The observation summary holds channel names and field paths. It never holds a field value.

### 5.3 API contract (`profiles/battery/contracts/*.yaml`)

An OpenAPI 3.1 document that the maintainer of the reference system supplies and pins.
Supported subset: `paths` with path templates, `get`, `responses.<status>.content.<media
type>.schema`, and local `#/components/schemas/...` references. A contract that uses anything
else gives status `unsupported` with `API.CONTRACT.UNSUPPORTED_FEATURE`.
Reason codes: `API.CONTRACT.STATUS`, `API.CONTRACT.CONTENT_TYPE`, `API.CONTRACT.SCHEMA`,
`API.CONTRACT.OK`.

### 5.4 Context allowlist

A profile constant `allowed_contexts` is not expressive enough, so the test purpose passes
`params.allowed_contexts`: a list of exact context URLs. No context is fetched.
Reason codes: `DATA.CONTEXT.MISSING`, `DATA.CONTEXT.NOT_ALLOWED`, `DATA.CONTEXT.OK`.

## 6. Fault flags

Each flag changes one behavior. `validation/fault-catalogue.yaml` states the expected outcome.

| Flag | Changed behavior |
| --- | --- |
| `api_wrong_content_type` | `/dpp/{id}` answers with `Content-Type: text/plain` |
| `api_schema_violation` | `/dpp/{id}` omits `operator` |
| `leak_fetch` | anonymous `/dpp/{id}` includes `restricted` with the canary |
| `leak_export` | anonymous `/dpp/{id}/export` includes the canary |
| `leak_search` | anonymous `/search` includes the canary |
| `leak_error` | the anonymous `404` body includes the canary in `detail` |
| `leak_html` | the anonymous HTML view includes the canary |
| `sig_invalid` | the JWS payload differs from the signed bytes |
| `sig_untrusted_issuer` | the JWS is signed by the leaf of the untrusted root |
| `cert_expired` | the JWS is signed by the expired leaf |
| `id_mismatch` | the passport `id` names serial `OTHER0001` |
| `resolver_404` | `/01/...` answers `404` |
| `redirect_out_of_scope` | `/01/...` answers `302` to `http://out-of-scope.example.test/` |
| `data_wrong_type` | `state_of_health_percent` is the string `"99"` |
| `data_missing_required` | `rated_capacity` is absent |
| `data_stale` | `updated_at` is `2025-01-01T00:00:00Z` |
| `data_wrong_unit` | `rated_capacity.unit` is `kWh` |
| `data_relationship` | `remaining_capacity.value` is larger than `rated_capacity.value` |
| `context_invalid` | `@context` is `["https://unpinned.example.test/ctx"]` |
| `registry_inconsistent` | the registry record names operator `urn:example:operator:9999` |
| `version_undeclared_change` | the last version entry repeats the previous version number with a different digest |

The fault `qr_payload_invalid` is a fixture, not a flag: `fixtures/reference/qr/invalid.png`
encodes plain text that is not a URL. The fault `unreachable` is a rig condition: no server runs.

## 7. Fixtures

```text
fixtures/reference/
  items/{ev,lmt,industrial}.json     anonymous item-level passports
  models/{ev,lmt,industrial}.json    model-level data
  roles.json                         role -> TEST-ONLY token
  secrets/TEST-ONLY-<role>.token     the same tokens, one file for each role, for `--secrets`
  pki/TEST-ONLY-*.pem                fixture PKI (section 4.5)
  qr/{ev,lmt,industrial,invalid}.png QR images
  ics/{ev,lmt,industrial}.yaml       declarations for each profile
  ixit/{ev,lmt,industrial}.yaml      test information; `origin_override` is set by the rig
  trust/TEST-ONLY-trust-bundle.json  anchors and keys for the reference system
  authorization/                     TEST-ONLY owner key and a signed test authorization
```

`scripts/gen_fixtures.py` writes the PKI, the QR images, the trust bundle, and the
authorization. Keys are random, so the generated files are committed. The script is rerun only
to rotate them. QR images are generated with zxing-cpp and Pillow (the `qr` extra).

## 8. Check parameters and outcomes

This section is the contract between the test pack and the adapters.

IXIT conventions for the reference rig:

- `endpoints.api` and `endpoints.registry`: base URLs in public form (`https://id.example.test`).
- `endpoints.public_origin` and `endpoints.origin_override`: see section 2.
- `samples.qr_image`: path of a QR image. `samples.identifier`: the public identifier as text.
- `samples.passport_id`: the `{id}` path segment, for example `09506000134352-EV0001`.
- `samples.aas_file`: path of an Asset Administration Shell JSON file (optional).

A sample path is relative to the directory of the IXIT file and must stay inside it.
The IXIT is untrusted input: see the architecture contract, section 9.1. The operator supplies
the trust bundle (`--trust`), the secrets directory (`--secrets`), and the confirmation of each
non-public host (`--allow-private-host 127.0.0.1`). An identity uses
`secret_ref: "file:TEST-ONLY-authority.token"`, and the operator confirms it with
`--role-secret authority=file:TEST-ONLY-authority.token`.

Shared helpers in `dppce.adapters.common`:

- `effective_url(ctx, url)`: applies the origin override.
- `identifier_text(ctx)`: the carrier identifier. If `samples.qr_image` exists, decode it (this
  needs the `qr` extra; without it the check is `unsupported`). Otherwise use
  `samples.identifier`. If neither exists, the check is `blocked` with `CARRIER.SAMPLE.MISSING`.
- `fetch_once(ctx, url, role)`: returns an earlier record of the same method, URL, and role if
  it has no error; otherwise fetches. This keeps the request count low and the replay stable.
- `unreachable(ctx, record)`: builds the outcome for a record with a transport error:
  status `completed`, `passed: false`, `unreachable: true`. Reason code
  `TRANSPORT.REDIRECT_OUT_OF_SCOPE` for that error, `TRANSPORT.DENIED` for `policy_denied`,
  `authorization_denied`, and `budget_exhausted`, and `TRANSPORT.UNREACHABLE` for the others.

A response that is not valid JSON where JSON is needed gives a `fail` with `<AREA>.RESPONSE.NOT_JSON`.
A truncated body gives status `blocked` with `TRANSPORT.BODY_TRUNCATED`: a partial body proves nothing.

| Check | Parameters | Pass | Fail and other outcomes |
| --- | --- | --- | --- |
| `carrier.qr_decode` | `artifact` (default `qr_image`) | `CARRIER.QR.OK`: one symbol with text | `CARRIER.QR.NOT_DECODED` (fail); sample missing: `blocked`, `CARRIER.SAMPLE.MISSING` |
| `identifier.parse` | `scheme` (default: `ics.identifier_scheme`) | `IDENTIFIER.SYNTAX.OK` | `IDENTIFIER.SYNTAX.INVALID` (fail); `IDENTIFIER.SCHEME.UNSUPPORTED` (`unsupported`); scheme `unknown`: `blocked`, `IDENTIFIER.SCHEME.UNKNOWN` |
| `identifier.resolve` | none | `IDENTIFIER.RESOLVED`: final status 200 with a JSON object | 404 or 410: `IDENTIFIER.UNRESOLVED` (fail); other status: `IDENTIFIER.RESOLUTION.STATUS` (fail) |
| `identifier.consistency` | none | `IDENTIFIER.CONSISTENT` | `IDENTIFIER.MISMATCH` (fail). Compares the carrier identifier, `samples.identifier` when both exist, and the `id` of the resolved passport |
| `api.contract` | `path` (for example `/dpp/{id}`), `method` (default `get`) | `API.CONTRACT.OK` | see section 5.3 |
| `data.jsonschema` | `document`: `item` or `model` | `DATA.SCHEMA.OK` | `DATA.SCHEMA.INVALID` (fail). The summary lists JSON paths and keywords, never values |
| `data.context` | `document`, `allowed_contexts` | `DATA.CONTEXT.OK` | see section 5.4 |
| `data.rules` | `document` (default `item`) | `DATA.RULES.OK` | see section 5.1 |
| `access.restricted_fields` | `role` (default `anonymous`) | `ACCESS.POLICY.ENFORCED` | see section 5.2 |
| `integrity.jws` | none | `INTEGRITY.OK` | first that applies: `INTEGRITY.SIGNATURE.INVALID`, `INTEGRITY.ISSUER.UNTRUSTED`, `INTEGRITY.CERT.EXPIRED`, `INTEGRITY.CERT.REVOKED`, `INTEGRITY.PAYLOAD.MISMATCH` (all fail); no trust bundle: `blocked`, `INTEGRITY.TRUST.MISSING`; mandatory status snapshot missing or stale: `blocked`, `INTEGRITY.STATUS.MISSING` |
| `persistence.versions` | none | `PERSISTENCE.OK` | `PERSISTENCE.UNDECLARED_CHANGE` (fail) |
| `registry.consistency` | none | `REGISTRY.OK` | `REGISTRY.INCONSISTENT` (fail); status 401, 403, or 404: `REGISTRY.LOOKUP.NOT_CONCLUSIVE` with `unreachable: true`, because a failed lookup does not prove a missing registration |
| `aas.validate` | `artifact` (default `aas_file`) | `AAS.VALID` | `AAS.INVALID` (fail); sample missing: `blocked`, `AAS.SAMPLE.MISSING` |

Document URLs: item `{api}/dpp/{id}`, model `{api}/dpp/{id}/model`, signed
`{api}/dpp/{id}/signed`, versions `{api}/dpp/{id}/versions`, registry `{registry}/registry/{id}`.
The resolver URL is the carrier identifier itself.

`integrity.jws` verifies in this order: (1) the JWS signature with the key of the leaf
certificate, algorithm allowlist `ES256`; (2) the chain from the leaf to an anchor of the trust
bundle; (3) the validity period of each certificate at the evaluation time; (4) the leaf serial
against the revocation snapshot; (5) the payload against the canonical bytes of the anonymous
item-level passport. Each step is a separate finding in the observation summary.

`persistence.versions` checks: version numbers strictly ascend; `updated_at` never decreases;
the last `content_digest` equals the digest of the current anonymous item-level passport.

## 9. Illustrative catalogue content

Requirement pack `illustrative/core` (file `catalogue/packs/illustrative-core.yaml`), all with
`authority_class: illustrative`, `review_status: draft-needs-review`, and source
`dppce-illustrative`. Test pack `battery/core` (file `testpacks/battery-core.yaml`), all with
`permitted_modes: [illustrative, exploratory]` and `profiles: ["*"]`.

| Requirement | Modality | Applicability | Test purposes |
| --- | --- | --- | --- |
| `ILL-CARRIER-001` | mandatory | `ics.carriers contains qr` | `TP-CARRIER-001` (`carrier.qr_decode`) |
| `ILL-ID-001` | mandatory | always | `TP-ID-001` (`identifier.parse`) |
| `ILL-ID-002` | mandatory | always | `TP-ID-002` (`identifier.resolve`) |
| `ILL-ID-003` | mandatory | always | `TP-ID-003` (`identifier.consistency`) |
| `ILL-API-001` | mandatory | always | `TP-API-001` (`api.contract`, path `/dpp/{id}`) |
| `ILL-DATA-001` | mandatory | always; `declared_support`: `ics.features.item_data eq true` | `TP-DATA-001` (`data.jsonschema`, item) |
| `ILL-DATA-002` | mandatory | always | `TP-DATA-002` (`data.jsonschema`, model) |
| `ILL-DATA-003` | mandatory | always | `TP-DATA-003` (`data.context`, item) |
| `ILL-DATA-004` | mandatory | always | `TP-DATA-004` (`data.rules`, item) |
| `ILL-ACCESS-001` | mandatory | always | `TP-ACCESS-001` (`access.restricted_fields`; `requires_scope: access_probe`) |
| `ILL-INTEGRITY-001` | mandatory | `ics.signature_format eq jws` | `TP-INTEGRITY-001` (`integrity.jws`) |
| `ILL-REGISTRY-001` | mandatory | always | `TP-REGISTRY-001` (`registry.consistency`) |
| `ILL-EV-ONLY-001` | mandatory | `ics.product_category eq ev` | `TP-ID-001` |
| `ILL-CAPACITY-001` | mandatory | `ics.characteristics.capacity_wh gt profile.capacity_threshold_wh` is not expressible, so the profile sets the constant and the pack uses `{fact: ics.characteristics.capacity_wh, op: gt, value: 2000}` | `TP-DATA-004` |
| `ILL-PERSIST-001` | recommended | always | `TP-PERSIST-001` (`persistence.versions`) |
| `ILL-MANUAL-001` | recommended | always | `TP-MANUAL-001` (`manual: true`, check `manual.review`) |
| `ILL-NFC-001` | optional | `ics.carriers contains nfc` | `TP-NFC-001` (check `carrier.nfc_read`, not registered) |
| `ILL-AAS-001` | optional | `ics.features.aas eq true` | `TP-AAS-001` (`aas.validate`) |

The threshold 2000 Wh in `ILL-CAPACITY-001` is a synthetic demonstration value in an
illustrative rule. It makes no legal statement.

Each profile selects the packs `illustrative/core`, `eu-battery/draft`, and
`en-jtc24/placeholders`, and the test pack `battery/core`. Each profile declares the facts
`capacity_wh` (integer, Wh), `placed_on_market_date` (date), `put_into_service_date` (date),
`mass_g` (integer, g), and `external_storage_only` (boolean).

The reference ICS files declare: `carriers: [qr]`, `identifier_scheme: gs1-digital-link`,
`signature_format: jws`, `granularity: item`, `features: {item_data: true, aas: false}`,
`characteristics.capacity_wh` from section 2, and `placed_on_market_date: "2027-03-01"`.
With the unmodified reference system, every executed test purpose passes and the overall
outcome in illustrative mode is `pass`.
