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
