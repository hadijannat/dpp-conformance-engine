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
    def __init__(
        self,
        fixtures: Path,
        *,
        faults: frozenset[str] = frozenset(),
        port: int = 0,
        system: ReferenceSystem | None = None,  # a test can serve a subclass, for example another URL layout
    ) -> None: ...
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

These paths are the URL layout of the reference system only. The engine does not assume them.
The IXIT declares a URL template for each fetched resource (architecture contract, section 9.2).
The test rig also serves a second layout, `/passports/{gtin}/{serial}/data`, to show this.

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
{"restricted": {"dismantling_notes": "CANARY-2b9c-dismantling", "supplier_reference": "CANARY-7f3a-supplier", "usage_log": "CANARY-4d1e-usage"}}
```

The `legitimate_interest` role gets `dismantling_notes` and `usage_log`. The `authority` role
gets all three fields. The anonymous role gets no `restricted` object.

The reference system models a non-conforming system. Its anonymous view holds synthetic fields,
such as `state_of_health_percent`, `remaining_capacity`, and `status`. These stand in for
non-public items. No field of the reference system is mapped to Annex XIII.

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
version: 0.2.0
basis: {class: illustrative}
restricted:                         # dotted paths in the item-level passport; one entry per path
  - {path: id, roles: [anonymous, legitimate_interest, authority]}
  - {path: category, roles: [anonymous, legitimate_interest, authority]}
  - {path: operator.identifier, roles: [anonymous, legitimate_interest, authority]}
  - {path: restricted.dismantling_notes, roles: [legitimate_interest, authority]}
  - {path: restricted.supplier_reference, roles: [authority]}
  - {path: restricted.usage_log, roles: [legitimate_interest, authority]}
canaries:                           # synthetic values; sandboxes only; one for each withheld field
  - {path: restricted.dismantling_notes, value: CANARY-2b9c-dismantling}
  - {path: restricted.supplier_reference, value: CANARY-7f3a-supplier}
  - {path: restricted.usage_log, value: CANARY-4d1e-usage}
channels:
  fetch: /dpp/{id}
  export: /dpp/{id}/export
  search: /search?q={serial}
  error: /dpp/{id}/does-not-exist
  html: /dpp/{id}.html
```

The policy states what the system owner declares. The check observes whether the system
enforces that declaration. It does not decide who has a legal entitlement.

Each entry in `restricted` names a path and the roles that may receive it. The path is
entitled for those roles and withheld from every other role. An entry that names every
declared role is a public path. The three public paths above are a synthetic reference list.
They are not a reading of Annex XIII. A policy that names one path in two entries of
`restricted`, or of `canaries`, is not valid. The check then gives `blocked` with
`ACCESS.POLICY.MISSING` and sends nothing.

Each role that the policy names must be in the `roles` list of the profile. Each battery
profile declares `anonymous`, `legitimate_interest`, and `authority`. A role outside that list
is an input error with exit code 2.

Each channel is a URL template under the `api` endpoint. It can use `{id}` and the parts that
`IXIT.id_parts` declares, for example `{serial}`. A channel outside the template grammar makes
the policy not valid: the check gives `blocked` with `ACCESS.POLICY.MISSING`. The check builds
every channel URL before the first request. A placeholder without a value gives `blocked` with
`ACCESS.NO_TARGET`, and nothing is sent.

The ICS names the policy in `access.policy`. The value `unknown` gives `blocked` with
`ACCESS.POLICY.NOT_DECLARED`. A value other than `policy_id` gives `blocked` with
`ACCESS.POLICY.ICS_MISMATCH`.

For the role under test, the check reads each channel. It always tries to parse the body as
JSON, whatever media type the system declares. A restricted path that the role may not see,
or a canary value in the body, is a leak. On a channel that is not JSON, only a canary
can be found: if a withheld field has no canary, the check is `blocked` with
`ACCESS.POLICY.NOT_FULLY_CHECKABLE`. It never passes on a partial look.

The check looks for a canary in the decoded text, in each string value of a JSON body, in the
redirect targets, and in the recorded `Location`, `Content-Location`, and `Link` values. It also
looks in the forms that an HTML character reference, a percent-encoding, or a JSON string escape
gives. It decodes the body with the byte order mark (UTF-32 before UTF-16), or with the declared
character set, or with UTF-8. A declared UTF-16 or UTF-32 body without a mark is read in both
byte orders. Text with NUL characters is also read as UTF-16 and UTF-32. The declared reading
must work: a body that it cannot decode gives `blocked` with `ACCESS.RESPONSE.NOT_DECODABLE`.
A body with a content or transfer coding gives `blocked` with `TRANSPORT.BODY_ENCODED`.

A withheld field that is present with the value `null` is withheld. Any other value, also an
empty string or a placeholder, is a leak. Response header values other than the URL headers
above are not recorded, so a canary in such a header is not found. If redaction removed a part
of a redirect or link URL, a canary could sit there: the check is then `blocked` with
`ACCESS.POLICY.NOT_FULLY_CHECKABLE`. The check does not find a value that a system hides on
purpose, for example with encryption or a private encoding.

For a role with an entitled path, the check also reads the `fetch` body. Each entitled path
must be at the root of that body, with a value other than `null`. Only `fetch` must give
content. The check reads the other channels for leaks only. A role with no withheld path reads
the `fetch` channel only.

- A `401` or `403` answer on `fetch` to a role with an entitled path gives
  `ACCESS.ENTITLEMENT.REFUSED`. The body of that answer does not change this.
- A `401` or `403` answer to a role with no entitled path is not a failure. The check still
  searches its body for leaks.
- An absent or `null` entitled path in a JSON `fetch` body gives `ACCESS.ENTITLEMENT.MISSING`.
  The message names the status of the `fetch` answer and the missing paths.
- A `fetch` body that is not JSON gives `blocked` with `ACCESS.RESPONSE.NOT_JSON`.
- A policy without a `fetch` channel gives `blocked` with `ACCESS.ENTITLEMENT.NO_FETCH_CHANNEL`.
- An answer with a status from 500 to 599 on any channel cannot be judged. It gives
  `TRANSPORT.SERVER_ERROR` with `unreachable: true`. The check still searches its body for a leak.

The check reads the channels in the order fetch, export, search, error, html. It stops after a
transport error. Then it takes the first outcome that applies, in this order:

1. a leak: `ACCESS.LEAK.<CHANNEL>`;
2. an entitlement failure: `ACCESS.ENTITLEMENT.REFUSED` or `ACCESS.ENTITLEMENT.MISSING`;
3. the first answer that cannot be judged, in reading order;
4. no `fetch` channel for a role with an entitled path;
5. a partial look: `ACCESS.POLICY.NOT_FULLY_CHECKABLE`;
6. a pass: `ACCESS.POLICY.ENFORCED`.

Section 8.2 of the architecture contract gives the full table.

A role other than `anonymous` needs a credential for the origin of the API. Without one, the
transport sends no request and the check reports `TRANSPORT.DENIED` with `unreachable: true`.
It never reports the anonymous view under the name of a role. Reason codes: `ACCESS.LEAK.FETCH`,
`ACCESS.LEAK.EXPORT`, `ACCESS.LEAK.SEARCH`, `ACCESS.LEAK.ERROR`, `ACCESS.LEAK.HTML`; the first
leaking channel in that order names the code. A pass gives `ACCESS.POLICY.ENFORCED`.
Each outcome names the probed role and the credential issuer. The issuer comes from the
validated authorization, never from a credential. The observation summary holds the role, the
issuer, channel names, field paths, and the `fetch` status. It never holds a field value.

### 5.3 API contract (`profiles/battery/contracts/*.yaml`)

An OpenAPI 3.1 document that the maintainer of the reference system supplies and pins.
Supported subset: `paths` with path templates, `get`, `responses.<status>.content.<media
type>.schema`, and local `#/components/schemas/...` references. A contract that uses anything
else gives status `unsupported` with `API.CONTRACT.UNSUPPORTED_FEATURE`.
Reason codes: `API.CONTRACT.STATUS`, `API.CONTRACT.CONTENT_TYPE`, `API.CONTRACT.SCHEMA`,
`API.CONTRACT.OK`.

The contract carries two OpenAPI extensions of this engine:

- `x-dppce-contract-id` (top level): the identifier that the ICS names in `api.contract`.
- `x-dppce-resource` (on a path item): the IXIT resource whose operation `api.contract` judges.

The check selects the operation from the contract, not from the IXIT. It takes the first row
that applies:

| Condition | Status | Reason code |
| --- | --- | --- |
| The profile names no contract, it cannot be read, or it is not a mapping | `blocked` | `API.CONTRACT.MISSING` |
| The ICS gives `unknown` for `api.contract` | `blocked` | `API.CONTRACT.NOT_DECLARED` |
| `x-dppce-contract-id` is missing or differs from the ICS value | `blocked` | `API.CONTRACT.ICS_MISMATCH` |
| The method is not `get` | `unsupported` | `API.CONTRACT.UNSUPPORTED_FEATURE` |
| The IXIT gives no template for the resource | `blocked` | `API.CONTRACT.NO_TARGET` |
| The `path` parameter differs from the template path | `blocked` | `API.CONTRACT.PATH_MISMATCH` |
| The contract marks no operation, or two, for the resource | `unsupported` | `API.CONTRACT.UNSUPPORTED_FEATURE` |
| The template path differs from the marked path | `blocked` | `API.CONTRACT.PATH_MISMATCH` |

Path parameter names do not count in the last comparison: `{passportId}` matches `{id}`.
None of these rows sends a request.

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
| `resolver_5xx` | `/01/...` answers `503` with a JSON error body |
| `resolver_html` | `/01/...` answers `200` with an HTML page |
| `redirect_out_of_scope` | `/01/...` answers `302` to `http://out-of-scope.example.test/` |
| `data_wrong_type` | `state_of_health_percent` is the string `"99"` |
| `data_missing_required` | `rated_capacity` is absent |
| `data_stale` | `updated_at` is `2025-01-01T00:00:00Z` |
| `data_wrong_unit` | `rated_capacity.unit` is `kWh` |
| `data_relationship` | `remaining_capacity.value` is larger than `rated_capacity.value` |
| `context_invalid` | `@context` is `["https://unpinned.example.test/ctx"]` |
| `registry_inconsistent` | the registry record names operator `urn:example:operator:9999` |
| `version_undeclared_change` | the last version entry repeats the previous version number with a different digest |
| `over_restrict_legitimate_interest` | the `legitimate_interest` passport omits `restricted.dismantling_notes` |
| `leak_supplier_to_legitimate_interest` | the `legitimate_interest` passport includes `restricted.supplier_reference` |
| `leak_usage_log_anonymous` | the anonymous passport includes `restricted.usage_log` with its canary |
| `deny_all` | every path answers `403` with `{"error": "forbidden"}` |

The fault `qr_payload_invalid` is a fixture, not a flag: `fixtures/reference/qr/invalid.png`
encodes plain text that is not a URL. Three more QR faults are fixtures too:

- `qr_wrong_shape`: `qr/TEST-ONLY-wrong-shape.png` encodes a GTIN of 13 digits.
- `qr_non_ascii_digits`: `qr/TEST-ONLY-non-ascii-digits.png` encodes the GTIN in Arabic-Indic digits.
- `qr_two_symbols`: `qr/degraded/TEST-ONLY-two-symbols.png` holds two readable QR symbols.

The fault `unreachable` is a rig condition: no server runs.

## 7. Fixtures

```text
fixtures/reference/
  items/{ev,lmt,industrial}.json     anonymous item-level passports
  models/{ev,lmt,industrial}.json    model-level data
  roles.json                         role -> TEST-ONLY token
  secrets/TEST-ONLY-<role>.token     the same tokens, one file for each role, for `--secrets`
  pki/TEST-ONLY-*.pem                fixture PKI (section 4.5)
  qr/{ev,lmt,industrial,invalid}.png QR images
  qr/TEST-ONLY-wrong-shape.png       QR image of fault F-30
  qr/TEST-ONLY-non-ascii-digits.png  QR image of fault F-31
  {ev,lmt,industrial}.ics.yaml       declarations for each profile
  {ev,lmt,industrial}.ixit.yaml      test information; the rig replaces `origin_override`
  trust/TEST-ONLY-trust-bundle.json  anchors and keys for the reference system
  trust/TEST-ONLY-manual-signing.key.pem  private key that signs TEST-ONLY manual results (purpose `manual`)
  authorization/                     TEST-ONLY owner key and a signed test authorization
```

`scripts/gen_fixtures.py` writes the PKI, the QR images, the trust bundle, and the
authorization. Keys are random, so the generated files are committed. The script is rerun only
to rotate them. QR images are generated with zxing-cpp and Pillow (the `qr` extra).
`scripts/gen_fixtures.py --fault-qr-only` writes only the QR images of faults F-30 and F-31. It
rotates no key.
`scripts/gen_fixtures.py --add-manual-key` adds only the manual signing key to the trust bundle.
The rig signs manual results with it for the synthetic reference system only.

## 8. Check parameters and outcomes

This section is the contract between the test pack and the adapters.

IXIT conventions for the reference rig:

- `endpoints.api` and `endpoints.registry`: base URLs in public form (`https://id.example.test`).
- `endpoints.public_origin` and `endpoints.origin_override`: see section 2.
- `samples.qr_image`: path of a QR image. `samples.identifier`: the public identifier as text.
- `samples.passport_id`: the `{id}` placeholder value, for example `09506000134352-EV0001`.
- `samples.aas_file`: path of an Asset Administration Shell JSON file (optional).
- `resources`: one URL template for each fetched resource: `item`, `model`, `signed`,
  `versions`, and `registry_record`. Each names an endpoint and a URL template.
- `id_parts`: splits `passport_id` at a fixed separator into named parts. The reference
  fixtures use separator `-` and the names `gtin` and `serial`.

The reference fixtures declare the reference layout of section 3:

```yaml
resources:
  item: {endpoint: api, path: "/dpp/{id}"}
  model: {endpoint: api, path: "/dpp/{id}/model"}
  signed: {endpoint: api, path: "/dpp/{id}/signed"}
  versions: {endpoint: api, path: "/dpp/{id}/versions"}
  registry_record: {endpoint: registry, path: "/registry/{id}"}
id_parts: {separator: "-", names: [gtin, serial]}
```

A sample path is relative to the directory of the IXIT file and must stay inside it.
The IXIT is untrusted input: see the architecture contract, section 9.1. The operator supplies
the trust bundle (`--trust`), the secrets directory (`--secrets`), and the confirmation of each
non-public origin (`--allow-private-host http://127.0.0.1:8765`). An identity uses
`secret_ref: "file:TEST-ONLY-authority.token"`, and the operator confirms it with
`--role-secret authority=file:TEST-ONLY-authority.token`.

Shared helpers in `dppce.adapters.common`:

- `effective_url(ctx, url)`: applies the origin override.
- `carrier_identifier(ctx)`: the carrier identifier. If `samples.qr_image` exists, decode it (this
  needs the `qr` extra; without it the check is `unsupported`). Otherwise use
  `samples.identifier`. If neither exists, the check is `blocked` with `CARRIER.SAMPLE.MISSING`.
- `fetch_once(ctx, url, role, accept)`: returns an earlier record of the same method, URL, role,
  and `Accept` value if it has no error; otherwise fetches. This keeps the request count low and
  the replay stable. The default `Accept` value is `*/*`.
- `resource_url(ctx, resource, area)` and `template_url(ctx, endpoint, template, area)`: build a
  URL from an IXIT template. A missing template, endpoint, or placeholder value gives `blocked`
  with `<AREA>.NO_TARGET`.
- `no_answer(ctx, record)`: builds the outcome for a record with a transport error or a server
  error: status `completed`, `passed: false`, `unreachable: true`. Reason code
  `TRANSPORT.REDIRECT_OUT_OF_SCOPE` for that error, `TRANSPORT.DENIED` for `policy_denied`,
  `authorization_denied`, and `budget_exhausted`, and `TRANSPORT.UNREACHABLE` for the others.
  A record with no transport error and a status from 500 to 599 gives `TRANSPORT.SERVER_ERROR`.
- `unusable(ctx, record)`: gives the outcome of `no_answer` for a transport error and for a
  status from 500 to 599. It also blocks a truncated or encoded body.

A response that is not valid JSON where JSON is needed gives a `fail` with `<AREA>.RESPONSE.NOT_JSON`.
The access check is the exception: it gives `blocked` with `ACCESS.RESPONSE.NOT_JSON`, because it
cannot look at the field paths of such a body (section 5.2).
A truncated body gives status `blocked` with `TRANSPORT.BODY_TRUNCATED`: a partial body proves nothing.
A body with a content coding or a transfer coding other than `identity` or `chunked` gives status
`blocked` with `TRANSPORT.BODY_ENCODED`: no check decompresses a body. Every header line counts.
An answer with a status from 500 to 599 is no answer, like a transport error. It gives
`TRANSPORT.SERVER_ERROR` with `unreachable: true`, so the step is `inconclusive` by default. This
is an owner decision of 2026-10-18. The access check still searches such a body for a leak. The
signed passport of `integrity.jws` keeps `INTEGRITY.TOKEN.NO_ANSWER` (section 8.1).

| Check | Parameters | Pass | Fail and other outcomes |
| --- | --- | --- | --- |
| `carrier.qr_decode` | `artifact` (default `qr_image`) | `CARRIER.QR.OK`: one symbol with text | `CARRIER.QR.NOT_DECODED` (fail); sample missing: `blocked`, `CARRIER.SAMPLE.MISSING` |
| `identifier.parse` | `scheme` (default: `ics.identifier_scheme`) | `IDENTIFIER.SYNTAX.OK` | `IDENTIFIER.SYNTAX.INVALID` (fail); `IDENTIFIER.SCHEME.UNSUPPORTED` (`unsupported`); scheme `unknown`: `blocked`, `IDENTIFIER.SCHEME.UNKNOWN` |
| `identifier.resolve` | `accept` (the `Accept` request header, printable ASCII), `accepted_media_types` (1 to 16 media types in lower case); both optional | `IDENTIFIER.RESOLVED`: final status 200 with a JSON object; `IDENTIFIER.RESOLVED.MEDIA_TYPE`: final status 200 with a listed media type that is not JSON | 404 or 410: `IDENTIFIER.UNRESOLVED` (fail); 500 to 599: `TRANSPORT.SERVER_ERROR` (`unreachable: true`); other status: `IDENTIFIER.RESOLUTION.STATUS` (fail); body not a JSON object where JSON is needed: `IDENTIFIER.RESPONSE.NOT_JSON` (fail); media type not listed: `IDENTIFIER.RESPONSE.MEDIA_TYPE` (fail); malformed parameter: `blocked`, `IDENTIFIER.PARAMS.INVALID`. The summary always records `media_type` |
| `identifier.consistency` | none | `IDENTIFIER.CONSISTENT` | `IDENTIFIER.MISMATCH` (fail). Compares the carrier identifier, `samples.identifier` when both exist, and the `id` of the resolved passport |
| `api.contract` | `resource` (default `item`), `method` (default `get`), `path` (optional; must equal the template path) | `API.CONTRACT.OK` | see section 5.3 |
| `data.jsonschema` | `document`: `item` or `model` | `DATA.SCHEMA.OK` | `DATA.SCHEMA.INVALID` (fail). The summary lists JSON paths and keywords, never values |
| `data.context` | `document`, `allowed_contexts` | `DATA.CONTEXT.OK` | see section 5.4 |
| `data.rules` | `document` (default `item`) | `DATA.RULES.OK` | see section 5.1 |
| `access.restricted_fields` | `role` (default `anonymous`) | `ACCESS.POLICY.ENFORCED` | see section 5.2 |
| `integrity.jws` | none | `INTEGRITY.OK` | see section 8.1 |
| `persistence.versions` | none | `PERSISTENCE.OK` | `PERSISTENCE.UNDECLARED_CHANGE` (fail) |
| `registry.consistency` | none | `REGISTRY.OK` | `REGISTRY.INCONSISTENT` (fail); status 401, 403, or 404: `REGISTRY.LOOKUP.NOT_CONCLUSIVE` with `unreachable: true`, because a failed lookup does not prove a missing registration |
| `aas.validate` | `artifact` (default `aas_file`) | `AAS.VALID` | `AAS.INVALID` (fail); sample missing: `blocked`, `AAS.SAMPLE.MISSING` |

### 8.1 Outcomes of `integrity.jws`

The check takes the first row that applies. A limit of this engine is `blocked`, which gives
`inconclusive`. Only a finding about the tested system is a `fail`.

| Order | Condition | Status | Reason code |
| --- | --- | --- | --- |
| 1 | No trust bundle is configured | `blocked` | `INTEGRITY.TRUST.MISSING` |
| 2 | The IXIT gives no URL template for `signed` or `item`, or such a URL cannot be built | `blocked` | `INTEGRITY.NO_TARGET` |
| 3 | The system answers with status 500 or higher | fail, `unreachable: true` | `INTEGRITY.TOKEN.NO_ANSWER` |
| 4 | The system answers with another status that is not 200 | fail | `INTEGRITY.TOKEN.NOT_AVAILABLE` |
| 5 | The body is not a compact JWS, a part of it cannot be decoded, or `x5c` does not hold certificates | fail | `INTEGRITY.TOKEN.MALFORMED` |
| 6 | The token has no `x5c` header | `blocked` | `INTEGRITY.KEY.UNSUPPORTED` |
| 7 | The token, or its `x5c` chain of more than 5 certificates, is larger than the limits of the engine | `blocked` | `INTEGRITY.TOKEN.TOO_LARGE` |
| 8 | The algorithm, the type, a header, or the key (type or curve) is outside the supported profile | `blocked` | `INTEGRITY.TOKEN.NOT_PROCESSABLE` |
| 9 | The signature does not verify with the key of the certificate | fail | `INTEGRITY.SIGNATURE.INVALID` |
| 10 | No path leads to a trusted anchor | fail | `INTEGRITY.ISSUER.UNTRUSTED` |
| 11 | The path has a constraint that the engine does not evaluate: name, policy, or inhibit-any-policy constraints, another critical extension, or extensions that cannot be read | `blocked` | `INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT` |
| 12 | The extended key usage of the leaf names a purpose that the engine does not know | `blocked` | `INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT` |
| 13 | The leaf does not permit a digital signature, or its extended key usage names other purposes only (for example TLS) | fail | `INTEGRITY.CERT.KEY_USAGE` |
| 14 | The trust anchor is expired or revoked in the operator's trust bundle | `blocked` | `INTEGRITY.TRUST.ANCHOR_INVALID` |
| 15 | A certificate below the anchor is outside its validity period | fail | `INTEGRITY.CERT.EXPIRED` |
| 16 | A mandatory status snapshot is missing or stale | `blocked` | `INTEGRITY.STATUS.MISSING` |
| 17 | A certificate below the anchor is in the revocation snapshot | fail | `INTEGRITY.CERT.REVOKED` |
| 18 | The published passport answers with a status from 500 to 599 | fail, `unreachable: true` | `TRANSPORT.SERVER_ERROR` |
| 19 | The published passport is not JSON | `blocked` | `INTEGRITY.PAYLOAD.NOT_COMPARABLE` |
| 20 | The signed payload and the published passport are different JSON values | fail | `INTEGRITY.PAYLOAD.MISMATCH` |

The supported profile is ES256 on curve P-256, with the key in the first `x5c` certificate.
The leaf may sign a document if its key usage permits a digital signature and its extended key
usage, when present, names `id-kp-documentSigning` (RFC 9336) or `anyExtendedKeyUsage`.
The path search tries each candidate issuer, so a cross-signed authority can appear twice.
A passport signed with the key of a self-signed anchor itself has the path from the anchor to
the anchor.
The payload is compared as a JSON value. Key order, white space, and number format do not matter.
The canonical form of the engine applies to its own decision body only, not to a passport.
The revocation snapshot lists serial numbers without their issuer. A serial number that is
revoked under one authority therefore also matches a certificate of a different authority.
An outcome message names the error code, never a value from the token.

Document URLs come from `IXIT.resources`. For the reference fixtures they are: item
`{api}/dpp/{id}`, model `{api}/dpp/{id}/model`, signed `{api}/dpp/{id}/signed`, versions
`{api}/dpp/{id}/versions`, and registry `{registry}/registry/{id}`.
The resolver URL is the carrier identifier itself.

`integrity.jws` follows the order of the table in section 8.1. Each step is a separate finding
in the observation summary.

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
| `ILL-API-001` | mandatory | always | `TP-API-001` (`api.contract`, resource `item`) |
| `ILL-DATA-001` | mandatory | always; `declared_support`: `ics.features.item_data eq true` | `TP-DATA-001` (`data.jsonschema`, item) |
| `ILL-DATA-002` | mandatory | always | `TP-DATA-002` (`data.jsonschema`, model) |
| `ILL-DATA-003` | mandatory | always | `TP-DATA-003` (`data.context`, item) |
| `ILL-DATA-004` | mandatory | always | `TP-DATA-004` (`data.rules`, item) |
| `ILL-ACCESS-001` | mandatory | always | `TP-ACCESS-001` (`access.restricted_fields`, role `anonymous`; `requires_scope: access_probe`) |
| `ILL-ACCESS-002` | mandatory | always | `TP-ACCESS-002` and `TP-ACCESS-003` (`access.restricted_fields`, roles `legitimate_interest` and `authority`; `requires_scope: access_probe`) |
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
`mass_g` (integer, g), and `external_storage_only` (boolean). Each profile declares the roles
`anonymous`, `legitimate_interest`, and `authority`.

The reference ICS files declare: `carriers: [qr]`, `identifier_scheme: gs1-digital-link`,
`signature_format: jws`, `granularity: item`, `features: {item_data: true, aas: false}`,
`characteristics.capacity_wh` from section 2, and `placed_on_market_date: "2027-03-01"`.
With the unmodified reference system, every executed test purpose passes and the overall
outcome in illustrative mode is `pass`.
