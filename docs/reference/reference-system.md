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

The server answers `GET`, `HEAD`, and `OPTIONS`. Every other method gets `501` from
`http.server`, and nothing changes.

- `HEAD` gets the status and the headers of `GET`, without a body.
- `OPTIONS` gets `204` with `Allow: GET, HEAD, OPTIONS` and these CORS headers:
  `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, HEAD, OPTIONS`, and
  `Access-Control-Allow-Headers: Accept, Authorization`. A `204` answer has no `Content-Type`
  and no `Content-Length`. Under the flag `deny_all`, `OPTIONS` gets `403`.

A header value with a line break is never sent. The server answers `400` in its place.

### 1.1 Family modules

The package `dppce.infrastructure.reference` holds family modules. A family module adds the
behavior of one implementation family, for example a resolver. The families are `resolver`
(section 4.6), `jose`, which owns the flag `signed_jws_json`, `credentials` (section 4.7),
`did` (section 4.8), and `aas` (section 4.9). The module docstring of the
package states the contract. In short:

- `FLAGS`: the fault flags that the module owns. Each flag name is in one place only.
- `respond(system, request)`: the answer to a `GET` or `HEAD` request, or `None` to pass it on.

The reference system asks each family in the order of `FAMILIES`, then the core routes. Under
`deny_all`, only the core routes answer. `FAULTS` is the union of the core flags and the flags
of each family. To add a family, write one module and add one entry to `FAMILIES`.

A family must not change the answer to a request of the version 1 snapshot, unless one of its
own flags is active. The snapshot holds each route, role, and fault flag of version 1. It uses
`GET` with no `Accept` header or with `Accept: */*`. The test
`tests/test_reference_system_v2.py` compares the answers with this snapshot. A family can add
answers for other paths, queries, or `Accept` values.

## 2. Identifiers and the origin override

Carriers hold the public identifier, for example
`https://id.example.test/01/09506000134352/21/EV0001`. The domain `example.test` is reserved
and never resolves. A test rig maps it to the local server:

- `IXIT.endpoints["public_origin"]` is `https://id.example.test`.
- `IXIT.endpoints["origin_override"]` is the local origin, for example `http://127.0.0.1:49152`.

A check sends a URL whose origin equals `public_origin` to `origin_override` in its place.
The origin is compared in its normal form, so `HTTPS://ID.EXAMPLE.TEST:443` counts too.
The helper `dppce.adapters.common.effective_url(ctx, url)` does this in one place. Each
observation that used it lists the transformation `origin_override`.
Identifier comparison always uses the public form.

Identifier scheme `gs1-digital-link` with the default form `dppce-item`: an HTTP or HTTPS URL
whose path has the form `/01/<14 digits>/21/<serial>`. The parser checks the GTIN check digit.
The schemes `https-url`, `did-web`, and `urn-uuid` also have a parser, which is experimental.
Section 8 of the architecture contract gives their rules. The scheme `unknown` gives `blocked`
with `IDENTIFIER.SCHEME.UNKNOWN`. Every other declared scheme gives the reason code
`IDENTIFIER.SCHEME.UNSUPPORTED` with status `unsupported`.

Three synthetic items, one for each profile:

| Profile | Category | Serial | Capacity (Wh) |
| --- | --- | --- | --- |
| `battery/ev` | `ev` | `EV0001` | 75000 |
| `battery/lmt` | `lmt` | `LMT0001` | 500 |
| `battery/industrial` | `industrial` | `IND0001` | 5000 |

## 3. Endpoints

All are `GET` or `HEAD` (section 1). `{id}` is `<gtin>-<serial>`, for example
`09506000134352-EV0001`.

The one exception is `POST /oauth/token` of the family `oauth`. It is the token endpoint of the
OAuth 2.0 client credentials grant. The client authenticates with HTTP Basic, and the form body is
`grant_type=client_credentials`. The answer is the TEST-ONLY bearer token of the role
`legitimate_interest` from `roles.json`. A wrong client gives `401`, and another grant gives `400`.
The endpoint changes no state. Each other `POST` gets `405`. A `POST` body above 4096 bytes gets `413`.

These paths are the URL layout of the reference system only. The engine does not assume them.
The IXIT declares a URL template for each fetched resource (architecture contract, section 9.2).
The test rig also serves a second layout, `/passports/{gtin}/{serial}/data`, to show this.

| Path | Answer |
| --- | --- |
| `/01/{gtin}/21/{serial}` | `303` with `Location: /dpp/{id}` |
| `/01/{gtin}/21/{serial}?linkType=linkset` | `200 application/linkset+json`: a linkset (section 4.6) |
| `/.well-known/gs1resolver` | `200 application/json`: the resolver description (section 4.6) |
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
  {"version": 1, "updated_at": "2026-09-01T08:00:00Z", "content_digest": "sha256:...", "raw_digest": "sha256:..."},
  {"version": 3, "updated_at": "2026-10-10T08:00:00Z", "content_digest": "sha256:...", "raw_digest": "sha256:..."}
]}
```

`content_digest` is `dppce.evidence.canonical.digest` of the anonymous item-level passport of
that version. `raw_digest` is the SHA-256 of the bytes that the item route serves for that
version. `TP-PERSIST-002` compares it with `digest_of: raw-sha256`. Declared update rule of the reference system: a change of content needs a higher
version number and a later or equal `updated_at`. The last entry describes the current document.
The check compares `updated_at` values as instants. Each value must be an RFC 3339 date-time with
an offset. `T` and `Z` may be lower case. A missing or other value breaks the rule. If the
current passport has no canonical form, for example because it holds a decimal number, the
digest cannot be compared. The check then gives `blocked` with
`PERSISTENCE.DIGEST.NOT_COMPARABLE`, unless another part of the rule already fails.

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

### 4.6 Resolver surface (family module `resolver`)

Module: `dppce.infrastructure.reference.resolver`. The behavior is synthetic. It follows
RFC 9110 for negotiation and RFC 9264 for the linkset.

The resolver path `/01/{gtin}/21/{serial}` gives a linkset in these cases:

- the query has `linkType=linkset` or `linkType=all`;
- the `Accept` header lists `application/linkset+json` with a weight above 0, and no other
  range has a higher weight.

A linkset answer has `Vary: Accept`. Every other request gets the core `303`, without `Vary`.
Thus `Accept: */*`, which the engine transport sends, gets the answer of version 1. The
passport is the only link, so each other `linkType` value also gets the `303`.

```json
{"linkset": [{"anchor": "https://id.example.test/01/09506000134352/21/EV0001",
  "https://dppce.example.test/rel/passport": [
    {"href": "https://id.example.test/dpp/09506000134352-EV0001", "type": "application/json"}]}]}
```

The relation type is synthetic and is in the reserved example domain. It is not a GS1 link
type. The `href` is the `Location` of the core answer in public form. A seeded resolver fault,
for example `resolver_404`, applies to the linkset request too.

`/.well-known/gs1resolver` gives a synthetic resolver description. The field names are those
of the GS1 Resolver Community Edition (Apache-2.0, commit `bf885fd`). The values are synthetic:

```json
{"name": "dppce synthetic reference resolver", "resolverRoot": "https://id.example.test",
 "supportedLinkType": [{"namespace": "https://dppce.example.test/rel/", "prefix": "dppce:"}],
 "supportedPrimaryKeys": ["01"]}
```

A malformed GS1 path, for example a GTIN of 13 digits, still gets `404`. The engine sends such
paths for the faults F-30 and F-31, so their answers stay the same.

### 4.7 VC-JOSE credential (family module `credentials`)

Module: `dppce.infrastructure.reference.credentials`. The behavior is synthetic. It follows the
W3C Recommendation VC-JOSE-COSE and RFC 7515.

A request for `/dpp/{id}/signed` with exactly `Accept: application/vc+jwt` gets `200` with the
media type `application/vc+jwt`. The body is a compact JWS with the protected header
`{"alg": "ES256", "kid": "TEST-ONLY-vc-issuer-key-1", "typ": "vc+jwt"}`. Every other request gets
the core answer, so the answer to `Accept: */*` stays the `dpp+jws` token of section 4.5.

The payload is `canonical_bytes` of this credential. The subject is the `id` of the anonymous
item-level passport:

```json
{"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"],
 "issuer": "urn:example:operator:0001", "validFrom": "2026-01-01T00:00:00Z",
 "validUntil": "2036-01-01T00:00:00Z",
 "credentialSubject": {"id": "https://id.example.test/01/09506000134352/21/EV0001"},
 "credentialStatus": {"id": "https://id.example.test/01/09506000134352/21/EV0001#status",
  "type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "41267",
  "statusListCredential": "https://id.example.test/credentials/status/1"}}
```

The TEST-ONLY leaf key of section 4.5 signs the credential. The TEST-ONLY trust bundle pins its
public key as `TEST-ONLY-vc-issuer-key-1`, with the issuer `urn:example:operator:0001` and the
purpose `passport`.

A request for `/credentials/status/1` gets `200` with the media type `application/vc+jwt`, for
every `Accept` value. The body is the status list credential, a compact JWS with the same
protected header and the same key. Its payload follows the W3C Recommendation Bitstring Status
List v1.0:

```json
{"@context": ["https://www.w3.org/ns/credentials/v2"],
 "id": "https://id.example.test/credentials/status/1",
 "type": ["VerifiableCredential", "BitstringStatusListCredential"],
 "issuer": "urn:example:operator:0001", "validFrom": "2026-01-01T00:00:00Z",
 "credentialSubject": {"id": "https://id.example.test/credentials/status/1#list",
  "type": "BitstringStatusList", "statusPurpose": "revocation",
  "encodedList": "<131072 bits, all 0>", "ttl": 315360000000}}
```

The `ttl` is 3650 days, so the list is fresh at the evaluation time of the rig.

### 4.8 DID document (family module `did`)

Module: `dppce.infrastructure.reference.did`. The behavior is synthetic. The public origin
`https://id.example.test` gives the DID `did:web:id.example.test`. Its DID document is at
`/.well-known/did.json`, with the media type `application/did+json`:

```json
{"id": "did:web:id.example.test",
 "verificationMethod": [{"id": "did:web:id.example.test#key-1", "type": "JsonWebKey",
   "controller": "did:web:id.example.test", "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}}],
 "assertionMethod": ["did:web:id.example.test#key-1"]}
```

The key is the public key of `fixtures/reference/pki/TEST-ONLY-leaf.cert.pem`. The document has
no `@context`, so a reader processes it as plain JSON. Every other path passes to the core.

### 4.9 AAS repository (family module `aas`)

Module: `dppce.infrastructure.reference.aas`. The behavior is synthetic. It follows the read
profiles SSP-002 of the AAS Repository and the Submodel Repository of IDTA-01002 Part 2, version
3.0.4. The repository is read-only and lives under `/api/v3.0`:

| Path | Answer |
| --- | --- |
| `/description` | `{"profiles": [...]}` with the two read profiles of version 3.0 |
| `/shells` | a paged result of two TEST-ONLY shells. With `limit=1`, the first page has a `cursor` for the second page |
| `/shells/{id}` | the shell, or `404` with a `messages` list |
| `/shells/{id}/submodel-refs` | a paged result of the references of the shell |
| `/submodels`, `/submodels/{id}` | the same for one TEST-ONLY submodel |

An `{id}` is the id, UTF-8, base64url-encoded without padding. The first shell has the id
`https://example.test/TEST-ONLY/aas/dpp-1` and references the submodel
`https://example.test/TEST-ONLY/submodel/dpp-metadata-1`. These are the ids of
`fixtures/aas/TEST-ONLY-dpp-valid.json`. A cursor holds `+`, `/`, and `=`, so a client must
percent-encode it. Every other path passes to the core.

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
The freshness limit is inclusive: an age of exactly `max_age_days` passes. An update time after
the evaluation time fails the rule. The value must have the form `YYYY-MM-DDTHH:MM:SSZ` in ASCII
digits.
Each rule must give the fields of its kind: `fields` with no empty entry, `field` and `allowed`,
`field` and `min` or `max`, `left` and `right`, or `field` and `max_age_days`. A pack with a rule
that lacks them cannot be read.
Field paths are dotted. A rule whose `when` expression is `false` is skipped; `unknown` makes
the check inconclusive with the reason code `DATA.RULES.APPLICABILITY_UNKNOWN`. If no rule
applies to the document, the check gives `blocked` with `DATA.RULES.NONE_APPLIED`.

Reason codes, in this order of precedence when more than one rule fails:
`DATA.COMPLETENESS.MISSING`, `DATA.UNIT.INVALID`, `DATA.RANGE.VIOLATED`,
`DATA.RELATIONSHIP.VIOLATED`, `DATA.FRESHNESS.STALE`, `DATA.FIELD.FORBIDDEN`,
`DATA.PATTERN.MISMATCH`, `DATA.EQUALITY.VIOLATED`. A pass gives `DATA.RULES.OK`.
The observation summary lists every failed rule id.

#### Version 2 (`dppce.rulepack/2`)

Version 2 is experimental (OD-11). It keeps the five kinds of version 1, with dotted `field`
paths. It adds four kinds that read a JSON Pointer (RFC 6901) in `path`. A pack of version 1
cannot use a kind of version 2. It also cannot give a key of version 2 a value other than its
default. The engine cannot read such a pack. A rule of a new kind other than `forbidden` needs a `path` other than the root.
`fixtures/rules/TEST-ONLY-web-rules-v2.yaml` is an example.

```yaml
schema_version: dppce.rulepack/2
rulepack_id: example/rules-v2
version: 0.1.0
rules:
  - {id: R-1, kind: pattern, document: item, path: /id, pattern: 'urn:example:[0-9]{4}', basis: {class: illustrative}}
  - {id: R-2, kind: forbidden, document: item, path: /restricted/usage_log, basis: {class: illustrative}}
  - {id: R-3, kind: equals, document: item, path: /granularity, value: item, basis: {class: illustrative}}
  - {id: R-4, kind: equals, document: item, path: /a/unit, other: /b/unit, basis: {class: illustrative}}
  - id: R-5
    kind: each
    document: item
    path: /cells
    rule: {kind: pattern, path: /code, pattern: '[A-Z]{2}[0-9]{2}'}
    basis: {class: illustrative}
```

| Kind | Fields | The rule breaks when |
| --- | --- | --- |
| `pattern` | `path`, `pattern`, optional `max_length` | The value is not a string, has more than `max_length` characters, or does not match the pattern as a whole. |
| `forbidden` | `path`, not the root | The field is present. A field with the value `null` is present. |
| `equals` | `path`, and one of `value` or `other` | One value is not a string, or the strings differ. `value` is a string constant. `other` is a second pointer. |
| `each` | `path`, not the root, and `rule` | The value is not an array, or an element breaks `rule`. |

The rules of a kind of version 2 judge an absent field as follows:

- An absent field never breaks `pattern`, `equals`, or `each`. Only `required_fields` and
  `forbidden` judge absence.
- For `equals` with `other`, an absent field on either side is not judged.
- A present value of the wrong type breaks the rule. A system under test therefore cannot turn a
  fail into `blocked` with a reshaped document.

The rule of `each` has a `kind` and the fields of that kind. It has no `id`, `document`, `basis`,
or `when`, and its kind is not `each`. Its paths start at the element. The path `""` is the
element itself. A failed `each` rule gives the reason code of its rule.

`max_length` is 256 by default and 512 at most. A longer value breaks the rule, so a system
cannot pad a value to escape the rule. The text comparison of `pattern` and `equals` is exact.
It does not fold case or normalize Unicode.

A pattern is a regular expression of this closed subset. A pack with any other pattern cannot be
read.

- The pattern has 1 to 256 characters. It matches the whole value. `^` and `$` are allowed and
  change nothing.
- An item is a literal character, `.`, an escaped symbol such as `\.`, a character class
  `[...]` or `[^...]`, or one of the class escapes `\d`, `\D`, `\w`, `\W`, `\s`, and `\S`.
- `\d`, `\w`, and `\s` match ASCII characters only. Another escaped letter or digit is refused,
  for example a backreference `\1`.
- A group is `(...)` or `(?:...)`. `|` separates alternatives. Lookaround, named groups, inline
  flags, and atomic groups are refused.
- A quantifier `*`, `+`, `?`, `{m}`, `{m,}`, or `{m,n}` applies to one item only, never to a
  group. Nested quantifiers are therefore refused. The bounds are 1000 at most.
- A lazy or a possessive quantifier is refused. A literal `{` is written `\{`.
- A pattern has at most three variable choices. A variable choice is a quantifier other than
  `{m}`, or a `|` outside a character class. A chain of alternatives is therefore refused.

These limits bound the work of the backtracking matcher on each value. With three choices, the
work grows at most with the cube of the value length.
Each rule has a budget of 2^24 units of pattern work on one answer.
Each match costs the square of the value length.
A value longer than `max_length` costs nothing.
A rule that would exceed its budget is not judged, and one rule cannot use the budget of another. If no rule fails, the check gives `blocked`
with `DATA.RULES.WORK_LIMIT` and names the rules.

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
  An answer with the status 429 gives `TRANSPORT.RATE_LIMITED` in the same way.

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
| `openapi` is not 3.0.x or 3.1.x, `jsonSchemaDialect` of a 3.1 contract is not the default, or a 3.0 Schema Object has no exact translation | `blocked` | `API.CONTRACT.UNSUPPORTED_VERSION` |
| The method is not `get` | `unsupported` | `API.CONTRACT.UNSUPPORTED_FEATURE` |
| The IXIT gives no template for the resource | `blocked` | `API.CONTRACT.NO_TARGET` |
| The `path` parameter differs from the template path | `blocked` | `API.CONTRACT.PATH_MISMATCH` |
| The contract marks no operation, or two, for the resource | `unsupported` | `API.CONTRACT.UNSUPPORTED_FEATURE` |
| The template path differs from the marked path | `blocked` | `API.CONTRACT.PATH_MISMATCH` |

Path parameter names do not count in the last comparison: `{passportId}` matches `{id}`.
None of these rows sends a request.

The check compares the response keys exactly, so it also gives `unsupported` before it fetches
for these features:

- a response key that is not a three-digit status, for example `default` or `2XX`;
- a media type key with a range, a parameter, or an upper-case letter;
- a `responses`, response, `content`, or media entry that is not a mapping, and a boolean schema;
- a response object with `$ref`;
- a `format` value that the engine cannot assert. The engine asserts `uri`, `date`, `email`,
  `idn-email`, `ipv4`, `ipv6`, and `uuid`. The set is fixed, so an installed package cannot change it.

An unquoted status key such as `200` in YAML names the same status as `'200'`.

After the fetch:

- The judged fetch must not follow a redirect. A redirect gives `blocked` with
  `API.CONTRACT.PATH_MISMATCH`: the transport does not record the status of a redirect hop, and
  the body belongs to another URL.
- A declared status without `content`, or with an empty `content` map, passes only if the
  response has no media type and no body. Otherwise the check gives `unsupported`.
- A schema that is not valid JSON Schema 2020-12, also in `components.schemas`, or that names
  another dialect or uses a keyword that its dialect ignores, gives `unsupported`. So does a
  local reference that does not resolve.
- The body may be any JSON value. A body that is not strict JSON gives `API.RESPONSE.NOT_JSON`.
  Numbers are exact decimals, so a value cannot round onto a schema bound.
- A body that is nested too deeply for the validator gives `blocked` with `API.RESPONSE.TOO_DEEP`.

### 5.4 Context allowlist

A profile constant `allowed_contexts` is not expressive enough, so the test purpose passes
`params.allowed_contexts`: a list of exact context URLs. No context is fetched.
The check reads every `@context` in the document, also in nested nodes and `@graph` members.
`DATA.CONTEXT.MISSING` depends on the top-level `@context` only.
Reason codes: `DATA.CONTEXT.MISSING`, `DATA.CONTEXT.NOT_ALLOWED`, `DATA.CONTEXT.OK`.

Two more context sources are experimental:

- The `Link` header of the fetched document. A link with the relation
  `http://www.w3.org/ns/json-ld#context` counts as a top-level context. A relative target is
  resolved against the URL of the document. The check ignores the header for
  `application/ld+json`.
- The parameter `context_files`. It maps an allowed context URL to a pinned JSON copy under the
  data root, for example `{"https://example.test/ctx": "contexts/ctx.json"}`. The check reads
  each `@context` string and each `@import` value in the copy. It follows a reference only into
  another pinned copy. An allowed context without a copy is judged by its URL only.

The check reads the recorded form of the header. Redaction reads each value as RFC 8288
link-values, so a quoted `,` or `;` does not split a value. It keeps a `type` of
`application/ld+json`, `application/linkset+json`, or `application/json`. It replaces each other
parameter, and each relation outside its closed list, with one marker.

- A link with the context relation names its target, whatever its other parameters are, for
  example `type="application/ld+json"` or a title.
- A link without the context relation is ignored, for example `rel=preload`.
- Redaction removes a value as a whole only if the value is not well-formed. Such a value names
  no context, so a document without a top-level context still gives `DATA.CONTEXT.MISSING`.
- A target that redaction changed, for example one with a `token` query parameter, is compared in
  its redacted form. It gives `DATA.CONTEXT.NOT_ALLOWED`.
- Such a target gives `blocked` with `DATA.CONTEXT.LINK_UNREADABLE` only if it equals the redacted
  form of an allowed URL. `DATA.CONTEXT.MISSING` and `DATA.CONTEXT.NOT_ALLOWED` come first.

The check judges the target of each context link. The JSON-LD 1.1 API, section 9.4.1, rejects
more than one context link.
A copy that is not a JSON object, or an `@import`
value that is not a string, gives `blocked` with `DATA.CONTEXT.FILE_INVALID`.

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
| `resolver_divergent` | `/01/...` answers `200` with the anonymous passport, with `version` one higher than at `/dpp/{id}` |
| `data_wrong_type` | `state_of_health_percent` is the string `"99"` |
| `data_missing_required` | `rated_capacity` is absent |
| `data_stale` | `updated_at` is `2025-01-01T00:00:00Z` |
| `data_wrong_unit` | `rated_capacity.unit` is `kWh` |
| `data_relationship` | `remaining_capacity.value` is larger than `rated_capacity.value` |
| `context_invalid` | `@context` is `["https://unpinned.example.test/ctx"]` |
| `registry_inconsistent` | the registry record names operator `urn:example:operator:9999` |
| `version_undeclared_change` | the last version entry repeats the previous version number with a different digest |
| `registry_extra_field_differs` | the registry `passport_url` names serial `OTHER0001`, not the passport identifier |
| `version_raw_digest_stale` | the last version entry repeats the `raw_digest` of the first entry |
| `over_restrict_legitimate_interest` | the `legitimate_interest` passport omits `restricted.dismantling_notes` |
| `leak_supplier_to_legitimate_interest` | the `legitimate_interest` passport includes `restricted.supplier_reference` |
| `leak_usage_log_anonymous` | the anonymous passport includes `restricted.usage_log` with its canary |
| `deny_all` | every path answers `403` with `{"error": "forbidden"}` |
| `resolver_linkset_as_passport` | family `resolver`: `/01/...` answers each request with the linkset of section 4.6, also with no `Accept` header or with `Accept: */*` |
| `resolver_linkset_invalid` | family `resolver`: the value of `linkset` is the link context object itself, not a list of link context objects |
| `resolver_linkset_no_dpp` | family `resolver`: the link of the linkset has the relation `https://dppce.example.test/rel/other`, not the passport relation |
| `resolver_linkset_anchor_mismatch` | family `resolver`: the `anchor` of the linkset names serial `OTHER0001` |
| `wellknown_wrong_root` | family `resolver`: `resolverRoot` of `/.well-known/gs1resolver` is `https://other.example.test` |
| `wellknown_redirect` | family `resolver`: `/.well-known/gs1resolver` answers `301` to `/resolver-description.json`, which serves the description file |
| `resolver_200_for_invalid` | family `resolver`: `/01/...` answers `200` with `{"status": "ok"}` for an unknown identifier, for example a GTIN with a wrong check digit |
| `negotiation_no_vary` | family `resolver`: `/01/...` answers `200` with an HTML page and no `Vary` header when the `Accept` weight of `text/html` is above that of `application/json` |
| `negotiation_wrong_type` | family `resolver`: `/01/...` answers `200` with the HTML page and `Vary: Accept` when `Accept` lists `application/json` with a weight above 0, or prefers `text/html` |
| `resolver_rate_limited` | family `resolver`: `/01/...` answers each default request (no `linkType`, and an `Accept` that does not prefer the linkset) with `429` and `Retry-After: 1`, every time |
| `resolver_redirect_302` | family `resolver`: `/01/...` answers each default request (no `linkType`, and an `Accept` that does not prefer the linkset) with `302` in place of `303`, to the same `Location` |
| `signed_jws_json` | family `jose`: `/dpp/{id}/signed` answers `200` with `Content-Type: application/jose+json` and the flattened JWS JSON serialization of the compact token. The members `protected`, `payload`, and `signature` are the three parts of that token. |
| `vc_tampered` | family `credentials`: the payload of the credential of section 4.7 names serial `OTHER0001` after signing |
| `vc_hs256_confusion` | family `credentials`: the credential header names `HS256`, and the signature is an HMAC-SHA256 with the DER public key of the TEST-ONLY leaf as the key |
| `vc_expired` | family `credentials`: the validly signed credential has `validFrom` `2025-01-01T00:00:00Z` and `validUntil` `2026-01-01T00:00:00Z` |
| `vc_untrusted_kid` | family `credentials`: the validly signed credential has the `kid` `TEST-ONLY-unknown-issuer-key`, which the trust bundle does not hold |
| `vc_alg_none` | family `credentials`: the credential header names `none`, and the signature part is empty |
| `did_id_mismatch` | family `did`: the `id` of the DID document is `did:web:other.example.test` |
| `did_private_key` | family `did`: the JWK of the verification method also holds the synthetic private member `d` |
| `did_redirect_off_host` | family `did`: `/.well-known/did.json` answers `302` to `https://other.example.test/.well-known/did.json`, outside the scope of the rig |
| `vc_status_revoked` | family `credentials`: the status list of section 4.7 sets the bit at index `41267` |
| `vc_status_list_unsigned` | family `credentials`: the signature of the status list covers a list with the bit at index `41267` set, and the served payload has the bit not set |
| `vc_status_list_stale` | family `credentials`: the `ttl` of the status list is `86400000`, one day after its `validFrom`, so the list is stale at the evaluation time of the rig |
| `vc_payload_schema_broken` | family `credentials`: the `credentialSubject` of the credential of section 4.7 is an empty object. The credential is signed validly |
| `aas_api_wrong_status` | family `aas`: `/api/v3.0/shells/{id}` answers `200` with an empty body for an unknown shell id |
| `aas_api_bad_paging` | family `aas`: `/api/v3.0/shells` and `/api/v3.0/submodels` ignore `limit` and answer every element without a `cursor` |
| `oauth_token_wrong_role` | family `oauth`: `POST /oauth/token` issues the token of the role `authority` to the TEST-ONLY client of the role `legitimate_interest` |
| `oauth_token_refused` | family `oauth`: `POST /oauth/token` answers `401` with `{"error": "invalid_client"}` to each client |

The fault `qr_payload_invalid` is a fixture, not a flag: `fixtures/reference/qr/invalid.png`
encodes plain text that is not a URL. Three more QR faults are fixtures too:

- `qr_wrong_shape`: `qr/TEST-ONLY-wrong-shape.png` encodes a GTIN of 13 digits.
- `qr_non_ascii_digits`: `qr/TEST-ONLY-non-ascii-digits.png` encodes the GTIN in Arabic-Indic digits.
- `qr_two_symbols`: `qr/degraded/TEST-ONLY-two-symbols.png` holds two readable QR symbols.
- `qr_qualifier_order`: `qr/TEST-ONLY-qualifier-order.png` encodes a GS1 Digital Link URI with the serial before the lot.
- `qr_model_level`: `qr/TEST-ONLY-model-level.png` encodes a GS1 Digital Link URI with a GTIN only.
- `qr_http_scheme`: `qr/TEST-ONLY-http-scheme.png` encodes the `ev` identifier with the `http` scheme.

The fault `unreachable` is a rig condition: no server runs.

A fault can also be a sample fixture. The rig setup key `samples` maps an IXIT sample name to
a fixture path, relative to the repository root. The rig copies the fixture beside the IXIT and
names the copy in `IXIT.samples`. A row in `validation/cases.py` uses this key, for example
`{"samples": {"aas_file": "<fixture path>"}}`.

## 7. Fixtures

```text
fixtures/reference/
  items/{ev,lmt,industrial}.json     anonymous item-level passports
  models/{ev,lmt,industrial}.json    model-level data
  roles.json                         role -> TEST-ONLY token
  secrets/TEST-ONLY-<role>.token     the same tokens, one file for each role, for `--secrets`
  secrets/TEST-ONLY-oauth-client-*   the TEST-ONLY client id and client secret of the oauth family
  pki/TEST-ONLY-*.pem                fixture PKI (section 4.5)
  qr/{ev,lmt,industrial,invalid}.png QR images
  qr/TEST-ONLY-wrong-shape.png       QR image of fault F-30
  qr/TEST-ONLY-non-ascii-digits.png  QR image of fault F-31
  qr/TEST-ONLY-qualifier-order.png   QR image of fault F-40
  qr/TEST-ONLY-model-level.png       QR image of fault F-41
  qr/TEST-ONLY-http-scheme.png       QR image of fault F-42
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
The bundle entry `TEST-ONLY-vc-issuer-key-1` pins the public key of the TEST-ONLY leaf for the
credential of section 4.7. It was added to the bundle by hand, and no key was rotated.

## 8. Check parameters and outcomes

This section is the contract between the test pack and the adapters.

IXIT conventions for the reference rig:

- `endpoints.api` and `endpoints.registry`: base URLs in public form (`https://id.example.test`).
- `endpoints.public_origin` and `endpoints.origin_override`: see section 2.
- `samples.qr_image`: path of a QR image. `samples.identifier`: the public identifier as text.
- `samples.passport_id`: the `{id}` placeholder value, for example `09506000134352-EV0001`.
- `samples.aas_file`: path of an Asset Administration Shell JSON file (optional).
- `resources`: one URL template for each fetched resource. The reference fixtures declare `item`,
  `model`, `signed`, `versions`, and `registry_record`. Each names an endpoint and a URL template.
- `id_parts`: splits `passport_id` at a fixed separator into named parts. The reference
  fixtures use separator `-` and the names `gtin` and `serial`.
- `item_target`: `template` (the default) or `resolved`. With `resolved`, `api.contract`, the
  data checks, and `integrity.jws` fetch the item from the URL that the carrier resolves to. The
  reference fixtures do not set it. See the architecture contract, section 9.2.

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
  with `<AREA>.NO_TARGET`. So does a placeholder value that is `.` or `..`: a server resolves such
  a dot segment to another resource.
- `no_reply(record)`: true for a record that holds no answer: a transport error, a 429, or a
  status from 500 to 599.
- `no_answer(ctx, record)`: builds the outcome for a record that `no_reply` finds: status
  `completed`, `passed: false`, `unreachable: true`. Reason code
  `TRANSPORT.REDIRECT_OUT_OF_SCOPE` for that error, `TRANSPORT.DENIED` for `policy_denied`,
  `authorization_denied`, and `budget_exhausted`, and `TRANSPORT.UNREACHABLE` for the others.
  A record with no transport error and the status 429 gives `TRANSPORT.RATE_LIMITED`. A record
  with no transport error and a status from 500 to 599 gives `TRANSPORT.SERVER_ERROR`.
- `unusable(ctx, record)`: gives the outcome of `no_answer` for a transport error, a 429, and a
  status from 500 to 599. It then calls `body_problem`.
- `body_problem(record)`: blocks a truncated or encoded body.
- `not_200(ctx, area, record, records)`: the data, persistence, and registry checks judge a
  document only with status 200. Status 401, 403, or 404 gives `blocked` with
  `<AREA>.RESPONSE.NOT_CONCLUSIVE`: an anonymous request that is refused or not found proves
  nothing about the document. Any other status gives a fail with `<AREA>.RESPONSE.STATUS`.

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
An answer with the status 429 is no answer too. It gives `TRANSPORT.RATE_LIMITED` with
`unreachable: true` in every check, `integrity.jws` included. The access check still searches such
a body for a leak. The transport waits for `Retry-After` once per fetch, for a `GET` or a `HEAD`
only. The value must be a number of seconds up to 5. The wait must fit the time limit and the
request budget. The transport then sends the request one more time.

| Check | Parameters | Pass | Fail and other outcomes |
| --- | --- | --- | --- |
| `carrier.qr_decode` | `artifact` (default `qr_image`) | `CARRIER.QR.OK`: one symbol with text | `CARRIER.QR.NOT_DECODED` (fail); sample missing: `blocked`, `CARRIER.SAMPLE.MISSING`; an image above the pixel limit, also one that Pillow reports as a decompression bomb: `blocked`, `CARRIER.SAMPLE.TOO_LARGE`; an image that cannot be read: `blocked`, `CARRIER.SAMPLE.UNREADABLE` |
| `identifier.parse` | `scheme` (default: `ics.identifier_scheme`), `require_https` (boolean, default `false`), `form` (`dppce-item` or `gs1-dl`, default `dppce-item`; for `gs1-digital-link` only) | `IDENTIFIER.SYNTAX.OK` | `IDENTIFIER.SYNTAX.INVALID` (fail), also for a payload that does not match the declared scheme `https-url`, `did-web`, or `urn-uuid`; with `require_https`, a valid identifier whose scheme is not `https`: `IDENTIFIER.SCHEME.NOT_HTTPS` (fail); a scheme without a parser: `IDENTIFIER.SCHEME.UNSUPPORTED` (`unsupported`); scheme `unknown`: `blocked`, `IDENTIFIER.SCHEME.UNKNOWN`; `require_https` not a boolean, or a `form` other than `dppce-item` with `https-url`, `did-web`, or `urn-uuid`: `blocked`, `IDENTIFIER.PARAMS.INVALID` |
| `identifier.resolve` | `accept` (the `Accept` request header, printable ASCII), `accepted_media_types` (1 to 16 media types in lower case), `require_https` (boolean, default `false`); all optional | `IDENTIFIER.RESOLVED`: final status 200 with a JSON object; `IDENTIFIER.RESOLVED.MEDIA_TYPE`: final status 200 with a listed media type that is not JSON | 404 or 410: `IDENTIFIER.UNRESOLVED` (fail); 429: `TRANSPORT.RATE_LIMITED` (`unreachable: true`); 500 to 599: `TRANSPORT.SERVER_ERROR` (`unreachable: true`); other status: `IDENTIFIER.RESOLUTION.STATUS` (fail); body not a JSON object where JSON is needed: `IDENTIFIER.RESPONSE.NOT_JSON` (fail); media type not listed: `IDENTIFIER.RESPONSE.MEDIA_TYPE` (fail); with `require_https`, a carrier URL whose scheme is not `https` (nothing is fetched) or a redirect target whose scheme is not `https`: `IDENTIFIER.SCHEME.NOT_HTTPS` (fail); malformed parameter: `blocked`, `IDENTIFIER.PARAMS.INVALID`. The summary always records `media_type` |
| `identifier.consistency` | `compare_item` (boolean, default `false`) | `IDENTIFIER.CONSISTENT` | `IDENTIFIER.MISMATCH` (fail). Compares the carrier identifier, `samples.identifier` when both exist, and the `id` of the resolved passport. With `compare_item`, the check also compares the resolved passport with the document at the `item` template, as JSON values. Different values give `IDENTIFIER.BINDING.MISMATCH` (fail). An item target that is not a JSON object with status 200 gives `blocked`, `IDENTIFIER.BINDING.NOT_COMPARABLE`. Architecture contract, section 8, gives the order |
| `api.contract` | `resource` (default `item`), `method` (default `get`), `path` (optional; must equal the template path) | `API.CONTRACT.OK` | see section 5.3 |
| `data.jsonschema` | `document`: `item` or `model`; optional `schema`, `source`, `sample`, `credential` (see below the table) | `DATA.SCHEMA.OK` | `DATA.SCHEMA.INVALID` (fail). The summary lists JSON paths and keywords, never values. Numbers are exact decimals. A `format` that the engine cannot assert: `blocked`, `DATA.SCHEMA.UNSUPPORTED_FORMAT`, before the fetch. A body nested too deeply to validate: `blocked`, `DATA.RESPONSE.TOO_DEEP`. A schema that is not valid in its dialect, or a local reference that does not resolve: `blocked`, `DATA.SCHEMA.MALFORMED`. A `$schema` other than 2020-12 or draft-07: `blocked`, `DATA.SCHEMA.DIALECT`. A keyword that the dialect ignores: `blocked`, `DATA.SCHEMA.MALFORMED` |
| `data.context` | `document`, `allowed_contexts`; optional `context_files`, `source`, `sample`, `credential` | `DATA.CONTEXT.OK` | see section 5.4 |
| `data.rules` | `document` (default `item`); optional `rule_pack`, `source`, `sample`, `credential` | `DATA.RULES.OK` | see section 5.1 |
| `access.restricted_fields` | `role` (default `anonymous`) | `ACCESS.POLICY.ENFORCED` | see section 5.2 |
| `integrity.jws` | none | `INTEGRITY.OK` | see section 8.1 |
| `integrity.jose` | `profile`, `key_source`, `did_sample`, `source`, `sample`, `accept`, `algorithms`; all optional | `INTEGRITY.JOSE.OK` | the architecture contract, section 8, gives each outcome and its order. The reference credential is in section 4.7 |
| `integrity.status_list` | `key_source`, `did_sample`, `source`, `sample`, `accept`, `list_source`, `list_sample`, `purpose`; all optional | `INTEGRITY.STATUS.OK` | the architecture contract, section 8, gives each outcome and its order. The reference status list is in section 4.7 |
| `persistence.versions` | `entries_pointer`, `version_field`, `time_field`, `digest_field`, `digest_of`, `version_kind` (the defaults are the layout of section 4.3) | `PERSISTENCE.OK` | `PERSISTENCE.UNDECLARED_CHANGE` (fail); no canonical form of the passport with `jcs-sha256`: `blocked`, `PERSISTENCE.DIGEST.NOT_COMPARABLE` (section 4.3); malformed parameter: `blocked`, `PERSISTENCE.PARAMS.INVALID` |
| `registry.consistency` | `fields` (1 to 16 pairs of `name`, `registry_pointer`, and `passport_pointer`; the default is the two pairs of section 4.4) | `REGISTRY.OK` | `REGISTRY.INCONSISTENT` (fail); a compared field absent on either side: `REGISTRY.FIELD.MISSING` (fail); malformed parameter: `blocked`, `REGISTRY.PARAMS.INVALID`. Values compare as JSON values, so `true` is not `1`. Lookup status 401, 403, or 404: `REGISTRY.LOOKUP.NOT_CONCLUSIVE` with `unreachable: true`, because a failed lookup does not prove a missing registration |
| `aas.validate` | `artifact` (default `aas_file`), `format` (`json`, `xml`, or `aasx`; default `json`), `metamodel_version` (default `3.0`) | `AAS.VALID`. The message names the format and the version that the check covers | `AAS.INVALID` (fail): the wrapped validator read the sample and rejected it, or the sample is not readable as the declared format, or an AASX package has no AAS specification part; a `metamodel_version` that the wrapped release does not verify, or an XML namespace that names such a version: `unsupported`, `AAS.VERSION.UNSUPPORTED`, and the sample is not read; malformed parameter: `blocked`, `AAS.PARAMS.INVALID`; sample missing: `blocked`, `AAS.SAMPLE.MISSING` |
| `aas.api_profile` | `endpoint` (default `aas`), `profile` (default `aas-repository-read`), `id_source` (default `aas_shell_id`), `id_pointer`, `max_requests` (default 6) | `AAS.API.OK`. The message names the probes that ran | `AAS.API.PROFILE` (fail), with the broken rule in `summary.rule`; the architecture contract, section 8, gives each outcome and its order. The reference repository is in section 4.9 |

The data checks take these optional parameters. Each one is experimental.

| Parameter | Checks | Meaning |
| --- | --- | --- |
| `source` | all three | No value: the resource that `document` names. `item` or `model`: that resource. `credential_payload`: the payload of a credential that verifies first. `embedded_jsonld`: each JSON-LD script of an HTML page. Any other value: the IXIT sample of that name |
| `sample` | all three | With `embedded_jsonld`: the IXIT sample that holds the HTML page. Without it, the check asks for the resource with `Accept: text/html` |
| `credential` | all three | With `credential_payload`: the parameters of `integrity.jose`, for example `accept` and `source` |
| `schema` | `data.jsonschema` | A schema file under the data root, in place of the profile schema |
| `rule_pack` | `data.rules` | A rule pack file under the data root, in place of the profile rule packs |
| `context_files` | `data.context` | A pinned copy under the data root for each of some allowed contexts (section 5.4) |

A run binds each file that `schema`, `rule_pack`, or `context_files` names. The outcomes of the sources are in the
architecture contract, section 8. An unverified credential gives `blocked`,
`DATA.CREDENTIAL.UNVERIFIED`. A page without a JSON-LD script gives a fail,
`DATA.EMBEDDED.MISSING`.

### 8.1 Outcomes of `integrity.jws`

The check takes the first row that applies. A limit of this engine is `blocked`, which gives
`inconclusive`. Only a finding about the tested system is a `fail`.

| Order | Condition | Status | Reason code |
| --- | --- | --- | --- |
| 1 | No trust bundle is configured | `blocked` | `INTEGRITY.TRUST.MISSING` |
| 2 | The IXIT gives no URL template for `signed` or `item`, or such a URL cannot be built. With `item_target: resolved`, the `item` URL is found at row 18 instead | `blocked` | `INTEGRITY.NO_TARGET` |
| 3 | The system answers with status 500 or higher, or with 429 | fail, `unreachable: true` | `INTEGRITY.TOKEN.NO_ANSWER`; for 429, `TRANSPORT.RATE_LIMITED` |
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
| 18 | With `item_target: resolved`, the carrier gives no resolved URL. A transport error, a 429, or a server error at the resolver gives `unreachable` | `blocked` | `INTEGRITY.NO_TARGET` |
| 19 | The published passport answers with a status from 500 to 599, or with 429 | fail, `unreachable: true` | `TRANSPORT.SERVER_ERROR`; for 429, `TRANSPORT.RATE_LIMITED` |
| 20 | The published passport is not JSON | `blocked` | `INTEGRITY.PAYLOAD.NOT_COMPARABLE` |
| 21 | The signed payload and the published passport are different JSON values | fail | `INTEGRITY.PAYLOAD.MISMATCH` |

The supported profile is ES256 on curve P-256, with the key in the first `x5c` certificate.
The leaf may sign a document if its key usage permits a digital signature and its extended key
usage, when present, names `id-kp-documentSigning` (RFC 9336) or `anyExtendedKeyUsage`.
The path search tries each candidate issuer, so a cross-signed authority can appear twice.
A passport signed with the key of a self-signed anchor itself has the path from the anchor to
the anchor.
The payload is compared as a JSON value. Key order, white space, and number format do not matter.
The canonical form of the engine applies to its own decision body only, not to a passport.
Each revoked serial number in the trust bundle names its issuer, by issuer name or by issuer key
identifier. A serial number matches a certificate only when the issuer matches too. A serial
number that is revoked under one authority therefore does not match a certificate of a different
authority. An entry with `revoked_at` applies from that time.
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
| `ILL-PERSIST-002` | recommended | always | `TP-PERSIST-002` (`persistence.versions`, `digest_of: raw-sha256`) |
| `ILL-REGISTRY-002` | mandatory | always | `TP-REGISTRY-002` (`registry.consistency`, three declared pairs) |
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
