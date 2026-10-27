# How to test a real system with authorization

Audience: operators of the engine.
Purpose: run the engine against a system that is not the local reference system, lawfully and safely.
Prerequisites: permission from the owner of the system, **before** the first request.

Research of public documentation is not permission to test a system.
Read-only access also needs the permission of the owner.

## What needs what

| Activity | What you need |
| --- | --- |
| Bounded read-only requests to a public origin | The owner's prior permission, and `--allow-remote-host ORIGIN` for each origin, such as `https://dpp.example.com` |
| Requests to a loopback or private origin | An entry in the IXIT, and `--allow-private-host ORIGIN` for each origin, such as `http://127.0.0.1:8765` |
| Requests as a role with a credential | A signed authorization that names the origin, and `--role-secret ROLE=REFERENCE` |
| Access probes, writes, tampering, fuzzing | A signed authorization that grants that scope |
| A server certificate from a private CA | `--ca-file` (see [Use a private CA or a client certificate](#use-a-private-ca-or-a-client-certificate)) |
| A server that asks for a client certificate | A signed authorization that names the origin, `--client-cert`, and `--client-key` |

In this version, writes, tampering, and fuzzing have no executable check. The transport
refuses them without a matching authorization.

## Steps

1. Agree the scope with the owner: origins, methods, roles, period, and request limit.
2. Ask the owner to sign an authorization for that scope. The payload format is the
   `authorization` schema. The owner signs it with `dppce authorize`:

   ```bash
   dppce keys generate --out owner.key.pem --passphrase-ref env:DPPCE_SECRET_OWNER_PASSPHRASE > owner.jwk.json
   dppce authorize --document authorization.json --key owner.key.pem --kid owner-key-1 \
     --passphrase-ref env:DPPCE_SECRET_OWNER_PASSPHRASE --out authorization.jws
   ```

   The owner generates the passphrase, for example with `secrets.token_urlsafe(32)`.
   The owner then sends you `authorization.jws` and `owner.jwk.json`.
3. Add the owner's public key to **your** trust bundle, with the purpose `authorization`.
   Get the key through a channel that you trust.

   ```bash
   dppce trust-bundle add-key --bundle trust.json --out trust-2.json --kid owner-key-1 \
     --issuer urn:example:owner --purpose authorization --public-key owner.jwk.json \
     --not-before 2026-01-01T00:00:00Z --not-after 2027-01-01T00:00:00Z
   ```

   The issuer must equal `issuer` in the authorization. Use `trust-2.json` from now on.
4. Write the ICS and the IXIT with the owner. Treat both files as untrusted input.
5. Set `network.allowed_hosts`, the request limit, the minimum interval, and a contact in the IXIT.
   The contact appears in the `User-Agent` header of each request.
6. Check the URL templates in `IXIT.resources` and the split in `IXIT.id_parts`.
   A template cannot change the scheme, the host, or the port of its endpoint.
7. Copy the data root and point a profile at the owner's contract and access policy.
   Add `x-dppce-contract-id` and an `x-dppce-resource` mark to your copy of the contract.
   Give the copy with `--data-root`. The run manifest records the hash of each bound file.
8. Run `dppce plan` first. Check which steps the plan executes and which it blocks.
9. Run `dppce run` with `--trust`, `--authorization`, and the confirmations.
   Name the data key with `--data-key-id`. Give `--create-data-key` the first time only.
10. Keep the data key directory apart from the run directory.
11. List the recordings past the retention period with `dppce purge --runs DIR --keys DIR`.
12. Check the list. Then delete those recordings with the same command and `--yes`.

## Choose a profile

Use a battery profile only for a battery passport. For another system, use a family profile.
A family profile pins no schema, no API contract, and no access policy.
Its requirements are illustrative and make no normative statement.

| Profile | Use it when the system |
| --- | --- |
| `family/web` | Serves a passport at an https URL, as JSON or as an HTML page |
| `family/gs1-resolver` | Resolves a GS1 Digital Link identifier to a passport |
| `family/aas` | Supplies Asset Administration Shell files in JSON, XML, or AASX form |
| `family/credentials` | Issues the passport as a verifiable credential, in the VC or UNTP style |

Each family profile reads only ICS fields: `identifier_scheme`, `signature_format`, `granularity`, and `features`.
A step that does not fit these declarations is not applicable. It is never a fail.
Declare `product_category: unknown` in the ICS.
An example ICS and IXIT for each family are in `profiles/family/examples/`.
The next section describes each family.

## Test a system by family

Every example ICS and IXIT in `profiles/family/examples/` is synthetic.
It points at the loopback reference system, and it makes no normative statement.
Copy the pair for your family. Then replace every value, including the origins and the samples.
Run `dppce plan` before `dppce run`, as in the steps above.

Every family profile selects every family test pack.
A step of another family is not applicable. It is never a fail.
A step that needs a value that you did not declare is not a pass.
An undeclared feature skips its step, and its requirement is inconclusive.

The reference system is the only system that the examples test as shipped.
A run on it shows that the engine works. It says nothing about your system.

### Plain web passport

- Profile: `family/web`.
- Example: `web.ics.yaml` and `web.ixit.yaml`.
- Checks:
  - `TP-WEB-RESOLVE-001`: resolution of the passport URL.
  - `TP-WEB-CONSISTENCY-001`: the identifier against the member id of the JSON passport.
  - `TP-WEB-INTEGRITY-001`: the signed passport (`signature_format: jws`).
  - `TP-WEB-VERSIONS-001`: the version history (`features.version_history`).
  - `TP-WEB-IDENTIFIER-001`: the syntax of an `https-url` identifier.
  - `TP-WEB-NEGOTIATION-001`: content negotiation.
  - `TP-WEB-RULES-001`: the TEST-ONLY rule pack of version 2. Its rules fit the reference
    passport only, so replace it with a pack for your system.

Operator decisions:

- Get the owner's permission. Then confirm each public origin with `--allow-remote-host`.
- Give the `item`, `signed`, and `versions` templates in the IXIT. A resource with no template is not tested.
- Give a trust bundle with `--trust`. Without the signer key in it, the signature step is inconclusive.
- Add `--ca-file` or the client certificate options if the server needs them.
  See [Use a private CA or a client certificate](#use-a-private-ca-or-a-client-certificate).

Limits:

- The engine does not validate the passport content against a schema. The profile pins none.
- A passing signature step shows that the signature matches a key in your trust bundle.
  It does not show that the signer is entitled to sign.
- The engine does not run scripts of a page.

### GS1 Digital Link resolver

- Profile: `family/gs1-resolver`.
- Example: `gs1-resolver.ics.yaml` and `gs1-resolver.ixit.yaml`.
- Checks:
  - `TP-GS1-SYNTAX-001`: the syntax of an item-level identifier.
  - `TP-GS1-SYNTAX-002`: the syntax of an uncompressed identifier of any granularity.
  - `TP-GS1-RESOLVE-001`: resolution of the identifier.
  - `TP-GS1-CONSISTENCY-001`: the identifier against the declaration and the passport.
  - `TP-GS1-GRANULARITY-001`: the granularity.
  - `TP-GS1-LINKSET-001`: the linkset.
  - `TP-GS1-WELLKNOWN-001`: the resolver description file.
  - `TP-GS1-CONFORMANCE-001`: the final status of a default, a linkset, and an invalid request.
  - `TP-GS1-EQUIVALENCE-001`: the identifier against a declared identifier in canonical form.

Operator decisions:

- Declare `identifier_scheme: gs1-digital-link` and the `granularity` in the ICS.
- Give the identifier as `samples.identifier`. Give the declared identifier file as `samples.gs1_declared`.
- Confirm the origin of the resolver with `--allow-remote-host`.
  The conformance step sends bounded read requests, including one for an invalid identifier.
  Name that request in the permission of the owner.

Limits:

- The engine parses uncompressed GS1 Digital Link URIs only.
- With item granularity, `TP-GS1-SYNTAX-001` accepts only the form `/01/<GTIN>/21/<serial>`.
  It fails any other form, a compressed URI and a URI with a path prefix included.
  This fail shows that the identifier has another form. It does not show a fault of the resolver.
- `TP-GS1-SYNTAX-002` accepts an uncompressed URI of any granularity. It gives `unsupported` for a compressed URI.
- The checks observe the answers of the resolver. They do not grade the resolver against a GS1 test suite.

### Asset Administration Shell file

- Profile: `family/aas`.
- Example: `aas.ics.yaml` and `aas.ixit.yaml`.
- Checks:
  - `TP-AAS-JSON-001`, `TP-AAS-XML-001`, and `TP-AAS-AASX-001`: validation of an AAS file in each form.
  - `TP-AAS-DPP-001`: the digital product passport metadata submodel of the JSON file.
  - `TP-AAS-CONSISTENCY-001`: the carrier identifier against the global asset identifier.
  - `TP-AAS-API-001`: a read probe of the AAS Repository API.

Operator decisions:

- Declare each form that you supply as `features.aas_json`, `aas_xml`, `aas_aasx`, and `aas_api`.
  Declare a form as `false` to leave its step out. An undeclared form skips its step.
  The requirement of a skipped step is inconclusive.
- Put your files next to the IXIT. Name them in `samples`. The example ships no AAS file.
  Without `aas.json`, the step is blocked with `AAS.SAMPLE.MISSING`.
- For the API probe, give the base URL as `endpoints.aas` and a shell identifier as `samples.aas_shell_id`.
  Confirm the origin of that endpoint like any other origin.

Limits:

- The file checks read the file and send no request. They show nothing about the server that holds the file.
- The API probe covers the read profile of the AAS Repository only. It does not write or change anything.
- A valid file does not show that the content is true.

### Verifiable credential and UNTP-style passport

- Profile: `family/credentials`.
- Example: `credentials.ics.yaml` and `credentials.ixit.yaml`.
- Checks:
  - `TP-VC-RESOLVE-001`: resolution of the credential URL.
  - `TP-VC-INTEGRITY-001`: the signed credential.
  - `TP-VC-JOSE-001`: the VC-JOSE credential with a pinned issuer key.
  - `TP-VC-DID-001`: the `did:web` document.
  - `TP-VC-CONSISTENCY-001`: the credential subject against the carrier identifier.
  - `TP-VC-STATUS-001`: the status list entry.

Operator decisions:

- Put the issuer key in your trust bundle, with the issuer equal to the DID. Get the key through a trusted channel.
- Decide for each third-party host whether you have permission for a live fetch.
  Without permission, use an offline sample.
  See [Resolve a did:web DID](#resolve-a-didweb-did) and [Check a credential status list](#check-a-credential-status-list).
- Replace `vc_json` in the IXIT with a credential of the system under test.
- `TP-VC-DID-001` names the DID of the reference system, and `TP-VC-STATUS-001` fetches the list live.
  For your issuer, or for an offline sample, import a test pack with your DID and mode.
- Add the TLS options if the server needs them.

Limits:

- The engine does not check an UNTP vocabulary or schema in this version. It checks the signature,
  the DID document, the status list, and the subject identifier.
- A DID document that resolves is not trusted until your trust bundle holds its key.
- A pass shows a valid proof. It does not show that the claims in the credential are true.

### Dataspace sample

The engine does not run a dataspace protocol. It has no catalog request, no contract negotiation,
and no transfer process. The capability manifest (`dppce capabilities`) lists `dataspace.protocol`
and `dataspace.catalog` as `interface_only`. No check uses them, so the engine plans no step for them.
The capability `access.oauth2` has the same state. The engine does not request a token.

The example set has no dataspace pair. No family profile declares a role other than `anonymous`,
and the anonymous role never carries a credential. A dataspace example would not test anything.

An operator can test the data plane of a connector with a token that the operator obtained.
The token comes from outside the engine, for example an endpoint data reference (EDR) token
from the connector.

1. Agree the scope with the owner. Include the data plane URL and the access probe.
2. Run the exchange with your own tools to get the token and the data plane URL.
3. Put the token in an environment variable, for example `DPPCE_SECRET_EDR`. Never put it in a file of the IXIT.
4. Copy the data root. Write a profile that declares a role, for example `bearer`, and an access policy.
   See [Add a check and a test pack](add-a-check-and-a-test-pack.md).
   The policy format is in the [reference system](../reference/reference-system.md).
5. Put the asset path in the `channels.fetch` template of the access policy, not in `resources.item`.
   The check `access.restricted_fields` reads only the `channels` templates.
6. Put the data plane base URL in `endpoints.api` in the IXIT. Set no `origin_override`.
   The check builds each channel URL under `endpoints.api`. The role credential is bound to that origin.
7. In the ICS, set `access.policy` to the `policy_id` of your policy.
   Without it, the step is blocked with `ACCESS.POLICY.NOT_DECLARED`.
8. Write a test pack with the step `access.restricted_fields` for that role.
   Set `requires_scope: access_probe` on the test purpose. The default scope is `read`.
9. Declare the identity in the IXIT: `role: bearer` and `secret_ref: env:DPPCE_SECRET_EDR`.
10. Get an authorization that names the data plane origin, the role, and the scope `access_probe`.
11. Run with `--role-secret bearer=env:DPPCE_SECRET_EDR`, `--trust`, and `--authorization`.

The engine sends the token as `Authorization: Bearer <token>` to the origin that the authorization names.
It sends it to no other origin. It removes the token from records.
A data plane that expects another header form refuses the request.
The step then fails with `ACCESS.ENTITLEMENT.REFUSED`.

What the run shows:

- The data plane gives the fields that your policy grants to that role, and it withholds the others.
- The answer was observed on the channels that your policy names.

What the run does not show:

- That the dataspace protocol steps are correct. The engine did not run them.
- That the token is well formed, has the right scope, or expires on time.
- That the catalog offer or the contract matches the data that the data plane serves.
- That the policy you wrote is the policy of the contract.

A token expires. An expired token makes the step fail with `ACCESS.ENTITLEMENT.REFUSED`.
This fail can come from the operator's token, not from the system.
Renew the token before each run.
A later version can add the OAuth 2.0 client credentials grant. That change would not add the dataspace protocol.

## Use a private CA or a client certificate

Some systems use a server certificate from a private certificate authority (CA).
Some ask the test host for a client certificate (mutual TLS).
Only you give these files, on the command line of `dppce run`. The ICS and the IXIT cannot name them.

| Option | What it does |
| --- | --- |
| `--ca-file PATH` | Adds the PEM certificates in the file to the default trust store. It never replaces that store. |
| `--client-cert PATH` | The PEM client certificate. Put the client certificate first and any intermediate certificates after it. |
| `--client-key PATH` | The PEM private key of the client certificate. The key can be encrypted. |
| `--client-key-passphrase-ref REFERENCE` | The secret reference of the key passphrase: `env:DPPCE_SECRET_<NAME>` or `file:<name>`. |

1. Get the CA certificate and the client certificate from the owner through a channel that you trust.
2. Make sure that the authorization names each origin that asks for the client certificate.
3. If the key is encrypted, put its passphrase in an environment variable or in a file in the `--secrets` directory.
4. Give `--ca-file` for a private CA. For a client certificate, give `--client-cert` and `--client-key` together.
   Give `--client-key-passphrase-ref` only for an encrypted key.
5. Read the standard error of the run. Compare each SHA-256 value with the value from the owner.

The engine applies these rules:

- The CA file applies to each https origin of the run.
- The engine sends the client certificate only to an origin that the validated authorization names.
  Every other origin gets a connection without it.
- `--client-cert` without a valid authorization is an input error.
- No option turns off certificate checks or host-name checks. The minimum version stays TLS 1.2.
- A server that refuses the run for a missing client certificate gives the transport error `tls`.
  The engine does not send that request again. With TLS 1.3, a server can reset the connection before
  the engine reads the refusal. The error is then `connect`.
- The log line of the CA file gives the SHA-256 of the file. The log line of the client certificate
  gives the SHA-256 of the certificate in DER form. The run manifest does not record either value.
- A file that is missing or cannot be used is an input error, with exit code 2. The run then sends no request.
  The message starts with a reason code, for example `TLS.CLIENT_KEY.PASSPHRASE` or `TLS.CLIENT_KEY.MISMATCH`.

The engine does not support an egress proxy. A proxy would connect to the system instead of the
engine. The engine could then not check the resolved address of the system.

## Resolve a did:web DID

The check `identity.did` reads the DID document of a credential issuer. Often a third party
operates that host, not the owner of the system under test. The owner cannot give permission for
a host of a third party. The check therefore has two modes.

| Mode | Parameters | What the engine does |
| --- | --- | --- |
| Offline copy | `did` and `source` | Reads the IXIT sample that `source` names. It sends no request. |
| Live fetch | `did` only | Fetches `https://<host>/.well-known/did.json` through the transport policy. |

Use the offline copy when you have no permission for the DID host.

1. Get the DID document from the owner as a file.
2. Name the file in `IXIT.samples`, for example `did_document: did.json`.
3. Give `source: did_document` in the parameters of the test purpose.

For a live fetch, you need the permission of the operator of the DID host. Add the host to
`network.allowed_hosts`. Give `--allow-remote-host ORIGIN` for the origin of the DID host.
Without this confirmation, the transport refuses the request. The step is then inconclusive with
`TRANSPORT.DENIED`, never a pass. The engine does not follow a redirect out of the scope.

The test purpose `TP-VC-DID-001` names the DID of the reference system. For a different DID, import
a test pack with that DID and the mode that you selected. The observation records the mode in
`source`.

A DID document that resolves is not trusted. Add the issuer key to your trust bundle with an
issuer equal to the DID. Get the key through a channel that you trust.

## Check a credential status list

The check `integrity.status_list` fetches the status list credential at the URL that the
credential names. Often a third party operates that host. A live fetch needs the origin of that
host in the transport policy, as for any other origin. It also needs the permission of the host
operator.

Without that permission, use an offline copy.

1. Get the status list credential from the owner as a file.
2. Name the file in `IXIT.samples`, for example `status_list: list.jwt`.
3. Give `list_source: sample` and `list_sample: status_list` in the parameters.

The `id` of the copy must be the `statusListCredential` URL. For `key_source: did`, an offline
DID document works the same way: name its sample in `did_sample`.

## Manual steps

A manual step needs a signed manual result. The engine does not perform the review.

1. Have the person who performed the step sign the result with their own key.
   The payload format is the `manualresult` schema.
2. Copy the `expected_evidence` items of the test purpose into the result in full and in order.
3. Put the digest of the test purpose in `test_purpose_digest`.
   Print it with `dppce manual digest --test-purpose ID`.
   Give the same `--data-root` and `--import-testpack` options as the run.
   Add `--json` to get the digest with the identifiers of the test purpose and the test pack.
   The check `manual.review` computes the digest with the same function.
   A hash of the YAML entry gives a different value.
4. Put the SUT version of the ICS in `sut_version`. If the ICS declares no version, put `null`.
5. Make sure that `performed_at` is in the validity period of the key.
   It must also not be after the evaluation time of the run.
6. Use a role such as `inspector`. Do not put a name in the result or in the key identifier.
7. Add the public key of that person to **your** trust bundle, with the purpose `manual`.
8. Give each result with `--manual-result PATH` on `dppce plan` and `dppce run`. Give `--trust` too.

A result for a step that the plan does not execute is an input error.
A result that the check refuses keeps the status `manual_unavailable`, with a `MANUAL.*` reason code.

## Disclose one record

The owner or a reader can ask for the evidence behind a result.
A record opening gives the salt and the plaintext of one record.

1. Find the record identifier in the observations of the result, for example `r0001`.
2. Write the opening:

   ```bash
   dppce open --run ./runs/r1 --keys ./keys --record r0001 --out r0001.opening.json
   ```

3. Read the warning. The file holds the plaintext of the record, with mode 0600.
4. Give the file only to a party that is entitled to it. A response body can hold personal data.
5. The reader checks the opening against the signed report, the file that `dppce sign` wrote:

   ```bash
   dppce verify --envelope SIGNED_REPORT.json --trust trust.json \
     --at 2026-10-14T00:00:00Z --opening r0001.opening.json
   ```

The dimension `opening` passes with `OPENING.RECORD.OK` when the record matches its commitment.

## What the engine enforces

- It refuses a host that is not in the allowlist, and a redirect that leaves the scope.
- It refuses a request outside the authorization: origin, method, role, period, or count.
- It sends a role credential only to an origin that the authorization names.
- It sends a TLS client certificate only to an origin that the authorization names.
- It removes secrets from records and encrypts each record.

## What stays your responsibility

- That the person who authorized the test has the right to do so.
- That personal data in responses are handled as the law requires.
- That the issuer and the accreditation status in the report are true.
  Set them with `--issuer-name`, `--issuer-id`, and `--accreditation-status`.
- That `--issuer-id` equals the issuer that the trust bundle of the reader names for your report key.
  A signed report with the issuer `unspecified` never verifies as complete.
- That the accreditation status is correct. The engine does not validate it.
  A status other than `not accredited` needs `--accreditation-reference`.
