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
3. Put the key passphrase in an environment variable or in a file in the `--secrets` directory.
4. Give the four options to `dppce run`. Give `--client-cert` and `--client-key` together.
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
