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

In this version, writes, tampering, and fuzzing have no executable check. The transport
refuses them without a matching authorization.

## Steps

1. Agree the scope with the owner: origins, methods, roles, period, and request limit.
2. Ask the owner to sign an authorization for that scope. The payload format is the
   `authorization` schema. `dppce.infrastructure.authorization.issue_authorization` signs one.
3. Add the owner's public key to **your** trust bundle, with the purpose `authorization`.
   Get the key through a channel that you trust.
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
10. Keep the data key directory apart from the run directory.
11. List the recordings past the retention period with `dppce purge --runs DIR --keys DIR`.
12. Check the list. Then delete those recordings with the same command and `--yes`.

## Manual steps

A manual step needs a signed manual result. The engine does not perform the review.

1. Have the person who performed the step sign the result with their own key.
   The payload format is the `manualresult` schema.
2. Copy the `expected_evidence` items of the test purpose into the result in full and in order.
3. Put the digest of the test purpose in `test_purpose_digest`.
   The digest is `sha256:` and the hex SHA-256 of the RFC 8785 JSON of the test purpose.
   It covers the test purpose as the engine loads it, with every default field filled in.
   That is `TestPurpose.model_dump(mode="json")`. A hash of the YAML entry gives a different value.
   No command prints this digest yet.
4. Put the SUT version of the ICS in `sut_version`. If the ICS declares no version, put `null`.
5. Make sure that `performed_at` is in the validity period of the key.
   It must also not be after the evaluation time of the run.
6. Use a role such as `inspector`. Do not put a name in the result or in the key identifier.
7. Add the public key of that person to **your** trust bundle, with the purpose `manual`.
8. Give each result with `--manual-result PATH` on `dppce plan` and `dppce run`. Give `--trust` too.

A result for a step that the plan does not execute is an input error.
A result that the check refuses keeps the status `manual_unavailable`, with a `MANUAL.*` reason code.

## What the engine enforces

- It refuses a host that is not in the allowlist, and a redirect that leaves the scope.
- It refuses a request outside the authorization: origin, method, role, period, or count.
- It sends a role credential only to an origin that the authorization names.
- It removes secrets from records and encrypts each record.

## What stays your responsibility

- That the person who authorized the test has the right to do so.
- That personal data in responses are handled as the law requires.
- That the issuer and the accreditation status in the report are true.
  Set them with `--issuer-name`, `--issuer-id`, and `--accreditation-status`.
