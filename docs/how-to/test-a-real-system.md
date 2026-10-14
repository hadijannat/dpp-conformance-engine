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
6. Run `dppce plan` first. Check which steps the plan executes and which it blocks.
7. Run `dppce run` with `--trust`, `--authorization`, and the confirmations.
8. Keep the data key directory apart from the run directory.
9. List the recordings past the retention period with `dppce purge --runs DIR --keys DIR`.
10. Check the list. Then delete those recordings with the same command and `--yes`.

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
