# Agent review of the adapters

Audience: maintainers, assessors, and the person who ratifies the ADRs.
Purpose: record the findings of the agent review of the adapters, how each one was checked, and
how each one was handled.
Prerequisites: read `docs/explanation/architecture.md` sections 8 and 9, and
`docs/reference/reference-system.md` sections 4, 5, and 8.

## Status

| Field | Value |
| --- | --- |
| Date | 2026-10-18 |
| Commit reviewed | `5aaca24` and the main branch at `6cbd042`. The adapter code is the same in both. |
| Fixes | `58f15d7..075b0a6` on branch `worktree-wf_46368434-d41-36` |
| Reviewers | AI agents. Finders, reproduce skeptics, and the fixer are AI agents. None of them wrote the code under review. |
| Nature | **An agent review. It is not an audit. No person has reviewed this record.** |

No review status of a catalogue entry was changed. No approval, reviewer name, or validation
result is stated here that a command did not produce.

## Scope

- `src/dppce/adapters/api.py`, `common.py`, `data.py`, `lifecycle.py`, `identifier.py`, and
  `carrier.py`
- `src/dppce/infrastructure/transport.py` and `clock.py`
- `validation/run.py`

## Method

1. Finders read the files of the scope and wrote a finding with a failure scenario for each
   defect.
2. A reproduce skeptic tried to refute each finding with a scratch test. The tests used loopback
   servers or in-process acquirers only. The skeptics did not edit the repository.
3. A finding counts as confirmed only if a test reproduced it.
4. The fixer added each reproducing test to the repository first and ran it against the code
   under review (red). Then the fixer changed the code until the test passed (green).

The tests are in `tests/test_review_adapters.py`, `tests/test_validation_controls.py`, and
`tests/test_transport_tls.py`. Each test name starts with the finding identifier where one
applies.

## Summary

| Outcome | Count |
| --- | --- |
| confirmed and fixed | 30 |
| refuted | 1 |

## Red runs

Each count comes from a pytest run of the new tests against the code before the fix.

| Fix commit | Tests | Result on the code before the fix |
| --- | --- | --- |
| `58f15d7` | api.contract, template URLs, validator | 31 failed, 6 passed |
| `58f15d7` | data-lifecycle-6 | 3 failed, 3 passed |
| `641252f` | data, persistence, registry, clock | 54 failed, 19 passed |
| `641252f` | the pinned update-time pattern | 1 failed |
| `a6e7d04` | identifier, carrier, control characters | 32 failed, 9 passed |
| `742f0e0` | credential scrub | 7 failed, 1 passed |
| `28eb959` | validation controls | 4 failed |

The passed tests are controls. They fix behavior that must stay, for example a real status
mismatch that still fails. In the last row, three unit tests failed because the new helper did
not exist yet. The fourth test reproduces the defect: `validation.run.main()` returned 0 with a
control step that stopped completing.

## Findings

| Id | Severity | File | Outcome | Handled |
| --- | --- | --- | --- | --- |
| api-common-1 | high | `api.py` | confirmed | fixed (`58f15d7`) |
| api-common-2 | medium | `common.py` | confirmed | fixed (`58f15d7`) |
| api-common-3 | low | `api.py` | confirmed | fixed (`58f15d7`) |
| api-common-4 | low | `api.py` | confirmed | fixed (`58f15d7`) |
| api-common-5 | low | `common.py` | confirmed | fixed (`58f15d7`) |
| api-common-6 | low | `api.py` | confirmed | fixed (`58f15d7`) |
| api-common-7 | low | `api.py` | confirmed | fixed (`58f15d7`) |
| api-common-8 | low | `common.py` | confirmed | fixed (`58f15d7`) |
| data-lifecycle-1 | high | `lifecycle.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-2 | medium | `lifecycle.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-3 | medium | `lifecycle.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-4 | medium | `lifecycle.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-5 | medium | `data.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-6 | medium | `data.py` | confirmed | fixed (`58f15d7`) |
| data-lifecycle-7 | low | `data.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-8 | low | `data.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-9 | low | `common.py` | confirmed | fixed (`58f15d7`) |
| data-lifecycle-10 | low | `data.py` | confirmed | fixed (`641252f`) |
| data-lifecycle-11 | low | `lifecycle.py` | refuted | not changed |
| identifier-carrier-1 | medium | `identifier.py` | confirmed | fixed (`a6e7d04`) |
| identifier-carrier-2 | medium | `common.py` | confirmed | fixed (`a6e7d04`) |
| identifier-carrier-3 | medium | `identifier.py` | confirmed | fixed (`a6e7d04`) |
| identifier-carrier-4 | medium | `identifier.py`, `transport.py` | confirmed | fixed (`a6e7d04`) |
| identifier-carrier-5 | low | `common.py` | confirmed | fixed (`a6e7d04`) |
| identifier-carrier-6 | low | `identifier.py` | confirmed | fixed (`a6e7d04`) |
| server-clock-fixes-1 | high | `transport.py` | confirmed | fixed (`742f0e0`) |
| server-clock-fixes-2 | medium | `transport.py` | confirmed | fixed (`742f0e0`) |
| server-clock-fixes-3 | medium | `validation/run.py` | confirmed | fixed (`28eb959`) |
| server-clock-fixes-4 | medium | `lifecycle.py` | confirmed | fixed (`641252f`) |
| server-clock-fixes-5 | medium | `clock.py` | confirmed | fixed (`641252f`) |
| server-clock-fixes-6 | low | `data.py` | confirmed | fixed (`641252f`) |

Some findings overlap. data-lifecycle-9 is api-common-8 for `data.jsonschema`.
server-clock-fixes-4 is data-lifecycle-2, and server-clock-fixes-6 is data-lifecycle-10.
identifier-carrier-1 and identifier-carrier-3 share one fix. Each finding has its own test.

## Evidence and handling

### api.contract

- **api-common-1.** The judged fetch followed a redirect. A 303 of the marked operation, or a
  second request that moved to another path or origin, gave `API.CONTRACT.OK` on another body.
  Now a judged fetch that followed a redirect gives `blocked`, `API.CONTRACT.PATH_MISMATCH`.
- **api-common-2.** A passport identifier of `.` or `..` made a dot segment in a template URL.
  Now `template_url` gives `<AREA>.NO_TARGET` and nothing is sent. The fix covers every check.
- **api-common-3.** A `default` or `2XX` key, a media range, or a status without content gave a
  false fail. Now such a contract is `unsupported` before the fetch. An unquoted `200` counts as
  `'200'`. A status without content passes only with an empty answer.
- **api-common-4.** A JSON array or scalar body gave `API.RESPONSE.NOT_JSON`. Now the body may
  be any strict JSON value.
- **api-common-5.** A deep body with a recursive schema raised `RecursionError`. Now
  `schema_errors` returns no result, and the check gives `blocked` with `<AREA>.RESPONSE.TOO_DEEP`.
- **api-common-6.** A boolean schema or a structure of another type raised an exception. Now it
  is `unsupported` before the fetch.
- **api-common-7.** A resolved URL with a query passed. Now `_within` refuses a query and a
  fragment.
- **api-common-8.** `format: uri` was not asserted, because no optional package was installed.
  Now the validator has a standard-library `uri` checker. A format that the engine cannot
  assert gives `unsupported` or `blocked`, never a pass.

### Data, persistence, and registry

- **data-lifecycle-1 and data-lifecycle-7.** A 401, 403, or 404 body was judged as the
  document. Now a document is judged only with status 200. 401, 403, and 404 give `blocked` with
  `<AREA>.RESPONSE.NOT_CONCLUSIVE`. Another status gives a fail with `<AREA>.RESPONSE.STATUS`.
- **data-lifecycle-2.** Update times were compared as text. Now they are RFC 3339 instants with
  an offset. A missing or invalid time breaks the declared rule.
- **data-lifecycle-3.** A passport with a decimal number gave `PERSISTENCE.UNDECLARED_CHANGE`.
  Now it gives `blocked` with `PERSISTENCE.DIGEST.NOT_COMPARABLE`, unless the rule already fails.
- **data-lifecycle-4.** Two absent fields counted as equal, and `true` equalled `1`. Now the
  check compares JSON values. An absent field gives `REGISTRY.FIELD.MISSING`.
- **data-lifecycle-5.** Only the top-level `@context` was read. Now every `@context` counts.
- **data-lifecycle-6.** Binary floats let a value round onto a schema bound. Now
  `data.jsonschema` and `api.contract` parse exact decimals. The schema numbers are decimals too.
- **data-lifecycle-8.** Zero applied rules gave `DATA.RULES.OK`. Now that gives `blocked` with
  `DATA.RULES.NONE_APPLIED`. A rule without the fields of its kind cannot be loaded.
- **data-lifecycle-9.** The same as api-common-8, for `data.jsonschema`.
- **data-lifecycle-10.** A future update time passed the freshness rule. Now it fails, as for
  the trust status snapshot in `integrity.py`. No clock tolerance was added.

### Identifier and carrier

- **identifier-carrier-1 and identifier-carrier-3.** An unparsable or hostless carrier text
  raised an exception or became a connectivity failure. Now one test, `is_http_url`, gives
  `IDENTIFIER.UNRESOLVED` or `IDENTIFIER.NOT_RESOLVABLE` and sends nothing.
- **identifier-carrier-2.** A decompression bomb and a broken PNG chunk raised exceptions. Now
  they give `CARRIER.SAMPLE.TOO_LARGE` and `CARRIER.SAMPLE.UNREADABLE`.
- **identifier-carrier-4.** The URL parser dropped tab, CR, and LF, so the record named a
  request that was never sent. Now the check refuses such a text. The transport refuses a URL
  with a control character or a space as `policy_denied`.
- **identifier-carrier-5.** The origin override compared raw text. Now it compares origins in
  normal form.
- **identifier-carrier-6.** A port that is not a number passed the parser. Now it fails.

### Transport, clock, and validation

- **server-clock-fixes-1.** Common echo forms of a credential stayed in the record. Now the scrub
  removes the plain form, both percent forms in either hex case, and the JSON form with `\/`.
- **server-clock-fixes-2.** A complete body lost a tail that matched a credential head. Now only
  a truncated body loses a cut head.
- **server-clock-fixes-3.** A control step that stopped completing dropped out of the metric.
  Now a control is as expected only if its run passes and every planned step completes.
- **server-clock-fixes-4.** The same as data-lifecycle-2.
- **server-clock-fixes-5.** `parse_stamp` accepted unpadded fields and Unicode digits. Now it
  accepts only the canonical ASCII form. The pinned update-time patterns use `[0-9]`.
- **server-clock-fixes-6.** The same as data-lifecycle-10.

### Refuted

- **data-lifecycle-11.** `aas.validate` passes an empty environment `{}`. The skeptic showed
  that this is the behavior of aas-test-engines 1.0.3. The AAS metamodel lets each top-level list
  be absent. The wrapped engine rejects `[]`, a scalar, `null`, and present but empty lists. The
  contract defines `AAS.VALID` as "the wrapped validator accepts the file". The message states
  the limit. The code was not changed. A stricter rule needs a contract decision of the owner.

## Contract changes in this round

The owner authorized T1 contract edits on 2026-10-18. These edits were made:

- `docs/explanation/architecture.md` section 8: a port after the host is ASCII digits only; the
  URL test of `identifier.consistency` and `identifier.resolve`.
- `docs/explanation/architecture.md` section 9: the refusal of a URL with a control character
  or a space; the forms that the scrub removes.
- `docs/explanation/architecture.md` section 9.1: no query and no fragment in a resolved URL;
  the judged fetch of `api.contract` follows no redirect.
- `docs/reference/reference-system.md`: the new reason codes and rules.
- `tests/test_server_errors.py`: status 499 now expects `DATA.RESPONSE.STATUS`. It is still a
  fail and still not `unreachable`. Only the reason code changed.
- `profiles/battery/schemas/item.schema.json` and
  `profiles/battery/contracts/reference-api.openapi.yaml`: `\d` became `[0-9]`.

## Open questions for the owner

- A 404 on the version history now gives `blocked`. A missing history could instead be a fail.
- A future update time fails freshness with no tolerance for clock skew.
- JSON Schema `pattern` uses Python `re`, not ECMA-262. `$` also matches before a final line
  feed. Only the pinned patterns were changed.
- A credential echoed in base64 or in a mix of forms is still not recognized.

## Transport over TLS

`tests/test_transport_tls.py` runs the policy transport against a loopback HTTPS server. The
test generates a TEST-ONLY certificate authority and leaf. It trusts the authority through
`SSL_CERT_FILE`, which the default verify paths read. Verification stays on. A trusted
certificate gives an answer. An untrusted certificate and a certificate for another host give
the transport error `tls`. A check then reports `TRANSPORT.UNREACHABLE`, never a pass.
