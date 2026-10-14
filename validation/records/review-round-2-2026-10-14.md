# Review round 2: all fixes since the first review round

Audience: maintainers, assessors, and the person who ratifies the ADRs.
Purpose: record the second and last review round of milestones M2 and M4, its findings, how each
one was checked, and how each one was handled.
Prerequisites: read the three round-1 records in this directory and `docs/readiness.md`.

## Status

| Field | Value |
| --- | --- |
| Date | 2026-10-14 |
| Commits reviewed | `ae33dcc..bb805d0` (the round-1 fixes) |
| Fixes reviewed by the follow-up reviewers | `7bbc652..b540aa9` on branch `fix/review-round-2` |
| Reviewers | AI models. Finders and contract skeptics: `claude-fable-5-1`. Reproduce skeptics: `claude-opus-5-5`. None of them wrote the code under review. |
| Nature | **An agent review. It is not a human approval and not an audit.** No review status of a catalogue entry was changed. |
| Run | Workflow `wf_a1f933e3-2e7`, 83 agents, at most 3 at a time. It stopped twice at a usage limit and was resumed from its cache. |

## Method

1. Six reviewers each took one area: transport, evidence, adapters, verdicts, legal drafts, and
   documentation with provenance. Each one worked read-only and wrote scripts in a scratch
   directory. Only the legal reviewer could read one official page (the consolidated Regulation).
2. Each finding above `info` went to skeptics who tried to refute it: a reproduce skeptic for
   each finding, and a contract skeptic for each finding of medium severity or above.
3. A completeness critic named four areas that no reviewer had examined. Four follow-up
   reviewers examined them. Their findings went through the same skeptics.

A limit of the method: the repair branch existed while the skeptics worked, and its worktree was
visible from the main checkout. Some skeptics judged a finding against the already-fixed branch
and wrote "not real" for that reason. This record marks those votes: the finding held for the
reviewed code, and the vote confirms the fix. The follow-up reviewers examined that branch on
purpose; that is how they found defects in the fixes.

## Summary

| Status | Count |
| --- | --- |
| confirmed | 37 |
| not verified: severity info, which gets no skeptic by design | 8 |
| confirmed for the reviewed code | 15 |
| refuted | 2 |

Two findings were refuted on their merits:

- `adapters-10`: revocation snapshots name serial numbers without their issuer. The skeptic
  showed that the trust bundle format cannot express more. It is now a documented limit
  (`docs/reference/reference-system.md`, section 8.1).
- `gap2-4`: the labels of the coverage ratios were not checked. The skeptic showed that section
  11.4 of the contract did not require it. The check was added as hardening, because a label
  such as "legal obligations" on a page next to "complete" would mislead a reader.

## Findings of the six areas

| Id | Severity | Title | Skeptic votes | Status | Handled |
| --- | --- | --- | --- | --- | --- |
| transport-1 | medium | F-06 fix incomplete: a hostile Location header still makes PolicyTransport.fetch raise ValueError | reproduce real; contract real | confirmed | fixed (7bbc652) |
| transport-2 | medium | An IXIT identity 'anonymous' with a secret_ref makes every anonymous request carry a bearer token; the anonymous access check then assesses an authenticated view | reproduce real; contract real | confirmed | fixed (7bbc652) |
| transport-3 | low | F-08 fix incomplete: artifact() blocks without end when the confirmed sample path becomes a FIFO | reproduce real | confirmed | fixed (7bbc652) |
| transport-4 | low | total_timeout_ms bounds one attempt of one hop, not one fetch; the real bound is (max_redirects+1) x (retries+1) x total_timeout_ms | reproduce real | confirmed | fixed (7bbc652) |
| transport-5 | low | F-17 fix incomplete: cmd_run compares a normalized origin with the raw authorization endpoint strings, so a trailing slash or capital letter silently drops every confirmed role credential | reproduce real | confirmed | fixed (7bbc652) |
| transport-6 | low | F-12 fix incomplete: redact_url leaves the URL fragment untouched, so a token in a Location fragment reaches the record in `redirects`, `Location`, and `Link` | reproduce real | confirmed | fixed (7bbc652) |
| transport-7 | low | F-14 fix incomplete: --allow-remote-host and --allow-private-host confirm a host, not an origin; the IXIT still chooses any port and scheme on it | reproduce real | confirmed | fixed (7bbc652 (the flags take an origin)) |
| transport-8 | low | The engine's own bearer token, echoed by the tested system in an allowlisted header or the body, is recorded verbatim | reproduce real | confirmed | fixed (7bbc652) |
| transport-9 | info | --retention-days has no range check: a negative value makes the recording expired on arrival; a huge value crashes with exit 3 | none | not verified (info) | fixed (7bbc652) |
| evidence-1 | medium | A signature whose protected header is deeply nested JSON makes the verifier raise RecursionError | reproduce real; contract real | confirmed | fixed (7bbc652) |
| evidence-2 | medium | A signed report may state a claim level, reason texts, and coverage counters that contradict its own body; the verifier reports it complete | reproduce real; contract real | confirmed | fixed (7bbc652) |
| evidence-3 | low | Purge deletes a fresh recording whose index pair was replaced by the authentic index pair of an expired recording made with the same key | reproduce real | confirmed | fixed (7bbc652) |
| evidence-4 | low | read_recording returns records in identifier text order, which is not acquisition order from the 10000th record on; replay then mismatches every record | reproduce real | confirmed | fixed (7bbc652) |
| evidence-5 | low | A file added to a recording directory between the content check and rmtree is deleted with it | reproduce real | confirmed | fixed (7bbc652, 14a223b) |
| evidence-6 | low | --retention-days accepts a negative value and writes a recording that is expired at creation | reproduce real | confirmed | fixed (7bbc652) |
| evidence-7 | low | parse_strict turns an out-of-range exponent into float inf although it claims to reject Infinity | reproduce real | confirmed | fixed (7bbc652) |
| evidence-8 | info | A recording written before the sealed index existed cannot be replayed or purged, and no migration is offered | none | not verified (info) | documented (097df74 (changelog)) |
| adapters-1 | medium | A chain with an unrecognized critical extension, InhibitAnyPolicy, or an EKU that excludes signing passes as INTEGRITY.OK (F-16 fix incomplete) | reproduce real; contract not real | confirmed for the reviewed code (contract lens read the fixed branch) | fixed (128b9ea) |
| adapters-2 | medium | A UTF-32 body with a BOM, or a UTF-16 body without a BOM, hides a canary and the channel passes (F-04 fix incomplete) | reproduce real; contract not real | confirmed for the reviewed code (contract lens read the fixed branch) | fixed (128b9ea) |
| adapters-3 | medium | A certificate in x5c with a malformed or duplicated extension makes jws_check raise ValueError; a tested system turns an ISSUER.UNTRUSTED fail into an engine error | reproduce real; contract real | confirmed | fixed (128b9ea) |
| adapters-4 | medium | A certificate whose key algorithm OID is unknown makes jws_check raise UnsupportedAlgorithm; no signature is needed | reproduce real; contract real | confirmed | fixed (128b9ea) |
| adapters-5 | medium | A JSON body nested about 500 levels deep makes restricted_fields raise RecursionError; a leaking system turns ACCESS.LEAK into an engine error | reproduce real; contract not real | confirmed for the reviewed code (contract lens read the fixed branch) | fixed (128b9ea) |
| adapters-6 | low | _same_json recurses in Python and raises RecursionError at object depth about 500; a legitimate deep passport becomes an engine error and a deep MISMATCH is not reported | reproduce real | confirmed | fixed (128b9ea) |
| adapters-7 | low | A protected header nested about 10000 levels deep (27 KB token) makes header_of raise RecursionError out of jws_check; no signature is needed | reproduce real | confirmed | fixed (7bbc652 (header_of)) |
| adapters-8 | low | An x5c with more than five certificates is reported as INTEGRITY.TOKEN.MALFORMED (fail, 'does not hold certificates') instead of an engine limit | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea) |
| adapters-9 | low | An expired or revoked trust anchor in the operator's bundle is reported as a fail of the tested system (INTEGRITY.CERT.EXPIRED / INTEGRITY.CERT.REVOKED) | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea) |
| adapters-10 | low | Revocation matches bare serial numbers across all issuers; a serial revoked under one anchor revokes an unrelated certificate under another | reproduce not real | refuted | documented as a limit (6ec9953 (reference-system.md, section 8.1)) |
| adapters-11 | low | trust_path stops at the first verifying candidate; a cross-signed intermediate listed before its trusted twin gives a false INTEGRITY.ISSUER.UNTRUSTED | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea) |
| adapters-12 | low | Hostile header values (alg, typ, header names) are copied unbounded into the outcome message and the signed report | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea) |
| adapters-13 | low | unusable reads only the first Content-Encoding header and never sees Transfer-Encoding; a gzip signed passport then fails as INTEGRITY.TOKEN.MALFORMED | reproduce real | confirmed | fixed (128b9ea) |
| adapters-14 | low | A canary in a redirect URL, Location, or Link header is not searched; the channel passes | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea, 59e148f) |
| adapters-15 | low | A withheld path that is present with null, a placeholder, or inside a schema description is reported as a leak | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (128b9ea) |
| adapters-16 | info | JSON string escapes are not among the searched forms: a canary written as CANARY-test in an HTML script or inside a nested JSON string passes | none | not verified (info) | fixed (128b9ea) |
| adapters-17 | low | reference-system.md sections 8 and 8.1 contradict the code and themselves after the fixes | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (6ec9953) |
| verdicts-1 | low | CAT018 warns for a manual step only; an automated deciding step with a fact-reading applicability can leave its path, the rest passes alone, and lint is silent | reproduce real | confirmed | fixed (59e148f) |
| verdicts-2 | low | In reviewed mode the on_unreachable barrier reads the mode only; a purpose that names a draft requirement still runs for an approved requirement whose path names it, and a connectivity failure becomes a `fail` with claim level `reviewed` | reproduce real | confirmed | fixed (59e148f) |
| verdicts-3 | info | `replay` with a corrupt inputs.json exits 3 "execution error" instead of 2 "invalid file" for three shapes | none | not verified (info) | fixed (59e148f) |
| verdicts-4 | info | `aggregate` hard-codes the label STEP.NOT_APPLICABLE for any step absent from a planned path | none | not verified (info) | fixed (59e148f, 14a223b) |
| legal-1 | medium | The F-01 clause turns the open status-change question into not_applicable for EUBAT-77-7A, 77-7B, 77-8 | reproduce real; contract not real | confirmed for the reviewed code (contract lens read the fixed branch) | fixed (bf121c5) |
| legal-2 | low | put_into_service_date can no longer change any result; the texts still describe a two-event trigger | reproduce real | confirmed | fixed (bf121c5) |
| legal-3 | low | EUBAT-13-7-LABELS: reason, paraphrase, unresolved list and pack scope_statement disagree on Article 13(4) and (5) | reproduce real | confirmed | fixed (bf121c5) |
| provenance-1 | medium | integrity.jws reports the engine's own certificate-chain cap (_MAX_CHAIN = 5) as a failure of the tested system | reproduce not real; contract not real | confirmed for the reviewed code (reproduce, contract lens read the fixed branch) | fixed (128b9ea (same as adapters-8)) |
| provenance-2 | low | readiness.md and threat-model.md say each of the 17 security findings has a regression test in tests/test_review_findings.py; F-13 is tested elsewhere | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (6ec9953) |
| provenance-3 | low | The count of gaps found by the automated commit reviews cannot be traced and differs between files | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (6ec9953) |
| provenance-4 | low | TASKS.md keeps undated work logs that contradict its own milestone table and the current state | reproduce not real | confirmed for the reviewed code (reproduce lens read the fixed branch) | fixed (6ec9953) |
| provenance-5 | low | reference-system.md section 7 names fixture paths that do not exist | reproduce real | confirmed | fixed (6ec9953) |
| provenance-6 | info | cli.md exit-code 2 row lags the architecture contract after the V-07 fix | none | not verified (info) | fixed (6ec9953) |
| provenance-7 | info | import-an-approved-pack.md mode table omits placeholders from exploratory mode | none | not verified (info) | fixed (6ec9953) |

## Areas that the completeness critic named

1. Round-2 fix commits 7bbc652..b540aa9 were not examined by any reviewer (every review states HEAD bb805d0). Transport-8 fix: the credential scrub covers headers and body but not Record.redirects
2. Evidence-2 fix (7bbc652): the verifier checks the per-category coverage buckets for their totals only, and the HTML report renders them
3. Evidence-5 fix (7bbc652): _delete_recording unlinks by path through a 'records' component that can be swapped for a symlink after the content check
4. Adapters-11 fix (128b9ea) applied although the finding was refuted: the new 'candidate in path' cycle guard in trust_path excludes a self-signed anchor from being its own issuer

## Findings of the follow-up reviews

| Id | Severity | Title | Skeptic votes | Status | Handled |
| --- | --- | --- | --- | --- | --- |
| gap1-1 | high | transport-8 fix is incomplete: the engine's own bearer token lands verbatim in Record.redirects (and so in the recording) while the same value in headers and body reads <removed> | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap1-2 | medium | The engine's token echoed as a response header NAME is kept verbatim in Record.headers | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap1-3 | low | New hole opened by the fix: a short or dictionary-word token rewrites the evidence body, and a check can then blame the tested system | reproduce real | confirmed | fixed (8a23b39) |
| gap1-4 | low | Scrub is byte-exact: a percent-encoded or base64 echo of the token survives in the body, while the docs claim the value is replaced | reproduce real | confirmed | fixed (8a23b39) |
| gap1-5 | low | When one token is a prefix of another, the tail of the longer token survives the scrub | reproduce real | confirmed | fixed (8a23b39) |
| gap1-6 | low | A token that straddles the body limit leaves its head in the truncated record | reproduce real | confirmed | fixed (8a23b39) |
| gap1-7 | info | CHANGELOG and the round-2 test docstring cite a review record that does not exist in the tree | none | not verified (info) | fixed (this record) |
| gap2-1 | high | Coverage buckets verify by their sum only: a signed report upgrades review status and authority class and verifies complete | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap2-2 | medium | Negative bucket counts pass the sum check and are rendered on the page | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap2-3 | medium | implementation ratio denominator is not tied to total_requirements; the numerator has no bound other than 0 and its own denominator | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap2-4 | low | Ratio labels are not checked: a signed report can label coverage as coverage of a law and verify complete | reproduce not real | refuted | applied as hardening (8a23b39) |
| gap2-5 | low | placeholders upper bound is total, not results_placeholders + excluded, and is not cross-checked with by_review_status | reproduce real | confirmed | fixed (8a23b39) |
| gap3-1 | high | purge check and delete go back to the filesystem by path; the recording directory can change identity in between, and a fresh recording is deleted while purge reports success | reproduce real; contract real | confirmed | fixed (8a23b39) |
| gap4-1 | medium | trust_path cycle guard refuses a self-signed anchor as its own issuer: a passport signed by the anchor's key regressed from INTEGRITY.OK to a fail charged to the tested system | reproduce real; contract real | confirmed | fixed (8a23b39) |

## Decisions made while fixing

- `transport-7`: `--allow-private-host` and `--allow-remote-host` take an origin, not a host.
  This changes the command line. A bare host is refused.
- `legal-1` and `legal-2`: a draft change. All 36 entries stay `draft-needs-review`. An
  evaluation of every entry over 500 declarations showed that the 32 rewritten expressions give
  the same results, and that the three status entries changed only from `false` to `unknown`.
- `gap1-3`: a credential needs 12 characters or more. The fixture tokens have 34.

## Not reviewed

- The rest of the code outside the commit ranges above.
- The content of any EN, ISO, IEC, or DIN document. None was read.
- A real system. Every reproduction used loopback servers and in-memory fakes.

## Overall assessment

This record makes no claim that the engine is correct. The round found defects in the round-1
fixes, and the follow-up reviews found defects in the round-2 fixes. Both kinds are fixed with
regression tests in `tests/test_review_round2.py`. Round 2 is the last review round that the
project brief permits for milestones M2 and M4. A further review needs a new decision.
