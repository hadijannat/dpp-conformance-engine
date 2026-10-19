# Agent review of the key tooling and the follow-ups

Audience: maintainers, assessors, and the owner.
Purpose: record the agent reviews of the key tooling package D6-08 and of four follow-ups. For
each finding, record how it was checked and how it was handled.
Prerequisites: read `docs/explanation/architecture.md` sections 9.1, 10, 10.2, 11.2, 11.3, and
11.4, and `validation/records/review-adapters-2026-10-18.md`.

## Status

| Field | Value |
| --- | --- |
| Date | 2026-10-18 |
| Package | D6-08, operator key tooling of `docs/research/gap-assessment-2026-10-15.md`. Four follow-ups. |
| Commits reviewed | `aa7b9ce` before the rebase. `b450905` for the review of the fixes. `276b598` before the rebase for the follow-ups. |
| Fixes | On `origin/main`. See the Findings tables and "Commit identifiers". |
| Reviewers | AI agents. Designers, finders, skeptics, fixers, and the integrator are AI agents. |
| Author | A development agent wrote this record. A second development agent corrected it after a record check. |
| Nature | **An agent review. It is not an audit. No person has reviewed this record.** |

One source calls its stage a security audit. That stage is an agent review too. This record calls
it the agent security review.

The agent that wrote this record ran only these commands: `git status`, `git log`, `git show`,
`git patch-id`, `git branch --contains`, `git merge-base`, `grep`, `sed`, and `ls`. It also ran
`python3 -I` scripts that extracted the journal results and the SR message, Vale, `git commit`,
and `git commit --amend`. The second agent ran read-only `git` and shell commands, `python3 -I`
extraction scripts, Vale, `uv run just docs`, `uv run just check`, and `git commit`.
Every other result here is quoted from a source in the next section. No review status of a
catalogue entry was changed. No approval, reviewer name, or validation result is stated here that
a command did not produce.

## Sources

The sources are on the development host, in the agent session store and its scratchpad. They
are not in the repository. "J2 line 70" means line 70 of the `journal.jsonl` file of J2. Each `result` line of
a journal holds the return value of one agent.

| Name | Source | Content |
| --- | --- | --- |
| J1 | workflow `wf_af5cd92c-bc5` | Design, design review, revised design, implementation, code review, fix |
| SR | agent `a6afdb1e88d6700d8`, last message | Agent security review of `f8ac8f5..aa7b9ce` |
| J2 | workflow `wf_6649f8e9-2fd` | Adversarial review of `aa7b9ce`: contract, tests, and docs lenses |
| J3 | workflow `wf_fe4c3c1d-bf9` | Integration, fixes, review of the fixes, second fix round |
| J4 | workflow `wf_f5e9efb3-8fb` | The four follow-ups, their review, and the fix |
| MUT | `final/mutation-results.txt` in the scratchpad | Output of `mutmut results --all true` for the `uv run just mutation` run at `8b3bfff` |

## Scope

- D6-08 adds `dppce keys generate`, `dppce authorize`, `dppce trust-bundle add-key`, `dppce open`,
  and `dppce prove`. It changes `dppce sign`, `dppce run`, `dppce verify`, and
  `python -m dppce.verifier`. It adds the contracts `dppce.opening/1` and `dppce.proof/1`.
- The source files are `src/dppce/cli.py`, `src/dppce/infrastructure/keys.py`,
  `src/dppce/evidence/disclosure.py`, `jws.py`, and `recording.py`, `src/dppce/verifier/verify.py`
  and `__main__.py`, and `src/dppce/models/results.py` and `__init__.py`. The list is in J1 line 9.
- Other files are `validation/rig.py`, `compose.yaml`, the tests, and the operator pages.
- The integration rebased D6-08 onto `d012334`, which holds the adapter review fixes (J3 line 3).
- The follow-ups change `src/dppce/infrastructure/transport.py`, `src/dppce/cli.py`
  (`_confirmed_origins` refuses port 0), `src/dppce/models/testing.py`, `pyproject.toml`
  (`[tool.mutmut]`), `disclosure.py`, and `verify.py` (J4 line 3).
- They also change four generated schemas (decision, envelope, opening, and proof) and the
  protected `docs/explanation/architecture.md`, sections 9.1 and 11.4 (J4 line 3).
- No review stage in the sources covers `12f57c8` and `b7b744c`, the file mode. This record lists
  `b7b744c` as owner decision 4, and `12f57c8` only as the step before it.

## Method

1. A design agent wrote the design. A design review agent wrote findings. A second design agent
   checked each finding against `f8ac8f5` and revised the design (J1 lines 3, 5, and 7).
2. An implementer committed failing tests first, then the code (J1 line 9).
3. A code review agent wrote findings. A fixer applied them with red tests first (J1 lines 11
   and 13).
4. The agent security review read `f8ac8f5..aa7b9ce`. It reproduced each finding with a probe.
5. The adversarial review had three lenses: contract, tests, and docs (J2). Each finder wrote
   findings with a reproduction. Two skeptics per finding tried to refute it.
6. The integrator rebased the package onto `d012334` and reported overlap findings (J3 line 3).
7. A fixer applied findings of steps 4 and 5. Each code fix has a test that failed first. Each
   test-gap test failed against a mutant first (J3 line 5).
8. A security lens and a correctness lens reviewed the fixes. Two skeptics per finding tried to
   refute each finding (J3). A second fixer committed the result (J3 line 43).
9. An implementer made the four follow-ups (J4 line 3). A security lens and a contract lens
   reviewed them, with two skeptics per finding. A fixer committed the result (J4 line 25).

The words for an outcome:

- **confirmed**: neither skeptic refuted the finding.
- **split**: one of two skeptics refuted the finding.
- **refuted**: both skeptics refuted the finding.
- **applied** or **reproduced**: the stage had no skeptic. Steps 1 to 4 and step 6 had none.

The adversarial review ran twice in part. The first contract skeptics and the first tests finder
ended as "failed" (J2 lines 30 and 32 to 43). The resumed workflow ran them again. It also ran
the docs finder again (J2 line 70). The docs lens therefore has two runs. Their DOC-1 and DOC-3
name the same defects. Their DOC-2 differ.

Four agents made an edit with a script, not with the Edit tool. Each one reported it: J1 lines 9
and 13, and J4 lines 3 and 25. The edits are in the commits.

## Summary

Some findings in different stages name one defect. The "Overlaps" paragraph names them. Do not
add the counts of the stages.

| Stage | Source | Findings | Outcome | Fixed | Not fixed |
| --- | --- | --- | --- | --- | --- |
| Design review | J1 line 5 | 8 | applied: 8 (J1 line 7) | 8, in the design | 0 |
| Code review | J1 line 11 | 3 | applied: 3 (J1 line 13) | 3 | 0 |
| Agent security review | SR | 3 findings and 7 notes | reproduced | 3 findings, 2 notes | 5 notes |
| Adversarial review | J2 | 15 distinct | confirmed: 14, refuted: 1 | 13 | 2 |
| Integration | J3 line 3 | 4 | no skeptic | 2, and 1 in part | 1 in part, 1 not a defect |
| Review of the fixes | J3 lines 8 and 21 | 8 | confirmed: 7, split: 1 | 8 | 0 |
| Review of the follow-ups | J4 lines 6 and 9 | 4 | confirmed: 3, split: 1 | 4 | 0 |

The 15 findings of the adversarial review are 6 of the contract lens, 5 of the tests lens, and 4
of the docs lens. The docs lens count is distinct over its two runs. Of the 2 not fixed, one is
confirmed and open (docs1-DOC-2), and one is refuted (contract-F6).

The 8 findings of the review of the fixes are 3 of the security lens and 5 of the correctness
lens. The 4 findings of the review of the follow-ups are 1 of the security lens and 3 of the
contract lens.

**Overlaps.** SR-F3 and contract-F5 are one defect. The J3 fixer list does not name contract-F5,
but the S3 guard in `a2352dc` covers it. SR-N3 is part of contract-F1. fixrev-SEC-1
and fixrev-R2 are one defect, fixrev-SEC-2 and fixrev-R1 are one, and fixrev-SEC-3 and
fixrev-R3 are one.

## Findings

The identifiers in the sources repeat across stages. This record adds a prefix for the stage.
The fixer labels S1 to S3, C1 to C4, T1 to T5, and D1 to D3 come from J3 line 5 and the commit
messages. Each fix commit is on `origin/main`.

### Design review (J1)

The design review findings have no identifier in J1. This record numbers them in J1 order.

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| DR-1 | should_fix | State the real key file parameters; raise the passphrase minimum to 32 bytes | applied | design, `0403e5f..38934da` |
| DR-2 | should_fix | `authorize` signs a coerced value | applied | design, `0403e5f..38934da` |
| DR-3 | should_fix | `add-key` writes a time that does not exist | applied | design, `0403e5f..38934da` |
| DR-4 | should_fix | A proof passes when the root of its tree fails | applied | design, `0403e5f..38934da` |
| DR-5 | should_fix | `sign --in-place` loses the mode and replaces a link | applied | design, `0403e5f..38934da` |
| DR-6 | should_fix | The design removes the ADR 0008 sentence | applied | design, `0403e5f..38934da` |
| DR-7 | should_fix | The rig cannot run the negative data key test | applied | design, `0403e5f..38934da` |
| DR-8 | should_fix | A `migrations.py` change with no behavior | applied | design, `0403e5f..38934da` |

### Code review (J1)

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| CR-1 | should_fix | `add-key` accepts an unpadded time with no reason code | applied | `98c7d64` |
| CR-2 | should_fix | `authorize` signs an unpadded time | applied | `98c7d64` |
| CR-3 | should_fix | Pages assume that `sign` writes in place | applied | `98c7d64` |

`f73dd3b` later replaced the time helper of CR-1 and CR-2 with `parse_stamp` (INT-2).

### Agent security review (SR)

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| SR-F1 | should_fix | A failed write leaves a partial file; `open` warns after the write | reproduced, fixed as S1 | `a2352dc` |
| SR-F2 | should_fix | A passphrase byte and its position appear on stderr, exit 3 | reproduced, fixed as S2 | `a2352dc` |
| SR-F3 | should_fix, low | `authorize` accepts a query, a fragment, or userinfo | reproduced, fixed as S3 | `a2352dc` |
| SR-N1 | note | Reading a key accepts any passphrase length and the old PEM encryption | owner decision 2, not changed | none |
| SR-N2 | note | Loose JWK parsing in `add-key` | not changed | none |
| SR-N3 | note | A duplicate JSON key gives no reason code | fixed with contract-F1 | `03a61d8` |
| SR-N4 | note | A proof can pass when `ordering` fails | owner decision 3 | `5fe675d` |
| SR-N5 | note | A case-insensitive file system gives `SIGN.OUTPUT.EXISTS` | not changed | none |
| SR-N6 | note | A link swap race in `sign --in-place`, by inspection only | not reproduced, not changed | none |
| SR-N7 | note | The salt string is malleable | not changed | none |

SR states that SR-N2 and SR-N7 give no false outcome. The bundle stores the canonical key. The
commitment binds the decoded salt bytes. SR-N5 is safe, because `O_EXCL` refuses the write.

### Adversarial review (J2)

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| contract-F1 | should_fix | `sign`, `prove`, and `open` give no reason code for JSON that is not strict | confirmed, fixed as C1 | `03a61d8` |
| contract-F2 | should_fix | A private JWK with a non-string member gives `TRUST.KEY.NOT_P256` | confirmed, fixed as C2 | `03a61d8` |
| contract-F3 | note | A key file that cannot be read gives no reason code | confirmed, fixed as C3 | `03a61d8` |
| contract-F4 | note | A data key id that is not valid gives no reason code | confirmed, fixed as C4 | `03a61d8` |
| contract-F5 | note | `authorize` accepts endpoints that are not origins | confirmed, fixed with S3 | `a2352dc` |
| contract-F6 | note | Reformatted proof and opening bytes pass | refuted | none |
| tests-TI-1 | should_fix | No test for the key rules of `authorize` | confirmed, fixed as T1 | `ee01901` |
| tests-TI-2 | should_fix | No test for an unusable data key | confirmed, fixed as T2 | `ee01901` |
| tests-TI-3 | should_fix | No test for a consistent forgery of an opening | confirmed, fixed as T3 | `ee01901` |
| tests-TI-4 | note | No test shows that a proof waits only for the root of its own tree | confirmed, fixed as T4 | `ee01901` |
| tests-TI-5 | note | The verdict case accepts a code that never occurs | confirmed, fixed as T5 | `ee01901` |
| docs-DOC-1 | note | The proof example key is not in the tutorial report | confirmed, fixed as D1 | `b450905` |
| docs-DOC-2 | note | The verify page calls the unsigned file the report | confirmed, fixed as D2 | `b450905` |
| docs-DOC-3 | note | The tutorial omits `validity` from the `not_checked` list | confirmed, fixed as D3 | `b450905` |
| docs1-DOC-2 | note | The standalone verifier paragraph omits the new options | confirmed, not fixed | none |

The docs- rows are the second docs run (J2 lines 70 and 77 to 82). The first run found DOC-1 and
DOC-3 too (J2 lines 5 and 12 to 17). Its DOC-2 is the docs1-DOC-2 row. That finding did not reach
the fixer.

### Integration (J3 line 3)

The integrator gave no severity.

| Id | Subject | Outcome | Fix commit |
| --- | --- | --- | --- |
| INT-1 | After the `Stamp` change, a bad period gave `AUTHORIZE.DOCUMENT.INVALID` | fixed | `f73dd3b` |
| INT-2 | `_exact_time` repeated the check of `parse_stamp` | removed | `f73dd3b` |
| INT-3 | The task text was wrong about the files that D8-05 changed | not a defect | none |
| INT-4 | `OpenedRecord.acquired_at` is a plain `str`; `Observation.acquired_at` uses `\d` | fixed in part | `7077837` |

### Review of the fixes (J3)

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| fixrev-SEC-1 | should_fix | A failed write of a new data key leaves a partial key | confirmed | `5f22f66` |
| fixrev-SEC-2 | should_fix | An origin with a tab, a line feed, or an edge control passes | confirmed | `5f22f66` |
| fixrev-SEC-3 | note | The origin refusal echoes a URL password | split | `5f22f66`, as fixrev-R3 |
| fixrev-R1 | should_fix | The same defect as fixrev-SEC-2 | confirmed | `5f22f66` |
| fixrev-R2 | should_fix | The same defect as fixrev-SEC-1 | confirmed | `5f22f66` |
| fixrev-R3 | note | The same defect as fixrev-SEC-3 | confirmed | `5f22f66` |
| fixrev-R4 | note | The data key message advises the flag that just failed | confirmed | `5f22f66` |
| fixrev-R5 | note | `origin_of` reads an explicit port 0 as the default port | confirmed, owner decision 3 | `83a08a4` |

### Review of the follow-ups (J4)

| Id | Severity | Subject | Outcome | Fix commit |
| --- | --- | --- | --- | --- |
| fu-SEC-N1 | note | No test kills mutant `x_validate_authorization__mutmut_18` | confirmed | `2311513` |
| fu-F1 | should_fix | Two how-to pages give only the root as the reason for `not_checked` | confirmed | `2311513` |
| fu-F2 | note | No test for the order of the root, ordering, and malformed-file rules | confirmed | `2311513` |
| fu-F3 | note | The section 9.1 sentence on the default port is not exact | split | `8b3bfff` |

## Refuted and split findings

- **contract-F6, refuted (J2 lines 68 and 69).** The opening and proof checks accept reformatted
  bytes. The finding read "exact canonical form" in step 2 as JCS bytes. Both skeptics showed
  that the contract uses the phrase for value-level exactness, as `is_exact` checks it. A byte
  reading would also refuse the files that `prove` and `open` write, which end with a line feed.
  The code was not changed. One skeptic notes a wording point: "canonical form" alone means JCS
  bytes in other sentences.
- **fixrev-SEC-3, split (J3 lines 15 and 19).** One skeptic refuted it: section 11.3 bans the
  print of a passphrase or a private key only. The other skeptic confirmed it as a note. Its
  twin fixrev-R3 is confirmed. `5f22f66` removed the value from the message.
- **fu-F3, split (J4 lines 18 and 19).** One skeptic refuted it: the sentence is true for the
  normal form. The other skeptic found it ambiguous: it does not fix the port 0 rule. The J4
  fixer applied only the three confirmed findings. `8b3bfff` rewrote the sentence, as `git log`
  shows.

## Owner decisions of 2026-10-18

The owner gave these decisions in the agent session on 2026-10-18. Earlier owner decisions of
2026-10-18 are in `state/progress.json`, milestone M7.

1. **D8-05 adapter review.** It may land. First, a check must refuse a stamp of a moment that
   does not exist. `dae6117` adds that check. The owner accepts the recorded defaults:
   - A 404 on the version history gives `blocked`.
   - A future update time fails, with no clock-skew tolerance.
   - A leap second fails the declared rule.
   - JSON Schema `pattern` uses Python `re`.
   - A credential echoed in base64 or in a mix of forms is not removed.

   `validation/records/review-adapters-2026-10-18.md` gives the detail.
2. **D6-08 key tooling.** It may land. The owner accepts the key defaults:
   - The shipped TEST-ONLY report key stays unencrypted. The tutorial, the README, and the rig
     pass `--allow-unencrypted-key`.
   - Key files use the fixed PKCS#8 parameters of the installed `cryptography` package:
     PBKDF2-HMAC-SHA256, 2048 iterations, and AES-256-CBC. A generated 32-byte passphrase
     compensates.
   - `sign` without `--out` or `--in-place` gives the argparse usage error, exit 2, with no
     reason code.
   - The 32-byte rule applies to `keys generate` only. Reading still accepts shorter passphrases
     and the traditional OpenSSL encrypted PEM. This closes SR-N1.
3. **Follow-ups to do and land.**
   - An explicit port 0 is never the default port, and the origin options refuse it: `83a08a4`.
     This closes fixrev-R5.
   - `Observation.acquired_at` uses the shared `Stamp` type: `7077837`. This closes INT-4 in
     part.
   - The mutmut configuration deselects the reason-code page test: `1019a8d`.
   - A proof or an opening is `not_checked` when ordering fails: `5fe675d`. This closes SR-N4.
4. **File mode.** New output files of `sign --out`, `authorize`, `trust-bundle add-key`, and
   `prove` have mode 0600: `b7b744c`. Before it, `12f57c8` set 0644, as its message states.

Not an owner decision: the coordinating agent landed W6-mut2 as the merge commit `dfd03b1`. The
merge keeps on a branch the hashes that the mutation record cites.

## Commit identifiers

The sources name some commits before a rebase. The first row maps as J3 line 3 states. For each
other row, `git patch-id --stable` gave the same patch identifier for both commits in this run.

| Source | Before the rebase | On `origin/main` |
| --- | --- | --- |
| J1 line 9, J3 line 3 | `1866480`, `dd3ff62`, `4d1b8ae`, `9526908`, `ff7b769`, `1c99c8c` | `0403e5f`, `f5f5cd6`, `5468c3b`, `61215c3`, `05747b5`, `38934da` |
| J1 line 13 | `aa7b9ce` | `98c7d64` |
| J4 line 3 | `ec3c888` | `83a08a4` |
| J4 line 3 | `b07ca67` | `7077837` |
| J4 line 3 | `6d1a500` | `1019a8d` |
| J4 line 3 | `276b598` | `5fe675d` |
| J4 line 25 | `83194a3` | `2311513` |

The commits of J3 (`f73dd3b`, `a2352dc`, `03a61d8`, `ee01901`, `b450905`, and `5f22f66`) have
the same identifiers on `origin/main`.

## Open items

- **docs1-DOC-2.** The standalone verifier paragraph names only
  `ENVELOPE --trust BUNDLE --at TIME`. It omits `--status-list`, `--opening`, and `--proof`. A
  `grep` in this run finds the text at `scripts/gen_reference_docs.py` line 88 and
  `docs/reference/cli.md` line 467.
- **INT-4, the rest.** `OpenedRecord.acquired_at` (`src/dppce/models/results.py` line 328) and
  `Record.acquired_at` (`src/dppce/infrastructure/interfaces.py` line 60) are plain `str`. Both
  files are protected. The J4 contract reviewer states that the commitment binds the value.
- **`not_checked` after `structure`.** An opening or a proof is also `not_checked` when
  `structure` fails. The how-to lines of fu-F1 do not say so. The J4 fixer asks the owner
  (J4 line 25).
- **Release how-to.** `docs/how-to/install-and-verify-a-release.md` does not state the changes
  of `sign` and `run` (J1 line 9). `git log` shows no change to it after `f8ac8f5`.
- **Other `\d` patterns.** `evaluation_time` in `models/results.py`, the `date` field of
  `models/catalogue.py`, and `_ISO_DATE` without `re.ASCII` are not changed (J4 line 3).
- **Tokens issued before `a2352dc`.** A token that names userinfo still authorizes the reduced
  origin (J3 line 5). The J3 security reviewer did not reproduce it end to end (J3 line 8).
- **SR-N2, SR-N5, SR-N6, and SR-N7.** These notes are not changed. The coordinating agent told
  the J3 fixer to leave SR-N2 and SR-N7. The owner decisions above do not name them.
- **Mutation run.** The J4 fixer did not run `uv run just mutation` (J4 line 25). The later run
  at `8b3bfff` lists `x_validate_authorization__mutmut_18` as killed (MUT line 5634). Its logs
  are on the development host only. No record in `validation/records/` describes that run.
- **Probe files.** Agent probes left TEST-ONLY keys in the system temporary directory of the
  development host (SR, and J2 line 18). An `ls` in this run still finds four such directories.
- **Scope of SR.** SR did not review the `cmd_run` changes, `validation/rig.py`, `compose.yaml`,
  or the pages. The contract and docs lenses cover parts of them.
- **File mode.** No agent review in the sources covers `12f57c8` and `b7b744c`.

Closed items: the design open point on `TrustedKey` times (J1 line 7) is closed. `dae6117` made
`TrustedKey.not_before` and `not_after` the `Stamp` type.
