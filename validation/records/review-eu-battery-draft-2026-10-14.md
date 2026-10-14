# Agent review of the draft pack `eu-battery/draft`

Audience: the human reviewer who will decide on each draft interpretation, and the maintainers of the catalogue.
Purpose: record an independent agent review of the 36 draft interpretations of Regulation (EU) 2023/1542, their test purposes, the 8 EN placeholders, the related source records, and the scope page.
Prerequisites: read `CLAUDE.md` (hard rules 5 and 6), `docs/explanation/architecture.md` sections 4 to 7, and `catalogue/templates/interpretation-review.md`.

## Status

| Field | Value |
| --- | --- |
| Reviewer | An AI model: `claude-fable-5-1` (Claude Fable 5.1), run as a subagent |
| Review date | 2026-10-14 |
| Commit reviewed | `200e65202a943cd2f82a7edc9278bfbcee90c07a` (HEAD at the start of the review) |
| Later commit | `ae33dcc5649eaab955d9cfa5f1039d6451d387d7` was made by a different task during this review. `git diff 200e652 ae33dcc` touches none of the reviewed files. It changes `docs/explanation/architecture.md` section 4 (illustrative requirements in reviewed mode, placeholders with tests). That change does not affect a conclusion below. |
| Kind of review | **This is an agent review. It is not a human approval. No review status was changed.** Every entry stays `draft-needs-review`. The 8 placeholders stay `placeholder`. This record proposes no approval and must not be copied into an `approval` field. |
| Files written | This file only. |
| Legal statements | This record makes no statement of legal compliance. It compares a draft with a legal text. A human must decide. |

## 1. Scope

Reviewed:

- `catalogue/packs/eu-battery-draft.yaml`: 36 requirements (`EUBAT-*`), all `legal_obligation`, all `mandatory`, all `draft-needs-review`.
- `testpacks/eu-battery-draft.yaml`: 41 test purposes (5 automated, 36 manual).
- `catalogue/packs/en-jtc24-placeholders.yaml`: 8 placeholders.
- `catalogue/sources.yaml`: the records `reg-eu-2023-1542`, `reg-eu-2025-1561`, `reg-eu-2026-1738`, `reg-eu-2024-1781`, `impl-reg-eu-2026-1778`, `impl-dec-eu-2026-1736`, `impl-dec-eu-2026-2048`, `batteries-art-77-9-implementing-act`, `draft-impl-reg-labelling-art-13-10`, `draft-del-reg-carbon-footprint-ev-art-7-1`, `draft-del-reg-recycled-content-art-8-1`, `ec-guidance-battery-passport-data-points`, `ec-faq-dpp-batteries`, and the eight `en-18xxx-2026` records.
- `docs/explanation/scope-and-legal-mapping.md`.

Compared with: `docs/research/raw/batteries-regulation.json`, `batteries-regulation.refutation.json`, `espr.json`, `commission-2026-acts.json`, `commission-2026-acts.refutation.json`, and the official text at EUR-Lex (section 2).

Not in scope: the content of any EN, ISO, IEC, or DIN document. No standard was fetched, quoted, or summarized.

## 2. Method

### 2.1 Provisions read at the official location on 2026-10-14

Source: `https://eur-lex.europa.eu/eli/reg/2023/1542/2026-08-13/eng` (EUR-Lex, consolidated version). The page returned content. Its text is 378 017 characters. It was read through a summarizing fetch tool in four windows (offsets 0, 100 000, 200 000, 300 000). The tool returns exact fragments of at most about 120 characters. No provision was compared character by character. The fragments were enough to settle each point below.

| Provision | Window | What was confirmed |
| --- | --- | --- |
| Header and front matter | 0 | `02023R1542 - EN - 13.08.2026 - 003.001`; M1 2024/1781, M2 2025/1561, M3 2026/1738; C1 to C4 as the source record lists them. |
| Art. 1(5), 1(6) | 0 | Military, war material, and space equipment excluded; nuclear-safety equipment excluded from Chapters III and IX. |
| Art. 3(1), points (11), (13), (14) | 0 | LMT: sealed, 25 kg or less, traction of wheeled vehicles, not an EV battery. Industrial: designed for industrial use, or any other battery above 5 kg that is not EV, LMT, or SLI. EV: traction battery of category L above 25 kg, or of categories M, N, O. No capacity threshold in any definition. |
| Art. 3(1), points (16), (17), (18) | 0 | Placing on the market is the first making available on the Union market. Putting into service is the first use in the Union of a battery that was not placed on the market before. |
| Art. 7(1), 7(5), 8(1), 8(4), 10(1), 14(1) | 0 | Categories and date formulas as the research file records them. Art. 8(1) second subparagraph gives 18 August 2033 for LMT batteries. |
| Art. 13(4), 13(6), 13(7), 13(9) | 0 | 13(6): date, points (a), (b), (c); the sentence on complete, up-to-date, accurate information is a separate closing sentence after point (c). 13(7) subject: the labels and the QR code of paragraphs 1 to 6. 13(4) uses "marked". |
| Art. 45, 47, 48(1), 52(3), 57(1), 57(8) | 100 000 | As the research file records them. 48(1) carries the M2 date 18 August 2027. |
| Art. 77(1) to (10) | 200 000 | All ten paragraphs. 77(5) and 77(6) are separate paragraphs. Both end with a reference to Article 78. 77(10) carries the C2 marker and names Regulation (EU) 2024/1781. |
| Art. 78, points (a) to (h) | 200 000 | All eight points. Point (b) names Annex XIII and the Article 77(9) implementing act. |
| Annex VI, Part C; Annex VII heading | 300 000 | Part C: high contrast, size readable by a commonly available reader; no symbology standard, no numeric limit. |
| Annex XIII, headings 1 to 4 | 300 000 | 1: public, model. 2: persons with a legitimate interest and the Commission, model. 3: notified bodies, market surveillance authorities, Commission. 4: persons with a legitimate interest, individual battery. |
| Annex XIII, items 1(c), (d), (e), (k), (q), (r), (s); 2(a) to (d); 3; 4(a) to (d) | 300 000 | As cited. 1(k) is limited to electric vehicle batteries. 1(q) names Article 13(4) and (5) with the C4 marker. Point 1 ends at (s); no item (t). 4(c) lists five status values. |
| Undated ELI `https://eur-lex.europa.eu/eli/reg/2023/1542/eng` | header | Same header `13.08.2026 - 003.001` on 2026-10-14. No later consolidation. |

No page held text addressed to an AI or an agent.

### 2.2 Not read at an official location today

- Art. 38(1) (manufacturer duty to mark and label when placing on the market or putting into service). The fetch tool mentioned it in paraphrase from the official page. No exact fragment was obtained.
- Annex VI, Part A; Art. 18; Art. 74(1); Art. 96; Art. 89.
- The Official Journal texts of corrigenda C1 to C4, of Regulations (EU) 2025/1561 and 2026/1738, of Implementing Regulation (EU) 2026/1778, and of Implementing Decisions (EU) 2026/1736 and 2026/2048. The source records for these rest on the research files.
- The Commission guidance version 2.0 and the Commission FAQ.
- No search for acts adopted after 2026-10-13 was made. The `legal_as_of` date of the pack was not re-validated beyond the header check above.

### 2.3 Commands

| Command | Result |
| --- | --- |
| `git rev-parse HEAD` | `200e652…` at the start, `ae33dcc…` at the end (see Status). |
| `git diff --stat 200e652 ae33dcc -- catalogue testpacks docs/research docs/explanation/scope-and-legal-mapping.md profiles fixtures/reference src/dppce/applicability.py src/dppce/models/expr.py` | Empty. The reviewed inputs did not change. |
| `uv run python <scratchpad script>` that loads the pack and evaluates eight ICS variants with `dppce.applicability.evaluate` | Exit 0. Read-only. Results in section 5. The script ran against the working tree, where a different task had uncommitted edits in `src/`; `applicability.py` and `expr.py` were unchanged. |
| `uv run python <scratchpad script>` that appends the clause of F-01 to each of the 35 affected expressions in memory and evaluates cases (a), (b), (d), (g), (x), (y) before and after | Exit 0. Read-only; the pack file was not changed. 35 entries patched. The wrong `true` of case (x) is observable in 26 entries with an EV declaration; `EUBAT-13-6B` shows it with a non-passport battery; 8 entries are masked by a sibling `const: unknown`. Results in F-01. |
| `python3 -I` scripts over the YAML (counts, pattern classification, test-purpose cross-reference) | Exit 0. 36 requirements, 41 test purposes, 8 placeholders. Every test purpose names only requirements that name it back. |
| `uv run ruff`, `uv run mypy`, `uv run pytest`, `uv run just check`, `dppce catalogue lint` | Not run. A different task was editing `src/` and `tests/`. |

## 3. Findings table

| Id | Requirement | Severity | Kind | Checked at official source |
| --- | --- | --- | --- | --- |
| F-01 | EUBAT-77-1 and 34 others (section 4.1) | high | applicability | yes |
| F-02 | EUBAT-77-1 and 34 others | medium | applicability | yes |
| F-03 | EUBAT-77-5 | medium | paraphrase | yes |
| F-04 | EUBAT-77-2-ACCESS | medium | paraphrase | yes |
| F-05 | EUBAT-77-2-ACCESS, EUBAT-78-B, EUBAT-78-F | medium | unresolved_missing | yes |
| F-06 | EUBAT-13-6A, EUBAT-13-6B | low | citation | yes |
| F-07 | EUBAT-77-7B | low | modality | yes |
| F-08 | EUBAT-AXIII-1E | low | applicability | yes |
| F-09 | EUBAT-13-7-LABELS | low | applicability | yes |
| F-10 | 27 of the 35 affected entries lack the recurring notes | low | unresolved_missing | no |
| F-11 | EUBAT-13-6, 13-6A, 13-6B, 13-7-QR | low | unresolved_missing | partly |
| F-12 | reg-eu-2026-1738 (source record) | low | source_record | no |
| F-13 | All 36 | info | assessment_path | no |
| F-14 | All entries that read `ics.product_category` | info | applicability | yes |
| F-15 | EUBAT-77-1 | info | applicability | yes |
| F-16 | EUBAT-13-6A, 13-6B, 77-5, 77-6 | info | unresolved_missing | yes |
| F-17 | reg-eu-2023-1542 (source record) | info | source_record | yes |

No finding of kind `protected_standard`, `authority_class`, or `legal_mapping` was made. See section 6.

## 4. Findings

### F-01 (high). The date clause gives `true` for a battery placed on the market before 2027-02-18

Affected: every entry whose applicability holds the clause `any: [placed_on_market_date ge 2027-02-18, put_into_service_date ge 2027-02-18]`. That is 35 of 36 entries: all except `EUBAT-13-7-LABELS`. The 32 entries with the category gate and the 3 date-only entries (`EUBAT-13-6`, `EUBAT-13-7-QR`, `EUBAT-AXIII-1K`).

Problem. A declaration with `placed_on_market_date: '2026-12-01'` and `put_into_service_date: '2027-03-01'` gives `true`. Eight entries say so in their `unresolved` list and add that the expression language cannot state the limit of Article 3(1), point (18). Both statements need correction.

Where the wrong `true` is observable today: in 27 of the 35 entries. In 26 of them an EV declaration shows it; in `EUBAT-13-6B` an industrial battery of 2 kWh or less shows it. In the other 8 entries (`EUBAT-77-7A`, `77-7B`, `77-8`, `78-B`, `78-F`, `AXIII-1C`, `AXIII-1D`, `AXIII-1E`) a sibling `const: unknown` sits in the same outer `all`, so `unknown` is the ceiling and the wrong `true` cannot surface. The fix still belongs in all 35: `false` beats `unknown`, so with the fix the 8 masked entries give `not_applicable` instead of `inconclusive` for case (b), and the mask disappears on the day the dependency act is adopted.

Evidence. Article 3(1), point (18), read today: putting into service is the first use of a battery that was not placed on the market before. Article 3(1), point (16): placing on the market is the first making available. For one battery the two events exclude each other. A battery placed on the market on 2026-12-01 has no putting-into-service event in the legal sense. Its only trigger is before 2027-02-18. Under the trigger reading that the draft adopts, Article 77(1) does not reach it. The expression says it does. The profile agrees with the law: `profiles/battery/ev.yaml` defines `put_into_service_date` as the first use if the battery was not placed on the market before.

The expression language can state the limit. `Compare` accepts `lt` on two ISO dates (`dppce.applicability._ordered`), and `Not` exists.

Proposed correction (for each of the 32 entries with the category gate; add the third branch to the outer `all`):

```yaml
applicability:
  all:
  - any:
    - fact: ics.product_category
      op: in
      value: [lmt, ev]
    - all:
      - fact: ics.product_category
        op: eq
        value: industrial
      - fact: ics.characteristics.capacity_wh
        op: gt
        value: 2000
  - any:
    - fact: ics.characteristics.placed_on_market_date
      op: ge
      value: '2027-02-18'
    - fact: ics.characteristics.put_into_service_date
      op: ge
      value: '2027-02-18'
  - not:
      fact: ics.characteristics.placed_on_market_date
      op: lt
      value: '2027-02-18'
```

For the three date-only entries, wrap the existing `any` and the new `not` in an `all`.

Run through the repository evaluator (section 2.3, second script), the corrected clause gives for `EUBAT-77-1`: (a) `true`, (b) `false`, (d) `false`, (g) `false`, (x) `false`, (y) `unknown`. For `EUBAT-13-6` and `EUBAT-AXIII-1K` the same. For the masked entry `EUBAT-78-B`: (a) `unknown`, (b) `false`, (x) `false`, (y) `unknown`. The mechanism: placed 2026-12-01 gives `not(true)` = `false`, and `false` wins in `all`.

Trade-off that a human must accept or reject: a declaration with `placed_on_market_date: unknown` and `put_into_service_date: '2027-03-01'` (own use, no placing on the market) goes from `true` to `unknown`, because `not(unknown)` is `unknown`. The language has no value that means "never placed on the market". A contract change could close that gap: a boolean profile fact such as `placed_on_market: false`, read with `eq`. That is a change to `profiles/battery/*.yaml` and the ICS fixtures. It is reported here, not applied.

Replace the unresolved point in the eight entries with the text of the trade-off above.

### F-02 (medium). Case (b) gives `unknown` where the definitions give `false`

Affected: the same 35 entries.

Problem. An EV battery placed on the market on 2026-12-01 with `put_into_service_date: unknown` evaluates to `unknown` (`any(false, unknown)`). The engine then reports `inconclusive` instead of `not_applicable`. This is the normal shape of a declaration: the reference fixture `fixtures/reference/ev.ics.yaml` declares `put_into_service_date: unknown`.

Reasoning from the definitions. Once `placed_on_market_date` holds a date, Article 3(1), point (18), rules out a later putting into service of that battery. The value `unknown` for `put_into_service_date` is then not missing information. It is a fact that cannot have a value. The law gives a clear answer for case (b): no trigger on or after 2027-02-18, so the passport duty of Article 77(1) does not apply. The expression should give `false`.

Proposed correction: the YAML of F-01. With it, case (b) gives `false`: `not(2026-12-01 lt 2027-02-18)` = `not(true)` = `false`, and `false` wins in `all`.

Residual question for the human reviewer (already in `EUBAT-77-1` unresolved): a battery placed before 2027-02-18 that is remanufactured and placed on the market again after that date. The second placing is a placing of that battery. The declaration should then carry the second date. The expression reads what is declared.

### F-03 (medium). `EUBAT-77-5` drops the reference to Article 78

Problem. The paraphrase ends with "machine-readable, structured, and searchable". Article 77(5), read today, ends that list with a clause that ties it to the essential requirements of Article 78. The paraphrase drops that condition.

Evidence. Fragments of Article 77(5) at window 200 000: open standards and interoperable format; transferable through an open interoperable data exchange network without vendor lock-in; machine-readable, structured and searchable, in accordance with the essential requirements of Article 78.

Proposed correction:

```yaml
paraphrase: All information in the battery passport is based on open standards, has an interoperable format,
  can be transferred through an open interoperable data exchange network without vendor lock-in, and is
  machine-readable, structured, and searchable, in line with the essential requirements of Article 78.
```

Also remove, in `EUBAT-77-5` and `EUBAT-77-6`, the unresolved point that the split of paragraphs 5 and 6 must be confirmed. It is confirmed: they are two paragraphs, and each names Article 78. Keep the point that the wording was not compared character by character.

### F-04 (medium). `EUBAT-77-2-ACCESS` drops the word that makes the restriction

Problem. The paraphrase says that notified bodies, market surveillance authorities, and the Commission "get" points 2 and 3, and that persons with a legitimate interest "get" points 2 and 4. Article 77(2), points (b) and (c), read today, make the information accessible **only** to those groups. The exclusivity is the obligation that the automated step `TP-EU-ACCESS-ANON` observes. The paraphrase does not state it.

Proposed correction:

```yaml
paraphrase: The general public gets the information of Annex XIII point 1. Points 2 and 3 are accessible
  only to notified bodies, market surveillance authorities, and the Commission. Points 2 and 4 are accessible
  only to natural or legal persons with a legitimate interest, for the purposes that the paragraph names.
```

### F-05 (medium). The Article 77(9) dependency is handled in two different ways

Problem. `EUBAT-78-B` and `EUBAT-78-F` carry `const: unknown` because the access rights depend on the Article 77(9) implementing act. `EUBAT-77-2-ACCESS` names the same dependency in `unresolved` but carries no `unknown` clause, and its paraphrase includes the legitimate-interest group. Its manual step asks the reviewer to compare the declared policy with "the three groups". For group (c) that comparison cannot be made before the act exists.

Both readings are defensible. The public boundary of Article 77(2), point (a), and the exclusivity of points (b) and (c) follow from the Regulation alone. Who is a person with a legitimate interest does not. The draft must say which part of the entry it assesses now.

Proposed correction (one of two; a human chooses). Either narrow the entry:

```yaml
title: The public gets Annex XIII point 1 and nothing from points 2 to 4
# paraphrase as in F-04, plus one sentence in the interpretation text:
# "This entry assesses the public boundary only. Which persons have a legitimate interest, and what they may
#  receive, is assessed under EUBAT-78-B and EUBAT-78-F and stays unknown until the Article 77(9) act exists."
```

Or add to the outer `all` of `EUBAT-77-2-ACCESS` the same clause as in `EUBAT-78-B`:

```yaml
  - const: unknown
    reason: The access rights of persons with a legitimate interest depend on the Article 77(9) implementing
      act. No adopted act was located as of 2026-10-13.
```

The first option keeps a testable public boundary. The second makes the entry inconclusive for every system.

### F-06 (low). `EUBAT-13-6A` and `EUBAT-13-6B` cite one point but paraphrase the closing sentence too

Problem. Both citations read `Art. 13(6), point (a)` or `point (b)`. Both paraphrases end with the duty that the information is complete, up to date, and accurate. That duty is a separate closing sentence of paragraph 6, after point (c) (read today). The citation is less precise than the content.

Proposed correction:

```yaml
citation: Art. 13(6), point (a) and closing sentence
```

and the same for point (b). Update the pack `scope_statement` to name the closing sentence.

### F-07 (low). `EUBAT-77-7B` states a legal effect, not a duty of the tested system

Problem. The entry paraphrases the second sentence of Article 77(7): when a battery becomes waste, responsibility for the Article 77(4) obligations passes to the producer, the producer responsibility organization, or the waste management operator. That is a transfer of responsibility. The duty that results is the Article 77(4) duty, already in `EUBAT-77-4`. The modality `mandatory` is defensible only if the entry is read as "the new responsible party holds the Article 77(4) duty". The interpretation text says that a passport system can show the transfer only if it records the responsible party. Nothing in Article 77(7) requires the passport to record that.

Proposed correction: state the reading in the interpretation text, or merge the entry into `EUBAT-77-4` as a second sentence of the paraphrase. If the entry stays, consider `testability: not_testable` for the passport system, with the manual step limited to organizational evidence. Whether the loader accepts `not_testable` together with a named test on a draft entry was not checked (commit `ae33dcc` tightened the loader for placeholders).

The same observation applies to `EUBAT-77-8` (the passport ceases after recycling; no obligated party). The draft already lists that as unresolved. No separate finding.

### F-08 (low). `EUBAT-AXIII-1E` says that no start date is fixed; for LMT batteries one is

Problem. The `reason` text says the start follows Article 8(1) and that no start date is fixed. Article 8(1), second subparagraph, read today, applies the first subparagraph to LMT batteries from 18 August 2033. That date is in the text. Under the trigger reading of the draft, an LMT battery with a trigger date before 2033-08-18 is outside Article 8(1), and the item is not applicable to it. The expression gives `unknown` for every LMT battery.

Proposed correction (reason text; the expression is for the human reviewer):

```yaml
reason: 'The start follows Article 8(1): for industrial and electric vehicle batteries the later of
  2028-08-18 and 24 months after the entry into force of a delegated act, which was not located as adopted
  as of 2026-10-13; for LMT batteries 2033-08-18, fixed in the text. Whether the item attaches by the trigger
  date of the battery is not settled. No date before 2028-08-18 is possible.'
```

### F-09 (low). `EUBAT-13-7-LABELS` gives `unknown` for a marking whose date is fixed

Problem. Article 13(7), read today, covers the labels and the QR code of paragraphs 1 to 6. Paragraph 4 (separate-collection symbol) applies from 18 August 2025 to all batteries. Paragraph 4 says "marked", not "label"; whether the symbol counts as a label under paragraph 7 is itself a reading. If it does, the entry folds a marking whose date is fixed and has passed into `const: unknown` with the labels of paragraphs 1 to 3.

Proposed correction: split the entry, or state in the reason that the `unknown` covers paragraphs 1 to 3 only and that paragraph 4 is outside the scope of the pack. Labels are not part of the data carrier, so the second option costs nothing.

### F-10 (low). Two recurring unresolved points appear in a few entries only

Problem. The put-into-service point (F-01) appears in 8 entries. The exclusion point (Article 1(5) and (6)) appears in 7. Both apply to each of the 35 entries that carry the date clause. A reviewer who reads `EUBAT-78-G` alone does not see them.

Proposed correction: move both points to the pack `scope_statement`, or add them to every affected entry. After F-01 is applied, replace the first point with the trade-off text.

### F-11 (low). The trigger for the QR code date has a basis in the text

Problem. `EUBAT-13-6`, `13-6A`, `13-6B`, and `13-7-QR` list as unresolved that Article 13(6) states a date and no trigger event, and that the draft borrows the trigger of Article 77(1). The research file records Article 38(1): a manufacturer ensures that a battery is marked and labelled under Article 13 when it places the battery on the market or puts it into service. The fetch tool reported the same in paraphrase from the official page today. No exact fragment was obtained, so this is marked "partly" checked.

Proposed correction: cite Article 38(1), point (b), as the basis of the trigger in the interpretation text, and keep the unresolved point until a human confirms the wording.

### F-12 (low). Source record `reg-eu-2026-1738` says `not_checked` and also cites an independent check

Problem. The record has `independent_check: not_checked`. Its `amendment_history` records the corrigendum of 2026-10-08 "as the independent check of the Commission acts found", and the uncertainties say that the check of Regulation (EU) 2023/1542 re-read Articles 53 and 59. The field and the text disagree. The record `reg-eu-2024-1781` has the same field value but explains it in its uncertainties; no finding for that one.

Proposed correction: keep `not_checked` and add one uncertainty line that says which parts a check of a different subject touched. Do not raise the value to `confirmed`.

### F-13 (info). No path of this pack can give `pass` or `fail` in the engine

Each of the 36 requirements has one path. Each path holds exactly one manual test purpose. `plan.py` gives a manual step `manual_unavailable` before any registry lookup. Section 7.1 maps that to `inconclusive`. Section 7.2, rule 6, makes the path `inconclusive`. So no partial automated check can give `pass`. The automated steps all have `on_check_failed: inconclusive`, so no step can give `fail` either. `TP-EU-INTEGRITY-JWS` leaves the path when `signature_format` is not `jws`; the path is then manual only and still cannot pass. This is by design (`OQ-015`, `OQ-016`). A reader of a report must know that every verdict from this pack is `inconclusive` or `not_applicable`.

### F-14 (info). The battery category is a declaration that nothing checks

The engine reads `ics.product_category` as a string. Article 3(1), points (11), (13), (14), read today, define the categories by design purpose and mass (25 kg, 5 kg). The profiles declare `mass_g`, and no entry reads it. A wrong category declaration gives a confident wrong applicability. A human may add a consistency rule to the profile (for example LMT needs `mass_g` of 25 000 or less). That is a profile change, not a pack change.

### F-15 (info). The capacity comparison

`capacity_wh gt 2000` matches "greater than 2 kWh": 2000 Wh gives `false`, 2001 Wh gives `true`, and the threshold sits under `product_category eq industrial` only. LMT and EV batteries have no capacity condition, as Article 77(1) states. The fact is an integer. A declared value between 2000 and 2001 Wh must be rounded by the declarant, and the profile gives no rounding rule. Article 3 defines neither capacity nor rated capacity (already in `unresolved` and `OQ-011`).

### F-16 (info). Unresolved points that today's reading settles

- `EUBAT-13-6A`, `EUBAT-13-6B`: the closing sentence of Article 13(6) stands after point (c) and applies to the information under each point. The point "the audit did not record how that sentence relates to each point" can be closed by a human.
- `EUBAT-13-6B`: point (b) was read today in fragments. It names paragraphs 1 to 5, Article 18, Article 52(3), and Article 74(1). The point "the independent check did not re-read point (b) word by word" can be narrowed to "not compared character by character".
- `EUBAT-77-5`, `EUBAT-77-6`: see F-03.

### F-17 (info). Source record `reg-eu-2023-1542`

The header at EUR-Lex on 2026-10-14 is unchanged from the record. `oj_citation.status` is `not_applicable` in `sources.yaml` and `cited` in the research JSON. The catalogue uses the field for standards citations, so the normalization is consistent. The record's `legal_as_of` stays 2026-10-13. This review did not search for acts adopted after that date.

## 5. Hand evaluation of the main applicability pattern

Pattern (32 entries): `all[ any[ category in {lmt, ev}, all[ category eq industrial, capacity_wh gt 2000 ] ], any[ placed ge 2027-02-18, put_into_service ge 2027-02-18 ] ]`. Semantics: a missing fact or `unknown` gives `unknown`; `all` is Kleene conjunction; `any` is Kleene disjunction. The column "Law" states the result under the draft's trigger reading and the definitions of Article 3(1), points (16) to (18), read today. It is this reviewer's reading, not a legal opinion.

| Case | Declaration | Category clause | Date clause | Expression | Law | Agree |
| --- | --- | --- | --- | --- | --- | --- |
| (a) | EV, placed 2027-03-01, service unknown | true | any(true, unknown) = true | **true** | passport duty applies | yes |
| (b) | EV, placed 2026-12-01, service unknown | true | any(false, unknown) = unknown | **unknown** | false: no later putting into service is possible (F-02) | no |
| (c) | LMT, placed 2027-03-01 | true (no capacity test) | true | **true** | applies | yes |
| (d) | industrial, 2000 Wh, placed 2027-03-01 | all(true, 2000 gt 2000 = false) = false; any = false | true | **false** | not applicable: not greater than 2 kWh | yes |
| (e) | industrial, 2001 Wh, placed 2027-03-01 | true | true | **true** | applies | yes |
| (f) | industrial, capacity unknown, placed 2027-03-01 | all(true, unknown) = unknown; any = unknown | true | **unknown** | unknown: the law needs the capacity | yes |
| (g) | portable, placed 2027-03-01 | in: false; eq industrial: false; any = false | true | **false** | not in Article 77(1) | yes |
| (h) | EV, both dates unknown | true | unknown | **unknown** | unknown: the law needs the trigger date | yes |
| (x) extra | EV, placed 2026-12-01, service 2027-03-01 | true | any(false, true) = true | **true** | false: the service date is void by definition (F-01) | no |
| (y) extra | EV, placed unknown, service 2027-03-01 | true | any(unknown, true) = true | **true** | true if the declaration is trusted | yes |

The repository evaluator gave the same values for `EUBAT-77-1` (section 2.3). Results of the variants under the same eight cases, from the same run:

| Entry | (a) | (b) | (c) | (d) | (e) | (f) | (g) | (h) | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `EUBAT-13-6` (date only) | true | unknown | true | true | true | true | true | unknown | QR code on all batteries: (d) and (g) `true` is right. |
| `EUBAT-13-6B` (negated gate) | false | false | false | true | false | unknown | true | false | (d) and (g) `true` is right; (f) `unknown` is right. |
| `EUBAT-AXIII-1K` (EV only) | true | unknown | false | false | false | false | false | unknown | Right for every case except (b). |
| `EUBAT-AXIII-1E` | unknown | unknown | unknown | false | unknown | unknown | false | unknown | (c) see F-08. |
| `EUBAT-78-B` | unknown | unknown | unknown | false | unknown | unknown | false | unknown | `unknown` inside scope until the Article 77(9) act exists; right. |
| `EUBAT-AXIII-4A` | true | unknown | true | false | unknown | unknown | false | unknown | (e) `unknown`: no fact for "rechargeable"; right. |
| `EUBAT-13-7-LABELS` | unknown for all | | | | | | | | See F-09. |

Checks asked for by the task: the comparison is strictly greater than 2000 Wh (case (d) `false`, case (e) `true`); the threshold is under the industrial branch only (case (c) `true` with 500 Wh); the trigger is "placed on the market or put into service" as an `any`; `2027-02-18` itself is included by `ge`.

## 6. Entries with no issue found

The following entries were read against the official text and the research files. Citation, paraphrase, modality, and authority class were found consistent. Each still carries the pattern defect of F-01 and F-02, and F-10 and F-13 apply to all.

`EUBAT-13-6`, `EUBAT-13-7-QR`, `EUBAT-77-1`, `EUBAT-77-2-CONTENT`, `EUBAT-77-3`, `EUBAT-77-3-STD`, `EUBAT-77-4`, `EUBAT-77-6`, `EUBAT-77-7A`, `EUBAT-77-8`, `EUBAT-77-10`, `EUBAT-78-A`, `EUBAT-78-C`, `EUBAT-78-D`, `EUBAT-78-E`, `EUBAT-78-G`, `EUBAT-78-H`, `EUBAT-AXIII-1`, `EUBAT-AXIII-1C`, `EUBAT-AXIII-1D`, `EUBAT-AXIII-1K`, `EUBAT-AXIII-2`, `EUBAT-AXIII-3`, `EUBAT-AXIII-4A`, `EUBAT-AXIII-4B`, `EUBAT-AXIII-4C`, `EUBAT-AXIII-4D`.

Points confirmed for these entries:

- Dependencies (task check 5). `EUBAT-AXIII-1C` and `EUBAT-AXIII-1D` give `unknown` with a stated reason and guess no date. `EUBAT-AXIII-1D` names the fixed date 2027-08-18 (Article 48(1) as amended, M2 marker read today) and explains why the expression still cannot decide. `EUBAT-78-B` and `EUBAT-78-F` give `unknown` for the Article 77(9) act. The source record `batteries-art-77-9-implementing-act` does not infer adoption from the deadline.
- Authority and mapping (task check 8). All 36 entries rest on `reg-eu-2023-1542` (`eu_regulation`). The two ESPR links in use are explicit in the Batteries Regulation: Article 77(10) (C2 marker read today) and Article 78, point (a). `EUBAT-78-A`, `EUBAT-78-E`, and `EUBAT-77-5` each say that they transfer nothing from Regulation (EU) 2024/1781 or from Implementing Decision (EU) 2026/1736. `EUBAT-77-3-STD`, `EUBAT-78-G`, and `EUBAT-78-H` name standards by number, year, and publisher only. No entry states the content of an EN, ISO, IEC, or DIN document.
- Placeholders. All 8 entries of `en-jtc24/placeholders` have `review_status: placeholder`, `paraphrase: ''`, `citation: ''`, `applicability: {const: unknown}`, `testability: not_testable`, no `interpretations`, no `assessment_paths`, no `approval`. Titles match the `en-18xxx-2026` source records. No clause and no content statement.
- Test purposes (task check 9). Each automated test purpose lists exactly the requirements whose paths name it. Each manual test purpose maps one to one. `TP-EU-QR-DECODE` on `EUBAT-13-6B` is weak evidence (a decoded image says nothing about the information behind the code), and its purpose text says so.
- Scope page. `docs/explanation/scope-and-legal-mapping.md` agrees with the pack: 36 drafts, the dates of section 5, the two ESPR links of section 4.1, and the "greater than" and "industrial only" statements. Section 4.2 and 4.3 transfer nothing.
- Source records. `reg-eu-2025-1561`, `impl-reg-eu-2026-1778` (published 2026-07-17, in force 2026-08-06), `impl-dec-eu-2026-1736` (2026-07-15, six standards, ESPR only), `impl-dec-eu-2026-2048` (EN 18060:2025, no mention of Article 77), the three draft-act records, and the two Commission guidance records match the research files and the refutation files in status and dates.

## 7. Not reviewed

- The 36 manual test purposes beyond their mapping and their `expected_evidence` headings. No manual review was performed.
- The content of the Commission guidance and FAQ. The entries cite them as non-binding aids only.
- Any act adopted or published after 2026-10-13.
- Article 38(1) exact wording; Annex VI Part A; Article 74(1); Article 18.
- The profiles `lmt.yaml` and `industrial.yaml` beyond their fact lists.
- `illustrative-core.yaml` and `testpacks/battery-core.yaml`.
- Lint, type check, and test suite (not run).

## 8. Overall assessment

The draft pack is careful about what it does not know. It invents no date, transfers nothing from the ESPR, states no content of a standard, and keeps every result `inconclusive` until a human reviews. The source records agree with the research files.

The one defect that matters is in the date clause (F-01, F-02). It is a single pattern in 35 entries, it has a small fix inside the expression language, and the fix has one trade-off that a human must accept or reject. Three paraphrases need a dropped condition or word restored (F-03, F-04) and one dependency needs one consistent treatment (F-05). The rest is precision.

This review is an agent review. It is not a human approval. It makes no claim that any entry is legally correct, and no review status was changed. A human reviewer must still complete `catalogue/templates/interpretation-review.md` for each entry.
