# IDTA 02099-1 DPP metadata template

Audience: contributors and reviewers.
Purpose: name the source and the license of the IDTA 02099-1 template, and tell how to check the
table of `aas.dpp_compose` against it.
Prerequisites: a local copy of the template file, for the optional test only.

This directory holds no copy of the template. The project uses the JSON template of IDTA 02099-1,
Digital Product Passport - Part 1: Metadata, version 1.0. The template release is the bug-fix
release 1.0.2.

- Repository: GitHub `admin-shell-io/submodel-templates`.
- Upstream path: `published/Digital Product Passport/Digital Product Passport Part-1/1/0/2/IDTA 02099-1_Template Digital Product Passport - Part 1.json`.
- Commit: `f3790038b6c9c2d7e5ebbb4609997468fadf3e85`.
- Retrieval date: 2026-10-25.
- SHA-256: `45d3f5ee78f628941816f4f6e30221f535a91c318114f41143328881c887eb85`.
- Git blob: `b3dd7e42bd681296e00b8571ab3745da4e1c2770`.

Source URL:
<https://github.com/admin-shell-io/submodel-templates/blob/f3790038b6c9c2d7e5ebbb4609997468fadf3e85/published/Digital%20Product%20Passport/Digital%20Product%20Passport%20Part-1/1/0/2/IDTA%2002099-1_Template%20Digital%20Product%20Passport%20-%20Part%201.json>

## License

The license is Creative Commons Attribution 4.0 International (CC-BY-4.0). The `LICENSE.txt`
file of the repository at the same commit gives it. The repository names no copyright holder. The
specification imprint names the publisher as "Industrial Digital Twin Association".

## Why the file is not here

The concept descriptions of the file hold definition text. IDTA names a European standard as the
source of that text. CLAUDE.md rule 5 does not let the project ship such text. So the project does
not vendor the file. The owner can grant an explicit exception later and vendor the pinned blob.

## Use in this project

The check `aas.dpp_compose` does not read the template at run time. It uses a table in
`src/dppce/adapters/aas.py`. The table holds the semanticId of the submodel. For each top-level
element, it holds the idShort, the semanticId, the cardinality, and the modelType. The table holds
identifiers only.

The test `test_the_table_equals_the_template` in `tests/test_adapters_aas_dpp.py` derives the same
table from the template file. It asserts that the two are equal. It runs only when an operator
supplies a local copy:

1. Get the file at the commit above from the repository.
2. Make sure that its SHA-256 is the value above.
3. Set `DPPCE_IDTA_02099_1_TEMPLATE` to the path of the file.
4. Run `uv run pytest tests/test_adapters_aas_dpp.py`.

When the variable is not set, the test is skipped. The test does not use the network.

`catalogue/sources.yaml` holds one record for the template, `idta-02099-1-template-1-0-2`, with
the same SHA-256.
