# How to pin an oracle

Audience: maintainers and contributors.
Purpose: vendor an open schema or data file so that the engine and the tests read a fixed copy.
Prerequisites: the GitHub CLI `gh`, and `uv sync --all-extras`.

An oracle is a published file that the engine or a test treats as the reference. A pin fixes the
file at one commit. The pin records the digest, so a change is visible.

Use only open files from a repository that you may copy. Read its license first. Never pin text of
an EN, ISO, IEC, or DIN document.

## Steps

1. Find the commit of the file. Use the full 40-character commit, not a branch name.
2. Read the `LICENSE` of the repository at that commit. Record the license and the holder.
3. Fetch the file at the commit. Do not use a tool that processes the text.

```bash
gh api -H "Accept: application/vnd.github.raw" \
  "repos/OWNER/REPO/contents/PATH?ref=COMMIT" > tests/vectors/NAME/FILE
```

4. Put the file under `tests/vectors/NAME/`. Put a file that the engine reads at run time under
   `testpacks/data/NAME/`. Do not edit the file.
5. Write `README.md` in the same directory. Give the source URL, the commit, the retrieval date,
   the license, and the SHA-256.
6. Add the holder to `REUSE.toml` as the upstream states it. Never use the project owner.
7. Add one record to `catalogue/sources.yaml` with `source_type: test_vector` and the SHA-256.
8. Add one pin to `catalogue/oracle-pins.yaml`. Copy the digest, URL, and date from the record.
9. Run the offline check.

```bash
uv run python scripts/check_oracle_pins.py
```

   The command exits 0 if every digest matches. It never uses the network.

## Bundle a schema set

A published schema often refers to other files. The engine fetches nothing, so such a schema gets
the reason code `DATA.SCHEMA.NOT_LOCAL`. Bundle the set into one file first.

1. Fetch every file of the set into one directory. Keep the relative layout.
2. Run the bundler on the root schema.

```bash
uv run python scripts/import_schema.py set/root.json --out bundle.json
```

3. Check the result. Every `$ref` starts with `#/`. The `$schema` of the root is unchanged.
4. Keep the fetched set as the pinned oracle. The bundle is a derived file, so name it as such.

The bundler stops with exit status 1 if a reference leaves the directory. It does not fetch a URL.

## Check for drift

The maintainer runs the drift check by hand, never in the tests.

```bash
uv run python scripts/check_oracle_pins.py --refresh
```

The command fetches each file at its pinned commit and at the default branch. It reports a pinned
object that changed and any upstream drift. A drift report does not fail a release. Decide on each
report whether to pin a new commit.
