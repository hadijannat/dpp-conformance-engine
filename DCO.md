# Developer Certificate of Origin

Audience: contributors.
Purpose: state how a contributor certifies the right to submit a change.
Prerequisites: none.

This project uses the Developer Certificate of Origin, version 1.1.
The full text is at <https://developercertificate.org/>. This file does not reproduce it.

## What you do

Add a sign-off line to each commit. Git adds it with the option `-s`.

```bash
git commit -s
```

The line has this form, with your real name and your email address:

```text
Signed-off-by: Your Name <you@example.org>
```

With that line you certify the statements of the certificate for that commit.

## Rules

- Sign only your own contribution.
- Never add a sign-off line for a different person.
- An automated tool or an AI assistant does not sign off. The person who submits the change
  reviews it and signs off.

## Commits made before this policy

A development agent created the first commits of this repository in one session.
Those commits have no sign-off line, because an agent must not sign for a person.
On 2026-10-15, the copyright holder certified them with commit `a6283be`. That commit names each
of the 87 commits up to `a1522ad` and has the sign-off of the copyright holder. See OQ-018 in
`docs/open-questions.md`.

## Sign-off for commits of a development agent

A development agent never adds a `Signed-off-by` line. The owner certifies its commits later,
with an empty sign-off commit.

1. Write a message file. Its first line is `DCO sign-off for agent commits`, and its second line
   is empty.
2. Add one line for each covered commit. Name each commit once, with its full 40-character hash:

   ```text
   I, Your Name <you@example.org>, hereby add my Signed-off-by to this commit: <full commit hash>
   ```

3. Make the empty commit with your own sign-off: `git commit --allow-empty --signoff -F <file>`.
4. Push the sign-off commit to the same branch or pull request as the covered commits.

## Automatic check

The `dco` job of the `ci` workflow runs `scripts/check_dco.py` on each pull request. It checks
each commit of the pull request, and merge commits too. A commit passes when one of these
conditions is true:

- The commit has a `Signed-off-by` trailer with the email address of its author.
- A sign-off commit in the same pull request names its full hash in the line form above. That
  sign-off commit has a `Signed-off-by` trailer with the email address of its own author.

The check compares email addresses and ignores case. It does not compare names. It checks the
trailers only. It cannot tell the owner from an agent that uses the same Git identity.

The check does not run on pushes to `main`. The owner signs agent commits there later.

The owner decides which author address is canonical. Before you make a sign-off commit, set
`user.email` to that address. Commit `a6283be` used a different address from the commits that it
covers (OQ-018).

Exit status 0 means that each commit has a sign-off. Exit status 1 prints `DCO.SIGNOFF.MISSING`
and the hash of each commit with no sign-off. Exit status 2 means wrong input or a Git failure.
