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

A development agent still does not sign off. The person who submits a later commit of an agent
reviews it and signs off.
