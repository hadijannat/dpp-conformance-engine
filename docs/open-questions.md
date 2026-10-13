# Open questions

Audience: maintainers and reviewers.
Purpose: record each question that the project cannot answer from verified evidence.
Prerequisites: none.

Each entry has a stable identifier. An entry is closed only when the stated evidence exists.
Agent agreement is not a human approval of normative content.

| ID | Question | Why it matters | Blocks | Status |
| --- | --- | --- | --- | --- |
| OQ-001 | Is `@hadijannat` the correct GitHub handle for CODEOWNERS? The value comes from the local `git config user.name`. It is not verified against GitHub. | CODEOWNERS routes reviews. A wrong handle routes them to nobody. | Publishing the repository | open |
| OQ-002 | Which person will act as the human reviewer who approves requirement interpretations? | Only a documented human approval can promote an interpretation to `approved`. | Reviewed execution mode | open |
| OQ-003 | Who is the report issuer, and what is the actual accreditation status of that issuer? | Reports must state issuer identity and accreditation status. The default is "not accredited". | Any report used outside a demonstration | open |
| OQ-004 | Is Docker available and authorized on the development host? The probe command was declined in the first session. | Docker Compose integrations and the container image cannot be run without it. | Container build and Compose checks | open |
| OQ-005 | Will the maintainer accept the Xcode license (`sudo xcodebuild -license accept`) so that Homebrew can install `just` and `vale`? | `brew install just vale` failed on this host for that reason. | Local Vale style checks; native `just` | open |
