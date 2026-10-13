# Tool and model routing

Audience: maintainers and reviewers of the development process.
Purpose: record which models and tools were found, how work is routed, and what was not available.
Prerequisites: none.

Recorded on 2026-10-13. This file describes the development session only.
The engine does not use a language model at run time. See ADR 0002.

## Models

The evidence for each row is one successful delegated task per alias.
The probe is workflow run `wf_490b8786-8f2`. Each agent reported the identifier that its own environment states.

| Alias | Delegation accepted | Identifier reported by the agent | Role in this project |
| --- | --- | --- | --- |
| `fable` | yes | `claude-fable-5-1` (Fable 5.1) | Independent review of catalogue interpretation, verdict aggregation, authorization, and evidence security. Milestone review. |
| `opus` | yes | `claude-opus-5-5` (Opus 5.5) | Substantial engineering. Legal-source research. The coordinating session also runs on this model. |
| `sonnet` | yes | `claude-sonnet-5-5` (Sonnet 5.5) | Bounded implementation, fixtures, documentation, and routine metadata checks. |
| `haiku` | yes | `claude-haiku-5-5` (Haiku 5.5) | Not assigned. No task in the plan is low-risk enough to need it. |

An `advisor` tool is also available. Its environment describes it as a stronger reviewer model.
Its identifier is not stated, so this file does not name one.

### Deviation from the requested role split

The task brief asks for Fable as advisor and coordinator.
The coordinating session runs on Opus 5.5 and cannot change its own model.
The compensating control is this: Fable performs the independent reviews, and the `advisor` tool is consulted before each approach is fixed and before each milestone is declared complete.

### Routing rules

1. Assign by complexity and risk. Security work and test work are not low-risk by default.
2. Each delegated task gets an objective, inputs, owned files, permitted tools, acceptance tests, and a return format.
3. Two tasks never own the same file at the same time.
4. At most three tasks run in parallel.
5. If a model is unavailable, the fallback is the next more capable model. The fallback is recorded here. A fallback never bypasses a permission or a safeguard.
6. Agent agreement is not a human approval. No agent can promote a requirement interpretation to `approved`.

## Tools found on the development host

| Tool | State | Evidence |
| --- | --- | --- |
| `uv` | available | `uv 0.9.24` |
| Python | available | `Python 3.12.3` (pyenv); 3.12.12, 3.12.13, 3.13.12, and 3.14.4 are also installed |
| `git` | available | `git version 2.51.2` |
| Homebrew | available, installs blocked | `Homebrew 6.0.17`; `brew install just vale` exited 1 because the Xcode license is not accepted |
| `just` | not installed | `command not found`. See OQ-005. |
| `vale` | not installed | `command not found`. See OQ-005. |
| Docker | not probed | The `docker --version` command was declined. See OQ-004. This is not evidence that Docker is absent. |
| Web search and web fetch | available | Tool schemas loaded in the session. Used for public-source research only. |

## Integrations

- A Docker integration server is configured but its connection closed. It was not used.
- A diagram integration server rejected its configured credentials. It was not used.
- Literature-search integrations are connected. They are not relevant to legal and standards metadata and were not used.

## Permission domains

Public documentation research is one permission domain.
Access to a system under test is a different permission domain.
No real system under test was contacted in this session.
