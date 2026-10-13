# Threat model

Audience: security reviewers, operators, and contributors.
Purpose: state what the engine protects, from whom, how, and what stays open.
Prerequisites: read the [architecture contract](architecture.md), sections 9 to 11.

This page describes the design and the tests in this repository. No independent security
audit has been done. An automated review of each commit ran during development. It found the
defects in section 5, and each one was fixed.

## 1. What the engine protects

| Asset | Why it matters |
| --- | --- |
| The verdict | A verdict that is better than the evidence supports misleads everyone who reads the report. |
| The report | A recipient must be able to detect a changed, shortened, or forged report. |
| The observations | Responses of a tested system can hold personal or commercially sensitive data. |
| The test host | The engine runs with the network access and the secrets of the operator. |
| Other systems | The engine must not be usable to attack a system that nobody authorized it to test. |
| The catalogue | A requirement interpretation must not gain authority that no human gave it. |

## 2. Who is trusted, and for what

| Party | Trusted for | Not trusted for |
| --- | --- | --- |
| The operator | The trust bundle, the confirmation of hosts and secrets, the evaluation time | Nothing is checked on the operator's behalf: a wrong trust bundle gives wrong trust. |
| The owner of the tested system | A signed authorization, once its key is in the operator's trust bundle | The ICS and the IXIT. They are untrusted input. |
| The tested system | Nothing | Its responses, redirects, media types, and signatures are untrusted data. |
| A report recipient | Nothing | A key that a report supplies is not a trusted issuer identity. |
| A development agent | Drafts | It cannot approve an interpretation or make a release. |

## 3. Trust boundaries

```text
operator --(command line: trust, confirmations)--> engine <--(ICS, IXIT: untrusted)-- supplier
engine --(policy transport)--> tested system (untrusted responses)
engine --(encrypted recording)--> storage ; data key kept apart
engine --(signed envelope)--> recipient --(standalone verifier + own trust bundle)--> decision
```

Text alternative: the operator gives trust and confirmations on the command line. The supplier
gives the ICS and the IXIT, which the engine treats as untrusted. The engine reaches the tested
system only through the policy transport. It stores an encrypted recording, with the data key
in a different place. It gives a signed envelope to a recipient, who verifies it with the
standalone verifier and the recipient's own trust bundle.

## 4. Threats and mitigations

| Threat | Mitigation | Test |
| --- | --- | --- |
| The engine is pointed at an internal service (request forgery) | Hosts need an allowlist entry. A non-public address also needs an operator confirmation. Every resolved address is checked. | `tests/test_transport.py` |
| A host name resolves to a public address for the check and a private one for the connection (DNS rebinding) | The transport resolves one time and connects to the checked address. A mixed answer is refused. | `tests/test_transport.py` |
| A private IPv4 address hides in an IPv6 translation prefix | An address is public only if any embedded IPv4 address is public too. Multicast and reserved ranges are excluded. | `tests/test_transport.py` |
| A redirect leads out of scope, or carries credentials to a different origin | The transport follows redirects itself and checks each hop. Credentials and caller headers stay with their origin. | `tests/test_transport.py` |
| A secret reaches a retained record | Request header values are recorded only for an allowlist of names. URL userinfo and credential-like query values are removed. | `tests/test_transport.py` |
| A large or endless response exhausts memory | Body size, redirect count, request count, and time are limited. A truncated body is flagged and proves nothing. | `tests/test_transport.py` |
| The supplier's IXIT names its own trust bundle and authorizes itself | The trust bundle comes only from the operator. | `docs/adr/0011` and `src/dppce/cli.py` |
| The supplier's IXIT names a secret of a different system | The operator must repeat each secret reference. References are limited to one prefix and one directory. | `tests/test_transport.py` |
| The supplier's IXIT names a local file to read | A path must stay inside the directory of the IXIT file. A symbolic link that leaves it is refused. | `tests/test_transport.py` |
| A YAML file runs code | A safe loader only. A Python object tag is rejected. An applicability rule is a data tree, not an expression. | `docs/adr/0004` |
| A schema or a context reference fetches a remote document | Validators are built with an empty registry. A non-local reference is refused. No context is fetched. | `src/dppce/adapters/common.py` |
| Untrusted text runs in the HTML report | Every value is escaped. The report has no script. | `src/dppce/report/html.py` |
| A report is changed after signing | The signature binds the digest of the whole decision body. | `tests/test_evidence.py` (E-01, E-06) |
| A result is removed, repeated, moved, or replaced | Counts, Merkle roots, and strictly ascending keys are verified. | `tests/test_evidence.py` (E-02 to E-05) |
| A file shows one verdict to the verifier and a different one to a reader | A repeated key is refused. The document must equal the canonical form of the validated model. | `tests/test_evidence.py` |
| The algorithm in a token header selects a weak algorithm | A fixed allowlist of one algorithm. The header never selects it. | `tests/test_evidence.py` (E-11) |
| A report is signed with an unknown or expired key | Signature validity and issuer trust are separate dimensions. A key from the report is not trusted. | `tests/test_evidence.py` (E-10, E-12) |
| The holder of any certificate from a trusted root issues passport certificates | Each issuer must be a certificate authority that can sign certificates, inside its path length. | `tests/test_adapters_security.py` |
| A revoked certificate passes because of text formatting | Serial numbers compare as integers, for every certificate of the path. | `tests/test_adapters_security.py` |
| A tested system hides a leak behind a wrong media type | The access check always tries to parse a body as JSON. A partial look never passes. | `tests/test_adapters_security.py` |
| An observation value can be guessed from its hash | Commitments are salted with 32 random bytes that stay in the encrypted record. | `tests/test_evidence.py` |
| A recording is read without the key, or one record is swapped | AES-256-GCM with the record identifier as associated data. Each record is compared with its commitment. | `tests/test_evidence.py` |
| A limit or a defect of the engine reads as a failure of the tested system | A check that raises is an error. A size limit is "too large". An unreachable system is inconclusive. | `tests/test_e2e_reference.py` |
| An unavailable adapter reads as a pass | The planner marks the step `unsupported`. Only a completed check can pass. | `tests/test_e2e_reference.py` |
| A test contacts a real system by accident | A test-suite guard refuses any connection that is not loopback. The CI job has no other network. | `tests/test_no_network.py` |
| An agent or a tool marks an interpretation approved | The loader needs a human approval record. The lint refuses an approved agent interpretation. No command writes an approval. | `docs/adr/0007` |

## 5. Defects found and fixed during development

Each one was found by an automated review of a commit, or by a test, before any release.

1. The verifier hashed the validated model, not the file. A repeated key, a coerced type, or a
   defaulted field could differ from what a reader sees.
2. An IPv6 translation address and a multicast address counted as public.
3. Caller headers crossed origins on a redirect, and recorded URLs kept credential-like values.
4. The IXIT could select the trust bundle, a secret, a local file, and a private host.
5. A size limit of the JOSE library was reported as an invalid signature on a valid passport.
6. A certificate path was accepted on a signature and a name alone.
7. Revocation compared serial numbers as text, for the leaf only.
8. The access check passed when it had nothing to probe.
9. The access check skipped the field paths when a body had a non-JSON label.

## 6. Open risks

| Risk | State |
| --- | --- |
| No independent security audit | Open. Needed before any production use. |
| The trust bundle and the data key are files on the operator's host | By design for development. KMS and PKCS#11 providers are interfaces only. |
| No trusted timestamp on a report | Open. RFC 3161 validation is not implemented (BL-004). |
| Revocation uses a static snapshot | By design: verification does no network I/O. A stale snapshot blocks a complete result when the policy needs status. |
| A hostile owner controls the tested system and its declared policy | The access check shows enforcement of the declared policy only. It cannot show that the policy is right. |
| The reference system and the checks come from the same project | Method validation shows that known faults are found. It does not show that all faults are found. |
| A denial of service against the engine by a slow tested system | Timeouts and budgets limit it. A parallel run scheduler does not exist. |
| The file-backed Merkle log | A development component. No protection against equivocation. |
| Dependencies | Pinned with hashes in `uv.lock`. No vulnerability scan ran in the development session. |
