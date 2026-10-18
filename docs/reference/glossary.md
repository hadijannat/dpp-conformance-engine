# Glossary

Audience: all readers.
Purpose: give each project term one meaning.
Prerequisites: none.

Use one term for one concept. Do not use a synonym for a term in this list.

| Term | Meaning |
| --- | --- |
| applicability | Whether a requirement or a test step applies to a system: `true`, `false`, or `unknown`. |
| approval record | The documented decision of a human reviewer that makes an interpretation `approved`. |
| attestation | The signed statement that binds the decision digest of one report. |
| authority class | The kind of authority behind a requirement: legal obligation, standard method, implementation contract, guidance, or illustrative. |
| authorization | A signed permission from the owner of a system for a test with a stated scope and period. |
| build provenance | The signed statement of the workflow, the tag, and the commit that built a release file. GitHub calls it an attestation. It is not the attestation of a report. |
| capability | Something the engine can do, with a state: supported, experimental, interface only, or unsupported. |
| check | Deterministic code that performs one test step. A test purpose names a check from the registry. |
| claim level | What a result can be cited as: none, illustrative, diagnostic, or reviewed. |
| commitment | A salted value that binds one raw record and does not disclose it. |
| conformance test report | The output of a run. It is not a certificate. |
| decision body | The canonical statement of one run: scope, versions, all outcomes, exclusions, counts, and commitments. |
| decision digest | The SHA-256 digest of the canonical decision body. |
| entitled path | A field path that the declared access policy gives to a role. The access check requires it on the `fetch` channel. |
| envelope | The decision body together with its signatures. It is the JSON report. |
| exclusion | Something in the selected catalogue that a run left out, with the reason. |
| execution mode | Illustrative, exploratory, or reviewed. The mode decides which requirements a run can assess. |
| ICS | Implementation Conformance Statement. What the owner declares about the system. |
| interpretation | A statement of what a source provision requires. Agent-authored interpretations are drafts. |
| IXIT | Implementation eXtra Information for Testing. What the tester needs to run the tests. |
| laboratory record | A document that a laboratory keeps under its own procedures. The engine does not produce it. |
| manual result | The signed result of one manual step. The person who performed the step signs it. It names a role and no person. |
| observation | A minimized record of what one check saw. It holds no restricted payload value. |
| operator | The person who runs the engine. The operator supplies the trust bundle and confirms sensitive inputs. |
| pack | A versioned set of requirements with a scope statement. |
| placeholder | A requirement entry with no paraphrase and no test. It marks a source that nobody has interpreted. |
| profile | The selection of packs, test packs, and resources for one product type. |
| record | One raw exchange or input artifact, kept encrypted in a recording. |
| recording | The encrypted records of one run. A replay evaluates a recording again. |
| reference system | The synthetic local DPP system in this repository. It is an example, not an authority. |
| requirement | One testable statement with a source, an authority class, a modality, and a review status. |
| reviewer signature | A second signature over a report with the declared role `reviewer`. A person makes it with a key that has the purpose `review`. It names a key and no person. |
| run | One execution of a plan against one system at one evaluation time. |
| signer role | The role that an attestation declares: `issuer` or `reviewer`. |
| status list | A list that the issuer of reports signs. One bit per report shows whether the issuer revoked or suspended it. |
| system under test | The DPP system that a run examines. |
| test purpose | A declarative description of one test step: what it checks, for which requirements, and how a result maps to a verdict. |
| trust bundle | The explicit list of keys and anchors that the operator trusts. |
| URL template | A path with named placeholders under an IXIT endpoint. It gives the URL of one fetched resource. It cannot change the scheme, the host, or the port. |
| verdict | `pass`, `fail`, `inconclusive`, `not_applicable`, or `error`. |
| verification | The check of a report against a trust bundle. It says nothing new about the tested system. |
