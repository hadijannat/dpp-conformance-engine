# dpp-conformance-engine

Audience: all readers.
Purpose: help each reader find the right page.
Prerequisites: none.

The engine tests Digital Product Passport systems against a catalogue of traceable
requirements, and it produces evidence that a recipient can verify.
Its output is a **conformance test report**. A report is not a certificate.

Version 0.1.0rc1 is a release candidate. It is not for production use.
Read the [readiness page](readiness.md) before you rely on a result.

## Find your page

| You are | Start here |
| --- | --- |
| A decision maker | [What the engine tests and what it does not claim](explanation/scope-and-legal-mapping.md), then [readiness](readiness.md) |
| An economic operator or a vendor | [Run the engine against the reference system](tutorials/first-run.md), then [declare your system](how-to/write-an-ics-and-an-ixit.md) |
| An assessor | [Architecture and verdict rules](explanation/architecture.md), [source audit](research/source-audit.md), [fault catalogue](how-to/run-the-method-validation.md) |
| An authority or a report recipient | [Verify a report](how-to/verify-a-report.md) |
| A contributor | [Architecture contract](explanation/architecture.md), [decision records](adr/README.md), [writing style](reference/writing-style.md) |
| An operator of the engine | [Test a real system with authorization](how-to/test-a-real-system.md), [threat model](explanation/threat-model.md) |

## How the documentation is organized

The documentation follows the Diataxis structure.

- **Tutorials** teach by one complete example.
- **How-to guides** give the steps for one task.
- **Reference** pages state facts: commands, schemas, capabilities, terms.
- **Explanation** pages give the reasons: architecture, scope, threats.
