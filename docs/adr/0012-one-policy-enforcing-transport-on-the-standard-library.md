# 0012. One policy-enforcing transport on the standard library

- Status: proposed (implemented in 0.1.0rc1; not ratified by a human maintainer)
- Date: 2026-10-13
- Deciders: the coordinating development agent; a human maintainer must ratify

## Context and problem

Every adapter needs the same protections: scope limits, protection against server-side request forgery and DNS rebinding, credential scoping, limits, and recording. An HTTP library that follows redirects and resolves names by itself makes those protections hard to guarantee.

## Decision

All network access goes through `dppce.infrastructure.transport.PolicyTransport`, built on `http.client`. It resolves a host once, checks every answer, and connects to the checked address. It follows redirects itself and checks each hop. An address counts as public only if it is public unicast and any embedded IPv4 address is public too. A transport failure is data in the record, never an exception and never a verdict. Secrets are removed before a record exists, with a default-deny rule for header values.

## Consequences

- Each protection has one implementation and one set of tests.
- No HTTP/2 and no connection reuse. That is acceptable for a bounded test run.
- A system that is reachable only through a NAT64 prefix needs an explicit entry.

## Alternatives considered

- A third-party HTTP client with hooks: more features, and less control over name resolution and redirects.
