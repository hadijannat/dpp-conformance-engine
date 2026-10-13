# How to write an ICS and an IXIT

Audience: economic operators and vendors who want a system tested.
Purpose: declare a system and give the tester what a run needs.
Prerequisites: read the [glossary](../reference/glossary.md) entries for ICS and IXIT.

## The ICS: what you declare

Copy `fixtures/reference/ev.ics.yaml` and change it. The schema is `ics` in the
[schema reference](../reference/schemas.md).

1. Name the system under test and give it a stable identifier.
2. Name the profile, for example `battery/ev`.
3. Declare the product category, the granularity, the identifier scheme, and the carriers.
4. Give the product facts in `characteristics`. Use integer units: watt-hours, grams.
   Write a date as `YYYY-MM-DD`.
5. Write `unknown` for a value that you do not know. Do not guess.

A value of `unknown` gives an inconclusive result for the requirements that need it.
It never gives "not applicable".

A declaration cannot waive a requirement. If you declare that a mandatory, applicable feature
is not implemented, the report shows a failure for that requirement.

## The IXIT: what the tester needs

Copy `fixtures/reference/ev.ixit.yaml` and change it. The schema is `ixit`.

1. Give the endpoints.
2. Give the samples: the path of a QR image, the identifier, and the passport identifier.
   A sample path must stay inside the directory of the IXIT file.
3. List the role identities. Give a secret **reference**, never a secret.
   A reference is `env:DPPCE_SECRET_<NAME>` or `file:<name>`.
4. Set the network policy: allowed hosts, request limit, minimum interval, and a contact.
5. Set the retention period for observations.

The tester confirms each non-public host and each secret reference on the command line.
The tester supplies the trust bundle. The IXIT cannot select it.

## Check the files

```bash
uv run dppce plan --profile battery/ev --ics my.ics.yaml --ixit my.ixit.yaml
```

The plan shows which requirements apply, which are unknown, and which steps will run.
