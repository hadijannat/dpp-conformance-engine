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
   The date must exist in the calendar. Otherwise plan, run, and replay stop with exit code 2.
5. Write `unknown` for a value that you do not know. Do not guess.
6. Name the API contract in `api.contract` and the access policy in `access.policy`.
   Use the identifier in the file: `x-dppce-contract-id` for a contract, `policy_id` for a policy.

A value of `unknown` gives an inconclusive result for the requirements that need it.
It never gives "not applicable".

The tester binds the contract and the policy through the profile. The ICS cannot select them.
If the ICS names a different identifier, the check is blocked and its result is inconclusive.

A declaration cannot waive a requirement. If you declare that a mandatory, applicable feature
is not implemented, the report shows a failure for that requirement.

## The IXIT: what the tester needs

Copy `fixtures/reference/ev.ixit.yaml` and change it. The schema is `ixit`.

1. Give the endpoints.
2. Give the samples: the path of a QR image, the identifier, and the passport identifier.
   A sample path must stay inside the directory of the IXIT file.
   Do not start a sample name with `manual/`. The engine reserves that namespace, and such a name is an input error.
3. Give a URL template in `resources` for each resource that the system serves: `item`,
   `model`, `signed`, `versions`, and `registry_record`. Each template names an endpoint and a path.
4. If a template uses a part of the passport identifier, declare the split in `id_parts`.
   Give a fixed separator and a name for each part.
5. List the role identities. Use only a role that the profile declares in `roles`.
   Another role is an input error (exit code 2). Give a secret **reference**, never a secret.
   A reference is `env:DPPCE_SECRET_<NAME>` or `file:<name>`.
6. Set the network policy: allowed hosts, request limit, minimum interval, and a contact.
7. Set the retention period for observations.

Example for a system that serves the passport at `/passports/<gtin>/<serial>/data`:

```yaml
samples:
  passport_id: 09506000134352.EV0001
resources:
  item: {endpoint: api, path: "/passports/{gtin}/{serial}/data"}
  registry_record: {endpoint: registry, path: "/lookup/{gtin}/{serial}"}
id_parts: {separator: ".", names: [gtin, serial]}
```

A template is a path under its endpoint. It starts with one `/` and has no fragment.
`{id}` is the passport identifier. Every other placeholder must be a name in `id_parts`.
The split uses the first separators only. The last part keeps any further separator.
A resource with no template is not tested: its checks are blocked. The engine has no default path.

The tester confirms each non-public host and each secret reference on the command line.
The tester supplies the trust bundle. The IXIT cannot select it.

## Check the files

```bash
uv run dppce plan --profile battery/ev --ics my.ics.yaml --ixit my.ixit.yaml
```

The plan shows which requirements apply, which are unknown, and which steps will run.
