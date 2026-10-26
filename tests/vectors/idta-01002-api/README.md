# IDTA-01002 AAS API read profiles

Audience: contributors and reviewers.
Purpose: name the source and the license of the AAS API files that `aas.api_profile` follows.
Prerequisites: none.

This directory holds no copy of the files. The check `aas.api_profile` follows IDTA-01002,
Specification of the Asset Administration Shell, Part 2: Application Programming Interfaces,
version 3.0.4. The project read these OpenAPI files of the repository on 2026-10-26:

| Upstream path | SHA-256 |
| --- | --- |
| `AssetAdministrationShellRepositoryServiceSpecification/V3.0_SSP-002.yaml` | `d4024e80fa0edad66e82dc790cde6fc642ff09fc8b575bdfefe62655739f2417` |
| `SubmodelRepositoryServiceSpecification/V3.0_SSP-002.yaml` | `c0654149b9b16d108b3b32f28475be851ceb734cffc26fd0105947ecef655ef4` |
| `Part2-API-Schemas/openapi.yaml` | `7ae85d69da0f2904b8f7765613e713a02f8ec89b870a5198818138bf37347dc8` |
| `Part1-MetaModel-Schemas/openapi.yaml` | `ab6612ef71fd4db20f110f5e30ab84254f7e93915e6aabf83f580a1da9e50a0b` |

- Repository: GitHub `admin-shell-io/aas-specs-api`.
- Tag: `v3.0.4`. Commit: `f7bb302f2b9969af663a6c8c5414954bc4d61d9b`.
- Retrieval date: 2026-10-26.

Source URL of the tag:
<https://github.com/admin-shell-io/aas-specs-api/tree/f7bb302f2b9969af663a6c8c5414954bc4d61d9b>

## License

The license is Creative Commons Attribution 4.0 International (CC-BY-4.0). The `LICENSE.txt`
file of the repository at the same commit gives it. Its SHA-256 is
`0caef66f639ab192462d6d7a8f2c65c53f8b238179ac5ed94abf437040839e3e`. The `info` block of each file
names the Industrial Digital Twin Association (IDTA) as the publisher, under CC BY 4.0.

## Why the files are not here

The AAS specifications are on the way to IEC standards. CLAUDE.md rule 5 does not let the project
ship text of such a document. The project did not check each description field of the files
against that rule. So the project does not vendor them.

## Use in this project

The check does not read the files at run time. `src/dppce/adapters/aas_api.py` holds the minimal
response shapes that the check judges, written by hand. These are the profile identifiers of the
service description and the paged result with `paging_metadata` and `result`. They are also the
`id` and `modelType` of a shell and a submodel, and the `type` and `keys` of a reference. The reference system family
`src/dppce/infrastructure/reference/aas.py` serves the same shapes.
