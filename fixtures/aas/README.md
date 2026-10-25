# Synthetic AAS samples

Audience: contributors. Purpose: fixtures for the `aas.validate` and `aas.dpp_compose` tests.
Prerequisites: none.

Each file is project-authored and synthetic. No file is a copy of an IDTA template.
Each sample holds one shell with an `example.test` identifier, or a deliberate defect.
The `TEST-ONLY-dpp-*` files use the semanticIds and idShorts of the pinned IDTA 02099-1
template in `tests/vectors/idta-02099-1`. They copy no other content of it.

| File | Expected outcome with aas-test-engines 1.0.3 |
| --- | --- |
| `environment-valid.json` | `AAS.VALID` |
| `environment-invalid.json` | `AAS.INVALID`: an empty shell list |
| `environment-valid.xml` | `AAS.VALID` |
| `environment-invalid.xml` | `AAS.INVALID`: an empty shell list |
| `environment-v3-1.xml` | `unsupported`, `AAS.VERSION.UNSUPPORTED`: the namespace names metamodel 3.1 |
| `environment-malformed.xml` | `AAS.INVALID`: not well-formed XML |
| `environment-doctype.xml` | `AAS.INVALID`: a document type declaration, which the parser refuses |
| `environment-doctype-utf16.xml` | `AAS.INVALID`: the same declaration in a UTF-16 body |
| `package-valid.aasx` | `AAS.VALID` |
| `package-invalid.aasx` | `AAS.INVALID`: the AAS part has an empty shell list |
| `package-no-spec.aasx` | `AAS.INVALID`: the package has no AAS specification part |
| `package-doctype.aasx` | `AAS.INVALID`: a relationships part holds a document type declaration |
| `package-repeated-key.aasx` | `AAS.INVALID`: the AAS part is JSON with a repeated key, which the strict parser refuses |
| `package-high-ratio.aasx` | `AAS.INVALID`: a member expands beyond the compression ratio that the check permits |
| `package-v3-1.aasx` | `unsupported`, `AAS.VERSION.UNSUPPORTED`: the XML AAS part names metamodel 3.1 |
| `package-corrupt-part.aasx` | `AAS.INVALID`: the compressed bytes of the AAS part are damaged, so the ZIP reader fails on it |

Each `TEST-ONLY-dpp-*` file gives `AAS.VALID` with `aas.validate`. With `aas.dpp_compose` the
files give these outcomes:

| File | Expected outcome of `aas.dpp_compose` |
| --- | --- |
| `TEST-ONLY-dpp-valid.json` | `AAS.DPP.OK`. The control C-FAMILY-AAS uses it. |
| `TEST-ONLY-dpp-element-missing.json` | `AAS.DPP.ELEMENT_MISSING`: no `dppStatus` element |
| `TEST-ONLY-dpp-id-mismatch.json` | `AAS.DPP.ID_MISMATCH`: the `uniqueProductIdentifier` is not the `globalAssetId` of the shell |
| `environment-valid.json` | `AAS.DPP.SUBMODEL_MISSING`: no DPP metadata submodel |
