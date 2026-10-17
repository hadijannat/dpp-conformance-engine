"""The capability manifest: what this version can and cannot do.

States: ``supported``, ``experimental``, ``interface_only``, ``unsupported``.
A capability that is not ``supported`` or ``experimental`` never produces a pass.
An ``interface_only`` entry is a deferred integration, not an implemented feature. Its
acceptance criteria say what must be true before the state may change.
"""

from __future__ import annotations

from importlib.util import find_spec

from dppce import __version__
from dppce.models import Capability, CapabilityManifest, CapabilityState

_S, _E, _I = CapabilityState.SUPPORTED, CapabilityState.EXPERIMENTAL, CapabilityState.INTERFACE_ONLY

# (id, adapter, state, description, optional import name, acceptance criteria for a state change)
_ENTRIES: tuple[tuple[str, str, CapabilityState, str, str | None, str], ...] = (
    (
        "carrier.qr",
        "carrier",
        _S,
        "Decode a QR image file with zxing-cpp. Image quality limits apply: "
        "the engine does not grade print quality.",
        "zxingcpp",
        "",
    ),
    (
        "carrier.nfc",
        "carrier",
        _I,
        "Read an NFC tag.",
        None,
        "A reader integration exists and is tested against physical tags in a recorded test campaign.",
    ),
    (
        "carrier.rfid",
        "carrier",
        _I,
        "Read an RFID tag.",
        None,
        "A reader integration exists and is tested against physical tags in a recorded test campaign.",
    ),
    ("identifier.parse", "identifier", _S, "Scheme-aware syntax check of the carrier payload.", None, ""),
    ("identifier.resolve", "identifier", _S, "Bounded resolution of an identifier to a passport.", None, ""),
    (
        "identifier.consistency",
        "identifier",
        _S,
        "Compare the identifier in the carrier, the resolver, "
        "the passport, and the ICS. Digital consistency does not prove physical authenticity.",
        None,
        "",
    ),
    (
        "api.contract",
        "api",
        _S,
        "Check a response against a pinned, maintainer-supplied OpenAPI "
        "contract. A subset of OpenAPI 3.1 is supported: status, media type, and JSON Schema.",
        None,
        "",
    ),
    (
        "api.fuzz",
        "api",
        _I,
        "Schemathesis fuzzing of the API.",
        None,
        "Runs only with a signed authorization that grants the scope 'fuzz'. Tested against the "
        "reference system with a request budget.",
    ),
    ("data.jsonschema", "data", _S, "Validate a document against a pinned JSON Schema.", None, ""),
    (
        "data.context",
        "data",
        _S,
        "Check JSON-LD context references against a pinned allowlist. No context is fetched.",
        None,
        "",
    ),
    (
        "data.rules",
        "data",
        _S,
        "Versioned rule packs: completeness, units, ranges, relationships, freshness.",
        None,
        "",
    ),
    (
        "data.shacl",
        "data",
        _I,
        "SHACL validation with pySHACL.",
        None,
        "pySHACL is an optional extra. Shapes are pinned local files. Results agree with the JSON "
        "Schema path on the shared fixtures, and disagreements are recorded.",
    ),
    (
        "access.policy",
        "access",
        _S,
        "Compare what each role receives with a declared access policy, "
        "across fetch, search, export, error, and HTML channels. Uses synthetic canaries.",
        None,
        "",
    ),
    (
        "integrity.jws",
        "integrity",
        _S,
        "Verify a JWS on a passport: signature validity, issuer trust, "
        "and certificate validity, as separate findings. A valid signature does not prove that the "
        "signed attributes are true.",
        None,
        "",
    ),
    (
        "integrity.cose",
        "integrity",
        _I,
        "Verify a COSE signature.",
        None,
        "A COSE profile with an algorithm allowlist and its own test vectors.",
    ),
    (
        "integrity.status_list",
        "integrity",
        _I,
        "Bitstring Status List retrieval and check.",
        None,
        "Status retrieval behind the transport, with a mock status service and staleness tests.",
    ),
    (
        "persistence.versions",
        "persistence",
        _E,
        "Compare version-aware observations with the declared "
        "update rule. A limited number of observations cannot prove lifetime availability.",
        None,
        "",
    ),
    (
        "persistence.scheduled",
        "persistence",
        _I,
        "Scheduled acquisition over time and backup references.",
        None,
        "A scheduler runs acquisitions at declared intervals and keeps each recording.",
    ),
    ("registry.mock", "registry", _S, "Passive lookup against a configurable mock registry.", None, ""),
    (
        "registry.official",
        "registry",
        _I,
        "Checks against an official registry environment.",
        None,
        "A separately authorized official environment is available. Passive checks are separate from "
        "registration and update operations.",
    ),
    (
        "aas.validate",
        "aas",
        _E,
        "Wrap a pinned aas-test-engines release. A valid Asset "
        "Administration Shell is not a complete DPP conformance statement.",
        "aas_test_engines",
        "",
    ),
    ("evidence.jws_es256", "evidence", _S, "Sign and verify reports with JWS ES256.", None, ""),
    (
        "evidence.devlog",
        "evidence",
        _I,
        "File-backed Merkle log for development.",
        None,
        "A log implementation exists in dppce.evidence, with append, inclusion-proof, and "
        "consistency-proof tests on local fixtures. Its documentation states whether it implements "
        "RFC 9162 and what protection it gives against equivocation.",
    ),
    ("evidence.cose", "evidence", _I, "COSE report signatures.", None, "A separately tested COSE profile."),
    (
        "evidence.rfc3161",
        "evidence",
        _I,
        "RFC 3161 timestamps on reports.",
        None,
        "See BL-004. A mock timestamp authority is used in tests.",
    ),
    (
        "evidence.status_list",
        "evidence",
        _I,
        "Bitstring Status List for report credentials.",
        None,
        "A separately tested profile with a mock status service.",
    ),
    (
        "evidence.untp_dcc",
        "evidence",
        _I,
        "Export a report as a UNTP Digital Conformity Credential.",
        None,
        "A pinned DCC version is selected by a maintainer. The export validates against that pinned "
        "schema without invented accreditation or endorsement claims.",
    ),
    (
        "evidence.qualified_seal",
        "evidence",
        _I,
        "Qualified electronic seal.",
        None,
        "A separately validated integration with a qualified trust service provider.",
    ),
    (
        "keys.kms",
        "infrastructure",
        _I,
        "Signing and data keys in a cloud KMS.",
        None,
        "An implementation of the Signer and DataKeyProvider protocols, tested against a KMS emulator.",
    ),
    (
        "keys.pkcs11",
        "infrastructure",
        _I,
        "Signing keys in a PKCS#11 device.",
        None,
        "An implementation of the Signer protocol, tested against a software token.",
    ),
)


def manifest() -> CapabilityManifest:
    """Build the manifest for this installation. ``available`` reflects installed extras."""
    return CapabilityManifest(
        schema_version="dppce.capabilities/1",
        engine_version=__version__,
        capabilities=tuple(
            Capability(
                id=ident,
                adapter=adapter,
                state=state,
                description=description,
                optional_dependency=module,
                available=module is None or find_spec(module) is not None,
                acceptance_criteria=criteria,
            )
            for ident, adapter, state, description, module, criteria in _ENTRIES
        ),
    )
