"""Draft an ICS and an IXIT for a family profile from the shipped examples (``dppce init``).

A draft is untrusted input, as every ICS and IXIT is (ADR 0011). It names no secret, no trust
bundle, and no authorization. The operator still confirms each origin and each secret on the
command line. The carrier is parsed offline with the parsers of ``identifier.parse``.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from dppce.adapters import gs1
from dppce.adapters.did import did_web_url

# The parsers and the level table of identifier.parse and identifier.granularity, so that a
# draft and the checks read a carrier in the same way.
from dppce.adapters.identifier import _LEVELS, _PARSERS
from dppce.catalogue import load_data
from dppce.infrastructure.transport import origin_of

FAMILIES: Final = ("web", "gs1-resolver", "aas", "credentials")
EXAMPLES: Final = Path("profiles") / "family" / "examples"
# The public origin of the synthetic examples. A carrier origin replaces it in each endpoint.
EXAMPLE_ORIGIN: Final = "https://id.example.test"
_UNSAFE = re.compile(r"[\s\x00-\x1f\x7f]")

_UNPARSED = (
    "the engine could not parse the carrier with a scheme that it knows. "
    "Declare the scheme of the system, or leave unknown: the scheme steps are then inconclusive."
)
_REAL = "Replace the synthetic example value with the value of the system under test."
_NOTES: Final[dict[str, str]] = {
    "schema_version": "the file format version. Keep it.",
    "sut": "the identity of the system under test.",
    "sut.name": _REAL,
    "sut.version": _REAL,
    "sut.operator": "the organization that operates the system under test. " + _REAL,
    "sut.identifier": "a stable URI or URN of the system under test. " + _REAL,
    "profile": "the family profile. It must equal --profile of dppce plan and dppce run.",
    "product_category": "unknown fits each family profile. A family profile declares no product category.",
    "granularity": "item, model, or batch: the level that one carrier identifies. Declare the real level.",
    "identifier_scheme": "the scheme of the carrier identifiers, for example gs1-digital-link or https-url.",
    "signature_format": "jws, cose, or none: how the system signs a passport. Declare the real format.",
    "features": "the optional features of the family.",
    "features.*": "true only if the system implements it. An undeclared feature makes its step inconclusive.",
    "endpoints": "the base URLs that the steps read.",
    "endpoints.api": "the base URL of the passport API of the system under test.",
    "endpoints.aas": "the base URL of the AAS API of the system under test.",
    "endpoints.public_origin": "the public origin that the carrier identifiers name.",
    "endpoints.origin_override": (
        "the loopback reference system. Delete this line to test the real system. A person then "
        "confirms the public origin with --allow-remote-host or an authorization."
    ),
    "samples": "the inputs of the steps. A missing sample makes its step inconclusive.",
    "samples.identifier": "one carrier identifier of the system under test.",
    "samples.passport_id": "the passport id that {id} takes in the resource paths.",
    "samples.gs1_declared": "a file next to this IXIT. Put the declaration of the system there.",
    "samples.vc_json": "a file next to this IXIT. Put one credential of the system there.",
    "samples.aas_json": "a file next to this IXIT. Put the AAS file of the system there.",
    "samples.aas_shell_id": "the identifier of one shell in the AAS API of the system under test.",
    "resources": "the URL path templates under an endpoint.",
    "resources.*": "one resource of the API. Delete it if the system does not serve it.",
    "resources.*.endpoint": "the key of the endpoint in 'endpoints'.",
    "resources.*.path": "the path of the reference system. Write the path of the API under test.",
    "network": "what the IXIT asks for. A person confirms each origin on the command line.",
    "network.allowed_hosts": "the hosts that the steps may contact. Name the host of each endpoint.",
    "network.allow_private_hosts": (
        "the loopback and private hosts. A person confirms each with --allow-private-host ORIGIN."
    ),
    "network.max_requests": "the upper limit of requests for one run. Agree it with the system owner.",
    "network.contact": "your contact address for the User-Agent header.",
    "trust": "a label only. The operator gives the trust bundle with --trust.",
    "trust.policy_version": "a label of the trust policy. It selects nothing.",
    "observation": "how long the recording is kept.",
    "observation.retention_days": "a request only. The operator decides with --retention-days.",
}


@dataclass(frozen=True)
class Draft:
    ics: str
    ixit: str
    derived: dict[str, str]


def _parsed_schemes(carrier: str) -> list[str]:
    """The schemes whose parser accepts ``carrier``, the most specific first."""
    found = [] if isinstance(gs1.parse(carrier), gs1.Problem) else ["gs1-digital-link"]
    return found + [name for name, problem in _PARSERS.items() if problem(carrier) is None]


def derive(carrier: str, preferred: str) -> dict[str, str]:
    """The ICS and IXIT values that ``carrier`` gives. ``preferred`` wins when it parses.

    A GS1 Digital Link URI is also an https URL, and the web steps gate on https-url.
    """
    if not carrier or _UNSAFE.search(carrier):
        raise ValueError(
            "INIT.CARRIER.INVALID: the carrier is empty or has whitespace or a control character"
        )
    schemes = _parsed_schemes(carrier)
    if not schemes:
        return {"identifier_scheme": "unknown"}
    derived = {"identifier_scheme": preferred if preferred in schemes else schemes[0]}
    link = gs1.parse(carrier)
    if not isinstance(link, gs1.Problem) and link.key == "01":
        derived["granularity"] = next((name for ai, name in _LEVELS if ai in link.qualifiers), "model")
    url = did_web_url(carrier) if derived["identifier_scheme"] == "did-web" else carrier
    if url is not None and url.lower().startswith(("http://", "https://")):
        derived["public_origin"] = origin_of(url)
    return derived


def _note(path: str, notes: dict[str, str]) -> str:
    general = re.sub(r"^(\w+)\.[^.]+", r"\1.*", path)
    return notes.get(path) or notes.get(general) or _REAL


def _emit(node: dict[str, Any], notes: dict[str, str], path: str = "", depth: int = 0) -> list[str]:
    """YAML with a review comment above each key. PyYAML writes no comments, so the keys go one by one."""
    lines: list[str] = []
    pad = "  " * depth
    for key, value in node.items():
        here = f"{path}.{key}" if path else str(key)
        lines.append(f"{pad}# review: {_note(here, notes)}")
        if isinstance(value, dict) and value:
            lines.append(f"{pad}{key}:")
            lines += _emit(value, notes, here, depth + 1)
        else:
            # safe_dump quotes each value, so a carrier cannot become a comment or a key.
            dumped = yaml.safe_dump({key: value}, sort_keys=False, width=10_000)
            lines += [pad + line for line in dumped.splitlines()]
    return lines


def _document(kind: str, family: str, body: dict[str, Any], notes: dict[str, str]) -> str:
    header = [
        f"# Draft {kind} of dppce init for the profile family/{family}. It is untrusted input.",
        f"# Source: the synthetic example {EXAMPLES.as_posix()}/{family}.{kind.lower()}.yaml",
        "# for the loopback reference system. Check each field below its 'review:' comment.",
    ]
    return "\n".join([*header, *_emit(body, notes)]) + "\n"


def draft(family: str, carrier: str | None, root: Path) -> Draft:
    """Draft the ICS and the IXIT of ``family``. Without a carrier, they equal the example."""
    if family not in FAMILIES:
        raise ValueError(f"INIT.FAMILY.UNKNOWN: choose one of {', '.join(FAMILIES)}")
    ics: dict[str, Any] = load_data(root / EXAMPLES / f"{family}.ics.yaml")
    ixit: dict[str, Any] = load_data(root / EXAMPLES / f"{family}.ixit.yaml")
    notes = dict(_NOTES)
    derived: dict[str, str] = {}
    if carrier is not None:
        derived = derive(carrier, str(ics.get("identifier_scheme", "")))
        ics["identifier_scheme"] = derived["identifier_scheme"]
        if derived["identifier_scheme"] == "unknown":
            notes["identifier_scheme"] = _UNPARSED
        else:
            others = [s for s in _parsed_schemes(carrier) if s != derived["identifier_scheme"]]
            notes["identifier_scheme"] = (
                "derived from the carrier. Check that the system declares this scheme."
                + (f" The carrier also parses as: {', '.join(others)}." if others else "")
            )
        if "granularity" in derived:
            ics["granularity"] = derived["granularity"]
            notes["granularity"] = "derived from the key qualifiers of the carrier. Check it."
        if "public_origin" in derived:
            origin = derived["public_origin"]
            ixit["endpoints"] = {
                key: origin + value.removeprefix(EXAMPLE_ORIGIN)
                if value.startswith(EXAMPLE_ORIGIN)
                else value
                for key, value in ixit["endpoints"].items()
            }
            notes["endpoints.public_origin"] = "derived from the carrier. Check it."
            notes["endpoints.api"] = "the origin of the carrier. Check the base URL of the API."
        # A synthetic sample of the reference system must not stand in for the real system:
        # without the sample, its step is inconclusive, never a fail that the example caused.
        samples = {
            name: value
            for name, value in ixit.get("samples", {}).items()
            if name not in ("identifier", "passport_id") and "TEST-ONLY" not in value
        }
        ixit["samples"] = {"identifier": carrier, **samples}
        notes["samples"] += " The synthetic samples of the example were removed. Add those of the system."
        notes["samples.identifier"] = "the carrier that you gave to dppce init."
    return Draft(_document("ICS", family, ics, notes), _document("IXIT", family, ixit, notes), derived)


Step = tuple[str, str | None]


def next_steps(family: str, ics: Path, ixit: Path) -> list[Step]:
    """The commands that the operator must still run. A decision names what a person decides."""
    files = f"--profile family/{family} --ics {shlex.quote(str(ics))} --ixit {shlex.quote(str(ixit))}"
    return [
        (
            "dppce keys generate --out <REPORT-KEY> --passphrase-ref env:DPPCE_SECRET_<NAME> > <PUBLIC-JWK>",
            "The operator decides which key signs the reports. Skip it if a trust bundle exists.",
        ),
        (
            "dppce trust-bundle add-key --policy-version <POLICY-VERSION> --kid <KID> --issuer <ISSUER-ID> "
            "--purpose report --public-key <PUBLIC-JWK> --not-before <START> --not-after <END> "
            "--out <TRUST-BUNDLE>",
            "The operator decides what the test host trusts. The IXIT cannot decide it.",
        ),
        (
            "dppce authorize --document <AUTHORIZATION-DOCUMENT> --key <OWNER-KEY> --kid <OWNER-KID> "
            "--out <AUTHORIZATION>",
            "Only the system owner signs it. Run it for role secrets, for a write, or for a public "
            "origin without a remote-host confirmation.",
        ),
        (f"dppce plan {files} --trust <TRUST-BUNDLE>", None),
        (
            f"dppce run {files} --trust <TRUST-BUNDLE> --allow-private-host <ORIGIN> "
            "--issuer-name <ISSUER-NAME> --issuer-id <ISSUER-ID> --keys <DATA-KEYS> --create-data-key "
            "--out <RUN-DIR>",
            "A person confirms each origin, chooses the trust bundle, and names the issuer. "
            "For a public origin, confirm it with --allow-remote-host <ORIGIN> or give "
            "--authorization <AUTHORIZATION>.",
        ),
    ]
