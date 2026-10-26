"""The engine against committed third-party test vectors (gap D8-01).

Each vector set is vendored unchanged under ``tests/vectors/<set>/``. Oracle data that the engine
reads at run time is vendored under ``testpacks/data/<set>/``. ``catalogue/sources.yaml``
holds one ``test_vector`` record for each file with its SHA-256. The tests run with no network.

Agreement is evidence, not proof. Where the engine and a vector set disagree, the disagreement
is listed in ``EXPECTED_DISAGREEMENTS`` with the side that the engine follows:

- D-JCS-1: the engine refuses floats in canonical JSON (ADR 0006, architecture section 11.1).
  The JCS files ``structures`` and ``values`` hold floats.
- D-JWS-1: the engine accepts only its own ``typ`` (architecture section 11.3, ADR 0008). The
  valid Wycheproof ES256 tokens carry no ``typ``, so the engine profile refuses them with TYPE.
- D-JWS-2: the engine has one signing profile, ES256 on P-256 (ADR 0008). It refuses every
  vector of a group without an EC P-256 key, and never as BAD_SIGNATURE.
- D-DL-1: ``identifier.parse`` accepts only ``/01/<GTIN>/21/<serial>`` (architecture section 8,
  gap D4-06). It refuses other GS1 Digital Link forms that GS1 accepts.
- D-DL-2: the form ``gs1-dl`` of ``identifier.parse`` (``dppce.adapters.gs1``) refuses the
  deprecated convenience alphas, as dl.c does by default. Three dl.c cases enable them without an
  option setter, so the extraction cannot tell them from default cases.
- D-X509-1: one x509-limbo chain has a root with serial number 0. The cryptography library warns
  when it loads that root, and the suite turns warnings into errors. The path code finds the chain
  when the test ignores this one warning.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import warnings
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning

from dppce.adapters import gs1
from dppce.adapters.identifier import parse_gs1_digital_link
from dppce.catalogue import load_catalogue
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.jws import SignatureError, header_of, verify_compact
from dppce.evidence.x509path import trust_path
from dppce.infrastructure.resources import data_root
from dppce.models import TrustAnchor

ROOT = data_root()
VECTORS = Path(__file__).resolve().parent / "vectors"
JCS = VECTORS / "jcs"
JCS_NAMES = ("arrays", "french", "structures", "unicode", "values", "weird")
WYCHEPROOF = VECTORS / "wycheproof" / "TEST-ONLY-json_web_signature_test.json"
GS1_DL = VECTORS / "gs1-syntax-engine" / "dl.c"
TYP = "dppce-attestation+jws"
PATH_SHAPE = "the path does not have the form /01/<14 digits>/21/<serial>"

LIMBO_SERIAL_ZERO = {"fastly.com.limbo.json"}

EXPECTED_DISAGREEMENTS: dict[str, object] = {
    "D-JCS-1": {"structures", "values"},
    "D-JWS-1": {18, 378},
    "D-JWS-2": "every vector of a group without an EC P-256 key",
    # dl.c accepts these three only after `ctx->permitConvenienceAlphas = true`, an option that
    # has no setter call, so the extraction counts them as default-option cases.
    "D-DL-2": [
        "https://a/gtin/12312312312333",
        "https://a/gtin/12312312312333/ser/ABC123",
        "https://a/sscc/006141411234567890",
    ],
    # The anchor of this chain, a public root, has serial number 0. The cryptography library loads
    # it and warns (RFC 5280 requires a positive serial). The suite sets filterwarnings to error.
    "D-X509-1": LIMBO_SERIAL_ZERO,
}


# -- Provenance ---------------------------------------------------------------------------------


def _vector_files() -> dict[str, bytes]:
    # testpacks/data holds vendored oracle files that the engine reads at run time.
    paths = sorted([*VECTORS.rglob("*"), *(ROOT / "testpacks" / "data").rglob("*")])
    return {
        path.relative_to(ROOT).as_posix(): path.read_bytes()
        for path in paths
        if path.is_file() and path.name != "README.md" and not path.name.startswith(".")
    }


def test_each_vendored_vector_file_has_one_source_record_with_its_hashes() -> None:
    files = _vector_files()
    records = [s for s in load_catalogue(ROOT).sources if s.source_type == "test_vector"]
    assert sorted(r.id for r in records) == sorted(files)
    for record in records:
        data = files[record.id]
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git blob id
        commit = re.fullmatch(r"commit ([0-9a-f]{40})", record.edition_or_version)
        assert record.sha256 == hashlib.sha256(data).hexdigest(), record.id
        assert f"Git blob {blob}" in record.hash_note, record.id
        assert commit is not None, record.id
        assert record.official_url.startswith("https://github.com/"), record.id
        assert commit[1] in record.official_url, record.id
        assert record.license_or_reuse_terms.startswith("Apache-2.0"), record.id


# -- RFC 8785 (JCS) -----------------------------------------------------------------------------


def _jcs(name: str) -> tuple[bytes, bytes]:
    return (JCS / "input" / f"{name}.json").read_bytes(), (JCS / "output" / f"{name}.json").read_bytes()


def _jcs_disagreements() -> set[str]:
    refused = set()
    for name in JCS_NAMES:
        source, expected = _jcs(name)
        try:
            actual = canonical_bytes(parse_strict(source))
        except CanonicalizationError as exc:
            reason = str(exc)
        else:
            assert actual == expected, name
            continue
        assert "floats are not permitted" in reason, name
        refused.add(name)
    return refused


def test_jcs_vectors_agree_except_the_documented_float_refusals() -> None:
    assert _jcs_disagreements() == EXPECTED_DISAGREEMENTS["D-JCS-1"]


@pytest.mark.parametrize("name", JCS_NAMES)
def test_the_rfc8785_library_agrees_on_every_jcs_vector(name: str) -> None:
    source, expected = _jcs(name)
    assert rfc8785.dumps(json.loads(source)) == expected


# -- Wycheproof JWS -----------------------------------------------------------------------------


def _wycheproof() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    document = json.loads(WYCHEPROOF.read_bytes())
    out = []
    for group in document["testGroups"]:
        key = group.get("public") or {}
        for test in group["tests"]:
            if not isinstance(test.get("jws"), str) or test.get("result") not in ("valid", "invalid"):
                pytest.fail(f"unexpected vector shape: tcId {test.get('tcId')}")
            out.append((key, test))
    return out


def _is_p256(key: dict[str, Any]) -> bool:
    return key.get("kty") == "EC" and key.get("crv") == "P-256"


def _payload(token: str) -> bytes:
    part = token.split(".")[1]
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def test_wycheproof_es256_vectors_agree_on_the_signature_step() -> None:
    checked = 0
    for key, test in _wycheproof():
        if not _is_p256(key):
            continue
        checked += 1
        token = test["jws"]
        # The vectors carry no typ, so the test passes the token's own typ to reach the key and
        # signature checks through the public path.
        try:
            typ = header_of(token).get("typ")
            payload = verify_compact(token, key, typ=typ)
        except SignatureError:
            assert test["result"] == "invalid", test["tcId"]
            continue
        assert test["result"] == "valid", f"tcId {test['tcId']} was accepted: {test['comment']}"
        assert payload == _payload(token), test["tcId"]
    assert checked == 41


def _profile_disagreements() -> dict[str, object]:
    valid_p256: set[int] = set()
    for key, test in _wycheproof():
        with pytest.raises(SignatureError) as caught:
            verify_compact(test["jws"], key, typ=TYP)
        if test["result"] != "valid":
            continue
        # Rule 7: a token outside the profile is never reported as a bad signature.
        assert caught.value.code != "BAD_SIGNATURE", test["tcId"]
        if _is_p256(key):
            assert caught.value.code == "TYPE", test["tcId"]
            valid_p256.add(test["tcId"])
        else:
            assert caught.value.code in {"ALGORITHM", "KEY", "MALFORMED", "TYPE"}, test["tcId"]
    return {"D-JWS-1": valid_p256, "D-JWS-2": EXPECTED_DISAGREEMENTS["D-JWS-2"]}


def test_the_engine_profile_refuses_every_wycheproof_vector_and_never_calls_a_valid_one_a_bad_signature() -> (
    None
):
    _profile_disagreements()


def test_the_computed_disagreements_equal_the_listed_ones() -> None:
    computed = {
        "D-JCS-1": _jcs_disagreements(),
        **_profile_disagreements(),
        "D-DL-2": [uri for uri, _ in _gs1_dl_disagreements()],
        "D-X509-1": _limbo_warned(),
    }
    assert computed == EXPECTED_DISAGREEMENTS


# -- GS1 Digital Link URI syntax ----------------------------------------------------------------

_LITERALS = r'((?:"(?:[^"\\\n]|\\.)*"\s*)+)'
_CALL = re.compile(
    rf"test_parseDLuri\(\s*(?P<err>\w+)\s*,\s*(?P<uri>{_LITERALS}),\s*(?P<out>{_LITERALS})\)\s*;"
    r"|gs1_encoder_set(?P<setter>\w+)\(\s*ctx\s*,\s*(?P<args>[^;()]*)\)\s*;"
)


def _strip_comments(text: str) -> str:
    """Remove C comments outside string and character literals. A regex strip also removes the
    ``//`` of a URL inside a string."""
    out: list[str] = []
    i, quote = 0, ""
    while i < len(text):
        char = text[i]
        if quote:
            out.append(text[i : i + 2] if char == "\\" else char)
            i += 2 if char == "\\" else 1
            quote = "" if char == quote else quote
        elif char in "\"'":
            quote = char
            out.append(char)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            assert end >= 0, "an unterminated comment"
            out.append(" ")
            i = end + 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _c_string(literals: str) -> str:
    def unescape(match: re.Match[str]) -> str:
        if match[1] not in ('"', "\\"):
            pytest.fail(f"unknown C escape \\{match[1]} in {literals!r}")
        return match[1]

    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', literals)
    return "".join(re.sub(r"\\(.)", unescape, part) for part in parts)


def _gs1_cases() -> tuple[list[tuple[str, str]], int, int]:
    """Return the default-option (expected error, URI) cases, the skipped count, and the call count."""
    cases, skipped, calls = _gs1_cases_with_output()
    return [(err, uri) for err, uri, _ in cases], skipped, calls


def _gs1_cases_with_output() -> tuple[list[tuple[str, str, str]], int, int]:
    """As ``_gs1_cases``, with the expected AI element string of each case (``^`` is FNC1)."""
    text = GS1_DL.read_bytes().decode("utf-8")
    start, end = "void test_dl_parseDLuri(void)", "void test_dl_URIunescape(void)"
    assert text.count(start) == 1
    assert text.count(end) == 1
    body = _strip_comments(text[text.index(start) : text.index(end)])
    active: set[str] = set()
    cases: list[tuple[str, str, str]] = []
    skipped = 0
    for match in _CALL.finditer(body):
        if match["setter"] is None:
            if active:
                skipped += 1
            else:
                cases.append((match["err"], _c_string(match["uri"]), _c_string(match["out"])))
            continue
        args = [a.strip() for a in match["args"].split(",")]
        name, value = match["setter"], args[-1]
        if name.startswith("Permit"):
            non_default = value == "true"
        elif name == "ValidationEnabled":
            non_default = value == "false"
        else:
            pytest.fail(f"unknown option setter {name}")
        option = name if len(args) == 1 else f"{name}:{args[0]}"
        if non_default:
            active.add(option)
        else:
            active.discard(option)
    calls = len(re.findall(r"\btest_parseDLuri\(", body)) - 1  # minus the #define
    return cases, skipped, calls


GS1_CASES, GS1_SKIPPED, GS1_CALLS = _gs1_cases()


def test_gs1_extraction_finds_every_default_option_case() -> None:
    assert len(GS1_CASES) + GS1_SKIPPED == GS1_CALLS
    assert (len(GS1_CASES), GS1_SKIPPED) == (108, 13)
    assert sum(err == "OK" for err, _ in GS1_CASES) == 63


def test_gs1_engine_never_accepts_what_the_reference_rejects() -> None:
    rejected = [uri for err, uri in GS1_CASES if err != "OK"]
    assert len(rejected) == 45
    assert [uri for uri in rejected if parse_gs1_digital_link(uri) is None] == []


def test_gs1_every_disagreement_is_the_documented_path_shape_refusal() -> None:
    results = [(err, uri, parse_gs1_digital_link(uri)) for err, uri in GS1_CASES]
    disagreements = [(err, uri, reason) for err, uri, reason in results if (err == "OK") != (reason is None)]
    assert len(disagreements) == 62
    assert {(err, reason) for err, _, reason in disagreements} == {("OK", PATH_SHAPE)}
    accepted = [uri for err, uri, reason in results if err == "OK" and reason is None]
    assert accepted == ["https://id.gs1.org/01/09520123456788/21/12345"]


# -- GS1 Digital Link URI syntax: the form gs1-dl ------------------------------------------------

GS1_CASES_WITH_OUTPUT = _gs1_cases_with_output()[0]


def _element_string(link: gs1.DigitalLink) -> str:
    """The AI element string that dl.c writes: FNC1 first and after each variable-length AI."""
    out, fnc1 = [], True
    for ai, value in link.elements:
        out.append(("^" if fnc1 else "") + ai + value)
        fnc1 = not gs1.dictionary().entries[ai].fixed
    return "".join(out)


def test_gs1_dl_never_accepts_what_the_reference_rejects() -> None:
    rejected = [uri for err, uri in GS1_CASES if err != "OK"]
    assert len(rejected) == 45
    assert [uri for uri in rejected if isinstance(gs1.parse(uri), gs1.DigitalLink)] == []
    # A rejected case is a fault of the URI, never the engine limit COMPRESSED.
    assert [uri for uri in rejected if getattr(gs1.parse(uri), "rule", None) == "COMPRESSED"] == []


def _gs1_dl_disagreements() -> list[tuple[str, gs1.DigitalLink | gs1.Problem]]:
    results = [(err, uri, gs1.parse(uri)) for err, uri, _ in _gs1_cases_with_output()[0]]
    return [
        (uri, result) for err, uri, result in results if (err == "OK") != isinstance(result, gs1.DigitalLink)
    ]


def test_gs1_dl_disagrees_only_on_the_convenience_alphas() -> None:
    disagreements = _gs1_dl_disagreements()
    assert [uri for uri, _ in disagreements] == EXPECTED_DISAGREEMENTS["D-DL-2"]
    assert {result.rule for _, result in disagreements if isinstance(result, gs1.Problem)} == {"KEY"}


def test_gs1_dl_extracts_the_element_string_of_every_accepted_case() -> None:
    accepted = [
        (uri, out, result)
        for err, uri, out in GS1_CASES_WITH_OUTPUT
        if err == "OK" and isinstance(result := gs1.parse(uri), gs1.DigitalLink)
    ]
    assert len(accepted) == 60
    assert [(uri, out) for uri, out, result in accepted if _element_string(result) != out] == []


# -- x509-limbo path validation ------------------------------------------------------------------

LIMBO = VECTORS / "x509-limbo" / "online"


def _limbo() -> dict[str, dict[str, Any]]:
    return {path.name: json.loads(path.read_bytes()) for path in sorted(LIMBO.glob("*.limbo.json"))}


def _cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _limbo_path(case: dict[str, Any], *, anchors: bool = True) -> list[x509.Certificate] | None:
    trusted = [
        TrustAnchor(name=f"TEST-ONLY-limbo-{i}", certificate_pem=pem)
        for i, pem in enumerate(case["trusted_certs"])
    ]
    return trust_path(
        _cert(case["peer_certificate"]),
        [_cert(pem) for pem in case["untrusted_intermediates"]],
        trusted if anchors else [],
    )


def test_limbo_vector_set_holds_only_successful_server_chains() -> None:
    cases = _limbo()
    assert len(cases) == 14
    # trust_path ignores time, names, and usage. Only SUCCESS chains of a SERVER validation are
    # claimed, so a vector of another kind must not enter the set unnoticed.
    assert {(c["expected_result"], c["validation_kind"]) for c in cases.values()} == {("SUCCESS", "SERVER")}


@pytest.mark.parametrize("name", sorted(_limbo()))
def test_trust_path_finds_the_limbo_chain_and_only_with_its_anchor(name: str) -> None:
    case = _limbo()[name]
    with warnings.catch_warnings():
        if name in LIMBO_SERIAL_ZERO:
            # The suite turns every warning into an error. The anchor loads with the warning only.
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        path = _limbo_path(case)
        assert path is not None, name
        assert _pem(path[0]) == case["peer_certificate"]
        assert _pem(path[-1]) in case["trusted_certs"]
        assert len(path) == len(case["untrusted_intermediates"]) + 2
        assert _limbo_path(case, anchors=False) is None


def _limbo_warned() -> set[str]:
    warned = set()
    for name, case in _limbo().items():
        try:
            _limbo_path(case)
        except CryptographyDeprecationWarning:
            warned.add(name)
    return warned
