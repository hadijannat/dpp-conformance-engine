"""Property tests of the parsers and the verifier entry point (gap D8-07).

Each test states an invariant and checks it on generated input. Generation is derandomized,
so a run is repeatable. The keys of the signed cases are still generated for each run.
"""

from __future__ import annotations

import base64
import contextlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from dppce.catalogue import CatalogueError, load_data
from dppce.evidence.canonical import MAX_SAFE_INTEGER, CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import _COMPACT, LocalSigner, SignatureError, header_of, sign_compact, verify_compact
from dppce.infrastructure.redaction import _SENSITIVE_PARAMETER, REMOVED, redact_url
from dppce.models import TrustBundle
from dppce.verifier import verify_json
from tests.support import ISSUER, make_envelope

SETTINGS = settings(max_examples=200, deadline=None, derandomize=True)
TYP = "dppce-attestation+jws"
CHECKED_AT = datetime(2026, 10, 13, 13, tzinfo=UTC)
DIMENSIONS = {
    "structure", "ordering", "results_root", "records_root", "counts", "signature", "issuer_trust",
    "manual_results", "status", "timestamp",
}  # fmt: skip
DEEP = "[" * 100_000

TEXT = st.text(st.characters(exclude_categories=("Cs",)), max_size=20)
# The domain of the engine's canonical bodies: no float, exact integers, text without surrogates.
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER) | TEXT,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(TEXT, inner, max_size=4),
    max_leaves=12,
)


# -- canonical.parse_strict ---------------------------------------------------------------------


@SETTINGS
@given(st.binary(max_size=300) | st.text(max_size=300))
@example(DEEP)
@example(b"\xff")
@example('{"a":1,"a":2}')
@example("1e999")
@example("NaN")
def test_parse_strict_raises_only_its_own_error(raw: bytes | str) -> None:
    with contextlib.suppress(CanonicalizationError):
        parse_strict(raw)


@SETTINGS
@given(JSON_VALUES)
def test_parse_strict_reads_back_every_canonical_value(value: Any) -> None:
    raw = canonical_bytes(value)
    assert parse_strict(raw) == value
    assert canonical_bytes(parse_strict(raw)) == raw


# -- catalogue.load_data ------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("load_data")


def _load(workdir: Path, name: str, raw: bytes) -> Any:
    path = workdir / name
    path.write_bytes(raw)
    return load_data(path)


@SETTINGS
@given(raw=st.binary(max_size=300))
@example(raw=DEEP.encode())
@example(raw=b"? [a]\n: 1\n")
@example(raw=b"!!python/object/apply:os.system [x]\n")
def test_load_data_raises_only_a_catalogue_error(workdir: Path, raw: bytes) -> None:
    for name in ("x.yaml", "x.json"):
        with contextlib.suppress(CatalogueError):
            _load(workdir, name, raw)


@SETTINGS
@given(value=JSON_VALUES, key=TEXT, first=JSON_VALUES, second=JSON_VALUES)
def test_load_data_reads_back_dumped_values_and_refuses_a_repeated_key(
    workdir: Path, value: Any, key: str, first: Any, second: Any
) -> None:
    assert _load(workdir, "v.json", json.dumps(value).encode()) == value
    assert _load(workdir, "v.yaml", yaml.safe_dump(value).encode()) == value
    repeated_yaml = yaml.safe_dump({key: first}) + yaml.safe_dump({key: second})
    repeated_json = (
        "{" + f"{json.dumps(key)}:{json.dumps(first)},{json.dumps(key)}:{json.dumps(second)}" + "}"
    )
    with pytest.raises(CatalogueError):
        _load(workdir, "r.yaml", repeated_yaml.encode())
    with pytest.raises(CatalogueError):
        _load(workdir, "r.json", repeated_json.encode())


# -- redaction.redact_url -----------------------------------------------------------------------

_NAMES = st.sampled_from(["token", "sig", "key", "code", "api_key", "Session", "page", "q", "lang", "id"])
# A '#' or '&' in a value would start a fragment or a new parameter. st.text() above covers both.
_VALUES = st.text(
    st.characters(codec="ascii", exclude_categories=("Cc",), exclude_characters="#&"), max_size=8
)


@st.composite
def _urls(draw: st.DrawFn, *, clean: bool = False) -> str:
    scheme = draw(st.sampled_from(["http://", "https://", "ftp://", ""]))
    userinfo = "" if clean else draw(st.sampled_from(["", "user@", "user:secret@", ":@"]))
    host = draw(st.sampled_from(["a.example", "127.0.0.1", "[::1]", "id.example.test:8443", ""]))
    path = draw(st.sampled_from(["", "/", "/01/09506000134352/21/EV0001", "/a b/%41"]))
    names = _NAMES.filter(lambda n: not _SENSITIVE_PARAMETER.search(n)) if clean else _NAMES
    pairs = draw(st.lists(st.tuples(names, _VALUES), max_size=3))
    query = ("?" + "&".join(f"{n}={v}" for n, v in pairs)) if pairs else ""
    fragment = "" if clean else draw(st.sampled_from(["", "#", "#f", "#access_token=x"]))
    return f"{scheme}{userinfo}{host}{path}{query}{fragment}"


@SETTINGS
@given(st.text(max_size=80) | _urls())
def test_redact_url_is_idempotent_and_leaves_no_secret(url: str) -> None:
    result = redact_url(url)
    assert redact_url(result) == result
    if result == REMOVED:
        return
    parts = urlsplit(result)
    assert (parts.username, parts.password, parts.fragment) == (None, None, "")
    assert not result.endswith("#")
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if _SENSITIVE_PARAMETER.search(name):
            assert value == REMOVED, result


@SETTINGS
@given(_urls(clean=True))
def test_redact_url_returns_a_clean_url_unchanged(url: str) -> None:
    assert redact_url(url) == url


# -- JWS compact parsing ------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_HEADERS = st.dictionaries(
    st.sampled_from(["alg", "typ", "kid", "crit", "x5c", "b64"]), JSON_VALUES, max_size=4
).map(lambda h: _b64(json.dumps(h).encode()))
_PARTS = st.lists(_HEADERS | st.binary(max_size=40).map(_b64) | st.text(max_size=10), min_size=1, max_size=4)


@SETTINGS
@given(token=st.text(max_size=200) | _PARTS.map(".".join))
def test_jws_parsing_raises_only_a_signature_error(signer: LocalSigner, token: str) -> None:
    codes = []
    for check in (lambda: header_of(token), lambda: verify_compact(token, signer.public_jwk(), typ=TYP)):
        try:
            check()
        except SignatureError as exc:
            codes.append(exc.code)
    if not _COMPACT.fullmatch(token):
        assert codes == ["MALFORMED", "MALFORMED"]


@SETTINGS
@given(payload=st.binary(max_size=300), typ=TEXT.filter(bool))
def test_a_signed_token_reads_back_its_header_and_payload(
    signer: LocalSigner, payload: bytes, typ: str
) -> None:
    token = sign_compact(payload, signer, typ=typ)
    assert header_of(token) == {"alg": "ES256", "kid": signer.key_id, "typ": typ}
    assert verify_compact(token, signer.public_jwk(), typ=typ) == payload


# -- verifier entry point -----------------------------------------------------------------------


@SETTINGS
@given(raw=st.text(max_size=200) | st.binary(max_size=200) | JSON_VALUES.map(json.dumps))
def test_verify_json_never_raises_and_never_completes_on_other_input(
    trust: TrustBundle, raw: str | bytes
) -> None:
    report = verify_json(raw, trust, CHECKED_AT)
    assert report.complete is False
    assert {d.name for d in report.dimensions} == DIMENSIONS


@pytest.fixture(scope="module")
def signed_raw(signer: LocalSigner, trust: TrustBundle) -> bytes:
    envelope = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    raw = canonical_bytes(envelope)
    assert verify_json(raw, trust, CHECKED_AT).complete is True
    return raw


@SETTINGS
@given(data=st.data())
def test_one_changed_byte_in_a_signed_envelope_never_verifies_as_complete(
    signed_raw: bytes, trust: TrustBundle, data: st.DataObject
) -> None:
    position = data.draw(st.integers(0, len(signed_raw) - 1), label="position")
    value = data.draw(st.integers(0, 255).filter(lambda v: v != signed_raw[position]), label="value")
    changed = signed_raw[:position] + bytes([value]) + signed_raw[position + 1 :]
    try:
        same = parse_strict(changed) == parse_strict(signed_raw)
    except CanonicalizationError:
        same = False
    if not same:
        assert verify_json(changed, trust, CHECKED_AT).complete is False
