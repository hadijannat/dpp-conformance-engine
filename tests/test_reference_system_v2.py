"""The reference system v2: same answers to old requests, plus HEAD, OPTIONS, and the resolver surface.

The snapshot in ``tests/fixtures/reference-system-snapshot.json`` was taken from the reference
system at 4990be0, before v2. Each request that a route answered then must get the same status,
the same headers, and the same body now, for every fault flag and role. This keeps the method
validation figures and the existing recordings the same.

Rewrite the snapshot only when a fixture body changes on purpose, and say why in the commit:
``uv run python -m tests.test_reference_system_v2 --write``.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from validation.rig import FIXTURES, AlternateLayout

from dppce.evidence.jws import header_of, payload_of, public_jwk_of, verify_compact
from dppce.infrastructure.reference_server import ReferenceServer, ReferenceSystem

SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "reference-system-snapshot.json"
# The fault flags of the reference system at 4990be0. A flag added later is new behavior.
BASE_FLAGS = (
    "api_wrong_content_type", "api_schema_violation", "leak_fetch", "leak_export", "leak_search",
    "leak_error", "leak_html", "sig_invalid", "sig_untrusted_issuer", "cert_expired", "id_mismatch",
    "resolver_404", "redirect_out_of_scope", "data_wrong_type", "data_missing_required", "data_stale",
    "data_wrong_unit", "data_relationship", "context_invalid", "registry_inconsistent",
    "version_undeclared_change", "over_restrict_legitimate_interest",
    "leak_supplier_to_legitimate_interest", "leak_usage_log_anonymous", "deny_all",
    "resolver_5xx", "resolver_html", "resolver_divergent",
)  # fmt: skip
_TOKENS = sorted(json.loads((FIXTURES / "roles.json").read_text(encoding="utf-8"))["tokens"])
# Anonymous with no Accept header, anonymous with the Accept header of the engine transport,
# and each role token with that header.
_VARIANTS: tuple[dict[str, str], ...] = (
    {},
    {"Accept": "*/*"},
    *({"Accept": "*/*", "Authorization": f"Bearer {token}"} for token in _TOKENS),
)


def _items() -> list[tuple[str, str]]:
    found = []
    for path in sorted((FIXTURES / "items").glob("*.json")):
        gtin, serial = json.loads(path.read_text(encoding="utf-8"))["id"].split("/01/")[1].split("/21/")
        found.append((gtin, serial))
    return found


def reference_targets() -> list[str]:
    """Every route of the reference layout, and paths that the engine sends for seeded faults."""
    targets = []
    for gtin, serial in _items():
        ident = f"{gtin}-{serial}"
        targets += [
            f"/01/{gtin}/21/{serial}",
            f"/dpp/{ident}",
            f"/dpp/{ident}/model",
            f"/dpp/{ident}/signed",
            f"/dpp/{ident}/versions",
            f"/dpp/{ident}/export",
            f"/dpp/{ident}.html",
            f"/dpp/{ident}/does-not-exist",
            f"/registry/{ident}",
            f"/search?q={serial}",
        ]
    targets += [
        "/01/09506000134352/21/UNKNOWN0",
        "/01/9506000134352/21/EV0001",  # QR fixture of fault F-30: a GTIN of 13 digits
        "/01/" + quote("٠٩٥٠٦٠٠٠١٣٤٣٥٢") + "/21/EV0001",  # QR fixture of fault F-31
        "/01/09506000134352",
        "/",
        "/search",
        "/search?q=",
        "/search?q=ev",
        "/registry/09506000134352-NOPE0",
        "/dpp/09506000134352-NOPE0",
    ]
    return targets


def alternate_targets() -> list[str]:
    targets = []
    for gtin, serial in _items():
        targets += [f"/01/{gtin}/21/{serial}", f"/lookup/{gtin}/{serial}", f"/find?q={serial}"]
        targets += [f"/passports/{gtin}/{serial}/{what}" for what in ("data", "model-data", "jws")]
        targets += [f"/passports/{gtin}/{serial}/{what}" for what in ("history", "export", "view", "missing")]
        targets += [f"/dpp/{gtin}-{serial}"]
    return targets


def _body(media_type: str, body: bytes) -> str:
    if media_type == "application/jose":
        # ES256 signs with a random nonce, so only the signature length is stable.
        header, payload, signature = body.decode("ascii").split(".")
        return f"{header}.{payload}.<{len(signature)} characters>"
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _exchange(origin: str, target: str, headers: dict[str, str]) -> list[Any]:
    host, port = origin.removeprefix("http://").rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
    seen = []
    for name, value in response.getheaders():
        if name == "Date":
            continue
        # The second part of the Server value names the Python version of the host.
        seen.append([name, value.split(" ")[0] if name == "Server" else value])
    return [response.status, seen, _body(response.getheader("Content-Type", ""), body)]


def observe(origin: str, targets: list[str]) -> dict[str, list[Any]]:
    return {target: [_exchange(origin, target, dict(v)) for v in _VARIANTS] for target in targets}


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def take_snapshot() -> dict[str, Any]:
    """The detail of every answer without a fault, and one digest for each fault flag."""
    snapshot: dict[str, Any] = {}
    layouts = (
        ("reference", ReferenceSystem, reference_targets()),
        ("alternate", AlternateLayout, alternate_targets()),
    )
    for layout, kind, targets in layouts:
        system = kind(FIXTURES)
        # One server for each layout: a server stop waits for its poll interval.
        with ReferenceServer(FIXTURES, system=system) as server:
            snapshot[layout] = {"none": observe(server.origin, targets)}
            for flag in BASE_FLAGS:
                system.faults = frozenset({flag})
                snapshot[layout][flag] = _digest(observe(server.origin, targets))
    return snapshot


def test_every_old_request_gets_the_answer_of_the_base_version() -> None:
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    actual = json.loads(json.dumps(take_snapshot()))
    for layout in ("reference", "alternate"):
        for target, answers in expected[layout]["none"].items():
            assert actual[layout]["none"][target] == answers, (layout, target)
        changed = [flag for flag in BASE_FLAGS if actual[layout][flag] != expected[layout][flag]]
        assert changed == [], layout


# -- new behavior -------------------------------------------------------------------------------

EV = ("09506000134352", "EV0001")
RESOLVER = f"/01/{EV[0]}/21/{EV[1]}"
LINKSET_TYPE = "application/linkset+json"


def _call(
    origin: str, method: str, target: str, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes]:
    host, port = origin.removeprefix("http://").rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        connection.request(method, target, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
    seen = {name: value for name, value in response.getheaders() if name != "Date"}
    return response.status, seen, body


def test_head_gives_the_status_and_headers_of_get_without_a_body() -> None:
    for faults in (frozenset(), frozenset({"deny_all"})):
        with ReferenceServer(FIXTURES, faults=faults) as server:
            for target in [*reference_targets(), f"{RESOLVER}?linkType=linkset", "/.well-known/gs1resolver"]:
                get_status, get_headers, get_body = _call(server.origin, "GET", target)
                head_status, head_headers, head_body = _call(server.origin, "HEAD", target)
                assert (head_status, head_headers, head_body) == (get_status, get_headers, b""), target
                assert head_headers["Content-Length"] == str(len(get_body)), target


def test_options_names_the_read_methods_and_the_cors_headers() -> None:
    with ReferenceServer(FIXTURES) as server:
        for target in ("*", RESOLVER, f"/dpp/{EV[0]}-{EV[1]}", "/.well-known/gs1resolver"):
            status, headers, body = _call(
                server.origin, "OPTIONS", target, {"Origin": "https://a.example.test"}
            )
            assert (status, body) == (204, b""), target
            assert headers["Allow"] == "GET, HEAD, OPTIONS"
            assert headers["Access-Control-Allow-Origin"] == "*"
            assert headers["Access-Control-Allow-Methods"] == "GET, HEAD, OPTIONS"
            assert headers["Access-Control-Allow-Headers"] == "Accept, Authorization"
            assert "Content-Length" not in headers
            assert "Content-Type" not in headers


def test_under_deny_all_only_the_core_answers_and_options_is_forbidden() -> None:
    with ReferenceServer(FIXTURES, faults=frozenset({"deny_all"})) as server:
        # The core has no route for this path, so a 403 here shows that no family answered.
        assert _call(server.origin, "GET", "/.well-known/gs1resolver")[0] == 403
        assert _call(server.origin, "OPTIONS", RESOLVER)[0] == 403


def test_the_reference_system_has_no_write_operation() -> None:
    with ReferenceServer(FIXTURES) as server:
        before = _call(server.origin, "GET", f"/dpp/{EV[0]}-{EV[1]}")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, _, _ = _call(server.origin, method, f"/dpp/{EV[0]}-{EV[1]}")
            assert status == 501, method
        assert _call(server.origin, "GET", f"/dpp/{EV[0]}-{EV[1]}") == before


def _linkset(origin: str, target: str, headers: dict[str, str] | None = None) -> Any:
    status, seen, body = _call(origin, "GET", target, headers)
    assert (status, seen["Content-Type"], seen["Vary"]) == (200, LINKSET_TYPE, "Accept"), target
    return json.loads(body)


def test_the_resolver_answers_a_linkset_on_request() -> None:
    expected = {
        "linkset": [
            {
                "anchor": f"https://id.example.test{RESOLVER}",
                "https://dppce.example.test/rel/passport": [
                    {"href": f"https://id.example.test/dpp/{EV[0]}-{EV[1]}", "type": "application/json"}
                ],
            }
        ]
    }
    with ReferenceServer(FIXTURES) as server:
        assert _linkset(server.origin, f"{RESOLVER}?linkType=linkset") == expected
        assert _linkset(server.origin, f"{RESOLVER}?linkType=all") == expected
        assert _linkset(server.origin, RESOLVER, {"Accept": LINKSET_TYPE}) == expected
        assert (
            _linkset(server.origin, RESOLVER, {"Accept": f"application/json;q=0.5, {LINKSET_TYPE}"})
            == expected
        )


def test_the_resolver_redirects_to_the_passport_for_any_other_request() -> None:
    accepts = ("*/*", "application/json", f"{LINKSET_TYPE};q=0", f"application/json, {LINKSET_TYPE};q=0.5")
    with ReferenceServer(FIXTURES) as server:
        default = _call(server.origin, "GET", RESOLVER, {"Accept": "*/*"})
        assert (default[0], default[1]["Location"]) == (303, f"/dpp/{EV[0]}-{EV[1]}")
        for accept in accepts:
            assert _call(server.origin, "GET", RESOLVER, {"Accept": accept}) == default, accept
        assert _call(server.origin, "GET", f"{RESOLVER}?linkType=gs1:dpp") == default


def test_a_resolver_fault_also_applies_to_a_linkset_request() -> None:
    for flag, status in (("resolver_404", 404), ("resolver_5xx", 503), ("deny_all", 403)):
        with ReferenceServer(FIXTURES, faults=frozenset({flag})) as server:
            assert _call(server.origin, "GET", f"{RESOLVER}?linkType=linkset")[0] == status, flag
    with ReferenceServer(FIXTURES) as server:
        assert _call(server.origin, "GET", f"/01/{EV[0]}/21/UNKNOWN0?linkType=linkset")[0] == 404


def test_the_linkset_follows_the_rig_layout() -> None:
    with ReferenceServer(FIXTURES, system=AlternateLayout(FIXTURES)) as server:
        document = _linkset(server.origin, f"{RESOLVER}?linkType=linkset")
    link = document["linkset"][0]["https://dppce.example.test/rel/passport"][0]
    assert link["href"] == f"https://id.example.test/passports/{EV[0]}/{EV[1]}/data"


def test_the_resolver_serves_a_synthetic_description_file() -> None:
    with ReferenceServer(FIXTURES) as server:
        status, headers, body = _call(server.origin, "GET", "/.well-known/gs1resolver")
    assert (status, headers["Content-Type"]) == (200, "application/json")
    document = json.loads(body)
    assert document["resolverRoot"] == "https://id.example.test"
    assert document["supportedPrimaryKeys"] == ["01"]
    assert "synthetic" in document["name"]


def test_flag_resolver_linkset_as_passport_answers_the_default_request_with_a_linkset() -> None:
    with ReferenceServer(FIXTURES) as server:
        expected = _linkset(server.origin, f"{RESOLVER}?linkType=linkset")
    with ReferenceServer(FIXTURES, faults=frozenset({"resolver_linkset_as_passport"})) as server:
        assert _linkset(server.origin, RESOLVER) == expected
        assert _linkset(server.origin, RESOLVER, {"Accept": "*/*"}) == expected
        # A route that is not the resolver keeps its core answer.
        assert _call(server.origin, "GET", f"/dpp/{EV[0]}-{EV[1]}")[1]["Content-Type"] == "application/json"


def test_flag_signed_jws_json_serves_the_compact_token_as_flattened_jws_json() -> None:
    signed = f"/dpp/{EV[0]}-{EV[1]}/signed"
    with ReferenceServer(FIXTURES) as server:
        compact = _call(server.origin, "GET", signed)[2].decode("ascii")
    with ReferenceServer(FIXTURES, faults=frozenset({"signed_jws_json"})) as server:
        status, headers, body = _call(server.origin, "GET", signed)
        other = _call(server.origin, "GET", f"/dpp/{EV[0]}-{EV[1]}")
    assert (status, headers["Content-Type"]) == (200, "application/jose+json")
    document = json.loads(body)
    assert sorted(document) == ["payload", "protected", "signature"]
    token = ".".join((document["protected"], document["payload"], document["signature"]))
    # The ES256 signature is randomized, so the header and the payload equal the compact token's.
    assert token.split(".")[:2] == compact.split(".")[:2]
    header = header_of(token)
    assert header["typ"] == "dpp+jws"
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    assert isinstance(leaf_key := leaf.public_key(), ec.EllipticCurvePublicKey)
    assert verify_compact(token, public_jwk_of(leaf_key), typ="dpp+jws") == payload_of(compact)
    assert other[1]["Content-Type"] == "application/json"


def test_fault_flags_are_the_core_flags_and_the_flags_of_each_family() -> None:
    from dppce.infrastructure import reference, reference_server  # noqa: PLC0415 - the unit under test

    family_flags = [family.FLAGS for family in reference.FAMILIES]
    assert reference_server.CORE_FAULTS.union(*family_flags) == reference_server.FAULTS
    # No flag is in two places.
    assert len(reference_server.FAULTS) == len(reference_server.CORE_FAULTS) + sum(map(len, family_flags))
    assert set(BASE_FLAGS) <= reference_server.FAULTS
    with pytest.raises(ValueError, match="no_such_flag"):
        ReferenceSystem(FIXTURES, frozenset({"no_such_flag"}))


def test_a_new_family_needs_one_families_entry_and_no_core_edit(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace  # noqa: PLC0415 - only this test needs it

    from dppce.infrastructure import reference  # noqa: PLC0415 - the unit under test

    def respond(system: ReferenceSystem, request: Any) -> Any:
        if request.target != "/demo" or "demo_flag" not in system.faults:
            return None
        return 200, "text/plain", request.method.encode("ascii"), {}

    demo = SimpleNamespace(FLAGS=frozenset({"demo_flag"}), respond=respond)
    monkeypatch.setattr(reference, "FAMILIES", (*reference.FAMILIES, demo))
    with ReferenceServer(FIXTURES, faults=frozenset({"demo_flag"})) as server:
        assert _call(server.origin, "GET", "/demo")[::2] == (200, b"GET")
        assert _call(server.origin, "GET", RESOLVER)[0] == 303
    with ReferenceServer(FIXTURES) as server:
        assert _call(server.origin, "GET", "/demo")[0] == 404


def test_the_header_injection_guard_covers_every_method(monkeypatch: pytest.MonkeyPatch) -> None:
    def hostile(self: Any, request: Any) -> Any:
        return 303, "text/plain", b"", {"Location": "/dpp/x\r\nX-Injected: 1"}

    monkeypatch.setattr(ReferenceSystem, "respond", hostile)
    with ReferenceServer(FIXTURES) as server:
        for method in ("GET", "HEAD", "OPTIONS"):
            status, headers, _ = _call(server.origin, method, RESOLVER)
            assert (status, "X-Injected" in headers) == (400, False), method


def test_the_rig_samples_key_swaps_a_sample_for_a_fixture(tmp_path: Path) -> None:
    from validation.rig import ROOT, ReferenceRig  # noqa: PLC0415 - only this test needs the rig

    source = "fixtures/reference/qr/invalid.png"
    with ReferenceRig(tmp_path, samples={"qr_image": source, "other_file": "fixtures/reference/roles.json"}):
        ixit = (tmp_path / "rig" / "ixit.yaml").read_text(encoding="utf-8")
    assert "qr_image: samples/qr_image.png" in ixit
    assert "other_file: samples/other_file.json" in ixit
    assert (tmp_path / "rig" / "samples" / "qr_image.png").read_bytes() == (ROOT / source).read_bytes()
    with pytest.raises(ValueError, match="escape"):
        ReferenceRig(tmp_path / "x", samples={"../escape": source})


@pytest.mark.qr
def test_a_swapped_sample_changes_the_outcome_of_the_run(tmp_path: Path) -> None:
    from validation.rig import ReferenceRig  # noqa: PLC0415 - only this test needs the rig

    with ReferenceRig(tmp_path, samples={"qr_image": "fixtures/reference/qr/invalid.png"}) as rig:
        step = rig.run().step("TP-ID-001")
    assert (step["verdict"], step["reason_code"]) == ("fail", "IDENTIFIER.SYNTAX.INVALID")


if __name__ == "__main__" and sys.argv[1:] == ["--write"]:
    SNAPSHOT.write_text(json.dumps(take_snapshot(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
