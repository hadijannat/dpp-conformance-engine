"""The reference system v2: same answers to old requests, plus HEAD, OPTIONS, and the resolver surface.

The snapshot in ``tests/fixtures/reference-system-snapshot.json`` was taken from the reference
system at 4990be0, before v2. Each request that a route answered then must get the same status,
the same headers, and the same body now, for every fault flag and role. This keeps the method
validation figures and the existing recordings the same.

Rewrite the snapshot only when a fixture body changes on purpose, and say why in the commit:
``uv run python -m tests.test_reference_system_v2 --write``.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

from validation.rig import FIXTURES, AlternateLayout

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


if __name__ == "__main__" and sys.argv[1:] == ["--write"]:
    SNAPSHOT.write_text(json.dumps(take_snapshot(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
