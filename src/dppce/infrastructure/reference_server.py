"""A minimal local reference DPP system for tests and demonstrations.

Specification: docs/reference/reference-system.md. All data are synthetic. The server is an
example and not a normative authority. It only reads: there is no write operation.
Fault flags seed one defect each, for the method validation in validation/.
"""

from __future__ import annotations

import argparse
import base64
import copy
import html
import http.server
import json
import re
import threading
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from dppce.evidence.canonical import canonical_bytes, digest
from dppce.evidence.jws import LocalSigner

PUBLIC_ORIGIN: Final = "https://id.example.test"
CANARY: Final = "CANARY-7f3a-supplier"
NOTES_CANARY: Final = "CANARY-2b9c-dismantling"
FAULTS: Final = frozenset(
    {
        "api_wrong_content_type", "api_schema_violation", "leak_fetch", "leak_export", "leak_search",
        "leak_error", "leak_html", "sig_invalid", "sig_untrusted_issuer", "cert_expired", "id_mismatch",
        "resolver_404", "redirect_out_of_scope", "data_wrong_type", "data_missing_required", "data_stale",
        "data_wrong_unit", "data_relationship", "context_invalid", "registry_inconsistent",
        "version_undeclared_change",
    }
)  # fmt: skip
_RESTRICTED: Final = {
    "dismantling_notes": ("legitimate_interest", "authority"),
    "supplier_reference": ("authority",),
}
_RESTRICTED_VALUES: Final = {"dismantling_notes": NOTES_CANARY, "supplier_reference": CANARY}
_ITEM_PATH: Final = re.compile(
    r"^/dpp/(?P<id>[0-9]{14}-[A-Za-z0-9]+)(?P<rest>/model|/signed|/versions|/export|\.html)?$"
)
_RESOLVER_PATH: Final = re.compile(r"^/01/(?P<gtin>[0-9]{14})/21/(?P<serial>[A-Za-z0-9]+)$")
_REGISTRY_PATH: Final = re.compile(r"^/registry/(?P<id>[0-9]{14}-[A-Za-z0-9]+)$")

Reply = tuple[int, str, bytes, dict[str, str]]


def _json(status: int, document: Any, media_type: str = "application/json") -> Reply:
    return status, media_type, json.dumps(document, sort_keys=True).encode("utf-8"), {}


class ReferenceSystem:
    """The behavior of the reference system, apart from the HTTP plumbing."""

    def __init__(self, fixtures: Path, faults: frozenset[str] = frozenset()) -> None:
        unknown = faults - FAULTS
        if unknown:
            raise ValueError(f"unknown fault flags: {sorted(unknown)}")
        self.faults = faults
        self._items: dict[str, dict[str, Any]] = {}
        self._models: dict[str, dict[str, Any]] = {}
        for path in sorted((fixtures / "items").glob("*.json")):
            item = json.loads(path.read_text(encoding="utf-8"))
            match = _RESOLVER_PATH.match(urlsplit(item["id"]).path)
            if match is None:
                raise ValueError(f"{path}: the id is not a /01/<gtin>/21/<serial> identifier")
            ident = f"{match['gtin']}-{match['serial']}"
            self._items[ident] = item
            self._models[ident] = json.loads((fixtures / "models" / path.name).read_text(encoding="utf-8"))
        self._tokens: dict[str, str] = json.loads((fixtures / "roles.json").read_text(encoding="utf-8"))[
            "tokens"
        ]
        pki = fixtures / "pki"
        self._signers = {
            name: (
                LocalSigner.from_pem(pki / f"TEST-ONLY-{name}.key.pem", f"TEST-ONLY-{name}"),
                x509.load_pem_x509_certificate((pki / f"TEST-ONLY-{name}.cert.pem").read_bytes()),
            )
            for name in ("leaf", "expired-leaf", "untrusted-leaf")
        }

    # -- documents ------------------------------------------------------------------------------

    def role_of(self, authorization: str | None) -> str:
        scheme, _, token = (authorization or "").partition(" ")
        return self._tokens.get(token, "anonymous") if scheme == "Bearer" else "anonymous"

    def item(self, ident: str, role: str, *, leak: bool = False) -> dict[str, Any]:
        """The item-level passport that ``role`` receives, with the seeded data faults."""
        document = copy.deepcopy(self._items[ident])
        faults = self.faults
        if "api_schema_violation" in faults:
            del document["operator"]
        if "id_mismatch" in faults:
            document["id"] = document["id"].rsplit("/", 1)[0] + "/OTHER0001"
        if "data_wrong_type" in faults:
            document["state_of_health_percent"] = str(document["state_of_health_percent"])
        if "data_missing_required" in faults:
            del document["rated_capacity"]
        if "data_stale" in faults:
            document["updated_at"] = "2025-01-01T00:00:00Z"
        if "data_wrong_unit" in faults:
            document["rated_capacity"]["unit"] = "kWh"
        if "data_relationship" in faults:
            document["remaining_capacity"]["value"] = document["rated_capacity"]["value"] + 1
        if "context_invalid" in faults:
            document["@context"] = ["https://unpinned.example.test/ctx"]
        restricted = {
            name: _RESTRICTED_VALUES[name] for name, roles in _RESTRICTED.items() if role in roles or leak
        }
        if restricted:
            document["restricted"] = restricted
        return document

    def versions(self, ident: str) -> dict[str, Any]:
        current = self.item(ident, "anonymous")
        first = {**current, "version": 1, "updated_at": "2026-09-01T08:00:00Z"}
        entries = [
            {"version": 1, "updated_at": first["updated_at"], "content_digest": digest(first)},
            {
                "version": current["version"],
                "updated_at": current["updated_at"],
                "content_digest": digest(current),
            },
        ]
        if "version_undeclared_change" in self.faults:
            # The content changed, but the version number did not.
            entries[0] = {**entries[0], "version": current["version"]}
        return {"versions": entries}

    def signed(self, ident: str) -> bytes:
        """Compact JWS over the canonical anonymous item-level passport, with the leaf in ``x5c``."""
        name = "leaf"
        if "sig_untrusted_issuer" in self.faults:
            name = "untrusted-leaf"
        elif "cert_expired" in self.faults:
            name = "expired-leaf"
        signer, certificate = self._signers[name]
        leaf = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")
        header = canonical_bytes({"alg": "ES256", "kid": signer.key_id, "typ": "dpp+jws", "x5c": [leaf]})

        def b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        payload = canonical_bytes(self.item(ident, "anonymous"))
        signature = signer.sign(f"{b64(header)}.{b64(payload)}".encode("ascii"))
        if "sig_invalid" in self.faults:
            # The payload changes after it was signed.
            payload = canonical_bytes({**self.item(ident, "anonymous"), "status": "repurposed"})
        return f"{b64(header)}.{b64(payload)}.{b64(signature)}".encode("ascii")

    def registry(self, ident: str) -> dict[str, Any]:
        item = self._items[ident]
        inconsistent = "registry_inconsistent" in self.faults
        return {
            "identifier": item["id"],
            "operator_identifier": "urn:example:operator:9999"
            if inconsistent
            else item["operator"]["identifier"],
            "passport_url": item["id"],
            "registered_at": "2026-09-01T08:00:00Z",
        }

    def view(self, ident: str, role: str) -> str:
        document = self.item(ident, role, leak="leak_html" in self.faults)
        rows = "".join(
            f'<tr><th scope="row">{html.escape(str(k))}</th><td>{html.escape(json.dumps(v))}</td></tr>'
            for k, v in sorted(document.items())
        )
        title = html.escape(str(document["id"]))
        return (
            f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title></head>'
            f"<body><h1>Synthetic battery passport</h1><table>{rows}</table></body></html>"
        )

    # -- routing --------------------------------------------------------------------------------

    def not_found(self, path: str) -> Reply:
        detail = f"No resource at {path}."
        if "leak_error" in self.faults:
            detail += f" Internal reference: {CANARY}."
        return _json(404, {"error": "not_found", "detail": detail})

    def handle(self, target: str, authorization: str | None) -> Reply:
        parts = urlsplit(target)
        path, role, faults = parts.path, self.role_of(authorization), self.faults
        if (resolver := _RESOLVER_PATH.match(path)) is not None:
            ident = f"{resolver['gtin']}-{resolver['serial']}"
            if "resolver_404" in faults or ident not in self._items:
                return self.not_found(path)
            if "redirect_out_of_scope" in faults:
                return 302, "text/plain", b"", {"Location": "http://out-of-scope.example.test/"}
            return 303, "text/plain", b"", {"Location": f"/dpp/{ident}"}
        if (registry := _REGISTRY_PATH.match(path)) is not None and registry["id"] in self._items:
            return _json(200, self.registry(registry["id"]))
        if path == "/search":
            text = (parse_qs(parts.query).get("q") or [""])[0].lower()
            leak = "leak_search" in faults
            hits = [self.item(i, role, leak=leak) for i in sorted(self._items) if text and text in i.lower()]
            return _json(200, {"results": hits})
        match = _ITEM_PATH.match(path)
        if match is None or match["id"] not in self._items:
            return self.not_found(path)
        ident, rest = match["id"], match["rest"]
        if rest == "/model":
            return _json(200, self._models[ident])
        if rest == "/signed":
            return 200, "application/jose", self.signed(ident), {}
        if rest == "/versions":
            return _json(200, self.versions(ident))
        if rest == "/export":
            passport = self.item(ident, role, leak="leak_export" in faults)
            return _json(200, {"format": "dppce-reference-export/1", "passport": passport})
        if rest == ".html":
            return 200, "text/html; charset=utf-8", self.view(ident, role).encode("utf-8"), {}
        media_type = "text/plain" if "api_wrong_content_type" in faults else "application/json"
        return _json(200, self.item(ident, role, leak="leak_fetch" in faults), media_type)


class ReferenceServer:
    """Serve a ``ReferenceSystem`` on the loopback interface."""

    def __init__(self, fixtures: Path, *, faults: frozenset[str] = frozenset(), port: int = 0) -> None:
        system = ReferenceSystem(fixtures, faults)

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "dppce-reference/1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                status, media_type, body, headers = system.handle(
                    self.path, self.headers.get("Authorization")
                )
                if any("\r" in value or "\n" in value for value in headers.values()):
                    # A value built from the request path must never start a new header line.
                    status, media_type, body, headers = (
                        400,
                        "application/json",
                        b'{"error":"bad_request"}',
                        {},
                    )
                self.send_response(status)
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value.replace("\r", "").replace("\n", ""))
                self.end_headers()
                self.wfile.write(body)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self._thread: threading.Thread | None = None

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> ReferenceServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dppce.infrastructure.reference_server", description=__doc__
    )
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures/reference"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--fault", action="append", default=[], choices=sorted(FAULTS))
    args = parser.parse_args(argv)
    server = ReferenceServer(args.fixtures, faults=frozenset(args.fault), port=args.port)
    print(f"synthetic reference DPP system on {server.origin}; faults: {sorted(args.fault) or 'none'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
