"""AAS family: a minimal read-only AAS repository of the reference system.

Synthetic behavior, after the read profiles SSP-002 of the AAS Repository and the Submodel
Repository service specifications of IDTA-01002 Part 2, version 3.0.4. The shapes are written by
hand from the open OpenAPI files; no file is vendored. The repository lives under ``PREFIX`` and
serves two TEST-ONLY shells, so that a list with ``limit=1`` has a second page, and one TEST-ONLY
submodel that the first shell references. An identifier in a path is base64url-encoded without
padding. Every other path passes to the core. The flags:

- ``aas_api_wrong_status`` (F-74): a GET of an unknown shell id answers 200 with an empty body.
- ``aas_api_bad_paging`` (F-75): a list request ignores ``limit`` and returns every element.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import parse_qs

from dppce.infrastructure.reference.base import Reply, Request, json_reply

if TYPE_CHECKING:
    from dppce.infrastructure.reference_server import ReferenceSystem

FLAGS: Final = frozenset(
    {
        # F-74: a GET of an unknown shell id answers 200 with an empty body, not 404.
        "aas_api_wrong_status",
        # F-75: a list request ignores limit and returns every element without a cursor.
        "aas_api_bad_paging",
    }
)
PREFIX: Final = "/api/v3.0"
# The first shell and the submodel have the ids of fixtures/aas/TEST-ONLY-dpp-valid.json, so the
# family control can also take the shell id from that sample.
SHELL_IDS: Final = ("https://example.test/TEST-ONLY/aas/dpp-1", "https://example.test/TEST-ONLY/aas/dpp-2")
SUBMODEL_ID: Final = "https://example.test/TEST-ONLY/submodel/dpp-metadata-1"
PROFILES: Final = (
    "https://admin-shell.io/aas/API/3/0/AssetAdministrationShellRepositoryServiceSpecification/SSP-002",
    "https://admin-shell.io/aas/API/3/0/SubmodelRepositoryServiceSpecification/SSP-002",
)
_ITEM: Final = re.compile(r"^/(?P<kind>shells|submodels)/(?P<id>[A-Za-z0-9_-]+)(?P<refs>/submodel-refs)?$")


def _reference(submodel: str) -> dict[str, Any]:
    return {"type": "ModelReference", "keys": [{"type": "Submodel", "value": submodel}]}


def _shell(ident: str) -> dict[str, Any]:
    shell: dict[str, Any] = {
        "id": ident,
        "idShort": "TEST_ONLY_shell",
        "modelType": "AssetAdministrationShell",
        "assetInformation": {
            "assetKind": "Instance",
            "globalAssetId": "https://example.test/TEST-ONLY/product/1",
        },
    }
    if ident == SHELL_IDS[0]:
        shell["submodels"] = [_reference(SUBMODEL_ID)]
    return shell


_SUBMODEL: Final = {"id": SUBMODEL_ID, "idShort": "TEST_ONLY_submodel", "modelType": "Submodel"}


def cursor_of(position: int) -> str:
    """The opaque cursor of a list position. It holds characters that a query must encode."""
    return f"TEST-ONLY+{position}/="


def _decoded(segment: str) -> str | None:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _not_found() -> Reply:
    message = {"messageType": "Error", "text": "not found", "code": "404"}
    return json_reply(404, {"messages": [message]})


def _page(items: list[dict[str, Any]], query: str, faults: frozenset[str]) -> Reply:
    if "aas_api_bad_paging" in faults:
        return json_reply(200, {"paging_metadata": {}, "result": items})
    fields = parse_qs(query)
    try:
        limit = int(fields["limit"][0]) if "limit" in fields else len(items)
    except ValueError:
        limit = 0
    cursor = fields.get("cursor", [""])[0]
    start = next((p for p in range(1, len(items)) if cursor == cursor_of(p)), 0 if not cursor else -1)
    if limit < 1 or start < 0:
        return json_reply(400, {"messages": [{"messageType": "Error", "text": "bad request", "code": "400"}]})
    metadata = {"cursor": cursor_of(start + limit)} if start + limit < len(items) else {}
    return json_reply(200, {"paging_metadata": metadata, "result": items[start : start + limit]})


def respond(system: ReferenceSystem, request: Request) -> Reply | None:
    if not request.path.startswith(PREFIX + "/"):
        return None
    path = request.path.removeprefix(PREFIX)
    if path == "/description":
        return json_reply(200, {"profiles": list(PROFILES)})
    if path == "/shells":
        return _page([_shell(i) for i in SHELL_IDS], request.query, system.faults)
    if path == "/submodels":
        return _page([dict(_SUBMODEL)], request.query, system.faults)
    match = _ITEM.match(path)
    ident = _decoded(match["id"]) if match else None
    if match is None or ident is None:
        return _not_found()
    if match["kind"] == "submodels":
        return json_reply(200, _SUBMODEL) if ident == SUBMODEL_ID and not match["refs"] else _not_found()
    if ident not in SHELL_IDS:
        if "aas_api_wrong_status" in system.faults and not match["refs"]:
            return 200, "application/json", b"", {}
        return _not_found()
    if match["refs"]:
        refs = [_reference(SUBMODEL_ID)] if ident == SHELL_IDS[0] else []
        return json_reply(200, {"paging_metadata": {}, "result": refs})
    return json_reply(200, _shell(ident))
