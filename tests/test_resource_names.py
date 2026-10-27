"""IXIT resource names for AAS endpoints and views (P2-23, OD-10).

The names `description`, `shells`, `submodels`, `view`, and `credential` are additive. The IXIT
version stays `dppce.ixit/1`, and an unknown name stays refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from dppce.models import ResourceName
from tests.test_url_templates import CONTRACT, REFERENCE, context, ixit, run, sent, write_data

ANY_200: dict[str, Any] = {"get": {"responses": {"200": {"content": {"application/json": {}}}}}}

NEW = ("description", "shells", "submodels", "view", "credential")
PATHS = {
    "description": "/description",
    "shells": "/shells",
    "submodels": "/submodels",
    "view": "/dpp/{id}/view",
    "credential": "/dpp/{id}/credential",
}


def test_the_new_names_are_resource_names() -> None:
    assert set(NEW) <= set(get_args(ResourceName))
    assert {"item", "model", "signed", "versions", "registry_record"} <= set(get_args(ResourceName))


@pytest.mark.parametrize("name", NEW)
def test_an_ixit_with_a_new_resource_name_loads(name: str) -> None:
    the_ixit = ixit(resources=REFERENCE | {name: {"endpoint": "api", "path": PATHS[name]}})
    assert the_ixit.schema_version == "dppce.ixit/1"
    assert name in the_ixit.resources


@pytest.mark.parametrize("name", ["nothing", "Description", "shell"])
def test_an_unknown_resource_name_is_refused(name: str) -> None:
    with pytest.raises(ValidationError):
        ixit(resources=REFERENCE | {name: {"endpoint": "api", "path": "/x"}})


@pytest.mark.parametrize("name", ["description", "shells"])
def test_api_contract_judges_an_aas_operation(name: str, tmp_path: Path) -> None:
    path = PATHS[name]
    write_data(tmp_path, contract=CONTRACT | {"paths": {path: {"x-dppce-resource": name, **ANY_200}}})
    resources: dict[str, Any] = REFERENCE | {name: {"endpoint": "api", "path": path}}
    ctx = context(tmp_path, "api.contract", params={"resource": name}, the_ixit=ixit(resources=resources))
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code) == (True, "API.CONTRACT.OK")
    (record,) = ctx.acquirer.records()
    assert record.url == f"https://id.example.test{path}"
    assert sent(ctx) == 1
