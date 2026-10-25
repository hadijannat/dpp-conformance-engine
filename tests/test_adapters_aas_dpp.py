"""aas.dpp_compose on synthetic AAS environments, against the pinned IDTA 02099-1 template.

The check needs no optional extra. Every problem of the sample shape is a fail, never `blocked`:
a system under test must not turn a fail into a step that is not judged (brief P2-09, item 7).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters import aas
from dppce.adapters.aas import aas_dpp_compose
from dppce.models import ExecutionStatus
from tests.support import ArtifactAcquirer, make_artifact
from tests.test_url_templates import context

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "fixtures" / "aas"
# The template is not vendored (CLAUDE.md rule 5, tests/vectors/idta-02099-1/README.md). An operator
# supplies a local copy of the pinned blob through this variable.
TEMPLATE = os.environ.get("DPPCE_IDTA_02099_1_TEMPLATE", "")
VALID = json.loads((SAMPLES / "TEST-ONLY-dpp-valid.json").read_text(encoding="utf-8"))


def _run(tmp_path: Path, body: bytes | None, **params: Any) -> Any:
    artifacts = {"aas_file": make_artifact("aas_file", body)} if body is not None else {}
    acquirer = ArtifactAcquirer(artifacts)
    ctx = context(tmp_path, "aas.dpp_compose", params=params, acquirer=acquirer)  # type: ignore[arg-type]
    return aas_dpp_compose(ctx)


def _changed(change: Any) -> bytes:
    document = copy.deepcopy(VALID)
    change(document)
    return json.dumps(document).encode()


def _verdict(outcome: Any) -> tuple[Any, Any, str]:
    return outcome.status, outcome.passed, outcome.reason_code


# -- The table is the pinned template ------------------------------------------------------------


@pytest.mark.skipif(not TEMPLATE, reason="set DPPCE_IDTA_02099_1_TEMPLATE to a local copy of the template")
def test_the_table_equals_the_template() -> None:
    body = Path(TEMPLATE).read_bytes()
    assert hashlib.sha256(body).hexdigest() == (
        "45d3f5ee78f628941816f4f6e30221f535a91c318114f41143328881c887eb85"
    )
    template = json.loads(body)
    (submodel,) = template["submodels"]
    assert submodel["semanticId"]["keys"][0]["value"] == aas.DPP_SUBMODEL_SEMANTIC_ID
    derived = tuple(
        (
            element["idShort"],
            element["semanticId"]["keys"][0]["value"],
            next(q["value"] for q in element["qualifiers"] if q["type"] == "SMT/Cardinality"),
        )
        for element in submodel["submodelElements"]
    )
    assert derived == aas.DPP_ELEMENTS
    assert aas.DPP_PRODUCT_ID in {name for name, _, _ in aas.DPP_ELEMENTS}


# -- Pass ------------------------------------------------------------------------------------------


def test_a_template_conformant_environment_passes_and_names_the_limit(tmp_path: Path) -> None:
    outcome = _run(tmp_path, (SAMPLES / "TEST-ONLY-dpp-valid.json").read_bytes())
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, True, "AAS.DPP.OK")
    assert "IDTA 02099-1" in outcome.message
    assert "not by itself a DPP" in outcome.message
    # Counts and template names only: no identifier value of the sample.
    assert outcome.observations[0].summary == {
        "dpp_submodels": 1,
        "missing_elements": [],
        "identifier_agrees": True,
    }


def test_the_semantic_id_matches_by_key_value_whatever_the_reference_type(tmp_path: Path) -> None:
    def model_reference(document: dict[str, Any]) -> None:
        document["submodels"][0]["semanticId"] = {
            "type": "ModelReference",
            "keys": [{"type": "Submodel", "value": aas.DPP_SUBMODEL_SEMANTIC_ID}],
        }

    outcome = _run(tmp_path, _changed(model_reference))
    assert outcome.reason_code == "AAS.DPP.OK"


def test_an_optional_element_may_be_absent(tmp_path: Path) -> None:
    # facilityId and contentSpecificationIds have the cardinality ZeroToOne in the template.
    names = {name for name, _, cardinality in aas.DPP_ELEMENTS if cardinality != "One"}
    assert names == {"facilityId", "contentSpecificationIds"}
    outcome = _run(tmp_path, (SAMPLES / "TEST-ONLY-dpp-valid.json").read_bytes())
    assert outcome.passed is True


# -- AAS.DPP.SUBMODEL_MISSING ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        (SAMPLES / "environment-valid.json").read_bytes(),
        b"{}",
        b"[]",
        b"not json",
        b'{"submodels": [], "submodels": []}',
        b'{"submodels": {}}',
        b'{"submodels": [7, null, "x"]}',
        b'{"submodels": [{"semanticId": "https://admin-shell.io/idta/cds/dppMetadata/1"}]}',
        b'{"submodels": [{"semanticId": {"keys": [{"value": "https://admin-shell.io/idta/cds/dppMetadata/2"}]}}]}',
    ],
    ids=[
        "valid-aas-without-dpp",
        "empty-environment",
        "list",
        "not-json",
        "repeated-key",
        "submodels-not-a-list",
        "submodels-not-objects",
        "semantic-id-not-a-reference",
        "other-semantic-id",
    ],
)
def test_an_environment_without_the_dpp_submodel_fails(body: bytes, tmp_path: Path) -> None:
    outcome = _run(tmp_path, body)
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, False, "AAS.DPP.SUBMODEL_MISSING")


# -- AAS.DPP.ELEMENT_MISSING -------------------------------------------------------------------------


def test_a_missing_required_element_fails_and_is_named(tmp_path: Path) -> None:
    outcome = _run(tmp_path, (SAMPLES / "TEST-ONLY-dpp-element-missing.json").read_bytes())
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, False, "AAS.DPP.ELEMENT_MISSING")
    assert outcome.observations[0].summary["missing_elements"] == ["dppStatus"]
    assert "dppStatus" in outcome.message


def _element(document: dict[str, Any], name: str) -> dict[str, Any]:
    elements: list[dict[str, Any]] = document["submodels"][0]["submodelElements"]
    return next(e for e in elements if e["idShort"] == name)


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(value=""),
        lambda e: e.pop("value"),
        lambda e: e.update(value=7),
        lambda e: e.update(semanticId={"keys": [{"value": "https://admin-shell.io/idta/cds/dppStatus/2"}]}),
        lambda e: e.pop("semanticId"),
        lambda e: e.update(idShort="status"),
    ],
    ids=["empty-value", "no-value", "value-not-text", "other-semantic-id", "no-semantic-id", "other-idshort"],
)
def test_a_required_element_needs_its_idshort_its_semantic_id_and_a_value(
    change: Any, tmp_path: Path
) -> None:
    outcome = _run(tmp_path, _changed(lambda d: change(_element(d, "dppStatus"))))
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, False, "AAS.DPP.ELEMENT_MISSING")
    assert outcome.observations[0].summary["missing_elements"] == ["dppStatus"]


def test_submodel_elements_that_are_not_a_list_miss_every_required_element(tmp_path: Path) -> None:
    outcome = _run(tmp_path, _changed(lambda d: d["submodels"][0].update(submodelElements={})))
    assert outcome.reason_code == "AAS.DPP.ELEMENT_MISSING"
    required = sorted(name for name, _, cardinality in aas.DPP_ELEMENTS if cardinality == "One")
    assert outcome.observations[0].summary["missing_elements"] == required


# -- AAS.DPP.ID_MISMATCH -------------------------------------------------------------------------------


def test_a_product_identifier_that_differs_from_the_global_asset_id_fails(tmp_path: Path) -> None:
    outcome = _run(tmp_path, (SAMPLES / "TEST-ONLY-dpp-id-mismatch.json").read_bytes())
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, False, "AAS.DPP.ID_MISMATCH")
    assert outcome.observations[0].summary["identifier_agrees"] is False
    # The message names no identifier value.
    assert "example.test" not in outcome.message


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["assetAdministrationShells"][0].pop("submodels"),
        lambda d: d["assetAdministrationShells"][0]["submodels"][0]["keys"][0].update(value="urn:x"),
        lambda d: d["assetAdministrationShells"][0]["assetInformation"].pop("globalAssetId"),
        lambda d: d["assetAdministrationShells"][0].pop("assetInformation"),
        lambda d: d.pop("assetAdministrationShells"),
        lambda d: d.update(assetAdministrationShells="x"),
        lambda d: d["assetAdministrationShells"][0]["assetInformation"].update(
            globalAssetId=None,
            specificAssetIds=[
                {"name": "uniqueProductIdentifier", "value": "https://example.test/TEST-ONLY/product/1"}
            ],
        ),
    ],
    ids=[
        "shell-without-references",
        "shell-references-another-submodel",
        "no-global-asset-id",
        "no-asset-information",
        "no-shells",
        "shells-not-a-list",
        "specific-asset-id-only",
    ],
)
def test_a_dpp_submodel_without_an_agreeing_shell_fails(change: Any, tmp_path: Path) -> None:
    outcome = _run(tmp_path, _changed(change))
    assert _verdict(outcome) == (ExecutionStatus.COMPLETED, False, "AAS.DPP.ID_MISMATCH")


def test_a_second_shell_that_disagrees_fails(tmp_path: Path) -> None:
    def second_shell(document: dict[str, Any]) -> None:
        shell = copy.deepcopy(document["assetAdministrationShells"][0])
        shell["id"] = "https://example.test/TEST-ONLY/aas/dpp-2"
        shell["assetInformation"]["globalAssetId"] = "https://example.test/TEST-ONLY/product/2"
        document["assetAdministrationShells"].append(shell)

    assert _run(tmp_path, _changed(second_shell)).reason_code == "AAS.DPP.ID_MISMATCH"


def test_each_dpp_submodel_is_judged(tmp_path: Path) -> None:
    def second_submodel(document: dict[str, Any]) -> None:
        submodel = copy.deepcopy(document["submodels"][0])
        submodel["id"] = "https://example.test/TEST-ONLY/submodel/dpp-metadata-2"
        document["submodels"].append(submodel)

    # No shell references the second submodel.
    outcome = _run(tmp_path, _changed(second_submodel))
    assert outcome.reason_code == "AAS.DPP.ID_MISMATCH"
    assert outcome.observations[0].summary["dpp_submodels"] == 2


# -- Not judged ----------------------------------------------------------------------------------------


def test_a_missing_sample_is_blocked_and_nothing_else_is(tmp_path: Path) -> None:
    outcome = _run(tmp_path, None)
    assert _verdict(outcome) == (ExecutionStatus.BLOCKED, None, "AAS.SAMPLE.MISSING")


def test_the_artifact_parameter_names_the_sample(tmp_path: Path) -> None:
    body = (SAMPLES / "TEST-ONLY-dpp-valid.json").read_bytes()
    acquirer = ArtifactAcquirer({"aas_json": make_artifact("aas_json", body)})
    ctx = context(tmp_path, "aas.dpp_compose", params={"artifact": "aas_json"}, acquirer=acquirer)  # type: ignore[arg-type]
    assert aas_dpp_compose(ctx).reason_code == "AAS.DPP.OK"
