"""The JSON Schemas stay in step with the models, and old documents upgrade to the current version."""

from __future__ import annotations

import jsonschema
import pytest

from dppce import schemas
from dppce.migrations import MigrationError, migrate
from dppce.models import ICS, SCHEMA_MODELS


def test_published_schemas_equal_the_models() -> None:
    expected = schemas.generate()
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in schemas.DIRECTORY.glob("*.schema.json")}
    assert on_disk == expected, "run `uv run just schemas`"


@pytest.mark.parametrize("stem", sorted(SCHEMA_MODELS))
def test_each_schema_is_a_valid_json_schema(stem: str) -> None:
    jsonschema.Draft202012Validator.check_schema(schemas.load(stem))


_ICS = {
    "schema_version": "dppce.ics/1",
    "sut": {"name": "Reference", "identifier": "urn:example:sut"},
    "profile": "battery/ev",
    "characteristics": {"capacity_wh": 75000},
}


def test_schema_and_model_agree_on_a_valid_and_an_invalid_document() -> None:
    validator = jsonschema.Draft202012Validator(schemas.load("ics"))
    assert not list(validator.iter_errors(_ICS))
    ICS.model_validate(_ICS)
    extra = {**_ICS, "surprise": 1}
    assert list(validator.iter_errors(extra))
    with pytest.raises(ValueError, match="surprise"):
        ICS.model_validate(extra)


def test_ics_0_upgrades_to_the_current_version() -> None:
    old = {
        "schema_version": "dppce.ics/0",
        "sut": {"name": "Reference", "identifier": "urn:example:sut"},
        "profile": "battery/ev",
        "capacity_kwh": 2.5,
        "placed_on_market": "2027-03-01",
    }
    new = migrate("ics", old)
    assert old["schema_version"] == "dppce.ics/0", "the input is not changed"
    ics = ICS.model_validate(new)
    assert ics.characteristics == {"capacity_wh": 2500, "placed_on_market_date": "2027-03-01"}
    assert migrate("ics", new) is new, "a current document is returned as it is"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"schema_version": "dppce.ics/99"}, "no migration"),
        ({}, "no migration"),
        ({"schema_version": "dppce.ics/0", "capacity_kwh": 0.0001234}, "whole number"),
        ({"schema_version": "dppce.ics/0", "capacity_kwh": "many"}, "not a number"),
    ],
)
def test_a_document_that_cannot_upgrade_is_rejected(document: dict[str, object], message: str) -> None:
    with pytest.raises(MigrationError, match=message):
        migrate("ics", document)


def test_unknown_kind_is_rejected() -> None:
    with pytest.raises(MigrationError, match="unknown document kind"):
        migrate("invoice", {})
