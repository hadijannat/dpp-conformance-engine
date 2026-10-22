"""aas.validate on the synthetic samples in fixtures/aas, with the real wrapped validator.

A format or a metamodel version that the wrapped release does not verify is `unsupported`, never a
fail (CLAUDE.md rule 7). `AAS.INVALID` is kept for a file that the validator read and rejected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.lifecycle import aas_validate
from dppce.models import ExecutionStatus
from tests.support import ArtifactAcquirer, make_artifact
from tests.test_url_templates import context

pytest.importorskip("aas_test_engines", reason="needs the optional 'aas' extra")

SAMPLES = Path(__file__).resolve().parent.parent / "fixtures" / "aas"


def _run(tmp_path: Path, sample: str | None, **params: Any) -> Any:
    artifacts = {"aas_file": make_artifact("aas_file", (SAMPLES / sample).read_bytes())} if sample else {}
    acquirer = ArtifactAcquirer(artifacts)
    outcome = aas_validate(context(tmp_path, "aas.validate", params=params, acquirer=acquirer))  # type: ignore[arg-type]
    return outcome, acquirer


@pytest.mark.parametrize(
    ("sample", "serialization"),
    [
        ("environment-valid.json", "json"),
        ("environment-valid.xml", "xml"),
        ("package-valid.aasx", "aasx"),
    ],
)
def test_a_valid_sample_of_each_format_passes_and_names_the_limit(
    sample: str, serialization: str, tmp_path: Path
) -> None:
    outcome, _ = _run(tmp_path, sample, format=serialization)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        "AAS.VALID",
    )
    assert f"covers the {serialization} serialization of metamodel 3.0 only" in outcome.message
    assert "not a complete DPP conformance statement" in outcome.message
    summary = outcome.observations[0].summary
    assert summary == {"format": serialization, "metamodel_version": "3.0", "valid": True}
    assert outcome.observations[0].transformations == ("aas_test_engines",)


@pytest.mark.parametrize(
    ("sample", "serialization"),
    [
        ("environment-invalid.json", "json"),
        ("environment-invalid.xml", "xml"),
        ("package-invalid.aasx", "aasx"),
    ],
)
def test_a_sample_that_the_validator_rejects_is_invalid(
    sample: str, serialization: str, tmp_path: Path
) -> None:
    outcome, _ = _run(tmp_path, sample, format=serialization)
    assert (outcome.passed, outcome.reason_code) == (False, "AAS.INVALID")
    assert "The wrapped validator rejects the file" in outcome.message
    assert outcome.observations[0].summary["valid"] is False


@pytest.mark.parametrize(
    ("sample", "serialization", "what"),
    [
        ("environment-valid.xml", "json", "JSON, or it has a repeated key, NaN, or Infinity"),
        ("environment-malformed.xml", "xml", "well-formed XML"),
        ("environment-doctype.xml", "xml", "XML without a document type declaration"),
        ("environment-doctype-utf16.xml", "xml", "XML without a document type declaration"),
        ("environment-valid.json", "aasx", "a ZIP package"),
        ("package-no-spec.aasx", "aasx", "an AASX package with an AAS specification part"),
        (
            "package-doctype.aasx",
            "aasx",
            "an AASX package whose part aasx/_rels/aasx-origin.rels is XML without a document type "
            "declaration",
        ),
        (
            "package-repeated-key.aasx",
            "aasx",
            "an AASX package whose part aasx/environment.json is JSON, or it has a repeated key, NaN, "
            "or Infinity",
        ),
        ("package-high-ratio.aasx", "aasx", "an AASX package within the size limits of the check"),
    ],
)
def test_a_sample_that_cannot_be_read_as_the_declared_format_is_invalid(
    sample: str, serialization: str, what: str, tmp_path: Path
) -> None:
    # The wrapped validator passes a package with no AAS part; the check does not (rule 7).
    outcome, _ = _run(tmp_path, sample, format=serialization)
    assert (outcome.passed, outcome.reason_code) == (False, "AAS.INVALID")
    assert outcome.message == f"The sample is not {what}."
    assert outcome.observations[0].summary["readable"] is False


def test_a_metamodel_version_outside_the_wrapped_release_is_unsupported_and_reads_nothing(
    tmp_path: Path,
) -> None:
    # The library accepts any version string and then verifies nothing, so this gate is the fix.
    outcome, acquirer = _run(tmp_path, "environment-valid.json", metamodel_version="3.2")
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "AAS.VERSION.UNSUPPORTED",
    )
    assert (
        outcome.message
        == "The wrapped validator verifies metamodel 3.0 only, not 3.2. The sample was not read."
    )
    assert acquirer.records() == ()


def test_an_xml_namespace_of_a_newer_metamodel_is_unsupported(tmp_path: Path) -> None:
    outcome, _ = _run(tmp_path, "environment-v3-1.xml", format="xml")
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.UNSUPPORTED,
        None,
        "AAS.VERSION.UNSUPPORTED",
    )
    assert "The XML namespace of the sample names metamodel 3.1" in outcome.message


@pytest.mark.parametrize(
    "params",
    [{"format": "yaml"}, {"format": 7}, {"metamodel_version": "3"}, {"metamodel_version": 3.0}],
    ids=["format-yaml", "format-int", "version-one-part", "version-float"],
)
def test_malformed_parameters_are_blocked_before_the_sample_is_read(
    params: dict[str, Any], tmp_path: Path
) -> None:
    outcome, acquirer = _run(tmp_path, "environment-valid.json", **params)
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        None,
        "AAS.PARAMS.INVALID",
    )
    assert acquirer.records() == ()


def test_a_missing_sample_is_blocked(tmp_path: Path) -> None:
    outcome, _ = _run(tmp_path, None)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "AAS.SAMPLE.MISSING")
