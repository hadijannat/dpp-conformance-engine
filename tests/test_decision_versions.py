"""Decision body versions: a new run writes dppce.decision/2, and a dppce.decision/1 body still verifies.

The fixture ``rc1-envelope-decision-v1.json`` is ``tests.support.make_envelope()`` as the code at
tag v0.1.0rc1 serialized it, when the default issuer was 'unspecified'. ``RC1_DIGEST`` is the
decision digest that the same code computed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import rfc8785
from pydantic import ValidationError

from dppce import schemas
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.envelope import build_decision, decision_digest, sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.models import DecisionBody, EvidenceEnvelope, TrustBundle
from dppce.verifier import verify_json
from tests.support import AT, ISSUER, make_envelope, make_manifest

RC1_ENVELOPE = Path(__file__).parent / "fixtures" / "rc1-envelope-decision-v1.json"
RC1_DIGEST = "sha256:2cbe87f51dbd46cc7fb0342b08cfe300d8752f0c977528abce32427729872ca8"


def _outcomes(raw: bytes, trust: TrustBundle) -> dict[str, str]:
    return {d.name: d.outcome for d in verify_json(raw, trust, AT).dimensions}


def _signed_document(signer: LocalSigner) -> dict[str, Any]:
    envelope = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    document: dict[str, Any] = json.loads(envelope.model_dump_json(by_alias=True))
    return document


def test_a_new_decision_body_is_version_2_and_carries_bound_files() -> None:
    template = make_envelope(("pass",)).decision
    decision = build_decision(
        manifest=make_manifest(bound_files={"rules.json": "unavailable"}),
        overall=template.overall,
        overall_reason=template.overall_reason,
        requirement_results=template.requirement_results,
        test_results=template.test_results,
        exclusions=(),
        conflicts=(),
        coverage=template.coverage,
        record_commitments=template.record_commitments,
    )
    assert decision.schema_version == "dppce.decision/2"
    assert template.schema_version == "dppce.decision/2"
    assert b'"bound_files":{"rules.json":"unavailable"}' in canonical_bytes(decision)
    assert b'"bound_files":{}' in canonical_bytes(template), "an empty mapping is still written"


def test_a_version_2_body_needs_a_manifest_with_bound_files() -> None:
    template = make_envelope(("pass",)).decision
    with pytest.raises(ValidationError, match="bound_files"):
        build_decision(
            manifest=make_manifest(bound_files=None),
            overall=template.overall,
            overall_reason=template.overall_reason,
            requirement_results=template.requirement_results,
            test_results=template.test_results,
            exclusions=(),
            conflicts=(),
            coverage=template.coverage,
            record_commitments=template.record_commitments,
        )


def test_an_rc1_version_1_body_keeps_its_digest_and_fails_only_issuer_trust(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    raw = RC1_ENVELOPE.read_bytes()
    document = json.loads(raw)
    assert document["decision"]["schema_version"] == "dppce.decision/1"
    assert "bound_files" not in document["decision"]["manifest"]
    # The digest over the document itself, with no model in between, is the one rc1 computed.
    assert "sha256:" + hashlib.sha256(rfc8785.dumps(document["decision"])).hexdigest() == RC1_DIGEST
    loaded = EvidenceEnvelope.model_validate(document)
    assert decision_digest(loaded.decision) == RC1_DIGEST, "the loaded body keeps its digest"
    # Sign it as rc1 did. Only the signature list changes; the decision bytes stay as rc1 wrote them.
    token = sign_envelope(loaded, signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z").signatures[-1]
    document["signatures"] = [token]
    report = verify_json(json.dumps(document).encode(), trust, AT)
    assert report.decision_digest == RC1_DIGEST
    # The rc1 fixture states the issuer 'unspecified'. ADR 0014: such a signed report is not complete.
    dimensions = {d.name: d for d in report.dimensions}
    mandatory = ("structure", "ordering", "results_root", "records_root", "counts", "signature")
    assert {name: dimensions[name].outcome for name in (*mandatory, "manual_results")} == dict.fromkeys(
        (*mandatory, "manual_results"), "pass"
    )
    assert dimensions["issuer_trust"].outcome == "fail"
    assert "ISSUER.STATEMENT.UNSPECIFIED" in dimensions["issuer_trust"].detail
    assert not report.complete


def test_a_version_1_body_with_bound_files_is_a_structure_error(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    document = _signed_document(signer)
    document["decision"]["schema_version"] = "dppce.decision/1"
    document["decision"]["manifest"]["bound_files"] = {}
    outcomes = _outcomes(json.dumps(document).encode(), trust)
    assert outcomes["structure"] == "fail"
    with pytest.raises(ValidationError, match="bound_files"):
        DecisionBody.model_validate(document["decision"])


def test_a_version_2_body_without_bound_files_is_a_structure_error(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    document = _signed_document(signer)
    assert document["decision"]["schema_version"] == "dppce.decision/2"
    del document["decision"]["manifest"]["bound_files"]
    outcomes = _outcomes(json.dumps(document).encode(), trust)
    assert outcomes["structure"] == "fail"
    with pytest.raises(ValidationError, match="bound_files"):
        DecisionBody.model_validate(document["decision"])


def test_the_published_schema_accepts_both_versions_and_no_other(signer: LocalSigner) -> None:
    """The pairing of version and bound_files is a model rule. The schema states the versions."""
    validator = jsonschema.Draft202012Validator(schemas.load("envelope"))
    version_2 = _signed_document(signer)
    assert list(validator.iter_errors(version_2)) == []
    assert list(validator.iter_errors(json.loads(RC1_ENVELOPE.read_bytes()))) == []
    version_2["decision"]["schema_version"] = "dppce.decision/3"
    assert not validator.is_valid(version_2)
