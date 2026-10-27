"""Report provenance in the run manifest: authorization, trust anchors, CA file, and test items.

Expected values come from docs/explanation/architecture.md, section 11.1 (owner decision OD-09).
A ``dppce.decision/3`` body records them. A ``dppce.decision/2`` body keeps its bytes and digest.
The runs read a declared identifier and a local QR image only. They send no request.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError
from validation.evidence_cases import TAMPER

from dppce import cli, models, schemas
from dppce.compare import compare
from dppce.evidence.canonical import canonical_bytes, digest
from dppce.evidence.envelope import build_decision, decision_digest, in_layout_of, sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.manual import SAMPLE_PREFIX
from dppce.models import DecisionBody, EvidenceEnvelope, RunManifest, TestItem, TrustBundle
from dppce.orchestrator import run as orchestrator  # noqa: TID251 - the run core builds the test items
from dppce.report.html import render
from dppce.report.junit import render_junit
from dppce.report.sarif import render_sarif
from dppce.verifier import verify_json
from tests.support import AT, ISSUER, make_artifact, make_envelope, make_manifest
from tests.test_replay_inputs import ICS, IXIT, PACK, TESTPACK, write_pair

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "fixtures" / "reference"
TRUST_FILE = REFERENCE / "trust" / "TEST-ONLY-trust-bundle.json"
TOKEN = REFERENCE / "authorization" / "TEST-ONLY-authorization.jws"
CA_FILE = REFERENCE / "pki" / "TEST-ONLY-root.cert.pem"
QR = REFERENCE / "qr" / "ev.png"
V2_ENVELOPE = Path(__file__).parent / "fixtures" / "envelope-decision-v2.json"
# make_envelope() as the code before dppce.decision/3 serialized and digested it (commit 0c8f36a).
V2_DIGEST = "sha256:dfba146dcb3a8b6093fdb712b5ae7a0a2209f7531d4dda6f68e2b40a123206ad"
DIGEST_A = "sha256:" + "a" * 64
PROVENANCE: dict[str, Any] = {
    "authorization_id": "TEST-ONLY-authorization-1",
    "authorization_digest": DIGEST_A,
    "remote_read_without_authorization": True,
    "passport_trust_hash": "sha256:" + "b" * 64,
    "trust_anchor_fingerprints": ("sha256:" + "c" * 64,),
    "ca_file_digest": "sha256:" + "d" * 64,
    "test_items": (TestItem(sample="identifier", kind="declared_identifier", value="urn:example:item:1"),),
}
NEW_FIELDS = tuple(PROVENANCE)


def _with(manifest: RunManifest, template: DecisionBody | None = None) -> EvidenceEnvelope:
    """The default test envelope with another manifest, built and validated as a run builds it."""
    t = template or make_envelope().decision
    decision = build_decision(
        manifest=manifest,
        overall=t.overall,
        overall_reason=t.overall_reason,
        requirement_results=t.requirement_results,
        test_results=t.test_results,
        exclusions=t.exclusions,
        conflicts=t.conflicts,
        coverage=t.coverage,
        record_commitments=t.record_commitments,
    )
    return EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision)


def _document(envelope: EvidenceEnvelope) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(envelope.model_dump_json(by_alias=True))
    return document


def _outcomes(document: dict[str, Any], trust: TrustBundle) -> tuple[dict[str, str], bool]:
    report = verify_json(json.dumps(document).encode(), trust, AT)
    return {d.name: d.outcome for d in report.dimensions}, report.complete


# -- the model and the schema ---------------------------------------------------------------------


def test_a_new_body_is_version_3_and_omits_absent_provenance() -> None:
    envelope = make_envelope()
    assert envelope.decision.schema_version == "dppce.decision/3"
    manifest = _document(envelope)["decision"]["manifest"]
    assert not set(NEW_FIELDS) & set(manifest), "an absent field is not written"


def test_a_version_3_body_with_provenance_round_trips_and_fits_the_schema(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    envelope = _with(make_manifest(**PROVENANCE))
    document = _document(envelope)
    manifest = document["decision"]["manifest"]
    assert manifest["authorization_digest"] == DIGEST_A
    assert manifest["remote_read_without_authorization"] is True
    assert manifest["test_items"] == [
        {"sample": "identifier", "kind": "declared_identifier", "value": "urn:example:item:1"}
    ]
    assert canonical_bytes(EvidenceEnvelope.model_validate(document)) == canonical_bytes(document)
    jsonschema.Draft202012Validator(schemas.load("envelope")).validate(document)
    signed = sign_envelope(envelope, signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    outcomes, complete = _outcomes(_document(signed), trust)
    assert complete, outcomes


@pytest.mark.parametrize("field", NEW_FIELDS)
@pytest.mark.parametrize("version", ["dppce.decision/1", "dppce.decision/2"])
def test_a_version_1_or_2_body_with_a_provenance_field_is_a_structure_error(
    field: str, version: str, signer: LocalSigner, trust: TrustBundle
) -> None:
    signed = sign_envelope(
        _with(make_manifest(**{field: PROVENANCE[field]})),
        signer,
        issuer=ISSUER,
        signed_at="2026-10-13T12:05:00Z",
    )
    document = _document(signed)
    document["decision"]["schema_version"] = version
    if version == "dppce.decision/1":
        del document["decision"]["manifest"]["bound_files"]
    with pytest.raises(ValidationError, match=r"dppce\.decision/3"):
        DecisionBody.model_validate(document["decision"])
    outcomes, _ = _outcomes(document, trust)
    assert outcomes["structure"] == "fail"


def test_a_version_3_body_needs_bound_files() -> None:
    with pytest.raises(ValidationError, match="bound_files"):
        _with(make_manifest(bound_files=None))


def test_a_written_default_is_not_the_canonical_form(signer: LocalSigner, trust: TrustBundle) -> None:
    """An absent value is omitted. A body that writes it is not exact, so the structure fails."""
    signed = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    document = _document(signed)
    document["decision"]["manifest"]["remote_read_without_authorization"] = False
    outcomes, _ = _outcomes(document, trust)
    assert outcomes["structure"] == "fail"


@pytest.mark.parametrize(
    "item",
    [
        {"sample": "qr_image", "kind": "sample_file", "value": "not a digest"},
        {"sample": "identifier", "kind": "payload", "value": "x"},
        {"sample": "identifier", "kind": "declared_identifier", "value": ""},
    ],
)
def test_a_test_item_is_closed(item: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        TestItem.model_validate(item)


def test_a_pinned_version_2_envelope_keeps_its_bytes_digest_and_verdicts(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    raw = V2_ENVELOPE.read_bytes()
    document = json.loads(raw)
    assert document["decision"]["schema_version"] == "dppce.decision/2"
    loaded = EvidenceEnvelope.model_validate(document)
    assert canonical_bytes(loaded) == canonical_bytes(document), "the loaded model is the document"
    assert decision_digest(loaded.decision) == V2_DIGEST
    signed = sign_envelope(loaded, signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
    report = verify_json(signed.model_dump_json(by_alias=True).encode(), trust, AT)
    assert report.decision_digest == V2_DIGEST
    assert report.complete, report.dimensions
    jsonschema.Draft202012Validator(schemas.load("envelope")).validate(document)


def test_a_version_2_layout_drops_the_provenance_and_keeps_bound_files() -> None:
    # make_envelope draws new record salts, so both bodies come from one template.
    template = make_envelope().decision
    v3 = _with(make_manifest(**PROVENANCE), template).decision
    v2 = in_layout_of(v3, "dppce.decision/2")
    assert v2.schema_version == "dppce.decision/2"
    assert v2.manifest.bound_files == {}
    expected = template.model_copy(update={"schema_version": "dppce.decision/2"})
    assert canonical_bytes(v2) == canonical_bytes(expected)
    assert not in_layout_of(v3, "dppce.decision/1").manifest.has_provenance()
    assert in_layout_of(v3, "dppce.decision/3") is v3


# -- E-16: the provenance is part of the signed body ----------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_digest", "sha256:" + "0" * 64),
        ("authorization_id", "TEST-ONLY-other-authorization"),
        ("ca_file_digest", "sha256:" + "0" * 64),
        ("trust_anchor_fingerprints", []),
        ("remote_read_without_authorization", False),
        ("test_items", []),
    ],
)
def test_e16_a_changed_provenance_field_breaks_the_signature(
    field: str, value: object, signer: LocalSigner, trust: TrustBundle
) -> None:
    signed = sign_envelope(
        _with(make_manifest(**PROVENANCE)), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z"
    )
    document = _document(signed)
    if value in (False, []):
        del document["decision"]["manifest"][field]  # the canonical form omits an absent value
    else:
        document["decision"]["manifest"][field] = value
    outcomes, complete = _outcomes(document, trust)
    assert outcomes["structure"] == "pass"
    assert outcomes["signature"] == "fail"
    assert not complete


def test_e16_the_validation_tamper_breaks_the_signature_also_without_an_authorization(
    signer: LocalSigner, trust: TrustBundle
) -> None:

    for manifest in (make_manifest(), make_manifest(**PROVENANCE)):
        signed = sign_envelope(_with(manifest), signer, issuer=ISSUER, signed_at="2026-10-13T12:05:00Z")
        document = _document(signed)
        TAMPER["change_authorization"](document)
        outcomes, complete = _outcomes(document, trust)
        assert (outcomes["structure"], outcomes["signature"], complete) == ("pass", "fail", False)


# -- reports ----------------------------------------------------------------------------------------


def test_the_html_report_shows_the_provenance_and_the_test_items_escaped() -> None:
    hostile = "<script>alert(1)</script>"
    items = (
        TestItem(sample="identifier", kind="declared_identifier", value=hostile),
        TestItem(sample="qr_image", kind="sample_file", value="sha256:" + "e" * 64),
    )
    page = render(_with(make_manifest(**(PROVENANCE | {"test_items": items}))))
    assert hostile not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    for text in (
        "TEST-ONLY-authorization-1",
        DIGEST_A,
        "sha256:" + "b" * 64,
        "sha256:" + "c" * 64,
        "sha256:" + "d" * 64,
        "sha256:" + "e" * 64,
        "qr_image",
    ):
        assert text in page
    assert "Remote read-only access without an authorization" in page
    plain = render(make_envelope())
    assert "Test items" in plain
    assert "Authorization digest" in plain


def test_junit_and_sarif_read_a_version_3_envelope() -> None:
    envelope = _with(make_manifest(**PROVENANCE))
    assert "testsuite" in render_junit(envelope)
    assert json.loads(render_sarif(envelope))["version"] == "2.1.0"


def test_compare_reports_provenance_as_a_plan_input_difference() -> None:
    a = make_envelope()
    b = _with(make_manifest(**PROVENANCE))
    document = compare(a, b)
    fields = {d["field"]: (d["a"], d["b"]) for d in document["plan_inputs"]}
    assert fields["authorization_digest"] == (None, DIGEST_A)
    assert fields["remote_read_without_authorization"] == (False, True)
    assert fields["test_items"] == (
        [],
        [{"sample": "identifier", "kind": "declared_identifier", "value": "urn:example:item:1"}],
    )
    assert set(fields) == set(NEW_FIELDS)
    assert document["verdicts_equal"] is True
    assert document["steps"] == []
    assert not compare(a, make_envelope())["plan_inputs"]
    # A version 2 body records no provenance, so it is not compared, as in a replay.
    v2 = EvidenceEnvelope.model_validate(json.loads(V2_ENVELOPE.read_bytes()))
    assert {d["field"] for d in compare(v2, b)["plan_inputs"]} == {"schema_version"}


# -- a run and its replay ---------------------------------------------------------------------------


class Run:
    """One reviewed run on a copied data root. It reads a declared identifier and a QR image only."""

    def __init__(self, tmp_path: Path, *extra: str, samples: dict[str, str] | None = None) -> None:
        self.root = tmp_path / "root"
        for name in ("catalogue", "profiles", "testpacks"):
            shutil.copytree(ROOT / name, self.root / name)
        pack, testpack = write_pair(tmp_path / "imports")
        shutil.copy(QR, tmp_path / "ev.png")
        declared = {**IXIT["samples"], "qr_image": "ev.png", "passport_id": "EV-0001"} | (samples or {})
        ixit = IXIT | {"samples": declared}
        (tmp_path / "ixit.json").write_text(json.dumps(ixit), encoding="utf-8")
        self.dir, self.keys = tmp_path / "run", tmp_path / "keys"
        self.code = cli.main(
            [
                "run", "--mode", "reviewed", "--profile", "battery/ev", "--ics", str(ICS),
                "--ixit", str(tmp_path / "ixit.json"), "--at", "2026-10-13T12:00:00Z",
                "--data-root", str(self.root), "--out", str(self.dir), "--keys", str(self.keys),
                "--create-data-key", "--import-pack", str(pack), "--import-testpack", str(testpack),
                "--pack", PACK, "--testpack", TESTPACK, *extra,
            ]
        )  # fmt: skip
        self.envelope = EvidenceEnvelope.model_validate_json((self.dir / "envelope.json").read_bytes())
        self.manifest = self.envelope.decision.manifest

    def replay(self, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
        capsys.readouterr()
        cli.main(["replay", "--run", str(self.dir), "--keys", str(self.keys), "--json"])
        summary: dict[str, Any] = json.loads(capsys.readouterr().out)
        return summary


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# The QR carrier step reads the qr_image sample only with the qr extra, and test_items
# lists only the sample files that the run read.
@pytest.mark.qr
def test_a_run_records_authorization_trust_ca_file_and_test_items(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path, "--trust", str(TRUST_FILE), "--authorization", str(TOKEN), "--ca-file", str(CA_FILE))
    assert run.code in (cli.EXIT_OK, cli.EXIT_SUT_FAIL, cli.EXIT_INCONCLUSIVE)
    m = run.manifest
    assert run.envelope.decision.schema_version == "dppce.decision/3"
    token = TOKEN.read_text(encoding="ascii").strip()
    assert m.authorization_digest == "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()
    assert m.authorization_id is not None
    assert m.authorization_id.startswith("TEST-ONLY")
    assert m.remote_read_without_authorization is False
    bundle = TrustBundle.model_validate_json(TRUST_FILE.read_bytes())
    assert m.passport_trust_hash == digest(bundle)
    der = [
        x509.load_pem_x509_certificate(a.certificate_pem.encode()).public_bytes(serialization.Encoding.DER)
        for a in bundle.anchors
    ]
    assert m.trust_anchor_fingerprints == tuple(
        sorted("sha256:" + hashlib.sha256(d).hexdigest() for d in der)
    )
    assert m.trust_anchor_fingerprints
    assert m.ca_file_digest == _sha256(CA_FILE)
    assert m.test_items == (
        TestItem(sample="identifier", kind="declared_identifier", value=IXIT["samples"]["identifier"]),
        TestItem(sample="passport_id", kind="declared_identifier", value="EV-0001"),
        TestItem(sample="qr_image", kind="sample_file", value=_sha256(QR)),
    )
    summary = run.replay(capsys)
    assert summary["match"] is True, summary


def test_a_remote_read_without_an_authorization_is_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path, "--allow-remote-host", "https://id.example.test")
    m = run.manifest
    assert m.remote_read_without_authorization is True
    assert (m.authorization_id, m.authorization_digest, m.passport_trust_hash, m.ca_file_digest) == (
        None,
        None,
        None,
        None,
    )
    assert m.trust_anchor_fingerprints == ()
    assert run.replay(capsys)["match"] is True


# The QR carrier step reads the qr_image sample only with the qr extra, and test_items
# lists only the sample files that the run read.
@pytest.mark.qr
def test_a_run_without_provenance_inputs_still_names_its_test_items(tmp_path: Path) -> None:
    run = Run(tmp_path)
    m = run.manifest
    assert m.remote_read_without_authorization is False
    assert [i.sample for i in m.test_items] == ["identifier", "passport_id", "qr_image"]
    document = json.loads((run.dir / "envelope.json").read_bytes())
    assert "authorization_digest" not in document["decision"]["manifest"]


def test_a_validated_authorization_is_not_a_remote_read_without_one(tmp_path: Path) -> None:
    run = Run(
        tmp_path,
        "--trust", str(TRUST_FILE), "--authorization", str(TOKEN),
        "--allow-remote-host", "https://id.example.test",
    )  # fmt: skip
    assert run.manifest.authorization_digest is not None
    assert run.manifest.remote_read_without_authorization is False


# -- test items carry no secret and no operator statement -------------------------------------------

CREDENTIAL_ID = (
    "https://op:TEST-ONLY-pw@id.example.test/01/09506000134352/21/EV0001?access_token=TEST-ONLY-secret"
)
REDACTED_ID = "https://id.example.test/01/09506000134352/21/EV0001?access_token=%3Cremoved%3E"


def test_tested_items_redact_an_identifier_and_skip_manual_results_and_failed_reads() -> None:
    ixit = models.IXIT.model_validate(
        IXIT | {"samples": {"identifier": CREDENTIAL_ID, "passport_id": "EV-0001"}}
    )
    records = (
        make_artifact("qr_image", b"TEST-ONLY-png", index=1),
        make_artifact(SAMPLE_PREFIX + "T-MAN", b"TEST-ONLY-jws", index=2),
        make_artifact("label_image", error="artifact_unavailable", index=3),
    )
    assert orchestrator.tested_items(ixit, records) == (
        TestItem(sample="identifier", kind="declared_identifier", value=REDACTED_ID),
        TestItem(sample="passport_id", kind="declared_identifier", value="EV-0001"),
        TestItem(
            sample="qr_image",
            kind="sample_file",
            value="sha256:" + hashlib.sha256(b"TEST-ONLY-png").hexdigest(),
        ),
    )


def test_a_credential_in_an_identifier_reaches_no_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = Run(tmp_path / "a", samples={"identifier": CREDENTIAL_ID})
    plain = Run(tmp_path / "b")
    assert (
        TestItem(sample="identifier", kind="declared_identifier", value=REDACTED_ID)
        in run.manifest.test_items
    )
    capsys.readouterr()
    cli.main(["compare", str(plain.dir / "envelope.json"), str(run.dir / "envelope.json")])
    printed = capsys.readouterr().out
    assert "identifier" in printed, "compare reports the changed test item"
    for text in (
        (run.dir / "envelope.json").read_text(encoding="utf-8"),
        (run.dir / "report.html").read_text(encoding="utf-8"),
        printed,
    ):
        assert "TEST-ONLY-secret" not in text
        assert "TEST-ONLY-pw" not in text
