"""The evidence faults of the fault catalogue as executable tamper functions.

Each function changes a parsed envelope in place, the way an attacker or a defect could.
The catalogue names the verification dimension that must then fail.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.disclosure import open_record
from dppce.evidence.envelope import sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.status import encode_list, sign_status_list
from dppce.infrastructure.interfaces import Record
from dppce.models import DecisionBody, EvidenceEnvelope, StatusList, StatusReference, TrustBundle, TrustedKey

Tamper = Callable[[dict[str, Any]], None]


def _decision(document: dict[str, Any]) -> dict[str, Any]:
    decision: dict[str, Any] = document["decision"]
    return decision


def _set_algorithm(document: dict[str, Any], algorithm: str, *, keep_signature: bool) -> None:
    header, payload, signature = document["signatures"][0].split(".")
    fields = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    fields["alg"] = algorithm
    forged = base64.urlsafe_b64encode(json.dumps(fields).encode()).rstrip(b"=").decode()
    document["signatures"][0] = f"{forged}.{payload}.{signature if keep_signature else ''}"


def _flip_verdict(document: dict[str, Any]) -> None:
    results = _decision(document)["requirement_results"]
    target = next(r for r in results if r["verdict"] in ("pass", "fail"))
    target["verdict"] = "fail" if target["verdict"] == "pass" else "pass"


def _duplicate_result(document: dict[str, Any]) -> None:
    results = _decision(document)["test_results"]
    results.append(results[-1])


def _drop_exclusion(document: dict[str, Any]) -> None:
    exclusions = _decision(document)["exclusions"]
    if not exclusions:
        raise LookupError("the envelope has no exclusion to drop")
    exclusions.pop()


def _change_counts(document: dict[str, Any]) -> None:
    counts = _decision(document)["verdict_counts"]
    counts["pass"], counts["fail"] = counts["pass"] + 1, max(counts["fail"] - 1, 0)


def _flip_manual_outcome(document: dict[str, Any]) -> None:
    """Change the outcome of a completed manual step. The signed result in the step still disagrees."""
    target = next(
        (
            t
            for t in _decision(document)["test_results"]
            if t["check"] == "manual.review" and t["verdict"] in ("pass", "fail")
        ),
        None,
    )
    if target is None:
        raise LookupError("the envelope has no completed manual step")
    flipped = "fail" if target["verdict"] == "pass" else "pass"
    target["verdict"] = flipped
    target["observations"][0]["summary"]["outcome"] = flipped


# Keyed by the `tamper` name in validation/fault-catalogue.yaml.
TAMPER: dict[str, Tamper] = {
    "flip_verdict": _flip_verdict,
    "omit_result": lambda d: _decision(d)["test_results"].pop(),
    "duplicate_result": _duplicate_result,
    "reorder_results": lambda d: _decision(d)["requirement_results"].reverse(),
    "substitute_result": lambda d: _decision(d)["test_results"][0].update(message="from a different run"),
    "change_scope": lambda d: _decision(d)["manifest"]["sut"].update(identifier="urn:example:other"),
    "drop_exclusion": _drop_exclusion,
    "change_counts": _change_counts,
    "substitute_commitment": lambda d: _decision(d)["record_commitments"][0].update(commitment="0" * 64),
    "alg_none": lambda d: _set_algorithm(d, "none", keep_signature=False),
    "flip_manual_outcome": _flip_manual_outcome,
    # Set, not changed: the field is absent from a run without an authorization.
    "change_authorization": lambda d: _decision(d)["manifest"].update(
        authorization_digest="sha256:" + "0" * 64
    ),
}
# These two need a different key or a different evaluation time, not a changed document.
NEEDS_SETUP = ("untrusted_key", "expired_key")


def change_redirect_status(decision: DecisionBody, records: Sequence[Record]) -> bytes:
    """E-17: open the first record with a hop status, then change its first hop status.

    The envelope holds commitments only, so the change is visible in a record opening, not in the
    envelope. The verifier must then fail the dimension ``opening``.
    """
    record = next((r for r in records if r.redirect_statuses), None)
    if record is None:
        raise LookupError("the recording has no record with a redirect hop status")
    document = json.loads(canonical_bytes(open_record(decision, record)))
    statuses = document["record"]["redirect_statuses"]
    statuses[0] = 308 if statuses[0] == 307 else 307
    return canonical_bytes(document)


@dataclass(frozen=True)
class Subject:
    """What the verifier gets for one evidence fault."""

    document: dict[str, Any]
    trust: TrustBundle
    status_list: bytes | None = None


Setup = Callable[[EvidenceEnvelope, LocalSigner, TrustBundle, datetime], Subject]
_SIGNED_AT = "2026-10-13T12:05:00Z"


def _report_key(trust: TrustBundle, signer: LocalSigner) -> TrustedKey:
    return next(k for k in trust.keys if k.kid == signer.key_id)


def _revoked_bit(signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle, at: datetime) -> Subject:
    """The issuer names a status entry, and its signed status list sets that bit to revoked."""
    key = _report_key(trust, signer)
    status_signer = LocalSigner.generate("TEST-ONLY-status-key-1")
    status_key = key.model_copy(
        update={
            "kid": status_signer.key_id,
            "purposes": ("status",),
            "public_jwk": status_signer.public_jwk(),
        }
    )
    entry = StatusReference(list_id="urn:example:TEST-ONLY-status-list-1", index=42)
    unsigned = signed.model_copy(update={"signatures": ()})
    resigned = sign_envelope(unsigned, signer, issuer=key.issuer, signed_at=_SIGNED_AT, status=entry)
    status_list = StatusList(
        schema_version="dppce.statuslist/1",
        id=entry.list_id,
        status_purpose="revocation",
        issued_at=(at - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        encoded_list=encode_list({entry.index}),
    )
    return Subject(
        json.loads(resigned.model_dump_json(by_alias=True)),
        trust.model_copy(update={"keys": (*trust.keys, status_key)}),
        sign_status_list(status_list, status_signer).encode("ascii"),
    )


def _role_swap(signed: EvidenceEnvelope, signer: LocalSigner, trust: TrustBundle, at: datetime) -> Subject:
    """The report key adds a second signature that declares the role reviewer."""
    issuer = _report_key(trust, signer).issuer
    swapped = sign_envelope(signed, signer, issuer=issuer, signed_at=_SIGNED_AT, role="reviewer")
    return Subject(json.loads(swapped.model_dump_json(by_alias=True)), trust)


# These need a new signature, a new key, or a status list, not only a changed document.
SETUP: dict[str, Setup] = {"revoked_bit": _revoked_bit, "role_swap": _role_swap}
