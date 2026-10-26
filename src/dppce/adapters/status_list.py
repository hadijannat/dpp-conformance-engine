"""Status adapter: the W3C Bitstring Status List entry of a credential (check ``integrity.status_list``).

The rules follow the W3C Recommendation "Bitstring Status List v1.0" of 15 May 2025. The check
verifies the credential as ``integrity.jose`` does, reads its ``BitstringStatusListEntry``, gets
the status list credential, verifies it under a pinned issuer key, and reads the bit.

The status list host is often a third party. A live fetch goes through the transport policy
only, so a host that the operator did not confirm gives no answer. An offline copy of the list
can come from an IXIT sample instead. The bitstring decoder is the one of ``dppce.evidence.status``
(read only). Its output is capped, so a GZIP bomb does not exhaust memory.

A fail of any rule comes before any limit of the engine. A limit applies to a well-formed input
of a form that this engine does not judge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final, Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from dppce.adapters.common import SERVER_ERRORS, blocked, fetch_once, is_http_url, no_answer, unusable
from dppce.adapters.jose import (
    _ACCEPT,
    _DID_URL,
    Dids,
    JoseParams,
    _acquire,
    _Finding,
    _judge,
    credential_gate,
    did_observations,
    finding_of,
    judged,
)
from dppce.evidence.canonical import parse_strict
from dppce.evidence.jose_profiles import JoseError, _moment, is_jws_json, parse
from dppce.evidence.status import MIN_BITS, StatusError, bit_is_set, decode_list
from dppce.infrastructure.interfaces import Record
from dppce.models import CheckOutcome, ExecutionStatus, JsonValue, Model, TrustBundle
from dppce.testdefs.registry import CheckContext, register

ENTRY_TYPE: Final = "BitstringStatusListEntry"
LIST_TYPE: Final = "BitstringStatusListCredential"
SUBJECT_TYPE: Final = "BitstringStatusList"
# Each entry can need a fetch. The limit bounds the requests of one step.
MAX_ENTRIES: Final = 4
_INDEX: Final = re.compile(r"[0-9]+")
# An index with more digits is outside every list that the decoder accepts.
_MAX_INDEX_DIGITS: Final = 64
_UNSUPPORTED: Final = ExecutionStatus.UNSUPPORTED
# The string members of a well-formed DataIntegrityProof, besides its type.
_PROOF_MEMBERS: Final = ("cryptosuite", "proofPurpose", "verificationMethod", "proofValue")
# The findings of integrity.jose on the list credential, as findings of the list.
_LIST_FAILS: Final = {
    "INTEGRITY.JOSE.ISSUER_UNTRUSTED": "INTEGRITY.STATUS.LIST_UNTRUSTED",
    "INTEGRITY.JOSE.KEY_NOT_VALID": "INTEGRITY.STATUS.LIST_UNTRUSTED",
    "INTEGRITY.JOSE.ISSUER_MISMATCH": "INTEGRITY.STATUS.LIST_UNTRUSTED",
    "INTEGRITY.JOSE.CLAIMS": "INTEGRITY.STATUS.LIST_MALFORMED",
    "INTEGRITY.JOSE.NOT_YET_VALID": "INTEGRITY.STATUS.LIST_VALIDITY",
    "INTEGRITY.JOSE.EXPIRED": "INTEGRITY.STATUS.LIST_VALIDITY",
}
_LIST_LIMITS: Final = {
    "INTEGRITY.JOSE.TOO_LARGE": ("INTEGRITY.STATUS.TOO_LARGE", ExecutionStatus.BLOCKED),
    "INTEGRITY.JOSE.UNSUPPORTED": ("INTEGRITY.STATUS.LIST_FORMAT", _UNSUPPORTED),
}


class StatusListParams(Model):
    key_source: Literal["trust_kid", "did"] = Field(
        default="trust_kid",
        description=(
            "The key source of integrity.jose for the credential and for the status list credential. "
            "trust_kid: the kid names a passport key of the trust bundle. did: the kid is a did:web "
            "DID URL, and a passport key of the trust bundle with the DID as its issuer matches its key."
        ),
    )
    did_sample: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description=(
            "Name of the IXIT sample that holds an offline copy of the DID document, for the key source did."
        ),
    )
    source: Literal["signed", "sample"] = Field(
        default="signed",
        description="signed: fetch the resource 'signed'. sample: read the IXIT sample that 'sample' names.",
    )
    sample: str = Field(
        default="credential",
        min_length=1,
        max_length=64,
        description="Name of the IXIT sample that holds an offline credential file, for the source 'sample'.",
    )
    accept: str | None = Field(
        default=None,
        description=(
            "Accept request header for the credential and the status list credential. Printable ASCII, "
            "1 to 256 characters."
        ),
    )
    list_source: Literal["live", "sample"] = Field(
        default="live",
        description=(
            "live: fetch the statusListCredential URL through the transport policy. sample: read the IXIT "
            "sample that 'list_sample' names. Its id must be the statusListCredential URL."
        ),
    )
    list_sample: str = Field(
        default="status_list",
        min_length=1,
        max_length=64,
        description=(
            "Name of the IXIT sample that holds an offline status list credential, for the list "
            "source 'sample'."
        ),
    )
    purpose: Literal["revocation", "suspension"] = Field(
        default="revocation",
        description="The statusPurpose of the entries to judge. A set bit fails the step.",
    )

    @field_validator("accept")
    @classmethod
    def _accept(cls, value: str | None) -> str | None:
        if value is not None and not _ACCEPT.fullmatch(value):
            raise ValueError("must be printable ASCII of 1 to 256 characters")
        return value

    @model_validator(mode="after")
    def _did(self) -> StatusListParams:
        if self.did_sample is not None and self.key_source != "did":
            raise ValueError("did_sample needs the key source did")
        return self

    def credential(self) -> JoseParams:
        return JoseParams(
            profile="vc-jose",
            key_source=self.key_source,
            did_sample=self.did_sample,
            source=self.source,
            sample=self.sample,
            accept=self.accept,
        )


class _Stop(Exception):  # noqa: N818 - a finding, not an error of the engine
    """A finding of a status entry: a fail (``passed`` False), a limit (None), or no answer."""

    def __init__(
        self,
        passed: bool | None,
        code: str,
        message: str,
        *,
        no_answer: bool = False,
        limit: ExecutionStatus = ExecutionStatus.BLOCKED,
    ) -> None:
        super().__init__(message)
        self.passed, self.code, self.message, self.no_answer, self.limit = (
            passed,
            code,
            message,
            no_answer,
            limit,
        )

    @property
    def deferred(self) -> bool:
        return self.passed is None or self.no_answer


def _malformed(message: str) -> _Stop:
    return _Stop(False, "INTEGRITY.STATUS.ENTRY_MALFORMED", message)


def _list_malformed(message: str) -> _Stop:
    return _Stop(False, "INTEGRITY.STATUS.LIST_MALFORMED", message)


@dataclass(frozen=True)
class _Entry:
    url: str
    index: int
    size: int


def _entry(item: dict[str, Any]) -> _Entry:
    """The rules of one BitstringStatusListEntry for the purpose. A malformed entry fails."""
    index = item.get("statusListIndex")
    if not isinstance(index, str) or not _INDEX.fullmatch(index):
        raise _malformed("The statusListIndex of an entry is not a base-10 integer in a string.")
    url = item.get("statusListCredential")
    if not isinstance(url, str) or not is_http_url(url):
        raise _malformed("The statusListCredential of an entry is not an http or https URL.")
    if item.get("id") == url:
        raise _malformed("The id of an entry is the URL of its status list.")
    size = item.get("statusSize", 1)
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise _malformed("The statusSize of an entry is not an integer greater than zero.")
    number = int(index) if len(index) <= _MAX_INDEX_DIGITS else 10**_MAX_INDEX_DIGITS
    return _Entry(url, number, size)


def _entries(document: dict[str, Any], purpose: str) -> list[_Entry]:
    """The entries of ``purpose``. Only the type and the purpose of another entry are read."""
    status = document.get("credentialStatus", [])
    matching: list[_Entry] = []
    other_type = False
    for item in status if isinstance(status, list) else [status]:
        if not isinstance(item, dict) or not isinstance(item.get("type"), str):
            raise _malformed("A credentialStatus entry is not a JSON object with a string type.")
        if item["type"] != ENTRY_TYPE:
            other_type = True
            continue
        if not isinstance(item.get("statusPurpose"), str):
            raise _malformed("The statusPurpose of an entry is not a string.")
        if item["statusPurpose"] == purpose:
            matching.append(_entry(item))
    if not matching and other_type:
        message = "The credential has status entries of a type other than BitstringStatusListEntry only."
        raise _Stop(None, "INTEGRITY.STATUS.ENTRY_TYPE", message, limit=_UNSUPPORTED)
    if not matching:
        message = f"The credential has no BitstringStatusListEntry for the purpose {purpose}."
        raise _Stop(False, "INTEGRITY.STATUS.ENTRY_MISSING", message)
    return matching


def _issuer(document: dict[str, Any]) -> object:
    issuer = document.get("issuer")
    return issuer.get("id") if isinstance(issuer, dict) else issuer


def _types(value: object) -> list[object]:
    return value if isinstance(value, list) else [value]


def _payload_id(body: bytes) -> object:
    """The id of a list credential before it is verified, to bind a sample to its entry."""
    try:
        payload = parse(body).payload
    except JoseError:
        payload = body
    try:
        document = parse_strict(payload)
    except (ValueError, RecursionError):
        return None
    return document.get("id") if isinstance(document, dict) else None


def _pinned_method(trust: TrustBundle, method: str, issuer: object) -> bool:
    """A DID URL whose DID is the credential issuer and the issuer of a pinned passport key.

    A pinned DID of another issuer is no tie: it would let a made-up proof make a limit.
    """
    did = method.partition("#")[0]
    return (
        bool(_DID_URL.fullmatch(method))
        and did == issuer
        and any(k.issuer == did and "passport" in k.purposes for k in trust.keys)
    )


def _proof_secured(body: bytes, url: str, issuer: object, trust: TrustBundle) -> bool:
    """A JSON credential with well-formed Data Integrity proofs only, and no JWS form.

    The list must also name the issuer of the credential and the URL of the entry, and each proof
    a pinned DID. Any other list falls through to the signature rule and fails, so a made-up
    proof cannot turn an unsigned list into a limit of the engine.
    """
    try:
        document = parse_strict(body)
    except (ValueError, RecursionError):
        return False
    if not isinstance(document, dict) or is_jws_json(document):
        return False
    if document.get("id") != url or _issuer(document) != issuer:
        return False
    proofs = _types(document.get("proof"))
    return bool(proofs) and all(
        isinstance(p, dict)
        and p.get("type") == "DataIntegrityProof"
        and all(isinstance(p.get(member), str) for member in _PROOF_MEMBERS)
        and _pinned_method(trust, p["verificationMethod"], issuer)
        for p in proofs
    )


class _Lists:
    """The status entries of one verified credential, judged in the order of the contract."""

    def __init__(
        self,
        ctx: CheckContext,
        trust: TrustBundle,
        params: StatusListParams,
        dids: Dids,
        records: list[Record],
    ) -> None:
        self.ctx, self.trust, self.params, self.dids, self.records = ctx, trust, params, dids, records
        self.fetched: dict[str, Record] = {}
        self.lists: list[dict[str, JsonValue]] = []

    def judge(self, credential: dict[str, Any]) -> int:
        """Judge every entry of the purpose. Returns the number of entries if each one passes."""
        matching = _entries(credential, self.params.purpose)
        deferred: list[_Stop] = []
        if len(matching) > MAX_ENTRIES:
            message = f"The credential has more than {MAX_ENTRIES} status entries for the purpose."
            deferred.append(_Stop(None, "INTEGRITY.STATUS.TOO_LARGE", message))
        for entry in matching[:MAX_ENTRIES]:
            item: dict[str, JsonValue] = {}
            self.lists.append(item)
            try:
                self._entry(entry, item, _issuer(credential))
            except _Stop as stop:
                if not stop.deferred:
                    raise
                deferred.append(stop)
        if deferred:
            raise deferred[0]
        return len(matching)

    def _record(self, url: str, item: dict[str, JsonValue]) -> Record:
        live = self.params.list_source == "live"
        key = url if live else "sample"
        if key not in self.fetched:
            ctx = self.ctx
            record = (
                fetch_once(ctx, url, accept=self.params.accept)
                if live
                else ctx.acquirer.artifact(self.params.list_sample)
            )
            self.fetched[key] = record
            self.records.append(record)
        record = self.fetched[key]
        if not live:
            if record.error == "body_too_large":
                raise _Stop(
                    None, "INTEGRITY.STATUS.TOO_LARGE", "The status list sample is larger than the limit."
                )
            if record.error is not None:
                message = f"The sample '{self.params.list_sample}' is not available."
                raise _Stop(None, "INTEGRITY.STATUS.SAMPLE_MISSING", message)
            if _payload_id(record.body) != url:
                message = "The id of the status list sample is not the statusListCredential URL of the entry."
                raise _Stop(None, "INTEGRITY.STATUS.LIST_UNBOUND", message)
            return record
        # Only a missing answer comes before the status rule, as in integrity.jose.
        if record.error is not None or record.status in SERVER_ERRORS:
            missing = no_answer(self.ctx, record)
            raise _Stop(False, missing.reason_code, missing.message, no_answer=True)
        item["status"] = record.status
        if record.status != 200:
            message = f"The status list URL answers {record.status}, not 200."
            raise _Stop(False, "INTEGRITY.STATUS.LIST_NOT_AVAILABLE", message)
        if (problem := unusable(self.ctx, record)) is not None:
            raise _Stop(None, problem.reason_code, problem.message)
        return record

    def _verify(self, record: Record, url: str, issuer: object) -> dict[str, Any]:
        """Verify the list credential with the code of integrity.jose under the profile vc-jose."""
        if _proof_secured(record.body, url, issuer, self.trust):
            message = (
                "The status list credential has a proof, for example Data Integrity, that this engine "
                "does not verify."
            )
            raise _Stop(None, "INTEGRITY.STATUS.LIST_FORMAT", message, limit=_UNSUPPORTED)
        params = JoseParams(
            profile="vc-jose", key_source=self.params.key_source, did_sample=self.params.did_sample
        )
        try:
            token = _judge(self.ctx, self.trust, params, record.body, findings={}, dids=self.dids)
        except (JoseError, _Finding) as exc:
            passed, code, message = finding_of(exc, {})
            text = f"The status list credential is refused. {message}"
            if isinstance(exc, _Finding) and exc.no_answer:
                raise _Stop(False, code, message, no_answer=True) from None
            if passed is None:
                code, limit = _LIST_LIMITS.get(code, (code, ExecutionStatus.BLOCKED))
                raise _Stop(None, code, text, limit=limit) from None
            raise _Stop(False, _LIST_FAILS.get(code, "INTEGRITY.STATUS.LIST_SIGNATURE"), text) from None
        document = parse_strict(token.payload, decimals=True)
        assert isinstance(document, dict)  # noqa: S101 - the vc-jose claims rule read one JSON object
        return document

    def _entry(self, entry: _Entry, item: dict[str, JsonValue], issuer: object) -> None:
        document = self._verify(self._record(entry.url, item), entry.url, issuer)
        # A pinned key of issuer B must not say that the credential of issuer A is not revoked.
        if _issuer(document) != issuer:
            message = (
                "The issuer of the verified status list credential is not the issuer of the "
                "credential. A delegated status issuer is not supported in this version."
            )
            raise _Stop(False, "INTEGRITY.STATUS.LIST_UNTRUSTED", message)
        # The signed id binds the list to the entry. Without it, a host can serve another list of
        # the same issuer, with the bit clear, at the URL of the entry.
        if document.get("id") != entry.url:
            raise _list_malformed(
                "The id of the verified status list credential is not the statusListCredential URL."
            )
        item |= {"signature": "valid", "issuer": "the issuer of the credential"}
        subject = document.get("credentialSubject")
        if LIST_TYPE not in _types(document.get("type")) or not isinstance(subject, dict):
            raise _list_malformed(
                "The list credential lacks the type BitstringStatusListCredential or a subject."
            )
        purposes = _types(subject.get("statusPurpose"))
        ttl = subject.get("ttl")
        if (
            SUBJECT_TYPE not in _types(subject.get("type"))
            or not isinstance(subject.get("encodedList"), str)
            or not purposes
            or not all(isinstance(p, str) for p in purposes)
            or ("ttl" in subject and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0))
        ):
            raise _list_malformed(
                "The status list lacks a type, an encodedList, a statusPurpose, or a valid ttl."
            )
        if self.params.purpose not in purposes:
            raise _Stop(
                False, "INTEGRITY.STATUS.PURPOSE", "The status list does not serve the purpose of the entry."
            )
        item["purpose"] = "matches"
        try:
            bits = decode_list(subject["encodedList"])
        except StatusError as exc:
            if exc.code == "STATUSLIST.FILE.TOO_LARGE":
                raise _Stop(None, "INTEGRITY.STATUS.TOO_LARGE", f"The status list {exc}.") from None
            raise _list_malformed("The encodedList is not a multibase base64url GZIP bitstring.") from None
        size = len(bits) * 8
        item["bits"] = size
        if size < MIN_BITS:
            raise _Stop(
                False, "INTEGRITY.STATUS.LIST_LENGTH", f"The status list has fewer than {MIN_BITS} entries."
            )
        # An entry holds statusSize bits from index times statusSize. The rules above do not
        # depend on the size, so the size limit comes after them.
        if (entry.index + 1) * entry.size > size:
            raise _Stop(
                False, "INTEGRITY.STATUS.INDEX_RANGE", "The statusListIndex is outside the status list."
            )
        if entry.size != 1:
            message = "The entry has a statusSize other than 1. This engine reads one-bit entries only."
            raise _Stop(None, "INTEGRITY.STATUS.SIZE_UNSUPPORTED", message, limit=_UNSUPPORTED)
        stale = self._staleness(document, ttl, item)
        is_set = bit_is_set(bits, entry.index)
        item["bit"] = "set" if is_set else "not set"
        # Revocation is not reversible, so an old list still shows it. Suspension is reversible.
        if is_set and (self.params.purpose == "revocation" or not stale):
            code = (
                "INTEGRITY.STATUS.REVOKED"
                if self.params.purpose == "revocation"
                else "INTEGRITY.STATUS.SUSPENDED"
            )
            raise _Stop(
                False,
                code,
                f"The status list sets the bit of the credential for the purpose {self.params.purpose}.",
            )
        if stale:
            message = "The validFrom of the status list and its ttl end before the evaluation time."
            raise _Stop(
                None, "INTEGRITY.STATUS.STALE", message + " A stale list does not show the current status."
            )

    def _staleness(self, document: dict[str, Any], ttl: object, item: dict[str, JsonValue]) -> bool:
        if not isinstance(ttl, int):
            item["ttl"] = "absent"
            return False
        if "validFrom" not in document:
            item["ttl"] = "not anchored"
            return False
        try:
            stale = _moment(document["validFrom"]) + timedelta(milliseconds=ttl) < self.ctx.evaluation_time
        except OverflowError:
            stale = False  # a ttl beyond the date range never ends
        item["ttl"] = "stale" if stale else "fresh"
        return stale


@register("integrity.status_list", capability="integrity.status_list", params=StatusListParams)
def status_list_check(ctx: CheckContext) -> CheckOutcome:
    try:
        params = StatusListParams.model_validate(ctx.params)
    except ValidationError:
        return blocked("INTEGRITY.STATUS.PARAMS", "The parameters are not valid. Nothing is read.")
    if ctx.trust is None:
        return blocked(
            "INTEGRITY.TRUST.MISSING", "No trust bundle is configured. Nothing is trusted by default."
        )
    credential = params.credential()
    acquired = _acquire(ctx, credential)
    if isinstance(acquired, CheckOutcome):
        return acquired
    record = acquired
    records = [record]
    findings: dict[str, JsonValue] = {"source": params.source, "list_source": params.list_source}
    dids: Dids = {}

    def outcome(
        passed: bool | None,
        code: str,
        message: str,
        *,
        no_answer: bool = False,
        limit: ExecutionStatus = ExecutionStatus.BLOCKED,
    ) -> CheckOutcome:
        kind: Literal["artifact", "exchange"] = "artifact" if record.kind == "artifact" else "exchange"
        observation = ctx.observation(0, kind=kind, records=records, summary={"findings": findings})
        observations = [observation, *did_observations(ctx, dids, 1)]
        return judged(passed, code, message, observations, no_answer=no_answer, limit=limit)

    if (gate := credential_gate(ctx, record, findings)) is not None:
        return gate if isinstance(gate, CheckOutcome) else outcome(*gate)
    try:
        token = _judge(ctx, ctx.trust, credential, record.body, findings=findings, dids=dids)
    except (JoseError, _Finding) as exc:
        return outcome(*finding_of(exc, findings), no_answer=isinstance(exc, _Finding) and exc.no_answer)
    document = parse_strict(token.payload, decimals=True)
    assert isinstance(document, dict)  # noqa: S101 - the vc-jose claims rule read one JSON object
    lists = _Lists(ctx, ctx.trust, params, dids, records)
    findings["lists"] = lists.lists  # type: ignore[assignment]  # a list of JSON objects
    try:
        count = lists.judge(document)
    except _Stop as stop:
        findings["entries"] = len(lists.lists)
        return outcome(stop.passed, stop.code, stop.message, no_answer=stop.no_answer, limit=stop.limit)
    findings["entries"] = count
    if all(item.get("ttl") == "fresh" for item in lists.lists):
        freshness = "Each list is fresh under its ttl."
    else:
        freshness = "For a list without a ttl or a validFrom, staleness was not judged."
    entries = "entry names" if count == 1 else "entries name"
    message = (
        f"The credential verifies. Its {count} status {entries} for the purpose {params.purpose} a "
        f"status list credential that verifies with a pinned issuer key, and the bit is not set. {freshness}"
    )
    return outcome(True, "INTEGRITY.STATUS.OK", message)
