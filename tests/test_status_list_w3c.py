"""The check integrity.status_list and the DID key source of integrity.jose (package P2-11).

Oracle: the W3C Recommendation "Bitstring Status List v1.0" of 15 May 2025, by name and date.
No W3C test vector is vendored: the test-suite repository has no recorded license. The lists here
are built with the standard library (gzip and base64), so the oracle does not share the decoder
of dppce.evidence.status. The expected outcome of each seeded fault comes from
validation/fault-catalogue.yaml, which was written before the check existed.

Every key is a TEST-ONLY key made at run time, or a TEST-ONLY key of fixtures/reference/pki.
Loopback servers and local files only.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dppce.adapters.status_list import StatusListParams
from validation.rig import FIXTURES

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.jose import JoseParams
from dppce.evidence.status import MAX_BITSTRING_BYTES, MIN_BITS
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.reference import credentials as reference_credentials
from dppce.infrastructure.reference import did as reference_did
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.models import CheckOutcome, ExecutionStatus, TrustBundle, Verdict
from tests.support import make_artifact, make_record
from tests.test_jose_profiles import (
    ISSUER,
    KID,
    NOW,
    SUBJECT,
    _family_run,
    _json,
    _steps,
    b64u,
    bundle,
    compact,
    failed,
    general,
    is_blocked,
    jwk,
    p256,
    vc,
)
from tests.test_review_findings import transport
from tests.test_url_templates import context, ixit, run

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "validation" / "fault-catalogue.yaml"
PURPOSE = "TP-VC-STATUS-001"
LIST_URL = "https://status.example.test/credentials/status/3"
INDEX = 94567
DID = "did:web:id.example.test"
DID_KID = DID + "#key-1"
HEADER: dict[str, Any] = {"alg": "ES256", "kid": KID, "typ": "vc+jwt"}


# -- builders -------------------------------------------------------------------------------------


def encoded(indices: tuple[int, ...] = (), size_bits: int = MIN_BITS) -> str:
    """A W3C encodedList, built with the standard library only."""
    data = bytearray(size_bits // 8)
    for index in indices:
        data[index // 8] |= 0x80 >> (index % 8)
    return "u" + b64u(gzip.compress(bytes(data)))


def entry(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "id": SUBJECT + "#status",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": str(INDEX),
        "statusListCredential": LIST_URL,
    }
    document |= changes
    return {k: v for k, v in document.items() if v is not None}


def credential(key: ec.EllipticCurvePrivateKey, status: Any = None, **changes: Any) -> str:
    """A VC-JOSE credential. ``status`` None gives the default entry; ``False`` gives no status."""
    value = entry() if status is None else None if status is False else status
    return compact(HEADER, vc(credentialStatus=value, **changes), key)


def list_payload(
    *,
    encoded_list: str | None = None,
    purpose: Any = "revocation",
    ttl: Any = None,
    subject: dict[str, Any] | None = None,
    **changes: Any,
) -> bytes:
    body: dict[str, Any] = {
        "id": LIST_URL + "#list",
        "type": "BitstringStatusList",
        "statusPurpose": purpose,
        "encodedList": encoded() if encoded_list is None else encoded_list,
    }
    if ttl is not None:
        body["ttl"] = ttl
    document: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": LIST_URL,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": ISSUER,
        "validFrom": "2026-10-01T00:00:00Z",
        "credentialSubject": body | (subject or {}),
    }
    document |= changes
    return _json({k: v for k, v in document.items() if v is not None})


def status_list(key: ec.EllipticCurvePrivateKey, header: dict[str, Any] | None = None, **changes: Any) -> str:
    return compact(header or HEADER, list_payload(**changes), key)


Route = tuple[int, bytes | str] | Record


class Routes:
    """An acquirer: the status list URLs get their own answers, every other URL gets the credential."""

    def __init__(
        self,
        credential_body: bytes | str,
        lists: dict[str, Route] | None = None,
        artifacts: dict[str, bytes | str] | None = None,
    ) -> None:
        self._credential = credential_body
        self._lists = lists or {}
        self._artifacts = {k: v.encode() if isinstance(v, str) else v for k, v in (artifacts or {}).items()}
        self._records: list[Record] = []
        self.requests: list[Request] = []

    def fetch(self, request: Request) -> Record:
        self.requests.append(request)
        route = self._lists.get(request.url, (200, self._credential))
        if isinstance(route, Record):
            record = replace(route, record_id=f"r{len(self._records) + 1:04d}", url=request.url)
        else:
            status, body = route
            raw = body.encode() if isinstance(body, str) else body
            record = replace(make_record(len(self._records) + 1, raw, request.url), status=status)
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        index = len(self._records) + 1
        if name in self._artifacts:
            record = make_artifact(name, self._artifacts[name], index=index)
        else:
            record = make_artifact(name, error="artifact_unavailable", index=index)
        self._records.append(record)
        return record

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)

    def list_requests(self) -> list[str]:
        return [r.url for r in self.requests if r.url in self._lists]


def check(tmp_path: Path, routes: Routes, trust: TrustBundle | None, **params: Any) -> CheckOutcome:
    ctx = context(tmp_path, "integrity.status_list", params=params, acquirer=routes, trust=trust)  # type: ignore[arg-type]
    return run(replace(ctx, evaluation_time=NOW))


def jose(tmp_path: Path, routes: Routes, trust: TrustBundle | None, **params: Any) -> CheckOutcome:
    ctx = context(tmp_path, "integrity.jose", params=params, acquirer=routes, trust=trust)  # type: ignore[arg-type]
    return run(replace(ctx, evaluation_time=NOW))


def passed(outcome: CheckOutcome, code: str = "INTEGRITY.STATUS.OK") -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        True,
        code,
    ), outcome.message


def unsupported(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.reason_code) == (ExecutionStatus.UNSUPPORTED, None, code)


def no_answer(outcome: CheckOutcome, code: str) -> None:
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        code,
    )


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return p256()


@pytest.fixture
def trust(key: ec.EllipticCurvePrivateKey) -> TrustBundle:
    return bundle({KID: jwk(key)})


def served(key: ec.EllipticCurvePrivateKey, *, cred: str | None = None, **list_changes: Any) -> Routes:
    body = status_list(key, **list_changes)
    return Routes(cred or credential(key), {LIST_URL: (200, body)})


# -- integrity.status_list: the list and the bit ---------------------------------------------------


def test_a_clear_bit_in_a_verified_list_passes_and_names_only_what_ran(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    routes = served(key)
    outcome = check(tmp_path, routes, trust)
    passed(outcome)
    assert "staleness was not judged" in outcome.message, "no ttl: the message says that it did not run"
    assert routes.list_requests() == [LIST_URL]
    summary = outcome.observations[0].summary["findings"]
    assert summary["entries"] == 1
    assert summary["lists"] == [
        {
            "status": 200,
            "signature": "valid",
            "issuer": "the issuer of the credential",
            "purpose": "matches",
            "bits": MIN_BITS,
            "bit": "not set",
            "ttl": "absent",
        }
    ]
    # No value of the system under test goes into the summary.
    assert str(INDEX) not in json.dumps(summary)
    assert LIST_URL not in json.dumps(summary)
    assert len(outcome.observations[0].record_ids) == 2


@pytest.mark.parametrize(("purpose", "code"), [("revocation", "REVOKED"), ("suspension", "SUSPENDED")])
def test_a_set_bit_fails_for_the_declared_purpose(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, purpose: str, code: str
) -> None:
    cred = credential(key, entry(statusPurpose=purpose))
    routes = served(key, cred=cred, purpose=purpose, encoded_list=encoded((INDEX,)))
    failed(check(tmp_path, routes, trust, purpose=purpose), f"INTEGRITY.STATUS.{code}")
    # The bit of a neighbor is not the bit of the credential.
    neighbors = served(key, cred=cred, purpose=purpose, encoded_list=encoded((INDEX - 1, INDEX + 1)))
    passed(check(tmp_path, neighbors, trust, purpose=purpose))


def test_index_zero_is_the_most_significant_bit_of_the_first_byte(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    cred = credential(key, entry(statusListIndex="0"))
    failed(
        check(tmp_path, served(key, cred=cred, encoded_list=encoded((0,))), trust), "INTEGRITY.STATUS.REVOKED"
    )
    passed(check(tmp_path, served(key, cred=cred, encoded_list=encoded((7,))), trust))


def test_a_list_with_several_purposes_serves_each_of_them(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    passed(check(tmp_path, served(key, purpose=["suspension", "revocation"]), trust))
    failed(check(tmp_path, served(key, purpose="suspension"), trust), "INTEGRITY.STATUS.PURPOSE")
    failed(check(tmp_path, served(key, purpose=[]), trust), "INTEGRITY.STATUS.LIST_MALFORMED")


def test_a_list_shorter_than_the_minimum_fails_and_an_index_outside_it_fails(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    short = served(key, encoded_list=encoded(size_bits=MIN_BITS - 8))
    failed(check(tmp_path, short, trust), "INTEGRITY.STATUS.LIST_LENGTH")
    for index in (str(MIN_BITS), "9" * 40):
        routes = served(key, cred=credential(key, entry(statusListIndex=index)))
        failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.INDEX_RANGE")
    # The last bit is inside the list.
    last = served(key, cred=credential(key, entry(statusListIndex=str(MIN_BITS - 1))))
    passed(check(tmp_path, last, trust))


def test_a_decompression_bomb_is_an_engine_limit_and_does_not_hide_a_revoked_entry(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    bomb = "u" + b64u(gzip.compress(bytes(MAX_BITSTRING_BYTES + 1)))
    assert len(bomb) < 64 * 1024, "the bomb is small on the wire"
    is_blocked(check(tmp_path, served(key, encoded_list=bomb), trust), "INTEGRITY.STATUS.TOO_LARGE")
    other = "https://status.example.test/credentials/status/4"
    entries = [entry(), entry(id=SUBJECT + "#status-2", statusListCredential=other)]
    routes = Routes(
        credential(key, entries),
        {
            LIST_URL: (200, status_list(key, encoded_list=bomb)),
            other: (200, status_list(key, id=other, encoded_list=encoded((INDEX,)))),
        },
    )
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.REVOKED")
    # In the other order too.
    routes = Routes(credential(key, entries[::-1]), routes._lists)
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.REVOKED")


@pytest.mark.parametrize("encoded_list", ["not multibase", "uAAAA", "u" + b64u(b"not gzip")])
def test_an_encoded_list_that_does_not_decode_is_malformed(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, encoded_list: str
) -> None:
    failed(check(tmp_path, served(key, encoded_list=encoded_list), trust), "INTEGRITY.STATUS.LIST_MALFORMED")


# -- staleness ------------------------------------------------------------------------------------

DAY_MS = 86_400_000


def test_ttl_staleness_is_judged_against_the_evaluation_time(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    # validFrom is 2026-10-01T00:00:00Z. The evaluation time is 2026-10-13T12:00:00Z.
    fresh = check(tmp_path, served(key, ttl=13 * DAY_MS), trust)
    passed(fresh)
    assert "fresh under its ttl" in fresh.message
    is_blocked(check(tmp_path, served(key, ttl=DAY_MS), trust), "INTEGRITY.STATUS.STALE")
    # No validFrom: the ttl has no anchor, so staleness is not judged and the message says so.
    unanchored = check(tmp_path, served(key, ttl=DAY_MS, validFrom=None), trust)
    passed(unanchored)
    assert "staleness was not judged" in unanchored.message
    for ttl in (-1, "86400000", True):
        failed(check(tmp_path, served(key, ttl=ttl), trust), "INTEGRITY.STATUS.LIST_MALFORMED")


def test_a_stale_list_still_fails_a_revoked_bit_but_not_a_suspended_one(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    # Revocation is not reversible (Bitstring Status List v1.0), so an old list still shows it.
    revoked = served(key, ttl=DAY_MS, encoded_list=encoded((INDEX,)))
    failed(check(tmp_path, revoked, trust), "INTEGRITY.STATUS.REVOKED")
    # Suspension is reversible: a stale list does not show the current suspension.
    cred = credential(key, entry(statusPurpose="suspension"))
    suspended = served(key, cred=cred, purpose="suspension", ttl=DAY_MS, encoded_list=encoded((INDEX,)))
    is_blocked(check(tmp_path, suspended, trust, purpose="suspension"), "INTEGRITY.STATUS.STALE")


# -- the list credential --------------------------------------------------------------------------


def test_a_list_signature_that_does_not_verify_fails(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    token = status_list(key)
    protected, _, signature = token.split(".")
    tampered = f"{protected}.{b64u(list_payload(encoded_list=encoded((1,))))}.{signature}"
    routes = Routes(credential(key), {LIST_URL: (200, tampered)})
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.LIST_SIGNATURE")
    unsecured = compact({"alg": "none", "kid": KID}, list_payload())
    routes = Routes(credential(key), {LIST_URL: (200, unsecured)})
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.LIST_SIGNATURE")


def test_a_list_without_a_securing_mechanism_fails_and_a_data_integrity_list_is_unsupported(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    plain = list_payload()
    failed(
        check(tmp_path, Routes(credential(key), {LIST_URL: (200, plain)}), trust),
        "INTEGRITY.STATUS.LIST_SIGNATURE",
    )
    proof = {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-rdfc-2019", "proofValue": "zTEST"}
    secured = _json({**json.loads(plain), "proof": proof})
    unsupported(
        check(tmp_path, Routes(credential(key), {LIST_URL: (200, secured)}), trust),
        "INTEGRITY.STATUS.LIST_FORMAT",
    )
    # A proof member of another shape is no securing mechanism that the engine knows of: a fail.
    odd = _json({**json.loads(plain), "proof": "TEST"})
    failed(
        check(tmp_path, Routes(credential(key), {LIST_URL: (200, odd)}), trust),
        "INTEGRITY.STATUS.LIST_SIGNATURE",
    )


def test_the_list_must_be_signed_by_a_pinned_key_of_its_own_issuer(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    stranger = p256()
    unknown = status_list(stranger, {"alg": "ES256", "kid": "TEST-ONLY-unknown", "typ": "vc+jwt"})
    failed(
        check(tmp_path, Routes(credential(key), {LIST_URL: (200, unknown)}), trust),
        "INTEGRITY.STATUS.LIST_UNTRUSTED",
    )
    # The pinned key belongs to the credential issuer, and the list names another issuer.
    other = status_list(key, issuer="urn:example:other-issuer")
    failed(
        check(tmp_path, Routes(credential(key), {LIST_URL: (200, other)}), trust),
        "INTEGRITY.STATUS.LIST_UNTRUSTED",
    )


def test_a_list_of_another_pinned_issuer_passes_and_the_summary_says_so(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    # The W3C Recommendation permits a status issuer other than the credential issuer.
    status_key = p256()
    trust = TrustBundle.model_validate(
        {
            **bundle({KID: jwk(key)}).model_dump(mode="json"),
            "keys": [
                *bundle({KID: jwk(key)}).model_dump(mode="json")["keys"],
                *bundle(
                    {"TEST-ONLY-status-key": jwk(status_key)}, issuer="urn:example:status-service"
                ).model_dump(mode="json")["keys"],
            ],
        }
    )
    header = {"alg": "ES256", "kid": "TEST-ONLY-status-key", "typ": "vc+jwt"}
    routes = Routes(
        credential(key),
        {LIST_URL: (200, status_list(status_key, header, issuer="urn:example:status-service"))},
    )
    outcome = check(tmp_path, routes, trust)
    passed(outcome)
    assert outcome.observations[0].summary["findings"]["lists"][0]["issuer"] == "another pinned issuer"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"validFrom": "2026-11-01T00:00:00Z"}, "INTEGRITY.STATUS.LIST_VALIDITY"),
        ({"validUntil": "2026-10-02T00:00:00Z"}, "INTEGRITY.STATUS.LIST_VALIDITY"),
        ({"type": ["VerifiableCredential"]}, "INTEGRITY.STATUS.LIST_MALFORMED"),
        ({"credentialSubject": "TEST"}, "INTEGRITY.STATUS.LIST_MALFORMED"),
        ({"subject": {"type": "StatusList2021"}}, "INTEGRITY.STATUS.LIST_MALFORMED"),
        ({"subject": {"encodedList": 7}}, "INTEGRITY.STATUS.LIST_MALFORMED"),
        ({"issuer": None}, "INTEGRITY.STATUS.LIST_MALFORMED"),
    ],
)
def test_the_list_credential_shape_and_validity_are_judged(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, changes: dict[str, Any], code: str
) -> None:
    failed(check(tmp_path, served(key, **changes), trust), code)


def test_the_list_must_answer_200_and_a_missing_answer_is_no_answer(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    failed(
        check(tmp_path, Routes(credential(key), {LIST_URL: (404, b"")}), trust),
        "INTEGRITY.STATUS.LIST_NOT_AVAILABLE",
    )
    no_answer(
        check(tmp_path, Routes(credential(key), {LIST_URL: (503, b"")}), trust), "TRANSPORT.SERVER_ERROR"
    )
    denied = replace(make_record(1), status=None, body=b"", error="policy_denied")
    no_answer(check(tmp_path, Routes(credential(key), {LIST_URL: denied}), trust), "TRANSPORT.DENIED")


def test_a_list_host_that_the_operator_did_not_confirm_is_never_contacted(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    # The real transport policy: the credential comes from a sample, the list host is not allowed.
    sample = tmp_path / "credential.jwt"
    sample.write_text(credential(key))
    ctx = context(
        tmp_path,
        "integrity.status_list",
        params={"source": "sample"},
        acquirer=transport(samples={"credential": sample}),  # type: ignore[arg-type]
        trust=trust,
    )
    outcome = run(replace(ctx, evaluation_time=NOW))
    no_answer(outcome, "TRANSPORT.DENIED")
    assert "connectivity failure" in outcome.message


def test_the_list_comes_from_an_ixit_sample_that_names_the_entry_url(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    routes = Routes(credential(key), artifacts={"status_list": status_list(key)})
    passed(check(tmp_path, routes, trust, list_source="sample"))
    assert [r.url for r in routes.requests if r.url == LIST_URL] == [], "a sample sends no list request"
    unbound = Routes(
        credential(key), artifacts={"status_list": status_list(key, id="https://status.example.test/x")}
    )
    is_blocked(check(tmp_path, unbound, trust, list_source="sample"), "INTEGRITY.STATUS.LIST_UNBOUND")
    nameless = Routes(credential(key), artifacts={"other": status_list(key, id=None)})
    is_blocked(
        check(tmp_path, nameless, trust, list_source="sample", list_sample="other"),
        "INTEGRITY.STATUS.LIST_UNBOUND",
    )
    missing = Routes(credential(key))
    is_blocked(check(tmp_path, missing, trust, list_source="sample"), "INTEGRITY.STATUS.SAMPLE_MISSING")


def test_a_revoked_bit_in_an_unbound_sample_is_not_a_fail(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    # The engine cannot show that the sample is the list of the entry, so its bit means nothing.
    sample = status_list(key, id="https://status.example.test/x", encoded_list=encoded((INDEX,)))
    routes = Routes(credential(key), artifacts={"status_list": sample})
    is_blocked(check(tmp_path, routes, trust, list_source="sample"), "INTEGRITY.STATUS.LIST_UNBOUND")


# -- the status entry of the credential -----------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    [
        False,
        [],
        entry(statusPurpose="suspension"),
        [entry(statusPurpose="refresh"), entry(statusPurpose="message")],
    ],
)
def test_a_credential_without_an_entry_for_the_purpose_fails(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, status: Any
) -> None:
    routes = served(key, cred=credential(key, status))
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.ENTRY_MISSING")
    assert routes.list_requests() == []


def test_an_entry_of_another_type_only_is_unsupported(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    other = entry(type="StatusList2021Entry")
    routes = served(key, cred=credential(key, other))
    unsupported(check(tmp_path, routes, trust), "INTEGRITY.STATUS.ENTRY_TYPE")
    # An entry of the known type for the purpose is judged next to it.
    both = served(key, cred=credential(key, [other, entry()]), encoded_list=encoded((INDEX,)))
    failed(check(tmp_path, both, trust), "INTEGRITY.STATUS.REVOKED")


@pytest.mark.parametrize(
    "status",
    [
        "TEST",
        [7],
        entry(statusListIndex=INDEX),
        entry(statusListIndex="12a"),
        entry(statusListIndex="-1"),
        entry(statusListIndex=None),
        entry(statusListCredential="not a url"),
        entry(statusListCredential="ftp://status.example.test/3"),
        entry(statusListCredential=None),
        entry(statusPurpose=None),
        entry(type=["BitstringStatusListEntry"]),
        entry(id=LIST_URL),
        entry(statusSize=0),
        entry(statusSize="1"),
    ],
)
def test_a_malformed_entry_fails_and_nothing_is_fetched(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle, status: Any
) -> None:
    routes = served(key, cred=credential(key, status))
    failed(check(tmp_path, routes, trust), "INTEGRITY.STATUS.ENTRY_MALFORMED")
    assert routes.list_requests() == []


def test_a_status_size_other_than_one_is_unsupported_and_does_not_hide_a_list_fail(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    sized = credential(key, entry(statusSize=2))
    unsupported(check(tmp_path, served(key, cred=sized), trust), "INTEGRITY.STATUS.SIZE_UNSUPPORTED")
    failed(check(tmp_path, served(key, cred=sized, purpose="suspension"), trust), "INTEGRITY.STATUS.PURPOSE")
    passed(check(tmp_path, served(key, cred=credential(key, entry(statusSize=1))), trust))


def test_more_entries_than_the_limit_are_judged_before_the_limit_applies(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    entries = [entry(id=f"{SUBJECT}#s{n}") for n in range(5)]
    is_blocked(
        check(tmp_path, served(key, cred=credential(key, entries)), trust), "INTEGRITY.STATUS.TOO_LARGE"
    )
    revoked = served(key, cred=credential(key, entries), encoded_list=encoded((INDEX,)))
    failed(check(tmp_path, revoked, trust), "INTEGRITY.STATUS.REVOKED")


def test_two_entries_for_one_list_fetch_it_once(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    entries = [entry(), entry(id=SUBJECT + "#status-2", statusListIndex="7")]
    routes = served(key, cred=credential(key, entries))
    outcome = check(tmp_path, routes, trust)
    passed(outcome)
    assert routes.list_requests() == [LIST_URL]
    assert outcome.observations[0].summary["findings"]["entries"] == 2


# -- the credential comes first -------------------------------------------------------------------


def test_a_credential_that_does_not_verify_fails_with_its_jose_finding_and_no_list_is_fetched(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    token = credential(key)
    protected, _, signature = token.split(".")
    tampered = f"{protected}.{b64u(vc(credentialStatus=entry(statusListIndex='1')))}.{signature}"
    routes = served(key, cred=tampered, encoded_list=encoded((INDEX,)))
    failed(check(tmp_path, routes, trust), "INTEGRITY.JOSE.SIGNATURE")
    assert routes.list_requests() == []
    expired = served(key, cred=credential(key, validUntil="2026-01-02T00:00:00Z"))
    failed(check(tmp_path, expired, trust), "INTEGRITY.JOSE.EXPIRED")


def test_invalid_parameters_and_a_missing_trust_bundle_are_blocked(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, trust: TrustBundle
) -> None:
    routes = served(key)
    is_blocked(check(tmp_path, routes, trust, purpose="refresh"), "INTEGRITY.STATUS.PARAMS")
    is_blocked(check(tmp_path, routes, trust, list_source="cache"), "INTEGRITY.STATUS.PARAMS")
    is_blocked(check(tmp_path, routes, None), "INTEGRITY.TRUST.MISSING")
    assert routes.requests == []


def test_the_parameter_model_is_closed() -> None:
    assert StatusListParams().model_dump() == {
        "key_source": "trust_kid",
        "did_sample": None,
        "source": "signed",
        "sample": "credential",
        "accept": None,
        "list_source": "live",
        "list_sample": "status_list",
        "purpose": "revocation",
    }
    with pytest.raises(ValueError, match="did_sample"):
        StatusListParams(did_sample="did_document")
    with pytest.raises(ValueError, match="key_source"):
        StatusListParams.model_validate({"key_source": "x5c"})


# -- integrity.jose with the key source did ------------------------------------------------------


def did_document(public: dict[str, str], **changes: Any) -> bytes:
    document: dict[str, Any] = {
        "id": DID,
        "verificationMethod": [
            {"id": DID_KID, "type": "JsonWebKey", "controller": DID, "publicKeyJwk": public}
        ],
        "assertionMethod": [DID_KID],
    }
    document |= changes
    return _json({k: v for k, v in document.items() if v is not None})


def did_trust(public: dict[str, str], **kw: Any) -> TrustBundle:
    return bundle({"TEST-ONLY-did-key-1": public}, issuer=DID, **kw)


def did_credential(key: ec.EllipticCurvePrivateKey, kid: str = DID_KID, **changes: Any) -> str:
    return compact({"alg": "ES256", "kid": kid, "typ": "vc+jwt"}, vc(issuer=DID, **changes), key)


def offline(token: str, document: bytes | None) -> Routes:
    artifacts: dict[str, bytes | str] = {"credential": token}
    if document is not None:
        artifacts["did_document"] = document
    return Routes(token, artifacts=artifacts)


DID_PARAMS: dict[str, Any] = {"key_source": "did", "source": "sample", "did_sample": "did_document"}


def test_a_did_key_that_a_pinned_key_of_the_did_matches_passes(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    outcome = jose(
        tmp_path, offline(did_credential(key), did_document(jwk(key))), did_trust(jwk(key)), **DID_PARAMS
    )
    assert (outcome.passed, outcome.reason_code) == (True, "INTEGRITY.JOSE.OK"), outcome.message
    ids = [o.id for o in outcome.observations]
    assert len(ids) == len(set(ids)) == 2, "the DID document has its own observation"


def test_resolution_is_not_trust_a_did_without_a_pinned_key_is_untrusted_and_not_fetched(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    routes = Routes(did_credential(key), artifacts={"credential": did_credential(key)})
    outcome = jose(tmp_path, routes, bundle({KID: jwk(key)}), key_source="did", source="sample")
    failed(outcome, "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    assert routes.requests == [], "the DID host is not contacted for an issuer that nothing pins"


def test_the_pinned_key_must_equal_the_key_of_the_did_document(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    outcome = jose(
        tmp_path, offline(did_credential(key), did_document(jwk(key))), did_trust(jwk(p256())), **DID_PARAMS
    )
    failed(outcome, "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    # A key that the document publishes and the trust bundle pins, but that did not sign.
    other = p256()
    outcome = jose(
        tmp_path, offline(did_credential(other), did_document(jwk(key))), did_trust(jwk(key)), **DID_PARAMS
    )
    failed(outcome, "INTEGRITY.JOSE.SIGNATURE")


@pytest.mark.parametrize(
    "changes",
    [
        {"assertionMethod": []},
        {"assertionMethod": None},
        {"verificationMethod": [], "assertionMethod": []},
        {"id": "did:web:other.example.test"},
    ],
)
def test_a_did_document_without_the_assertion_method_or_that_breaks_a_rule_is_untrusted(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey, changes: dict[str, Any]
) -> None:
    routes = offline(did_credential(key), did_document(jwk(key), **changes))
    failed(jose(tmp_path, routes, did_trust(jwk(key)), **DID_PARAMS), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")


def test_a_kid_that_is_not_a_did_web_url_is_untrusted_or_unsupported(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    trust = did_trust(jwk(key))
    for kid in (KID, DID, DID + "#", "did:web:127.0.0.1#key-1"):
        routes = offline(did_credential(key, kid), did_document(jwk(key)))
        failed(jose(tmp_path, routes, trust, **DID_PARAMS), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    other_method = offline(did_credential(key, "did:key:zTEST#zTEST"), did_document(jwk(key)))
    is_blocked(jose(tmp_path, other_method, trust, **DID_PARAMS), "INTEGRITY.JOSE.UNSUPPORTED")


def test_a_did_method_without_a_jwk_is_an_engine_limit_that_does_not_hide_a_fail(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    multibase = {"id": DID_KID, "type": "Multikey", "controller": DID, "publicKeyMultibase": "zTEST"}
    document = did_document(jwk(key), verificationMethod=[multibase])
    trust = did_trust(jwk(key))
    is_blocked(
        jose(tmp_path, offline(did_credential(key), document), trust, **DID_PARAMS),
        "INTEGRITY.JOSE.UNSUPPORTED",
    )
    payload = vc(issuer=DID)
    good = compact({"alg": "ES256", "kid": DID_KID, "typ": "vc+jwt"}, payload, key)
    bad = compact({"alg": "ES256", "kid": DID_KID + "x", "typ": "vc+jwt"}, payload, key)
    for pair in ((good, bad), (bad, good)):
        body = general(*pair).decode()
        failed(
            jose(tmp_path, offline(body, document), trust, **DID_PARAMS), "INTEGRITY.JOSE.ISSUER_UNTRUSTED"
        )


def test_the_credential_issuer_must_be_the_did_and_the_pinned_key_must_be_valid(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    token = compact({"alg": "ES256", "kid": DID_KID, "typ": "vc+jwt"}, vc(), key)  # issuer is not the DID
    routes = offline(token, did_document(jwk(key)))
    failed(jose(tmp_path, routes, did_trust(jwk(key)), **DID_PARAMS), "INTEGRITY.JOSE.ISSUER_UNTRUSTED")
    revoked = did_trust(jwk(key), revoked=("TEST-ONLY-did-key-1",))
    routes = offline(did_credential(key), did_document(jwk(key)))
    failed(jose(tmp_path, routes, revoked, **DID_PARAMS), "INTEGRITY.JOSE.KEY_NOT_VALID")


def test_a_missing_did_sample_is_blocked_and_a_did_host_without_an_answer_is_no_answer(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    trust = did_trust(jwk(key))
    is_blocked(
        jose(tmp_path, offline(did_credential(key), None), trust, **DID_PARAMS), "IDENTITY.DID.SAMPLE_MISSING"
    )
    denied = replace(make_record(1), status=None, body=b"", error="policy_denied")
    routes = Routes(
        did_credential(key),
        {"https://id.example.test/.well-known/did.json": denied},
        artifacts={"credential": did_credential(key)},
    )
    no_answer(jose(tmp_path, routes, trust, key_source="did", source="sample"), "TRANSPORT.DENIED")


def test_the_did_sample_parameter_needs_the_did_key_source() -> None:
    assert JoseParams(key_source="did").key_source == "did"
    with pytest.raises(ValueError, match="did_sample"):
        JoseParams(did_sample="did_document")


def _leaf() -> ec.EllipticCurvePrivateKey:
    pem = (FIXTURES / "pki" / "TEST-ONLY-leaf.key.pem").read_bytes()
    private = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    return private


def test_a_live_did_document_of_the_reference_system_gives_the_key_through_the_transport(
    tmp_path: Path,
) -> None:
    leaf = _leaf()
    assert jwk(leaf) == reference_did.PUBLIC_JWK
    sample = tmp_path / "credential.jwt"
    sample.write_text(did_credential(leaf))
    with ReferenceServer(FIXTURES) as server:
        endpoints = {
            "api": server.origin,
            "public_origin": "https://id.example.test",
            "origin_override": server.origin,
        }
        ctx = context(
            tmp_path,
            "integrity.jose",
            params={"key_source": "did", "source": "sample"},
            the_ixit=ixit(endpoints=endpoints),
            acquirer=transport(samples={"credential": sample}),  # type: ignore[arg-type]
            trust=did_trust(reference_did.PUBLIC_JWK),
        )
        outcome = run(replace(ctx, evaluation_time=NOW))
    assert (outcome.passed, outcome.reason_code) == (True, "INTEGRITY.JOSE.OK"), outcome.message


def test_the_status_list_can_take_its_keys_from_a_did(
    tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    header = {"alg": "ES256", "kid": DID_KID, "typ": "vc+jwt"}
    cred = compact(header, vc(issuer=DID, credentialStatus=entry()), key)
    routes = Routes(
        cred,
        {LIST_URL: (200, compact(header, list_payload(issuer=DID), key))},
        artifacts={"credential": cred, "did_document": did_document(jwk(key))},
    )
    passed(check(tmp_path, routes, did_trust(jwk(key)), **DID_PARAMS))


# -- the reference system: control C-FAMILY-VC and F-69, F-70, B-18 -------------------------------


def _status_cases() -> list[dict[str, Any]]:
    document = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    entries = (*document["sut_faults"], *document["boundary_cases"])
    return [e for e in entries if e.get("test_purpose") == PURPOSE]


def test_the_catalogue_names_the_status_faults() -> None:
    cases = _status_cases()
    assert [c["id"] for c in cases] == ["F-69", "F-70", "B-18"]
    assert all(c["profiles"] == ["family/credentials"] for c in cases)
    assert {c["fault"] for c in cases} <= reference_credentials.FLAGS


def test_control_c_family_vc_still_passes_with_the_status_list(tmp_path: Path) -> None:
    envelope = _family_run(tmp_path)
    steps = _steps(envelope)
    assert steps[PURPOSE] == ("pass", "INTEGRITY.STATUS.OK")
    assert all(v[0] == "pass" for k, v in steps.items() if k.startswith("TP-VC-")), steps
    assert envelope.decision.overall is Verdict.PASS


@pytest.mark.parametrize("case", _status_cases(), ids=lambda c: str(c["id"]))
def test_each_seeded_status_fault_gives_the_catalogue_outcome(case: dict[str, Any], tmp_path: Path) -> None:
    envelope = _family_run(tmp_path, frozenset({case["fault"]}))
    steps = _steps(envelope)
    assert steps[PURPOSE] == (case["expected"]["verdict"], case["expected"]["reason_code"])
    # Each flag changes the status list only: the credential itself still verifies.
    assert steps["TP-VC-JOSE-001"] == ("pass", "INTEGRITY.JOSE.OK")
