"""Security properties of the integrity and access adapters.

Certificate paths: a signature and a matching name are not enough to make an issuer.
Revocation: serial numbers compare as integers, for every certificate of the path.
Access: a check that probed nothing never passes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from dppce.adapters.access import AccessPolicy, restricted_fields
from dppce.adapters.integrity import trust_path
from dppce.evidence.x509path import revoked
from dppce.infrastructure.interfaces import Record, Request
from dppce.models import (
    ICS,
    IXIT,
    Authorization,
    ExecutionStatus,
    Profile,
    RevokedCertificate,
    TestPurpose,
    TrustAnchor,
    TrustBundle,
)
from dppce.testdefs.registry import CheckContext
from tests.support import make_record

START, END = datetime(2026, 1, 1, tzinfo=UTC), datetime(2036, 1, 1, tzinfo=UTC)
Pair = tuple[ec.EllipticCurvePrivateKey, x509.Certificate]


def issue(
    subject: str,
    parent: Pair | None,
    *,
    ca: bool,
    path_length: int | None = None,
    constraints: bool = True,
    cert_sign: bool | None = None,
) -> Pair:
    """Issue a test certificate. ``parent`` None makes it self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(parent[1].subject if parent else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(START)
        .not_valid_after(END)
    )
    if constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if cert_sign is not None:
        usage = x509.KeyUsage(
            digital_signature=True, key_cert_sign=cert_sign, crl_sign=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        )  # fmt: skip
        builder = builder.add_extension(usage, critical=True)
    return key, builder.sign(parent[0] if parent else key, hashes.SHA256())


def bundle(*anchors: x509.Certificate, **more: Any) -> TrustBundle:
    return TrustBundle(
        schema_version="dppce.trust/2",
        policy_version="test",
        anchors=tuple(
            TrustAnchor(
                name="test", certificate_pem=a.public_bytes(serialization.Encoding.PEM).decode("ascii")
            )
            for a in anchors
        ),
        **more,
    )


# -- certificate paths ------------------------------------------------------------------------


def test_a_leaf_under_a_trusted_root_has_a_path() -> None:
    root = issue("root", None, ca=True)
    leaf = issue("leaf", root, ca=False)
    assert trust_path(leaf[1], [], bundle(root[1])) == [leaf[1], root[1]]


def test_an_intermediate_authority_is_accepted_inside_the_path_length() -> None:
    root = issue("root", None, ca=True, path_length=1)
    middle = issue("middle", root, ca=True, path_length=0)
    leaf = issue("leaf", middle, ca=False)
    assert trust_path(leaf[1], [middle[1]], bundle(root[1])) == [leaf[1], middle[1], root[1]]


def test_the_holder_of_an_end_certificate_cannot_issue_certificates() -> None:
    """The attack that a name-and-signature check alone accepts."""
    root = issue("root", None, ca=True)
    honest = issue("honest leaf", root, ca=False)
    forged = issue("forged leaf", honest, ca=False)
    forged[1].verify_directly_issued_by(honest[1])  # the signature and the names do match
    assert trust_path(forged[1], [honest[1]], bundle(root[1])) is None


def test_an_issuer_without_basic_constraints_is_not_an_authority() -> None:
    root = issue("root", None, ca=True)
    bare = issue("no constraints", root, ca=False, constraints=False)
    leaf = issue("leaf", bare, ca=False)
    assert trust_path(leaf[1], [bare[1]], bundle(root[1])) is None


def test_an_authority_that_may_not_sign_certificates_is_refused() -> None:
    root = issue("root", None, ca=True, cert_sign=False)
    leaf = issue("leaf", root, ca=False)
    assert trust_path(leaf[1], [], bundle(root[1])) is None


def test_the_path_length_constraint_is_enforced() -> None:
    root = issue("root", None, ca=True, path_length=0)  # no authority may sit below this root
    middle = issue("middle", root, ca=True)
    leaf = issue("leaf", middle, ca=False)
    assert trust_path(leaf[1], [middle[1]], bundle(root[1])) is None


def test_a_different_root_and_a_self_signed_leaf_give_no_path() -> None:
    root, other = issue("root", None, ca=True), issue("other root", None, ca=True)
    assert trust_path(issue("leaf", other, ca=False)[1], [], bundle(root[1])) is None
    assert trust_path(issue("self", None, ca=False)[1], [], bundle(root[1])) is None
    assert trust_path(issue("leaf", root, ca=False)[1], [], bundle()) is None, (
        "an empty bundle trusts nothing"
    )


# -- revocation -------------------------------------------------------------------------------


def _revoked(serial: str, issuer: x509.Certificate) -> RevokedCertificate:
    """An entry scoped by the issuer name of ``issuer``'s certificates (trust bundle version 2)."""
    return RevokedCertificate(serial=serial, issuer_name=issuer.subject.rfc4514_string(), revoked_at=None)


@pytest.mark.parametrize("form", ["{:x}", "{:X}", "0{:x}", "00{:X}"])
def test_a_revoked_serial_matches_in_any_hexadecimal_form(form: str) -> None:
    root = issue("root", None, ca=True)
    leaf = issue("leaf", root, ca=False)
    trust = bundle(root[1], revoked_certificates=(_revoked(form.format(leaf[1].serial_number), root[1]),))
    assert revoked([leaf[1], root[1]], trust.revoked_certificates, START)


def test_colons_and_a_revoked_authority_are_handled() -> None:
    root = issue("root", None, ca=True)
    middle = issue("middle", root, ca=True)
    leaf = issue("leaf", middle, ca=False)
    text = f"{middle[1].serial_number:x}"
    text = text if len(text) % 2 == 0 else "0" + text
    with_colons = ":".join(text[i : i + 2] for i in range(0, len(text), 2)).upper()
    path = [leaf[1], middle[1], root[1]]
    trust = bundle(root[1], revoked_certificates=(_revoked(with_colons, root[1]),))
    assert revoked(path, trust.revoked_certificates, START), "any certificate of the path counts"
    assert not revoked(
        path, bundle(root[1], revoked_certificates=(_revoked("01", root[1]),)).revoked_certificates, START
    )
    assert not revoked(path, bundle(root[1]).revoked_certificates, START)


@pytest.mark.parametrize("serial", ["not-hex", "", "12 34", "0x1f", "12::34"])
def test_a_serial_that_cannot_be_parsed_is_rejected_when_the_bundle_loads(serial: str) -> None:
    with pytest.raises(ValidationError):
        bundle(revoked_certificates=({"serial": serial, "issuer_name": "CN=root", "revoked_at": None},))


# -- access -----------------------------------------------------------------------------------


class _Canned:
    """An acquirer that answers every request with one canned body.

    ``by_url`` gives a status and a body for one URL. ``truncated`` names URLs whose body is cut.
    """

    def __init__(
        self,
        body: bytes = b"{}",
        media_type: str = "application/json",
        *,
        status: int = 200,
        by_url: dict[str, tuple[int, bytes]] | None = None,
        truncated: frozenset[str] = frozenset(),
    ) -> None:
        self._body, self._media_type, self._records = body, media_type, []  # type: ignore[var-annotated]
        self._status, self._by_url, self._truncated = status, by_url or {}, truncated

    def fetch(self, request: Request) -> Record:
        status, body = self._by_url.get(request.url, (self._status, self._body))
        base = make_record(len(self._records) + 1, body, request.url)
        record = Record(
            **{
                **base.__dict__,
                "headers": (("Content-Type", self._media_type),),
                "role": request.role,
                "status": status,
                "truncated": request.url in self._truncated,
            }
        )
        self._records.append(record)
        return record

    def artifact(self, name: str) -> Record:
        raise AssertionError("not used")

    def records(self) -> tuple[Record, ...]:
        return tuple(self._records)


def _context(
    tmp_path: Path,
    policy: dict[str, Any],
    acquirer: _Canned,
    *,
    role: str | None = None,
    authorization: Authorization | None = None,
) -> CheckContext:
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(policy), encoding="utf-8")
    purpose = TestPurpose.model_validate(
        {
            "id": "TP-X",
            "title": "t",
            "requirements": ["R"],
            "profiles": ["*"],
            "applicability": {"const": "true"},
            "stimulus": {"check": "access.restricted_fields", "params": {"role": role} if role else {}},
            "permitted_modes": ["illustrative"],
        }
    )
    profile = Profile.model_validate(
        {
            "schema_version": "dppce.profile/1",
            "id": "p/x",
            "title": "t",
            "product_category": "x",
            "access_policy": "policy.yaml",
            "packs": [],
            "testpacks": [],
        }
    )
    ics = ICS.model_validate(
        {
            "schema_version": "dppce.ics/1",
            "sut": {"name": "s", "identifier": "urn:x"},
            "profile": "p/x",
            "access": {"policy": "test/policy"},
        }
    )
    ixit = IXIT.model_validate(
        {
            "schema_version": "dppce.ixit/1",
            "endpoints": {"api": "http://sut.example"},
            "samples": {"passport_id": "09506000134352-EV0001"},
            "resources": {"item": {"endpoint": "api", "path": "/dpp/{id}"}},
            "id_parts": {"separator": "-", "names": ["gtin", "serial"]},
        }
    )
    return CheckContext(
        purpose=purpose,
        ics=ics,
        ixit=ixit,
        profile=profile,
        acquirer=acquirer,
        evaluation_time=datetime(2026, 10, 13, tzinfo=UTC),
        data_root=tmp_path,
        authorization=authorization,
    )


_POLICY: dict[str, Any] = {
    "schema_version": "dppce.accesspolicy/1",
    "policy_id": "test/policy",
    "version": "1",
    "basis": {"class": "illustrative"},
    "restricted": [{"path": "restricted.secret", "roles": ["authority"]}],
    "canaries": [{"path": "restricted.secret", "value": "CANARY-test"}],
    "channels": {"fetch": "/dpp/{id}"},
}


def test_a_clean_channel_passes_and_a_leak_fails(tmp_path: Path) -> None:
    clean = restricted_fields(_context(tmp_path, _POLICY, _Canned(b'{"id": "x"}')))
    assert (clean.passed, clean.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    by_path = restricted_fields(
        _context(tmp_path, _POLICY, _Canned(b'{"a": [{"restricted": {"secret": "other"}}]}'))
    )
    assert (by_path.passed, by_path.reason_code) == (False, "ACCESS.LEAK.FETCH")
    by_canary = restricted_fields(_context(tmp_path, _POLICY, _Canned(b"<p>CANARY-test</p>", "text/html")))
    assert (by_canary.passed, by_canary.reason_code) == (False, "ACCESS.LEAK.FETCH")
    assert "CANARY-test" not in by_canary.model_dump_json(), "a field value never reaches an observation"


@pytest.mark.parametrize(
    "changes",
    [
        {"restricted": [], "canaries": []},  # nothing is given to or withheld from anyone
        {"channels": {}},  # nowhere to look
    ],
)
def test_a_check_that_probed_nothing_never_passes(changes: dict[str, Any], tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _POLICY | changes, _Canned(b"{}")))
    assert (outcome.status, outcome.passed) == (ExecutionStatus.BLOCKED, None)
    assert outcome.reason_code == "ACCESS.POLICY.NOTHING_TO_PROBE"


# -- positive entitlement (gap D5-02) ----------------------------------------------------------

_FETCH = "http://sut.example/dpp/09506000134352-EV0001"
_EXPORT = _FETCH + "/export"
_FORBIDDEN = b'{"error": "forbidden"}'
# The anonymous role gets the public path `id`. Only the authority role gets the secret.
_PUBLIC: dict[str, Any] = _POLICY | {
    "restricted": [
        {"path": "id", "roles": ["anonymous", "authority"]},
        {"path": "restricted.secret", "roles": ["authority"]},
    ]
}
_TWO_CHANNELS = {"fetch": "/dpp/{id}", "export": "/dpp/{id}/export"}


def _summary(outcome: Any) -> dict[str, Any]:
    return dict(outcome.observations[0].summary)


def test_a_role_with_nothing_withheld_is_probed_for_entitlement(tmp_path: Path) -> None:
    """Criterion 4 of gap D5-02. This case gave NOTHING_TO_PROBE before."""
    policy = _POLICY | {"restricted": [{"path": "restricted.secret", "roles": ["anonymous"]}], "canaries": []}
    empty = _Canned(b"{}")
    outcome = restricted_fields(_context(tmp_path, policy, empty))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.ENTITLEMENT.MISSING")
    assert len(empty.records()) == 1, "a role with nothing withheld reads the fetch channel only"
    withheld = restricted_fields(_context(tmp_path, policy, _Canned(b'{"restricted": {"secret": null}}')))
    assert (withheld.passed, withheld.reason_code) == (False, "ACCESS.ENTITLEMENT.MISSING")
    served = restricted_fields(_context(tmp_path, policy, _Canned(b'{"restricted": {"secret": "v"}}')))
    assert (served.passed, served.reason_code) == (True, "ACCESS.POLICY.ENFORCED")


def test_a_policy_that_names_a_path_twice_is_not_valid(tmp_path: Path) -> None:
    twice = [
        {"path": "restricted.secret", "roles": ["anonymous"]},
        {"path": "restricted.secret", "roles": ["authority"]},
    ]
    with pytest.raises(ValidationError, match="more than once"):
        AccessPolicy.model_validate(_POLICY | {"restricted": twice})
    canaries = [
        {"path": "restricted.secret", "value": "CANARY-a"},
        {"path": "restricted.secret", "value": "b"},
    ]
    with pytest.raises(ValidationError, match="more than once"):
        AccessPolicy.model_validate(_POLICY | {"canaries": canaries})
    acquirer = _Canned()
    outcome = restricted_fields(_context(tmp_path, _POLICY | {"restricted": twice}, acquirer))
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.POLICY.MISSING")
    assert acquirer.records() == ()


@pytest.mark.parametrize("status", [401, 403])
def test_an_entitled_role_refused_with_401_or_403_fails(status: int, tmp_path: Path) -> None:
    outcome = restricted_fields(
        _context(tmp_path, _POLICY, _Canned(_FORBIDDEN, status=status), role="authority")
    )
    assert (outcome.status, outcome.passed) == (ExecutionStatus.COMPLETED, False)
    assert outcome.reason_code == "ACCESS.ENTITLEMENT.REFUSED"


def test_a_refusal_with_a_body_that_cannot_be_searched_still_fails(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _PUBLIC, _Canned(b"", status=403)))
    assert (outcome.status, outcome.passed) == (ExecutionStatus.COMPLETED, False)
    assert outcome.reason_code == "ACCESS.ENTITLEMENT.REFUSED", "not blocked NOT_JSON"


def test_a_refusal_on_fetch_outranks_a_truncated_body_on_export(tmp_path: Path) -> None:
    acquirer = _Canned(by_url={_FETCH: (403, _FORBIDDEN)}, truncated=frozenset({_EXPORT}))
    outcome = restricted_fields(_context(tmp_path, _PUBLIC | {"channels": _TWO_CHANNELS}, acquirer))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.ENTITLEMENT.REFUSED")
    assert len(acquirer.records()) == 2


def test_a_leak_outranks_an_unsearchable_body_on_an_earlier_channel(tmp_path: Path) -> None:
    acquirer = _Canned(
        by_url={_FETCH: (200, b"not json"), _EXPORT: (200, b'{"restricted": {"secret": "x"}}')}
    )
    outcome = restricted_fields(_context(tmp_path, _POLICY | {"channels": _TWO_CHANNELS}, acquirer))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.EXPORT")


@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_where_everything_is_withheld_is_acceptable(status: int, tmp_path: Path) -> None:
    """Criterion 2 of gap D5-02, second half: the anonymous role is entitled to nothing here."""
    outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(_FORBIDDEN, status=status)))
    assert (outcome.passed, outcome.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    # The stated limit: a body that cannot be searched for leaks is not judged.
    empty = restricted_fields(_context(tmp_path, _POLICY, _Canned(b"", status=status)))
    assert (empty.status, empty.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.RESPONSE.NOT_JSON")


def test_a_refusal_on_a_channel_other_than_fetch_is_read_for_leaks_only(tmp_path: Path) -> None:
    acquirer = _Canned(by_url={_FETCH: (200, b'{"id": "x"}'), _EXPORT: (403, _FORBIDDEN)})
    outcome = restricted_fields(_context(tmp_path, _PUBLIC | {"channels": _TWO_CHANNELS}, acquirer))
    assert (outcome.passed, outcome.reason_code) == (True, "ACCESS.POLICY.ENFORCED")


def test_the_missing_message_names_the_fetch_status(tmp_path: Path) -> None:
    acquirer = _Canned(b'{"error": "not found"}', status=404)
    outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer, role="authority"))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.ENTITLEMENT.MISSING")
    assert "404" in outcome.message
    assert "restricted.secret" in outcome.message
    assert _summary(outcome)["fetch_status"] == 404
    assert _summary(outcome)["entitlement_missing"] == ["restricted.secret"]


def test_the_deny_all_system_gives_no_pass_for_any_role(tmp_path: Path) -> None:
    """Criterion 3 of gap D5-02, on the shipped reference policy."""
    shipped = Path(__file__).resolve().parent.parent / "profiles/battery/access/reference-policy.yaml"
    policy = yaml.safe_load(shipped.read_text(encoding="utf-8")) | {"policy_id": "test/policy"}
    for role in ("anonymous", "legitimate_interest", "authority"):
        outcome = restricted_fields(_context(tmp_path, policy, _Canned(_FORBIDDEN, status=403), role=role))
        assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.ENTITLEMENT.REFUSED"), role


def test_an_entitled_path_found_only_in_a_nested_object_is_missing(tmp_path: Path) -> None:
    for body in (b'{"wrap": {"restricted": {"secret": "v"}}}', b"[]"):
        outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body), role="authority"))
        assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.ENTITLEMENT.MISSING"), body


def test_entitlement_without_a_fetch_channel_never_passes(tmp_path: Path) -> None:
    acquirer = _Canned()
    policy = _POLICY | {"channels": {"export": "/dpp/{id}/export"}}
    outcome = restricted_fields(_context(tmp_path, policy, acquirer, role="authority"))
    assert (outcome.status, outcome.reason_code) == (
        ExecutionStatus.BLOCKED,
        "ACCESS.ENTITLEMENT.NO_FETCH_CHANNEL",
    )
    assert acquirer.records() == ()


def test_entitlement_on_a_fetch_body_that_is_not_json_is_blocked(tmp_path: Path) -> None:
    acquirer = _Canned(b"<p>x</p>", "text/html")
    outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer, role="authority"))
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.RESPONSE.NOT_JSON")


def test_a_leak_outranks_a_missing_entitlement(tmp_path: Path) -> None:
    outcome = restricted_fields(_context(tmp_path, _PUBLIC, _Canned(b'{"restricted": {"secret": "x"}}')))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


def test_every_outcome_names_the_role_and_the_credential_issuer(tmp_path: Path) -> None:
    grant = Authorization.model_validate(
        {
            "schema_version": "dppce.authorization/1",
            "authorization_id": "TEST-ONLY-authorization",
            "issuer": "urn:example:owner",
            "subject": "urn:example:test-lab",
            "sut_identifier": "urn:x",
            "endpoints": ["http://sut.example"],
            "methods": ["GET"],
            "roles": ["anonymous", "authority"],
            "scopes": ["read", "access_probe"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "max_requests": 10,
        }
    )
    body = b'{"restricted": {"secret": "CANARY-test"}}'
    authority = restricted_fields(
        _context(tmp_path, _POLICY, _Canned(body), role="authority", authorization=grant)
    )
    assert (authority.passed, authority.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    assert "Probed role: 'authority'" in authority.message
    assert "urn:example:owner" in authority.message
    assert (_summary(authority)["role"], _summary(authority)["credential_issuer"]) == (
        "authority",
        "urn:example:owner",
    )
    assert "CANARY-test" not in authority.model_dump_json(), "a field value never reaches an outcome"
    anonymous = restricted_fields(_context(tmp_path, _POLICY, _Canned(b"{}"), authorization=grant))
    assert (_summary(anonymous)["role"], _summary(anonymous)["credential_issuer"]) == ("anonymous", None)
    context = _context(tmp_path, _POLICY, _Canned(), role="authority", authorization=grant)
    (tmp_path / "policy.yaml").unlink()
    missing = restricted_fields(context)
    assert missing.reason_code == "ACCESS.POLICY.MISSING"
    assert "Probed role: 'authority'" in missing.message
    assert "urn:example:owner" in missing.message


def test_a_body_that_claims_json_and_cannot_be_read_is_not_clean(tmp_path: Path) -> None:
    for body in (b"{not json", b'{"a": 1, "a": 2}'):
        outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body)))
        assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "ACCESS.RESPONSE.NOT_JSON")


def test_the_declared_media_type_cannot_switch_off_the_path_check(tmp_path: Path) -> None:
    """A JSON body with a non-JSON label, holding a withheld field whose value is not a canary."""
    body = b'{"restricted": {"secret": "a value that no canary names"}}'
    for label in ("text/plain", "application/octet-stream", ""):
        outcome = restricted_fields(_context(tmp_path, _POLICY, _Canned(body, label)))
        assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH"), label


def test_a_channel_that_is_not_json_passes_only_if_every_withheld_field_has_a_canary(tmp_path: Path) -> None:
    html = _Canned(b"<p>nothing to see</p>", "text/html")
    covered = restricted_fields(_context(tmp_path, _POLICY, html))
    assert (covered.passed, covered.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    two = _POLICY | {
        "restricted": [
            {"path": "restricted.secret", "roles": ["authority"]},
            {"path": "restricted.unmarked", "roles": ["authority"]},
        ]
    }
    partial = restricted_fields(_context(tmp_path, two, _Canned(b"<p>nothing to see</p>", "text/html")))
    assert (partial.status, partial.passed) == (ExecutionStatus.BLOCKED, None)
    assert partial.reason_code == "ACCESS.POLICY.NOT_FULLY_CHECKABLE"
    seen = restricted_fields(_context(tmp_path, two, _Canned(b'{"restricted": {"unmarked": 1}}')))
    assert (seen.passed, seen.reason_code) == (False, "ACCESS.LEAK.FETCH"), "JSON channels check every path"


def test_a_policy_with_an_unknown_channel_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown channels"):
        AccessPolicy.model_validate(_POLICY | {"channels": {"fetch": "/x", "websocket": "/y"}})
