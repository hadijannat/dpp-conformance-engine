"""The policy transport, redaction, replay, authorization, and confinement of untrusted input.

Every server here is a loopback server that the test starts. No test reaches an external host.
A fake resolver stands in for DNS, so that rebinding and public-address cases need no network.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from dppce.cli import UsageError, _confined
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import AuthorizationError, issue_authorization, validate_authorization
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.keys import FileDataKeyProvider, KeyError_, resolve_secret
from dppce.infrastructure.redaction import is_public_address, redact_url
from dppce.infrastructure.reference_server import ReferenceServer
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.infrastructure.transport import PolicyTransport, TransportConfig
from dppce.migrations import migrate
from dppce.models import Authorization, NetworkPolicy, RevokedKey, TrustBundle
from tests.support import ISSUER, Handler, LoopbackServer, reply

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "reference"
GS1_RESOLVER_PATH = "/01/09506000134352/21/EV0001"
LOCAL: dict[str, Any] = {
    "allowed_hosts": ("127.0.0.1", "localhost"),
    "allow_private_hosts": ("127.0.0.1", "localhost"),
}
Start = Callable[[Handler], LoopbackServer]


class FakeResolver:
    def __init__(self, addresses: list[str]) -> None:
        self._addresses = addresses

    def resolve(self, host: str, port: int) -> list[str]:
        return self._addresses


def transport(policy: dict[str, Any] | None = None, **config: Any) -> PolicyTransport:
    settings = TransportConfig(
        policy=NetworkPolicy(**(LOCAL if policy is None else policy)), engine_version="1.2.3", **config
    )
    return PolicyTransport(settings, FrozenClock(NOW), sleep=lambda _: None)


def authorization(**changes: Any) -> Authorization:
    fields: dict[str, Any] = {
        "schema_version": "dppce.authorization/1",
        "authorization_id": "TEST-ONLY-authz-1",
        "issuer": ISSUER,
        "subject": "urn:example:tester",
        "sut_identifier": "urn:example:sut",
        "endpoints": ("http://sut.example",),
        "methods": ("GET", "POST"),
        "roles": ("anonymous",),
        "scopes": ("read", "write"),
        "not_before": "2026-10-01T00:00:00Z",
        "not_after": "2026-10-31T00:00:00Z",
        "max_requests": 5,
    }
    return Authorization.model_validate(fields | changes)


# -- destinations -----------------------------------------------------------------------------

_PUBLIC = ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:93.184.216.34"]
_NOT_PUBLIC = [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",  # noqa: S104
    "192.0.2.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
    "::", "::1", "fc00::1", "fe80::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1",  # IPv4-mapped
    "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::5db8:d822",  # NAT64
    "64:ff9b:1::a00:1",  # NAT64, local use
    "2002:a00:1::1", "2002:7f00:1::1", "2002:5db8:d822::1",  # 6to4
    "2001:0:4136:e378:8000:63bf:f5ff:fffe",  # Teredo
]  # fmt: skip


@pytest.mark.parametrize("address", _PUBLIC)
def test_public_unicast_addresses_are_public(address: str) -> None:
    assert is_public_address(address)


@pytest.mark.parametrize("address", _NOT_PUBLIC)
def test_private_special_and_translated_addresses_are_not_public(address: str) -> None:
    assert not is_public_address(address)


def test_loopback_needs_both_lists(loopback: Start) -> None:
    server = loopback(reply)
    assert transport().fetch(Request("GET", f"{server.origin}/ok")).status == 200
    assert (
        transport({"allowed_hosts": ("127.0.0.1",)}).fetch(Request("GET", f"{server.origin}/ok")).error
        == "policy_denied"
    )
    assert transport({}).fetch(Request("GET", f"{server.origin}/ok")).error == "policy_denied"
    assert len(server.seen) == 1, "a denied request never leaves the host"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://127.0.0.1/x",
        "gopher://127.0.0.1/",
        "http://user:pw@127.0.0.1/ok",
        "http:///x",
        "http://127.0.0.1:99999/",
    ],
)
def test_other_schemes_userinfo_and_bad_urls_are_denied(url: str) -> None:
    assert transport().fetch(Request("GET", url)).error == "policy_denied"


@pytest.mark.parametrize(
    "addresses",
    [
        ["93.184.216.34", "127.0.0.1"],
        ["::ffff:127.0.0.1"],
        ["169.254.169.254"],
        ["64:ff9b::a00:1"],
        ["10.0.0.5", "93.184.216.34"],
    ],
)
def test_a_host_that_resolves_to_any_non_public_address_is_denied(addresses: list[str]) -> None:
    """One private answer among public ones is a DNS rebinding attempt."""
    settings = TransportConfig(policy=NetworkPolicy(allowed_hosts=("sut.example",)), engine_version="x")
    engine = PolicyTransport(settings, FrozenClock(NOW), FakeResolver(addresses))
    assert engine.fetch(Request("GET", "http://sut.example/")).error == "policy_denied"


def test_a_public_host_needs_an_authorization_or_the_operator_statement() -> None:
    settings = TransportConfig(policy=NetworkPolicy(allowed_hosts=("sut.example",)), engine_version="x")
    engine = PolicyTransport(settings, FrozenClock(NOW), FakeResolver(["93.184.216.34"]))
    assert engine.fetch(Request("GET", "http://sut.example/")).error == "authorization_denied"


def test_a_name_that_does_not_resolve_is_a_dns_error() -> None:
    class Broken:
        def resolve(self, host: str, port: int) -> list[str]:
            raise OSError("no such host")

    settings = TransportConfig(policy=NetworkPolicy(allowed_hosts=("sut.example",)), engine_version="x")
    assert (
        PolicyTransport(settings, FrozenClock(NOW), Broken())
        .fetch(Request("GET", "http://sut.example/"))
        .error
        == "dns"
    )


# -- redirects and limits ---------------------------------------------------------------------


def _redirecting(target: str) -> Handler:
    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        if request.path.startswith("/hop"):
            reply(request, 302, b"", {"Location": target})
        else:
            reply(request)

    return handler


def test_an_in_scope_redirect_is_followed_and_recorded(loopback: Start) -> None:
    server = loopback(_redirecting("/landed"))
    record = transport().fetch(Request("GET", f"{server.origin}/hop"))
    assert (record.status, record.error) == (200, None)
    assert record.redirects == (f"{server.origin}/landed",)


def test_an_out_of_scope_redirect_ends_the_request(loopback: Start) -> None:
    server = loopback(_redirecting("http://out-of-scope.example.test/"))
    record = transport().fetch(Request("GET", f"{server.origin}/hop"))
    assert record.error == "redirect_out_of_scope"
    assert record.redirects == ("http://out-of-scope.example.test/",)


def test_a_redirect_loop_stops_at_the_limit(loopback: Start) -> None:
    server = loopback(lambda r: reply(r, 302, b"", {"Location": "/again"}))
    record = transport(LOCAL | {"max_redirects": 2}).fetch(Request("GET", f"{server.origin}/again"))
    assert record.error == "too_many_redirects"
    assert len(server.seen) == 3


def test_a_large_body_is_cut_and_flagged(loopback: Start) -> None:
    server = loopback(lambda r: reply(r, body=b"x" * 5000))
    record = transport(LOCAL | {"max_body_bytes": 1024}).fetch(Request("GET", f"{server.origin}/big"))
    assert (len(record.body), record.truncated) == (1024, True)


def test_the_request_budget_and_the_minimum_interval(loopback: Start) -> None:
    server = loopback(reply)
    waits: list[float] = []
    settings = TransportConfig(
        policy=NetworkPolicy(**LOCAL, max_requests=2, min_interval_ms=500), engine_version="x"
    )
    engine = PolicyTransport(settings, FrozenClock(NOW), sleep=waits.append, monotonic=lambda: 0.0)
    outcomes = [engine.fetch(Request("GET", f"{server.origin}/ok")).error for _ in range(3)]
    assert outcomes == [None, None, "budget_exhausted"]
    assert waits == [0.5], "the second request waits for the interval; the third is never sent"


def test_a_refused_connection_is_data_and_is_retried_only_as_configured() -> None:
    record = transport(LOCAL | {"retries": 2, "timeout_ms": 500}).fetch(Request("GET", "http://127.0.0.1:1/"))
    assert (record.error, record.status, record.attempts) == ("connect", None, 3)


def test_the_user_agent_identifies_the_engine_and_the_contact(loopback: Start) -> None:
    server = loopback(reply)
    transport(LOCAL | {"contact": "lab@example.org"}).fetch(Request("GET", f"{server.origin}/ok"))
    assert server.seen[0]["User-Agent"] == "dppce/1.2.3 (+lab@example.org)"


# -- secrets ----------------------------------------------------------------------------------


def test_secrets_reach_only_their_origin_and_never_the_record(loopback: Start) -> None:
    other = loopback(reply)
    first = loopback(_redirecting(f"http://localhost:{other.port}/landed?token=LEAK-4"))
    engine = transport(credentials={"auditor": (first.origin, "TEST-ONLY-LEAK-1")})
    request = Request(
        "GET",
        f"{first.origin}/hop?api_key=LEAK-2",
        role="auditor",
        headers={"X-Tenant": "LEAK-3", "Accept": "application/json"},
    )
    record = engine.fetch(request)
    # Architecture section 9: a role request stops at a cross-origin hop. If it continued with
    # no credential, the record would show the anonymous view under the name of the role.
    assert record.error == "redirect_out_of_scope"
    assert first.seen[0]["Authorization"] == "Bearer TEST-ONLY-LEAK-1"
    assert first.seen[0]["X-Tenant"] == "LEAK-3"
    assert other.seen == [], "the credential stays with its origin: the other origin gets no request"
    assert "LEAK" not in repr(record), "no secret reaches the record"

    anonymous = engine.fetch(
        Request("GET", f"{first.origin}/hop?api_key=LEAK-2", headers={"X-Tenant": "LEAK-3"})
    )
    assert anonymous.status == 200
    assert "Authorization" not in other.seen[0], "an anonymous request carries no credential"
    assert "X-Tenant" not in other.seen[0], "caller headers stay with the first origin"
    assert "LEAK" not in repr(anonymous), "no secret reaches the record"


def test_response_secrets_are_removed_from_the_record(loopback: Start) -> None:
    server = loopback(lambda r: reply(r, headers={"Set-Cookie": "sid=LEAK", "ETag": '"v3"'}))
    record = transport().fetch(Request("GET", f"{server.origin}/ok"))
    assert record.header("set-cookie") == "<removed>"
    assert record.header("etag") == '"v3"'


def test_url_redaction_changes_nothing_else() -> None:
    plain = "https://sut.example/01/09506000134352/21/A%20B?lang=en+gb"
    assert redact_url(plain) == plain
    redacted = redact_url("https://user:pw@sut.example/x?access_token=S1&lang=en&sig=S2")
    assert "S1" not in redacted
    assert "S2" not in redacted
    assert "pw" not in redacted
    assert "lang=en" in redacted


# -- writes and authorization -----------------------------------------------------------------


def test_a_write_needs_an_authorization_with_an_active_scope(loopback: Start) -> None:
    server = loopback(reply)
    assert transport().fetch(Request("POST", f"{server.origin}/x", body=b"1")).error == "authorization_denied"
    read_only = authorization(endpoints=(server.origin,), scopes=("read",))
    assert (
        transport(authorization=read_only).fetch(Request("POST", f"{server.origin}/x", body=b"1")).error
        == "authorization_denied"
    )
    writer = authorization(endpoints=(server.origin,))
    assert (
        transport(authorization=writer).fetch(Request("POST", f"{server.origin}/x", body=b"1")).status == 200
    )
    assert len(server.seen) == 1


def test_options_is_a_read_and_records_the_cors_headers() -> None:
    # OD-06: OPTIONS joins GET and HEAD. It needs no authorization with an active scope.
    with ReferenceServer(FIXTURES) as server:
        record = transport().fetch(Request("OPTIONS", f"{server.origin}{GS1_RESOLVER_PATH}"))
    assert (record.method, record.status, record.error) == ("OPTIONS", 204, None)
    assert record.header("access-control-allow-origin") == "*"
    assert record.header("access-control-allow-methods") == "GET, HEAD, OPTIONS"
    assert record.header("access-control-allow-headers") == "Accept, Authorization"
    assert record.header("allow") == "GET, HEAD, OPTIONS"


def test_an_authorization_still_names_options_to_permit_it(loopback: Start) -> None:
    server = loopback(reply)
    engine = transport(authorization=authorization(endpoints=(server.origin,), methods=("GET",)))
    assert engine.fetch(Request("OPTIONS", f"{server.origin}/x")).error == "authorization_denied"
    assert server.seen == []


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoints": ("http://elsewhere.example",)},
        {"methods": ("HEAD",)},
        {"roles": ("authority",)},
        {"not_after": "2026-10-02T00:00:00Z"},
        {"not_before": "2026-10-20T00:00:00Z"},
    ],
)
def test_an_authorization_limits_every_request(changes: dict[str, Any], loopback: Start) -> None:
    server = loopback(reply)
    engine = transport(authorization=authorization(endpoints=(server.origin,)).model_copy(update=changes))
    assert engine.fetch(Request("GET", f"{server.origin}/ok")).error == "authorization_denied"
    assert not server.seen


def test_an_authorization_caps_the_request_count(loopback: Start) -> None:
    server = loopback(reply)
    engine = transport(authorization=authorization(endpoints=(server.origin,), max_requests=1))
    assert [engine.fetch(Request("GET", f"{server.origin}/ok")).error for _ in range(2)] == [
        None,
        "budget_exhausted",
    ]


def test_only_a_trusted_issuer_can_authorize(signer: LocalSigner, trust: TrustBundle) -> None:
    token = issue_authorization(authorization(), signer)
    assert validate_authorization(token, trust, NOW, "urn:example:sut") == authorization()
    cases: list[tuple[str, Any, datetime, str]] = [
        ("AUTHZ.SUT.MISMATCH", trust, NOW, "urn:example:other"),
        ("AUTHZ.EXPIRED", trust, datetime(2026, 11, 5, tzinfo=UTC), "urn:example:sut"),
        (
            "AUTHZ.ISSUER.KEY_NOT_VALID",
            trust.model_copy(update={"revoked_keys": (RevokedKey(kid=signer.key_id, revoked_at=None),)}),
            NOW,
            "urn:example:sut",
        ),
        ("AUTHZ.ISSUER.UNTRUSTED", trust.model_copy(update={"keys": ()}), NOW, "urn:example:sut"),
    ]
    # The key must have the kid of the token and the purpose "authorization", not only one of them.
    key = trust.keys[0]
    for changed in ({"purposes": ("report",)}, {"kid": "TEST-ONLY-other-key"}):
        keys = (key.model_copy(update=changed),)
        cases.append(
            ("AUTHZ.ISSUER.UNTRUSTED", trust.model_copy(update={"keys": keys}), NOW, "urn:example:sut")
        )
    # A dppce.trust/1 bundle that revoked the kid keeps that effect after migration.
    version_1 = json.loads(trust.model_dump_json(exclude={"revoked_certificates", "revoked_keys"}))
    del version_1["timestamp_anchors"]
    version_1.update(schema_version="dppce.trust/1", revoked_kids=[signer.key_id], revoked_serials=[])
    migrated = TrustBundle.model_validate(migrate("trust", version_1))
    cases.append(("AUTHZ.ISSUER.KEY_NOT_VALID", migrated, NOW, "urn:example:sut"))
    for code, bundle, at, sut in cases:
        with pytest.raises(AuthorizationError) as caught:
            validate_authorization(token, bundle, at, sut)
        assert caught.value.code == code
    forged = issue_authorization(authorization(), LocalSigner.generate(signer.key_id))
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(forged, trust, NOW, "urn:example:sut")
    assert caught.value.code == "AUTHZ.SIGNATURE.INVALID"
    impostor = issue_authorization(authorization(issuer="urn:example:impostor"), signer)
    with pytest.raises(AuthorizationError) as caught:
        validate_authorization(impostor, trust, NOW, "urn:example:sut")
    assert caught.value.code == "AUTHZ.ISSUER.MISMATCH"


# -- artifacts and replay ---------------------------------------------------------------------


def test_artifacts_are_read_through_the_transport(tmp_path: Path) -> None:
    image = tmp_path / "qr.png"
    image.write_bytes(b"image-bytes")
    engine = transport(samples={"qr_image": image}, max_artifact_bytes=64)
    record = engine.artifact("qr_image")
    assert (record.kind, record.url, record.body, record.error) == (
        "artifact",
        "artifact:qr_image",
        b"image-bytes",
        None,
    )
    assert engine.artifact("missing").error == "artifact_unavailable"
    image.write_bytes(b"x" * 65)
    assert engine.artifact("qr_image").error == "body_too_large"
    assert [r.record_id for r in engine.records()] == ["r0001", "r0002", "r0003"]


def test_replay_serves_the_recording_in_sequence(loopback: Start) -> None:
    server = loopback(reply)
    engine = transport()
    request = Request("GET", f"{server.origin}/ok?token=SECRET")
    recorded = engine.fetch(request)
    replay = ReplayAcquirer(engine.records())
    assert replay.fetch(request) is recorded, "the redacted record matches the same request"
    assert replay.complete()
    assert replay.fetch(request).error == "recording_mismatch", "nothing is left to serve"
    changed = ReplayAcquirer(engine.records())
    assert changed.fetch(Request("GET", f"{server.origin}/other")).error == "recording_mismatch"
    assert not changed.complete()
    assert not ReplayAcquirer(engine.records()).complete(), "an unserved record means the inputs changed"


# -- untrusted IXIT ---------------------------------------------------------------------------


def test_a_secret_reference_cannot_name_an_arbitrary_secret(tmp_path: Path) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "TEST-ONLY-role.token").write_text("value\n")
    (tmp_path / "outside.txt").write_text("private")
    assert resolve_secret("file:TEST-ONLY-role.token", secrets_dir=secrets) == "value"
    assert resolve_secret("env:DPPCE_SECRET_X", environ={"DPPCE_SECRET_X": "v"}) == "v"
    refused: list[tuple[str, dict[str, Any]]] = [
        ("env:AWS_SECRET_ACCESS_KEY", {"environ": {"AWS_SECRET_ACCESS_KEY": "k"}}),
        ("env:DPPCE_SECRET_UNSET", {"environ": {}}),
        ("file:../outside.txt", {"secrets_dir": secrets}),
        (f"file:{tmp_path / 'outside.txt'}", {"secrets_dir": secrets}),
        ("file:TEST-ONLY-role.token", {}),
        ("vault:x", {}),
    ]
    for reference, options in refused:
        with pytest.raises(KeyError_):
            resolve_secret(reference, **options)


def test_an_ixit_path_cannot_leave_the_ixit_directory(tmp_path: Path) -> None:
    base = tmp_path / "ixit"
    base.mkdir()
    (base / "qr.png").write_bytes(b"x")
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    os.symlink(outside, base / "link.png")
    assert _confined(base, "qr.png", "sample") == (base / "qr.png").resolve()
    assert _confined(base, "https://id.example.test/01/1/21/A", "sample") is None, (
        "a text value is not a file"
    )
    for escape in ("../outside.txt", str(outside), "link.png"):
        with pytest.raises(UsageError, match="outside the directory"):
            _confined(base, escape, "sample")


def test_data_keys_are_created_private_and_checked(tmp_path: Path) -> None:
    provider = FileDataKeyProvider(tmp_path / "keys")
    path = provider.create()
    assert path.stat().st_mode & 0o777 == 0o600
    key = provider.data_key(provider.default_key_id())
    assert len(key) == 32
    assert provider.create() == path, "create is idempotent"
    assert provider.data_key(provider.default_key_id()) == key
    path.write_bytes(b"short")
    for key_id in (provider.default_key_id(), "absent", "../escape"):
        with pytest.raises(KeyError_):
            provider.data_key(key_id)


def test_the_network_guard_refuses_a_name_lookup() -> None:
    # Rule 3: a mutant of transport.py must not send a real DNS query from the developer host.
    with pytest.raises(AssertionError, match="tests use loopback only"):
        socket.getaddrinfo("dns.example.test", 80)
    assert socket.getaddrinfo("127.0.0.1", 80)
    assert socket.getaddrinfo("LocalHost", 80)
