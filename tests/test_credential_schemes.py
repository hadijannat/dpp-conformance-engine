"""Credential schemes of a role: bearer, a named header, and OAuth 2.0 client credentials (P2-28).

Every server here is a loopback server that the test starts, or the loopback reference system.
Every client id, client secret, and token is a TEST-ONLY value. No test reaches another host.
"""

from __future__ import annotations

import base64
import contextlib
import http.server
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError
from validation.rig import FIXTURES, ReferenceRig

from dppce.cli import main
from dppce.evidence.jws import LocalSigner
from dppce.infrastructure.authorization import issue_authorization
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import REMOVED, SAFE_REQUEST_HEADERS
from dppce.infrastructure.reference import oauth
from dppce.infrastructure.reference.base import Request as ReferenceRequest
from dppce.infrastructure.reference_server import ReferenceServer, ReferenceSystem
from dppce.infrastructure.transport import OAuthClient, PolicyTransport, TransportConfig
from dppce.models import Authorization, NetworkPolicy, RoleIdentity, Scope, Verdict
from tests.support import ISSUER, LoopbackServer, reply

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
LOCAL: dict[str, Any] = {"allowed_hosts": ("127.0.0.1",), "allow_private_hosts": ("127.0.0.1",)}
CLIENT_ID = "TEST-ONLY-client-1"
CLIENT_SECRET = "TEST-ONLY-client-secret-0123456789"
TOKEN = "TEST-ONLY-issued-token-abcdefghijk"
STATIC = "TEST-ONLY-static-key-0123456789"
SECRETS = (CLIENT_SECRET, TOKEN, STATIC)


def _authorization(origin: str, **changes: Any) -> Authorization:
    fields: dict[str, Any] = {
        "schema_version": "dppce.authorization/1",
        "authorization_id": "TEST-ONLY-authz-oauth",
        "issuer": ISSUER,
        "subject": "urn:example:tester",
        "sut_identifier": "urn:example:sut",
        "endpoints": (origin,),
        "methods": ("GET",),
        "roles": ("anonymous", "auditor"),
        "scopes": ("read", "credential"),
        "not_before": "2026-10-01T00:00:00Z",
        "not_after": "2026-10-31T00:00:00Z",
        "max_requests": 20,
    }
    return Authorization.model_validate(fields | changes)


def _transport(policy: dict[str, Any] | None = None, **config: Any) -> PolicyTransport:
    settings = TransportConfig(policy=NetworkPolicy(**(policy or LOCAL)), engine_version="1.2.3", **config)
    return PolicyTransport(settings, FrozenClock(NOW), sleep=lambda _: None)


def _body(request: http.server.BaseHTTPRequestHandler) -> bytes:
    return request.rfile.read(int(request.headers.get("Content-Length") or 0))


class TokenSystem:
    """A loopback token endpoint at /token and a resource at /data that echoes the token."""

    def __init__(self, token_reply: tuple[int, bytes] | None = None, resource_status: int = 200) -> None:
        self.token_reply = token_reply or (
            200,
            json.dumps({"access_token": TOKEN, "token_type": "Bearer", "expires_in": 300}).encode(),
        )
        self.resource_status = resource_status
        self.posts: list[dict[str, Any]] = []
        self.server = LoopbackServer(self.handle)
        self.origin = self.server.origin

    def handle(self, request: http.server.BaseHTTPRequestHandler) -> None:
        if request.command == "POST":
            self.posts.append({"headers": dict(request.headers.items()), "body": _body(request)})
            status, body = self.token_reply
            reply(request, status, body)
            return
        # The resource echoes the Authorization value. The engine must scrub it from the record.
        echo = json.dumps({"seen": request.headers.get("Authorization", "")}).encode()
        reply(request, self.resource_status, echo, {"X-Echo": request.headers.get("Authorization", "")})

    def client(self, token_url: str | None = None) -> dict[str, OAuthClient]:
        return {
            "auditor": OAuthClient(self.origin, token_url or f"{self.origin}/token", CLIENT_ID, CLIENT_SECRET)
        }

    def gets(self) -> list[dict[str, str]]:
        return [seen for seen in self.server.seen if seen["path"] != "/token"]


@pytest.fixture
def tokens() -> Any:
    systems: list[TokenSystem] = []

    def start(*args: Any, **kwargs: Any) -> TokenSystem:
        system = TokenSystem(*args, **kwargs)
        systems.append(system)
        return system

    yield start
    for system in systems:
        system.server.close()


def _no_secret(*records: Record) -> None:
    for record in records:
        for secret in SECRETS:
            assert secret not in repr(record), "no secret reaches a record"


# -- the declaration ---------------------------------------------------------------------------


def test_the_default_scheme_is_bearer_and_keeps_the_old_form() -> None:
    identity = RoleIdentity(role="auditor", secret_ref="env:DPPCE_SECRET_AUDITOR")
    assert identity.scheme == "bearer"
    # The IXIT hash and every recording stay as they were: a default leaves no new key.
    assert identity.model_dump(mode="json") == {
        "role": "auditor",
        "secret_ref": "env:DPPCE_SECRET_AUDITOR",
        "description": "",
    }


def test_the_credential_scope_exists() -> None:
    assert Scope("credential") is Scope.CREDENTIAL


def test_a_header_role_needs_a_header_name_that_is_a_token() -> None:
    good = RoleIdentity(role="r", scheme="header", header_name="X-Api-Key", secret_ref="env:DPPCE_SECRET_R")
    assert good.header_name == "X-Api-Key"
    for name in (None, "", "X Api", "X:Api", "X-Api\r\nHost", "Ä-Key", "x" * 65):
        with pytest.raises(ValidationError):
            RoleIdentity(role="r", scheme="header", header_name=name, secret_ref="env:DPPCE_SECRET_R")
    with pytest.raises(ValidationError):
        RoleIdentity(role="r", scheme="header", header_name="X-Api-Key")


@pytest.mark.parametrize(
    "name",
    sorted(
        {
            "Host", "cookie", "Connection", "Keep-Alive", "Proxy-Authorization", "TE", "Trailer",
            "Transfer-Encoding", "Upgrade", "Content-Length", "Accept-Encoding",
            *SAFE_REQUEST_HEADERS,
        }
    ),
)  # fmt: skip
def test_a_header_role_cannot_use_a_reserved_or_recorded_header(name: str) -> None:
    # A value of a safe request header is kept in the record, so a secret there would be disclosed.
    with pytest.raises(ValidationError):
        RoleIdentity(role="r", scheme="header", header_name=name, secret_ref="env:DPPCE_SECRET_R")
    with pytest.raises(ValidationError):
        RoleIdentity(role="r", scheme="header", header_name=name.upper(), secret_ref="env:DPPCE_SECRET_R")


def test_an_oauth_role_names_an_endpoint_key_and_two_references() -> None:
    identity = RoleIdentity(
        role="r",
        scheme="oauth2_client_credentials",
        token_endpoint="token",
        client_id_ref="file:TEST-ONLY-client-id",
        secret_ref="file:TEST-ONLY-client-secret",
    )
    assert identity.token_endpoint == "token"
    base: dict[str, Any] = {
        "role": "r",
        "scheme": "oauth2_client_credentials",
        "token_endpoint": "token",
        "client_id_ref": "file:x",
        "secret_ref": "file:y",
    }
    for change in (
        {"token_endpoint": None},
        {"token_endpoint": "https://token.example.test/token"},
        {"client_id_ref": None},
        {"client_id_ref": "TEST-ONLY-the-id-itself"},
        {"secret_ref": None},
        {"header_name": "X-Api-Key"},
    ):
        with pytest.raises(ValidationError):
            RoleIdentity.model_validate(base | change)


def test_a_bearer_role_takes_no_field_of_another_scheme() -> None:
    for change in ({"header_name": "X-Api-Key"}, {"token_endpoint": "token"}, {"client_id_ref": "file:x"}):
        with pytest.raises(ValidationError):
            RoleIdentity.model_validate({"role": "r", "secret_ref": "file:y"} | change)


# -- the header scheme -------------------------------------------------------------------------


def test_a_header_role_sends_its_secret_in_that_header_only(loopback: Any) -> None:
    server = loopback(lambda r: reply(r, body=json.dumps({"echo": r.headers.get("X-Api-Key")}).encode()))
    engine = _transport(
        credentials={"auditor": (server.origin, STATIC)}, credential_headers={"auditor": "X-Api-Key"}
    )
    record = engine.fetch(Request("GET", f"{server.origin}/data", role="auditor"))
    assert server.seen[0]["X-Api-Key"] == STATIC
    assert "Authorization" not in server.seen[0], "the header scheme sends no bearer token"
    assert ("X-Api-Key", REMOVED) in record.request_headers
    assert REMOVED.encode() in record.body, "an echo of the secret is removed from the body"
    _no_secret(record)
    anonymous = engine.fetch(Request("GET", f"{server.origin}/data"))
    assert "X-Api-Key" not in server.seen[1], "the anonymous role carries no credential"
    _no_secret(anonymous)


def test_the_transport_refuses_a_header_whose_value_it_records() -> None:
    with pytest.raises(ValueError, match="header"):
        _transport(
            credentials={"auditor": ("http://127.0.0.1:1", STATIC)}, credential_headers={"auditor": "Accept"}
        )


# -- OAuth 2.0 client credentials --------------------------------------------------------------


def test_an_oauth_role_gets_one_token_and_sends_it_as_a_bearer_token(tokens: Any) -> None:
    system = tokens()
    engine = _transport(oauth_clients=system.client(), authorization=_authorization(system.origin))
    first = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    second = engine.fetch(Request("GET", f"{system.origin}/data?again=1", role="auditor"))
    assert (first.status, second.status) == (200, 200)
    assert len(system.posts) == 1, "one token request per role and run"
    post = system.posts[0]
    # RFC 6749, sections 2.3.1 and 4.4.2: HTTP Basic client authentication and a form body.
    expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert post["headers"]["Authorization"] == f"Basic {expected}"
    assert post["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(post["body"].decode()) == {"grant_type": ["client_credentials"]}
    assert [seen["Authorization"] for seen in system.gets()] == [f"Bearer {TOKEN}"] * 2
    assert all(CLIENT_SECRET not in json.dumps(seen) for seen in system.gets()), (
        "the secret stays at the token endpoint"
    )
    # The token exchange is not a record. The records are the two role requests, scrubbed.
    assert [r.url for r in engine.records()] == [f"{system.origin}/data", f"{system.origin}/data?again=1"]
    assert ("X-Echo", REMOVED) in first.headers
    assert json.loads(first.body) == {"seen": f"Bearer {REMOVED}"}
    _no_secret(*engine.records())


def test_an_oauth_client_secret_is_scrubbed_if_the_resource_echoes_it(loopback: Any, tokens: Any) -> None:
    system = tokens()
    echo = loopback(lambda r: reply(r, body=json.dumps({"leak": CLIENT_SECRET}).encode()))
    clients = {"auditor": OAuthClient(system.origin, f"{system.origin}/token", CLIENT_ID, CLIENT_SECRET)}
    engine = _transport(oauth_clients=clients, authorization=_authorization(system.origin))
    engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    anonymous = engine.fetch(Request("GET", f"{echo.origin}/x"))
    _no_secret(anonymous)


def test_the_anonymous_role_never_asks_for_a_token(tokens: Any) -> None:
    system = tokens()
    engine = _transport(oauth_clients=system.client(), authorization=_authorization(system.origin))
    assert engine.fetch(Request("GET", f"{system.origin}/data")).status == 200
    assert system.posts == []
    assert "Authorization" not in system.gets()[0]


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": ("read", "access_probe")},  # no credential scope
        {"scopes": ("read", "write", "tamper", "fuzz")},  # an active scope is not the credential scope
        {"endpoints": ("http://127.0.0.1:1",)},  # the token endpoint origin is not named
        {"roles": ("anonymous",)},  # the role is not granted
        {"not_after": "2026-10-02T00:00:00Z"},  # expired
    ],
)
def test_no_token_request_without_a_credential_authorization(tokens: Any, changes: dict[str, Any]) -> None:
    system = tokens()
    engine = _transport(oauth_clients=system.client(), authorization=_authorization(system.origin, **changes))
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert system.posts == [], "no POST leaves the host"
    assert system.gets() == [], "without a token, the role request is not sent"
    assert record.error == "authorization_denied"


def test_no_token_request_without_any_authorization(tokens: Any) -> None:
    system = tokens()
    engine = _transport(oauth_clients=system.client())
    assert (
        engine.fetch(Request("GET", f"{system.origin}/data", role="auditor")).error == "authorization_denied"
    )
    assert system.server.seen == []


class _Resolver:
    def __init__(self, table: dict[str, list[str]]) -> None:
        self._table = table

    def resolve(self, host: str, port: int) -> list[str]:
        return self._table[host]


def test_a_client_secret_goes_only_over_https_except_to_loopback(tokens: Any) -> None:
    system = tokens()
    token_url = "http://token.example.test/token"
    policy = {"allowed_hosts": ("127.0.0.1", "token.example.test"), "allow_private_hosts": ("127.0.0.1",)}
    authorization = _authorization(system.origin, endpoints=(system.origin, "http://token.example.test"))
    settings = TransportConfig(
        policy=NetworkPolicy(**policy),
        engine_version="1.2.3",
        oauth_clients=system.client(token_url),
        authorization=authorization,
    )
    # A public address over plain http: the secret would cross the network in clear text.
    resolver = _Resolver({"127.0.0.1": ["127.0.0.1"], "token.example.test": ["93.184.216.34"]})
    engine = PolicyTransport(settings, FrozenClock(NOW), resolver=resolver, sleep=lambda _: None)
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "authorization_denied"
    assert system.server.seen == []


@pytest.mark.parametrize(
    "answer",
    [
        (401, b'{"error":"invalid_client"}'),
        (400, b'{"error":"unsupported_grant_type"}'),
        (302, b""),
        (500, b"{}"),
        (200, b"not json"),
        (200, b'{"token_type":"Bearer"}'),
        (200, json.dumps({"access_token": TOKEN, "token_type": "mac"}).encode()),
        (200, json.dumps({"access_token": TOKEN}).encode()),
        (200, json.dumps({"access_token": "TEST-ONLY-1", "token_type": "Bearer"}).encode()),  # too short
        (200, json.dumps({"access_token": TOKEN + "\r\nX: y", "token_type": "Bearer"}).encode()),
        (200, json.dumps({"access_token": TOKEN + " x", "token_type": "Bearer"}).encode()),
        (200, json.dumps({"access_token": 12345678901234, "token_type": "Bearer"}).encode()),
        # A repeated key: two parsers could read two different tokens.
        (
            200,
            b'{"access_token":"'
            + TOKEN.encode()
            + b'","access_token":"TEST-ONLY-other-token","token_type":"Bearer"}',
        ),
        (200, b"[" + b"1," * 2000 + b"1]"),  # larger than the body limit
    ],
)
def test_a_refused_or_unusable_token_answer_sends_no_role_request(
    tokens: Any, answer: tuple[int, bytes]
) -> None:
    system = tokens(token_reply=answer)
    engine = _transport(
        {**LOCAL, "max_body_bytes": 2048},
        oauth_clients=system.client(),
        authorization=_authorization(system.origin),
    )
    first = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    second = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert (first.error, second.error) == ("authorization_denied", "authorization_denied")
    assert len(system.posts) == 1, "a refused client is not asked again in the same run"
    assert system.gets() == []
    _no_secret(first, second)


def test_an_unreachable_token_endpoint_is_no_answer() -> None:
    clients = {
        "auditor": OAuthClient("http://127.0.0.1:1", "http://127.0.0.1:1/token", CLIENT_ID, CLIENT_SECRET)
    }
    engine = _transport(oauth_clients=clients, authorization=_authorization("http://127.0.0.1:1"))
    assert engine.fetch(Request("GET", "http://127.0.0.1:1/data", role="auditor")).error == "connect"


def test_a_token_that_the_resource_refuses_gives_the_answer_of_the_resource(tokens: Any) -> None:
    system = tokens(resource_status=403)
    engine = _transport(oauth_clients=system.client(), authorization=_authorization(system.origin))
    first = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    second = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    # The answer of the resource is the observation. The engine does not ask for a new token,
    # so a token endpoint cannot turn the refusal of a role into no answer.
    assert (first.status, first.error, second.status) == (403, None, 403)
    assert len(system.posts) == 1


def test_the_token_request_counts_against_the_request_budget(tokens: Any) -> None:
    system = tokens()
    engine = _transport(
        oauth_clients=system.client(), authorization=_authorization(system.origin, max_requests=1)
    )
    assert engine.fetch(Request("GET", f"{system.origin}/data", role="auditor")).error == "budget_exhausted"
    assert len(system.posts) == 1


def test_a_check_cannot_post_with_the_credential_scope(tokens: Any) -> None:
    system = tokens()
    engine = _transport(
        authorization=_authorization(system.origin, methods=("GET", "POST"), scopes=("read", "credential"))
    )
    record = engine.fetch(Request("POST", f"{system.origin}/token", body=b"grant_type=client_credentials"))
    assert record.error == "authorization_denied"
    assert system.posts == []


# -- the reference system ----------------------------------------------------------------------


def _token_request(
    secret: str = oauth.CLIENT_SECRET, body: bytes = b"grant_type=client_credentials"
) -> ReferenceRequest:
    basic = base64.b64encode(f"{oauth.CLIENT_ID}:{secret}".encode()).decode()
    headers = {"authorization": f"Basic {basic}", "content-type": "application/x-www-form-urlencoded"}
    return ReferenceRequest("POST", oauth.PATH, headers, body)


def test_the_reference_token_endpoint_issues_a_token_that_the_core_accepts() -> None:
    system = ReferenceSystem(FIXTURES)
    status, media_type, body, headers = system.respond(_token_request())
    assert (status, media_type, headers.get("Cache-Control")) == (200, "application/json", "no-store")
    document = json.loads(body)
    assert document["token_type"] == "Bearer"
    assert system.role_of(f"Bearer {document['access_token']}") == oauth.ROLE
    for refused in (
        _token_request(secret="TEST-ONLY-wrong-secret"),
        _token_request(body=b"grant_type=password"),
        ReferenceRequest("POST", oauth.PATH, {}, b"grant_type=client_credentials"),
    ):
        assert system.respond(refused)[0] in (400, 401)


def test_the_reference_flags_change_the_issued_token() -> None:
    wrong = ReferenceSystem(FIXTURES, frozenset({"oauth_token_wrong_role"}))
    document = json.loads(wrong.respond(_token_request())[2])
    assert wrong.role_of(f"Bearer {document['access_token']}") == "authority"
    refused = ReferenceSystem(FIXTURES, frozenset({"oauth_token_refused"}))
    assert refused.respond(_token_request())[0] == 401


def test_the_reference_system_answers_no_other_post() -> None:
    system = ReferenceSystem(FIXTURES)
    assert system.respond(ReferenceRequest("POST", "/dpp/09506000134352-EV0001", {}, b""))[0] == 405
    assert system.respond(ReferenceRequest("GET", oauth.PATH))[0] == 404, "a GET is not a token request"
    denied = ReferenceSystem(FIXTURES, frozenset({"deny_all"}))
    assert denied.respond(_token_request())[0] == 403


def test_the_reference_server_reads_a_bounded_post_body() -> None:
    import http.client  # noqa: PLC0415 - only this test talks raw HTTP

    with ReferenceServer(FIXTURES) as server:
        port = int(server.origin.rsplit(":", 1)[1])
        request = _token_request()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", oauth.PATH, body=request.body, headers=dict(request.headers))
        assert connection.getresponse().status == 200
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", oauth.PATH, body=b"x" * 5000, headers=dict(request.headers))
        assert connection.getresponse().status == 413
        connection.close()


def test_the_secret_files_hold_the_reference_client() -> None:
    secrets = FIXTURES / "secrets"
    assert (secrets / "TEST-ONLY-oauth-client-id").read_text(encoding="utf-8").strip() == oauth.CLIENT_ID
    assert (secrets / "TEST-ONLY-oauth-client-secret").read_text(
        encoding="utf-8"
    ).strip() == oauth.CLIENT_SECRET
    assert oauth.CLIENT_ID.startswith("TEST-ONLY-")
    assert oauth.CLIENT_SECRET.startswith("TEST-ONLY-")


# -- a run through the command line ------------------------------------------------------------

OAUTH_ARGUMENTS = (
    "--role-secret", "legitimate_interest=file:TEST-ONLY-oauth-client-secret",
    "--role-client-id", "legitimate_interest=file:TEST-ONLY-oauth-client-id",
)  # fmt: skip


def _credential_authorization(rig: ReferenceRig, scopes: tuple[str, ...]) -> tuple[str, str]:
    """Replace the authorization of the rig with one that grants ``scopes``; return its option.

    A family example IXIT names no authorization, so the run gets it with --authorization.
    """
    owner = LocalSigner.from_pem(
        FIXTURES / "authorization" / "TEST-ONLY-owner.key.pem", "TEST-ONLY-owner-key-1"
    )
    path = rig.work / "rig" / "authorization" / "TEST-ONLY-authorization.jws"
    authorization = Authorization(
        schema_version="dppce.authorization/1",
        authorization_id="TEST-ONLY-rig-authorization",
        issuer="urn:example:operator:0001",
        subject="urn:example:test-lab",
        sut_identifier="urn:example:sut:reference-dpp",
        endpoints=(rig.origin,),
        methods=("GET",),
        roles=("anonymous", "legitimate_interest", "authority"),
        scopes=scopes,
        not_before="2026-01-01T00:00:00Z",
        not_after="2036-01-01T00:00:00Z",
        max_requests=1000,
    )
    path.write_text(issue_authorization(authorization, owner) + "\n", encoding="ascii")
    return "--authorization", str(path)


def _oauth_run(tmp_path: Path, faults: frozenset[str] = frozenset()) -> tuple[ReferenceRig, Any, str]:
    with ReferenceRig(tmp_path, "family/oauth", faults=faults) as rig:
        granted = _credential_authorization(rig, ("read", "access_probe", "credential"))
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            result = rig.run(extra=(*OAUTH_ARGUMENTS, *granted))
        return rig, result, captured.getvalue()


def test_an_oauth_run_passes_on_the_unmodified_reference_system_and_replays(tmp_path: Path) -> None:
    rig, result, stderr = _oauth_run(tmp_path)
    assert result.step("TP-OAUTH-ACCESS-001") == {
        "verdict": "pass",
        "reason_code": "ACCESS.POLICY.ENFORCED",
        "status": "completed",
    }
    for secret in (oauth.CLIENT_SECRET, oauth.ROLE_TOKEN, oauth.WRONG_ROLE_TOKEN):
        assert secret not in stderr, "no secret reaches the log"
        for path in result.run_dir.rglob("*"):
            if path.is_file():
                assert secret.encode() not in path.read_bytes(), path
    code, summary = rig.replay(result)
    assert code == 0, summary
    assert summary["match"] is True


def test_a_token_of_the_wrong_role_shows_the_leak(tmp_path: Path) -> None:
    _, result, _ = _oauth_run(tmp_path, frozenset({"oauth_token_wrong_role"}))
    assert result.step("TP-OAUTH-ACCESS-001")["verdict"] == "fail"
    assert result.step("TP-OAUTH-ACCESS-001")["reason_code"] == "ACCESS.LEAK.FETCH"


def test_a_refused_token_gives_no_answer_never_a_pass(tmp_path: Path) -> None:
    _, result, _ = _oauth_run(tmp_path, frozenset({"oauth_token_refused"}))
    step = result.step("TP-OAUTH-ACCESS-001")
    assert (step["verdict"], step["reason_code"]) == ("inconclusive", "TRANSPORT.DENIED")
    assert result.envelope.decision.overall is not Verdict.PASS


def _usage(rig: ReferenceRig, extra: tuple[str, ...]) -> str:
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        code = main([*rig.run_arguments(rig.work / "out"), "--create-data-key", *extra])
    assert code == 2
    return captured.getvalue()


def test_the_operator_confirms_both_references_of_an_oauth_role(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, "family/oauth") as rig:
        granted = _credential_authorization(rig, ("read", "access_probe", "credential"))
        assert "--role-client-id" in _usage(rig, (*OAUTH_ARGUMENTS[:2], *granted))
        assert "--role-secret" in _usage(rig, (*OAUTH_ARGUMENTS[2:], *granted))
        # The IXIT cannot make the engine send another secret of the laboratory as the client id.
        wrong = ("--role-client-id", "legitimate_interest=file:TEST-ONLY-authority.token")
        assert "--role-client-id" in _usage(rig, (*OAUTH_ARGUMENTS[:2], *wrong, *granted))


def test_an_oauth_role_needs_the_credential_scope_before_the_run(tmp_path: Path) -> None:
    with ReferenceRig(tmp_path, "family/oauth") as rig:
        granted = _credential_authorization(rig, ("read", "access_probe"))
        assert "'credential'" in _usage(rig, (*OAUTH_ARGUMENTS, *granted))


def test_the_token_endpoint_is_an_endpoint_key_of_the_ixit(tmp_path: Path) -> None:
    identity = {
        "role": "legitimate_interest",
        "scheme": "oauth2_client_credentials",
        "token_endpoint": "missing",
        "client_id_ref": "file:TEST-ONLY-oauth-client-id",
        "secret_ref": "file:TEST-ONLY-oauth-client-secret",
    }
    changes = {"identities": [{"role": "anonymous"}, identity]}
    with ReferenceRig(tmp_path, "family/oauth", ixit_changes=changes) as rig:
        granted = _credential_authorization(rig, ("read", "access_probe", "credential"))
        assert "'missing'" in _usage(rig, (*OAUTH_ARGUMENTS, *granted))
