"""Tests for the survivors of the mutation run of 2026-10-28.

The run is ``uv run just mutation`` (mutmut 3.8.0) at commit 5824386. Each test names, in its
docstring, the surviving mutants that it kills. A mutant name is ``dppce.<module>.x_<function>__mutmut_<n>``,
or ``xǁ<Class>ǁ<method>`` for a method. The numbers refer to the source at 5824386: mutmut numbers
the mutants of a function in source order, so a later change to a function can move them.
The record is ``validation/records/mutation-2026-10-28.md``.

Every server is a loopback server that the test starts. No test contacts another host. A name that is
not a loopback name ends in ``.test`` and resolves through a table. Tokens and secrets are TEST-ONLY values.
"""

from __future__ import annotations

import http.server
import json
import re
import socket
import ssl
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

import pytest

from dppce.evidence import disclosure
from dppce.evidence.canonical import canonical_bytes
from dppce.evidence.disclosure import MAX_OPENING_BYTES
from dppce.evidence.envelope import records_root, sign_envelope
from dppce.evidence.jws import LocalSigner
from dppce.evidence.recording import record_commitments
from dppce.infrastructure.clock import FrozenClock
from dppce.infrastructure.interfaces import Request
from dppce.infrastructure.redaction import (
    BASE_UNKNOWN,
    QUERY_UNKNOWN,
    _live,
    hides_base_path,
    parse_link,
    reads_apart,
    redact_link,
    redirect_mark,
    resolutions,
)
from dppce.infrastructure.transport import PolicyTransport, TransportConfig, _pending_alert
from dppce.models import EvidenceEnvelope, NetworkPolicy, StatusReference, TrustBundle
from dppce.verifier import __main__ as command
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from dppce.verifier.verify import verify_json
from tests.support import (
    AT,
    ISSUER,
    KID,
    make_envelope,
    make_record,
    reply,
)
from tests.test_credential_schemes import (
    LOCAL,
    NOW,
    TOKEN,
    TokenSystem,
    _authorization,
    _transport,
)
from tests.test_mutation_gaps_round2 import as_document

REMOVED_TARGET = "%3Cremoved%3E"
REMOVED = "<removed>"


@pytest.fixture
def tokens() -> Iterator[Callable[..., TokenSystem]]:
    """Starts a loopback token endpoint and a resource. Each one is closed after the test."""
    systems: list[TokenSystem] = []

    def start(*args: Any, **kwargs: Any) -> TokenSystem:
        systems.append(TokenSystem(*args, **kwargs))
        return systems[-1]

    yield start
    for system in systems:
        system.server.close()


# -- redaction: Link targets --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "kept"),
    [
        ("..", True),  # a leading dot segment alone is kept
        ("..?x", False),  # a dot segment at the end before a query is read apart
        ("x:..", False),  # a dot segment in a URL with a scheme is read apart
        ("x:./", False),
        ("x:a//b", True),  # a scheme: the path is not a relative path, so empty segments are kept
        (".ab", False),  # pyld drops the first "." of a path that starts with "." and has 3 characters
        (".a", True),
        ("./a", True),
    ],
)
def test_the_kept_or_removed_form_of_a_link_target_with_dot_segments(target: str, kept: bool) -> None:
    """The decision of ``_changed_by_urljoin`` for each target, seen through ``redact_link``.

    Kills:
    dppce.infrastructure.redaction.x__changed_by_urljoin__mutmut_45, 50, 54, 55, 58, 72
    """
    expected = f"<{target}>" if kept else f"<{REMOVED_TARGET}>"
    assert redact_link(f"<{target}>") == expected


def test_a_value_that_cannot_be_a_field_value_is_not_complete() -> None:
    """``_live`` gives a boolean, not None, for ``complete``.

    Kills:
    dppce.infrastructure.redaction.x__live__mutmut_14
    """
    assert _live("<a>\x00").complete is False


def test_a_quoted_pair_in_a_relation_loses_its_backslash_only() -> None:
    """A relation word that is quoted with a pair keeps the quoted character and nothing else.

    Kills:
    dppce.infrastructure.redaction.x_parse_link__mutmut_80
    """
    assert parse_link('<a b>; rel="a\\"b"').links[0].relations == ('a"b',)


@pytest.mark.parametrize("value", ["application/json\xa0", "application/jsonX", "Xapplication/json"])
def test_a_type_with_a_character_beyond_space_and_tab_is_not_a_kept_type(value: str) -> None:
    """Only a space and a tab are stripped from an unquoted parameter value.

    Kills:
    dppce.infrastructure.redaction.x_parse_link__mutmut_82, 85
    """
    link = parse_link(f"<a>; type={value}").links[0]
    assert (link.media_type, link.other) == (None, True)


def test_a_parameter_without_a_value_reads_as_an_empty_value() -> None:
    """``rel`` with no value is an empty relation list, not a word.

    Kills:
    dppce.infrastructure.redaction.x_parse_link__mutmut_84
    """
    assert parse_link("<a>; rel").links[0].relations == ()


def test_a_relation_outside_the_closed_list_keeps_its_lower_case_spelling() -> None:
    """A word of the list gets the spelling of the list. Another word is lower case.

    Kills:
    dppce.infrastructure.redaction.x_parse_link__mutmut_118, 119, 120, 122
    """
    assert parse_link("<a>; rel=Xself").links[0].relations == ("xself",)
    assert parse_link("<a>; rel=Self").links[0].relations == ("self",)


@pytest.mark.parametrize(
    ("value", "recorded"),
    [
        # "\xa0" is white space for jsonld.js. The engine reads it as part of the name, so the two
        # readers disagree on the type: the value is not complete.
        ("<a>;\xa0type=application/ld+json", "<a>; <removed>, <removed>"),
        # "\x85" is white space for pyld only. pyld reads an unquoted type as empty, so there is no
        # disagreement.
        ("<a>;\x85type=application/ld+json", "<a>; <removed>"),
        ("<a>; type=application/ld+json", '<a>; type="application/ld+json"'),
    ],
)
def test_the_type_check_against_the_processor_models_uses_each_model_as_it_reads(
    value: str, recorded: str
) -> None:
    """The jsonld.js pass reads an unquoted type. The pyld pass reads an unquoted type as empty.

    Kills:
    dppce.infrastructure.redaction.x__types_agree__mutmut_1, 2, 21, 22, 23
    """
    assert redact_link(value) == recorded


# -- redaction: redirect targets ----------------------------------------------------------------


def test_a_scheme_only_target_is_not_a_relative_path_for_a_marked_or_odd_base() -> None:
    """A target with a scheme and no authority is not a relative path.

    Kills:
    dppce.infrastructure.redaction.x_resolutions__mutmut_6
    dppce.infrastructure.redaction.x_hides_base_path__mutmut_11
    dppce.infrastructure.redaction.x__reads_unknown__mutmut_4
    """
    assert resolutions("http://h/a//b/c", "x:y") == ("x:y",)
    assert hides_base_path("http://h/%3Cremoved%3E/x", "x:a") is False
    assert hides_base_path("http://h/x" + BASE_UNKNOWN, "x:a") is False
    assert hides_base_path("http://h/x" + BASE_UNKNOWN, "a") is True


def test_the_two_readings_of_a_relative_path_on_a_base_with_a_dot_segment() -> None:
    """pyld reads the base as sent. WHATWG removes the dot segments of the directory.

    Kills:
    dppce.infrastructure.redaction.x_resolutions__mutmut_24, 25, 30
    dppce.infrastructure.redaction.xǁ_Directoryǁ__init____mutmut_13, 20
    dppce.infrastructure.redaction.xǁ_Directoryǁmerge__mutmut_10
    dppce.infrastructure.redaction.x__without_dots__mutmut_9
    """
    assert resolutions("http://h/c/a;/../;?x=1#<removed>", "%2E#") == ("http://h/c/%2E", "http://h/c/")
    assert resolutions("http://h/x/%2e%2e/y", "z") == ("http://h/x/%2e%2e/z", "http://h/z")


def test_a_target_with_only_a_fragment_keeps_the_query_of_the_base() -> None:
    """Kills:
    dppce.infrastructure.redaction.x_resolutions__mutmut_34
    """
    assert resolutions("http://h/..;x/%2E/\\/%2e?x=1", "#f") == (
        "http://h/..;x/%2E/\\/%2e?x=1#f",
        "http://h/..;x///?x=1#f",
    )


def test_a_final_dot_segment_of_the_base_leaves_a_directory() -> None:
    """Kills:
    dppce.infrastructure.redaction.x__without_dots__mutmut_18, 19, 21
    """
    assert resolutions("http://h/a/b/.", "#f") == ("http://h/a/b/.#f", "http://h/a/b/#f")


@pytest.mark.parametrize(
    ("base", "location", "apart"),
    [
        ("http://h/x", "a//", True),  # urljoin removes an empty segment of a relative path
        ("http://h/./x", "y", True),  # a dot segment in the base path
        ("http://h/x", "./a", False),  # a plain "./" is read the same way by every reader
        ("http://h/x", "a/%2e", True),  # "%2e" is a dot for WHATWG URL, not for urljoin
        ("http://h/x", "a;;", False),
        ("http://h/x", "p;q/a;", False),
        ("http://h/x/y", "a;/b;", False),
        ("http://h/x", "a/b;c/d;", False),
        ("http://h/x", "b/;", False),
        ("http://h/x", "b;x", False),
        ("http://h/x", "https:/;", True),
        ("http://h/x", "mailto:////;", False),
        ("http://h/x", "mailto:///;", True),
        ("http://h/x", "https:?", True),  # urlunparse writes "https://" for "https:"
        ("http://h/x", "b?x\ty", True),  # urlparse removes a tab, so the query is not as sent
        ("http://h/x", "b#x\ty", True),
    ],
)
def test_reads_apart_for_each_form_of_location(base: str, location: str, apart: bool) -> None:
    """Kills:
    dppce.infrastructure.redaction.x_reads_apart__mutmut_9, 29, 46
    dppce.infrastructure.redaction.x__odd_path__mutmut_4
    dppce.infrastructure.redaction.x__dot__mutmut_15
    dppce.infrastructure.redaction.x__without_empty_ends__mutmut_12, 16, 18, 21, 23, 24, 25, 33
    dppce.infrastructure.redaction.x__without_empty_ends__mutmut_34, 35, 36, 38, 39, 41
    """
    assert reads_apart(base, location) is apart


def test_the_mark_of_a_redirect_target() -> None:
    """The mark follows the rules of ``redirect_mark``.

    Kills:
    dppce.infrastructure.redaction.x_redirect_mark__mutmut_18, 42
    dppce.infrastructure.redaction.x__without_empty_ends__mutmut_19
    """
    previous = "http://h/x" + BASE_UNKNOWN
    # A previous base mark and a ";" parameter: the unknown base wins over the unknown query.
    assert redirect_mark(previous, "http://h/x", "b;") == BASE_UNKNOWN
    # A relative reference after a same-scheme prefix still reads the base path.
    assert redirect_mark(previous, "http://h/x", "http:1:b") == BASE_UNKNOWN
    # The first ";" of the last segment is not the last character, so no parameter is dropped.
    assert redirect_mark("", "http://h/x", "a;b;") == ""
    assert redirect_mark("", "http://h/x", "b;") == QUERY_UNKNOWN
    # A location that urlparse reads with an empty authority and a ";" drops nothing: no parameter.
    assert redirect_mark("", "http://h/x", "mailto:////;") == QUERY_UNKNOWN


# -- transport: TLS alert, Retry-After -----------------------------------------------------------


def test_a_pending_alert_needs_a_tls_socket_and_a_tls_error() -> None:
    """Only a TLS socket whose next read gives a TLS error has a pending alert.

    Kills:
    dppce.infrastructure.transport.x__pending_alert__mutmut_2, 6, 7
    """
    assert _pending_alert(None) is False
    plain = socket.socket()
    try:
        assert _pending_alert(plain) is False
    finally:
        plain.close()
    tls = mock.MagicMock(spec=ssl.SSLSocket)
    tls.recv.side_effect = ssl.SSLError("alert")
    assert _pending_alert(tls) is True
    tls.recv.side_effect = ConnectionResetError()
    assert _pending_alert(tls) is False
    tls.recv.side_effect = None
    tls.recv.return_value = b""
    assert _pending_alert(tls) is False


def _answers(*replies: tuple[int, dict[str, str]]) -> Callable[[http.server.BaseHTTPRequestHandler], None]:
    """A handler that gives the replies in order and repeats the last one."""
    left = list(replies)

    def handle(request: http.server.BaseHTTPRequestHandler) -> None:
        status, headers = left.pop(0) if len(left) > 1 else left[0]
        reply(request, status, b"{}", headers)

    return handle


def _waiting(waits: list[float]) -> PolicyTransport:
    config = TransportConfig(policy=NetworkPolicy(**LOCAL), engine_version="1")
    return PolicyTransport(config, FrozenClock(NOW), sleep=waits.append, monotonic=lambda: 0.0)


@pytest.mark.parametrize(
    ("value", "waited"),
    [
        ("0", [0]),  # zero seconds is a valid delay: one retry at once
        ("0003", [3]),  # leading zeros do not make the number longer than the cap
        ("50", []),  # trailing zeros count: 50 is above the cap of 5
        ("10", []),
    ],
)
def test_a_retry_after_is_read_as_a_decimal_number(value: str, waited: list[int], loopback: Any) -> None:
    """Leading zeros are stripped, trailing zeros are not, and 0 is a number.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_retry_delay__mutmut_17, 18, 20
    """
    server = loopback(_answers((429, {"Retry-After": value}), (200, {})))
    waits: list[float] = []
    record = _waiting(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (waits, record.attempts, record.status) == (waited, 2 if waited else 1, 200 if waited else 429)


# -- transport: the token request of an OAuth 2.0 role -------------------------------------------


@pytest.fixture
def create_connection_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    """Each (address, timeout) that the transport gives to socket.create_connection."""
    seen: list[tuple[Any, Any]] = []
    real = socket.create_connection

    def spy(address: Any, timeout: Any = None, *args: Any, **kwargs: Any) -> socket.socket:
        seen.append((address, timeout))
        return real(address, timeout, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", spy)
    return seen


@pytest.mark.parametrize(
    ("contact", "agent"),
    [
        ("", "dppce/1.2.3"),
        ("TEST-ONLY-contact@example.test", "dppce/1.2.3 (+TEST-ONLY-contact@example.test)"),
    ],
)
def test_the_token_request_names_the_engine_and_asks_for_json_without_encoding(
    contact: str, agent: str, tokens: Any
) -> None:
    """Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_39, 40, 41, 42, 44, 45, 46, 47, 48
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_49, 50, 51, 52, 53, 54, 55, 56
    """
    system = tokens()
    engine = _transport(
        {**LOCAL, "contact": contact},
        oauth_clients=system.client(),
        authorization=_authorization(system.origin),
    )
    engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    sent = system.posts[0]["headers"]
    assert (sent["User-Agent"], sent["Accept"], sent["Accept-Encoding"]) == (
        agent,
        "application/json",
        "identity",
    )


def test_the_token_request_is_bound_by_the_total_time_of_the_request(
    tokens: Any, create_connection_calls: list[tuple[Any, Any]]
) -> None:
    """The socket timeout of the token request is the shorter of the two limits.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_81, 82
    """
    system = tokens()
    engine = _transport(
        {**LOCAL, "timeout_ms": 2000, "total_timeout_ms": 500},
        oauth_clients=system.client(),
        authorization=_authorization(system.origin),
    )
    engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert create_connection_calls[0][1] == 0.5


class _Names:
    """Answers from a table. A name outside the table is a DNS failure."""

    def __init__(self, table: dict[str, list[str]]) -> None:
        self._table = table

    def resolve(self, host: str, port: int) -> list[str]:
        if host not in self._table:
            raise OSError("no such host")
        return self._table[host]


def _with_names(
    system: TokenSystem, token_url: str, table: dict[str, list[str]], **auth: Any
) -> PolicyTransport:
    policy = {
        "allowed_hosts": ("127.0.0.1", "token.test"),
        "allow_private_hosts": ("127.0.0.1",),
    }
    settings = TransportConfig(
        policy=NetworkPolicy(**policy),
        engine_version="1.2.3",
        oauth_clients=system.client(token_url),
        authorization=_authorization(system.origin, **auth),
    )
    return PolicyTransport(settings, FrozenClock(NOW), resolver=_Names(table), sleep=lambda _: None)


def test_a_token_endpoint_that_does_not_resolve_is_a_dns_error(tokens: Any) -> None:
    """Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_19, 21, 22, 23, 24, 25
    """
    system = tokens()
    engine = _with_names(
        system,
        "http://token.test/token",
        {"127.0.0.1": ["127.0.0.1"]},
        endpoints=(system.origin, "http://token.test"),
    )
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "dns"
    assert system.server.seen == []


def test_a_token_endpoint_outside_the_authorization_is_denied_not_a_dns_error(tokens: Any) -> None:
    """Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_20, 23, 26, 27
    """
    system, elsewhere = tokens(), tokens()
    engine = _with_names(
        system, f"{elsewhere.origin}/token", {"127.0.0.1": ["127.0.0.1"]}, endpoints=(system.origin,)
    )
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "authorization_denied"
    assert elsewhere.server.seen == []
    assert system.server.seen == []


def test_the_client_secret_goes_to_an_https_endpoint_at_a_public_address(
    tokens: Any, create_connection_calls: list[tuple[Any, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An https token endpoint is not refused for its address. The connection is made to the address.

    The test replaces ``socket.create_connection`` for the public address, so nothing leaves the host.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_30, 31
    """
    system = tokens()
    engine = _with_names(
        system,
        "https://token.test/token",
        {"127.0.0.1": ["127.0.0.1"], "token.test": ["93.184.216.34"]},
        endpoints=(system.origin, "https://token.test"),
    )

    def refuse(address: Any, timeout: Any = None, *args: Any, **kwargs: Any) -> socket.socket:
        create_connection_calls.append((address, timeout))
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", refuse)
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "connect"
    assert [address for address, _ in create_connection_calls] == [("93.184.216.34", 443)]


def test_the_token_request_does_not_use_a_spent_budget(tokens: Any) -> None:
    """Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_37, 38
    """
    system = tokens()
    engine = _transport(
        oauth_clients=system.client(), authorization=_authorization(system.origin, max_requests=1)
    )
    assert engine.fetch(Request("GET", f"{system.origin}/data")).status == 200
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "budget_exhausted"
    assert system.posts == []


def _token_json(token: str = TOKEN) -> bytes:
    return json.dumps({"access_token": token, "token_type": "Bearer"}).encode()


@pytest.mark.parametrize(
    "answer",
    [
        (401, _token_json()),  # a refusal with a usable body is still a refusal
        (500, _token_json()),
        (200, _token_json() + b" " * 3000),  # cut by the body limit: the cut body is not read
    ],
)
def test_a_token_in_a_refused_or_cut_answer_is_not_used(tokens: Any, answer: tuple[int, bytes]) -> None:
    """Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_85, 87
    """
    system = tokens(token_reply=answer)
    engine = _transport(
        {**LOCAL, "max_body_bytes": 2048},
        oauth_clients=system.client(),
        authorization=_authorization(system.origin),
    )
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.error == "authorization_denied"
    assert system.gets() == []


def test_a_token_is_removed_from_a_record_in_the_percent_encoded_bearer_form(tokens: Any) -> None:
    """An echo of ``Bearer%20<token>`` is removed as the echo of ``Bearer <token>`` is.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_121
    """
    system = tokens(resource_body=f"seen Bearer%20{TOKEN} end".encode())
    engine = _transport(oauth_clients=system.client(), authorization=_authorization(system.origin))
    record = engine.fetch(Request("GET", f"{system.origin}/data", role="auditor"))
    assert record.body == f"seen Bearer {REMOVED} end".encode()


# -- verifier: supplied files, signer rows, lifecycle text, the standalone command --------------

SIGNED_AT = "2026-10-13T12:05:00Z"


@pytest.fixture
def disclosing(signer: LocalSigner) -> tuple[EvidenceEnvelope, bytes, bytes]:
    """A signed report with one committed record, and an opening and a proof that match it."""
    first = make_record(1)
    commitments = record_commitments([first])
    decision = make_envelope().decision.model_copy(
        update={"record_commitments": commitments, "records_root": records_root(commitments)}
    )
    envelope = sign_envelope(
        EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision),
        signer,
        issuer=ISSUER,
        signed_at=SIGNED_AT,
    )
    opening = canonical_bytes(disclosure.open_record(envelope.decision, first))
    proof = canonical_bytes(disclosure.prove(envelope.decision, "T:TP-001"))
    return envelope, opening, proof


def test_a_supplied_opening_or_proof_is_a_mandatory_dimension_of_the_report(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes], trust: TrustBundle
) -> None:
    """With a signed report that passes, each supplied file adds a dimension and the report is complete.

    Kills:
    dppce.verifier.verify.x_verify__mutmut_5, 6
    dppce.verifier.verify.x_verify_json__mutmut_10, 16
    """
    envelope, opening, proof = disclosing
    document = as_document(envelope)
    for files in ({"opening": opening}, {"proof": proof}, {"opening": opening, "proof": proof}):
        for report_of in (
            verify(document, trust, AT, **files),
            verify_json(envelope.model_dump_json(by_alias=True), trust, AT, **files),
        ):
            assert {d.name: d.outcome for d in report_of.dimensions}.items() >= dict.fromkeys(
                files, "pass"
            ).items()
            assert report_of.complete is True


def test_the_standalone_verifier_reads_an_opening_and_a_proof_and_writes_indented_json(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
    trust: TrustBundle,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Kills:
    dppce.verifier.__main__.x_main__mutmut_56, 59, 112, 113, 114, 148, 154, 157, 158
    """
    envelope, opening, proof = disclosing
    files = {
        "envelope.json": envelope.model_dump_json(by_alias=True).encode(),
        "trust.json": trust.model_dump_json().encode(),
    }
    files |= {"opening.json": opening, "proof.json": proof}
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    code = verifier_main(
        [
            str(tmp_path / "envelope.json"),
            "--trust",
            str(tmp_path / "trust.json"),
            "--at",
            "2026-10-14T00:00:00Z",
            "--opening",
            str(tmp_path / "opening.json"),
            "--proof",
            str(tmp_path / "proof.json"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith('{\n  "schema_version"')
    shown = json.loads(out)
    assert shown["complete"] is True
    assert {d["name"]: d["outcome"] for d in shown["dimensions"]}["opening"] == "pass"
    assert {d["name"]: d["outcome"] for d in shown["dimensions"]}["proof"] == "pass"


class _RecordingPath(type(Path())):  # type: ignore[misc] - a Path whose open() records each read size
    reads: ClassVar[list[int | None]] = []

    def open(self, mode: str = "r", *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        handle = super().open(mode, *args, **kwargs)
        real = handle.read

        def read(size: int | None = -1) -> bytes:
            _RecordingPath.reads.append(size)
            return real(size)  # type: ignore[no-any-return]

        handle.read = read  # type: ignore[method-assign]
        return handle


def test_the_standalone_verifier_reads_one_byte_more_than_the_limit_of_a_file(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
    trust: TrustBundle,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file is read up to its limit plus one byte, so that the verifier can refuse a longer file.

    Kills:
    dppce.verifier.__main__.x_main__mutmut_82, 84
    """
    envelope, opening, _ = disclosing
    (tmp_path / "envelope.json").write_bytes(envelope.model_dump_json(by_alias=True).encode())
    (tmp_path / "trust.json").write_bytes(trust.model_dump_json().encode())
    (tmp_path / "opening.json").write_bytes(opening)
    _RecordingPath.reads = []
    monkeypatch.setattr(command, "Path", _RecordingPath)
    verifier_main(
        [
            str(tmp_path / "envelope.json"),
            "--trust",
            str(tmp_path / "trust.json"),
            "--at",
            "2026-10-14T00:00:00Z",
            "--opening",
            str(_RecordingPath(tmp_path / "opening.json")),
        ]
    )
    # The envelope and the trust bundle are read whole (-1). The opening is read up to the limit plus one.
    assert _RecordingPath.reads == [-1, -1, MAX_OPENING_BYTES + 1]


def test_the_standalone_verifier_help_names_the_command_and_each_argument(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The help text is what an operator reads first.

    Kills:
    dppce.verifier.__main__.x_main__mutmut_2, 3, 4, 5, 6, 7, 10, 13, 16, 17, 18, 22, 26, 30, 31, 32
    dppce.verifier.__main__.x_main__mutmut_35, 38, 42, 43, 44, 47, 50, 53, 54, 57, 60, 63, 64, 67, 70, 73, 74
    """
    monkeypatch.setenv("COLUMNS", "300")
    with pytest.raises(SystemExit) as stop:
        verifier_main(["--help"])
    assert stop.value.code == 0
    text = capsys.readouterr().out
    for phrase in (
        "usage: python -m dppce.verifier",
        "Run the verifier without the rest of the engine:",
        "evidence envelope (JSON)",
        "explicit trust bundle (JSON)",
        "evaluation time, for example 2026-10-13T12:00:00Z",
        "signed status list file of the report issuer; nothing is fetched",
        "record opening to check against the report",
        "inclusion proof to check against the report",
    ):
        # The phrase stands alone: a mutant that wraps it in letters does not match.
        assert re.search(rf"(?m)(^|\s){re.escape(phrase)}(\s|$)", text), phrase


def test_every_signature_gets_a_row_whatever_the_one_before_it_was(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """A header that cannot be read, a key that the bundle lacks, and a signature over another body
    each give a row, and the search goes on to the next signature.

    Kills:
    dppce.verifier.verify.x__signers__mutmut_25, 30, 39
    """
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    elsewhere = sign_envelope(make_envelope(("fail",)), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    unknown = sign_envelope(make_envelope(), stranger, issuer=ISSUER, signed_at=SIGNED_AT)
    good = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    tokens_ = ("x", unknown.signatures[0], elsewhere.signatures[0], good.signatures[0])
    document = as_document(good.model_copy(update={"signatures": tokens_}))
    signers = {d.name: d for d in verify(document, trust, AT).dimensions}["signers"]
    assert signers.detail.split("; ") == [
        "signature 1: SIGNER.SIGNATURE.INVALID, the header cannot be read",
        "signature 2: key 'TEST-ONLY-unknown-key': SIGNER.KEY.UNKNOWN, not checked",
        f"signature 3: key '{KID}' of issuer '{ISSUER}': SIGNER.SIGNATURE.INVALID",
        f"signature 4: key '{KID}' of issuer '{ISSUER}' as issuer: SIGNER.ROLE.OK.",
    ]


def test_the_signer_row_states_valid_until_supersedes_and_the_status_entry(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """Each lifecycle statement of a signature is added to its row, in this order, and only if it is stated.

    Kills:
    dppce.verifier.verify.x__lifecycle__mutmut_2, 3, 4, 7, 10
    """
    plain = sign_envelope(make_envelope(), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    rich = sign_envelope(
        make_envelope(),
        signer,
        issuer=ISSUER,
        signed_at=SIGNED_AT,
        valid_until="2026-12-31T00:00:00Z",
        supersedes="sha256:" + "a" * 64,
        status=StatusReference(list_id="L'1", index=3),
    )
    row = " of issuer 'urn:example:test-lab' as issuer: SIGNER.ROLE.OK"
    assert {d.name: d.detail for d in verify(as_document(plain), trust, AT).dimensions}[
        "signers"
    ] == f"signature 1: key 'TEST-ONLY-report-key-1'{row}."
    assert (
        {d.name: d.detail for d in verify(as_document(rich), trust, AT).dimensions}["signers"]
        == f"signature 1: key 'TEST-ONLY-report-key-1'{row}, valid until 2026-12-31T00:00:00Z, "
        f'supersedes sha256:{"a" * 64}, status list "L\'1" index 3.'
    )


def _dimensions_of(document: dict[str, Any], trust: TrustBundle) -> dict[str, tuple[str, str]]:
    return {d.name: (d.outcome, d.detail) for d in verify(document, trust, AT).dimensions}


NO_SIGNATURE = "The envelope has no signature."
UNSIGNED = "no issuer signature passes issuer_trust."


def test_the_details_of_a_valid_report_without_a_signature(trust: TrustBundle) -> None:
    """The details that a reader of the report sees are the published ones. Codes are not in doubt here.

    Kills:
    dppce.verifier.verify.x__ordering__mutmut_21, 22, 23
    dppce.verifier.verify.x__verified__mutmut_4, 5, 6
    dppce.verifier.verify.x__issuer__mutmut_4, 5, 6
    dppce.verifier.verify.x__signers__mutmut_4, 5, 6
    dppce.verifier.verify.x__timestamps__mutmut_10, 11, 12
    dppce.verifier.verify.x__manual_results__mutmut_8, 9, 10
    dppce.verifier.verify.x_body_dimensions__mutmut_39, 40, 41, 62, 63, 64
    dppce.verifier.verify.x__counts__mutmut_84, 85, 86
    dppce.verifier.verify.x__status__mutmut_19
    dppce.verifier.verify.x__validity__mutmut_6
    """
    assert _dimensions_of(as_document(make_envelope()), trust) == {
        "structure": ("pass", "The envelope matches the schema."),
        "ordering": ("pass", "Every list is strictly ascending by identifier."),
        "results_root": ("pass", "The root over 6 results equals the stated root."),
        "records_root": ("pass", "The root over the record commitments equals the stated root."),
        "counts": (
            "pass",
            "Counts, verdicts, coverage totals, and the overall outcome equal the recomputed values.",
        ),
        "signature": ("missing", NO_SIGNATURE),
        "issuer_trust": ("not_checked", "There is no signature to attribute."),
        "signers": ("missing", NO_SIGNATURE),
        "manual_results": ("pass", "The report holds no completed manual step."),
        "status": ("not_checked", f"STATUSLIST.REPORT.UNSIGNED: {UNSIGNED}"),
        "validity": ("not_checked", f"VALIDITY.REPORT.UNSIGNED: {UNSIGNED}"),
        "timestamp": ("not_checked", "The envelope has no timestamp evidence."),
    }


def test_the_details_of_a_report_that_no_trusted_key_signed(trust: TrustBundle) -> None:
    """Kills:
    dppce.verifier.verify.x__verified__mutmut_75, 76, 77
    dppce.verifier.verify.x__issuer__mutmut_62, 63, 64
    """
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    envelope = sign_envelope(make_envelope(), stranger, issuer=ISSUER, signed_at=SIGNED_AT)
    shown = _dimensions_of(as_document(envelope), trust)
    unknown = "No signature names a key in the trust bundle."
    assert shown["signature"] == ("not_checked", unknown)
    assert shown["issuer_trust"] == ("fail", f"{unknown} A key that only the report supplies is not trusted.")


def test_the_details_of_a_signature_over_another_body_and_of_conflicting_lifecycles(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """Kills:
    dppce.verifier.verify.x__verified__mutmut_49, 50, 51
    dppce.verifier.verify.x__signers__mutmut_83
    dppce.verifier.verify.x__timestamps__mutmut_18
    """
    other = sign_envelope(make_envelope(("fail",)), signer, issuer=ISSUER, signed_at=SIGNED_AT)
    body = make_envelope()
    bound_elsewhere = body.model_copy(update={"signatures": other.signatures})
    shown = _dimensions_of(as_document(bound_elsewhere), trust)
    assert shown["signature"] == ("fail", "A signature verifies but does not bind this decision body.")

    first = sign_envelope(
        body, signer, issuer=ISSUER, signed_at=SIGNED_AT, valid_until="2026-12-31T00:00:00Z"
    )
    both = sign_envelope(
        first, signer, issuer=ISSUER, signed_at=SIGNED_AT, valid_until="2026-11-30T00:00:00Z"
    )
    outcome, detail = _dimensions_of(as_document(both), trust)["signers"]
    assert outcome == "fail"
    assert detail.startswith(
        "SIGNER.LIFECYCLE.CONFLICT: the issuer signatures that pass issuer_trust state different "
        "status, valid_until, or supersedes values. signature 1: "
    )

    unsigned = as_document(body)
    unsigned["timestamp_evidence"] = ["AAAA"]
    assert _dimensions_of(unsigned, trust)["timestamp"] == (
        "not_checked",
        "TIMESTAMP.SIGNATURE.NONE: no signature verifies, so no timestamp can bind one.",
    )


def test_the_details_of_a_signed_report_that_states_nothing_more(
    signed: EvidenceEnvelope, trust: TrustBundle
) -> None:
    """Kills:
    dppce.verifier.verify.x__status__mutmut_34
    dppce.verifier.verify.x__validity__mutmut_14
    """
    shown = _dimensions_of(as_document(signed), trust)
    assert shown["status"] == (
        "not_checked",
        "STATUSLIST.REFERENCE.NONE: no issuer signature that passes issuer_trust names a status entry.",
    )
    assert shown["validity"] == (
        "not_checked",
        "VALIDITY.PERIOD.NOT_STATED: no issuer signature states valid_until.",
    )


def test_the_details_of_a_report_whose_structure_or_body_is_wrong(trust: TrustBundle) -> None:
    """Kills:
    dppce.verifier.verify.x_verify__mutmut_37, 38, 39
    dppce.verifier.verify.x__ordering__mutmut_18
    dppce.verifier.verify.x_body_dimensions__mutmut_9, 10, 11, 12, 13, 53, 54, 55, 69, 70, 71
    """
    # A number that pydantic reads from 6.0 is not in the exact canonical form.
    inexact = as_document(make_envelope())
    inexact["decision"]["results_count"] = 6.0
    shown = _dimensions_of(inexact, trust)
    assert shown["structure"] == (
        "fail",
        "The envelope is not valid: the document is not in the exact canonical form of the schema "
        "(a field is missing, a type differs, or a number is not an integer)",
    )
    skipped = ("not_checked", "Not checked because the structure is not valid.")
    assert {name: value for name, value in shown.items() if name != "structure"} == dict.fromkeys(
        ("ordering", "results_root", "records_root", "counts", "signature", "issuer_trust", "signers",
         "manual_results", "status", "validity", "timestamp"),
        skipped,
    )  # fmt: skip

    broken = as_document(make_envelope(("pass", "pass")))
    decision = broken["decision"]
    decision["requirement_results"].reverse()
    decision["test_results"].reverse()
    decision["results_root"] = decision["records_root"] = "0" * 64
    shown = _dimensions_of(broken, trust)
    assert shown["ordering"] == (
        "fail",
        "Not strictly ascending (a duplicate or a reorder): requirement results, test results.",
    )
    assert shown["results_root"] == (
        "fail",
        "The recomputed results root or count differs from the stated one.",
    )
    assert shown["records_root"] == ("fail", "The recomputed records root differs from the stated one.")
