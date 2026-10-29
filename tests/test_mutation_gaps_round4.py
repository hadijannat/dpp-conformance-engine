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

import base64
import http.server
import json
import os
import re
import shutil
import socket
import ssl
import threading
import zlib
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from dppce.evidence import disclosure, merkle, x509path
from dppce.evidence import jose_profiles as jose
from dppce.evidence.canonical import CanonicalizationError, canonical_bytes, parse_strict
from dppce.evidence.disclosure import MAX_OPENING_BYTES
from dppce.evidence.envelope import in_layout_of, records_root, sign_envelope
from dppce.evidence.jws import (
    MAX_PAYLOAD_BYTES,
    LocalSigner,
    SignatureError,
    payload_of,
    public_jwk_from,
    public_jwk_of,
    sign_compact,
    signature_value,
)
from dppce.evidence.manual import (
    ManualResultError,
    claimed_test_purpose,
    verify_manual_result,
)
from dppce.evidence.recording import (
    _INDEX_AAD,
    REDIRECT_STATUSES,
    RecordingError,
    _aad,
    _delete_recording,
    purge_expired,
    read_index,
    read_recording,
    record_commitments,
    record_from_json,
    record_to_json,
    write_recording,
)
from dppce.evidence.status import (
    MAX_BITSTRING_BYTES,
    MAX_TOKEN_BYTES,
    MIN_BITS,
    STATUS_LIST_TYP,
    StatusError,
    bit_is_set,
    decode_list,
    encode_list,
    read_status_list,
)
from dppce.evidence.x509path import MAX_CHAIN, path_gap, trust_path
from dppce.infrastructure.authorization import (
    AuthorizationError,
    issue_authorization,
    validate_authorization,
)
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
from dppce.infrastructure.transport import PolicyTransport, TransportConfig, _forms, _pending_alert
from dppce.models import (
    EvidenceEnvelope,
    ManualResult,
    NetworkPolicy,
    RecordCommitment,
    StatusList,
    StatusReference,
    TrustAnchor,
    TrustBundle,
    TrustedKey,
)
from dppce.verifier import __main__ as command
from dppce.verifier import verify
from dppce.verifier.__main__ import main as verifier_main
from dppce.verifier.verify import verify_json
from tests.core import builders as core_builders
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
from tests.test_manual_results import (
    MANUAL,
    PURPOSE_DIGEST,
    REFUSALS,
    UNIT_TRUST,
    _token,
    run_check,
)
from tests.test_manual_results import _key as _manual_key
from tests.test_mutation_gaps_round2 import as_document
from tests.test_report_status import ISSUED_AT, LIST_ID, STATUS_SIGNER
from tests.test_report_status import _key as _status_key
from tests.test_timestamps import FAULTS, Tsa, check, dim, with_tokens
from tests.tsa_support import tsa_ca, tsa_cert

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
    dppce.infrastructure.redaction.x__changed_by_urljoin__mutmut_40, 45, 50, 54, 55, 58, 72
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
    """
    assert resolutions("http://h/c/a;/../;?x=1#<removed>", "%2E#") == ("http://h/c/%2E", "http://h/c/")
    assert resolutions("http://h/x/%2e%2e/y", "z") == ("http://h/x/%2e%2e/z", "http://h/z")


def test_a_target_with_only_a_fragment_keeps_the_query_of_the_base() -> None:
    """Kills:
    dppce.infrastructure.redaction.x_resolutions__mutmut_34
    dppce.infrastructure.redaction.x__without_dots__mutmut_9
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


def _waiting(waits: list[float], *, now: float = 0.0, **policy: Any) -> PolicyTransport:
    config = TransportConfig(policy=NetworkPolicy(**(LOCAL | policy)), engine_version="1")
    return PolicyTransport(config, FrozenClock(NOW), sleep=waits.append, monotonic=lambda: now)


@pytest.mark.parametrize(
    ("value", "waited"),
    [
        ("0", [0]),  # zero seconds is a valid delay: one retry at once
        ("0003", [3]),  # leading zeros do not make the number longer than the cap
        ("5", [5]),  # the cap itself is allowed
        ("50", []),  # trailing zeros count: 50 is above the cap of 5
        ("10", []),
    ],
)
def test_a_retry_after_is_read_as_a_decimal_number(value: str, waited: list[int], loopback: Any) -> None:
    """Leading zeros are stripped, trailing zeros are not, and 0 is a number.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_retry_delay__mutmut_17, 18, 20, 29
    """
    server = loopback(_answers((429, {"Retry-After": value}), (200, {})))
    waits: list[float] = []
    record = _waiting(waits).fetch(Request("GET", f"{server.origin}/x"))
    assert (waits, record.attempts, record.status) == (waited, 2 if waited else 1, 200 if waited else 429)


@pytest.mark.parametrize("now", [0.0, 10.0])
def test_a_retry_after_that_equals_the_time_left_is_not_waited_for(now: float, loopback: Any) -> None:
    """The delay must be shorter than the time left. The time left is the deadline less the clock.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_retry_delay__mutmut_30, 31
    """
    server = loopback(_answers((429, {"Retry-After": "2"}), (200, {})))
    waits: list[float] = []
    record = _waiting(waits, now=now, total_timeout_ms=2000).fetch(Request("GET", f"{server.origin}/x"))
    assert (record.status, record.attempts, waits) == (429, 1, [])


def test_the_wait_between_requests_is_not_slept_when_it_is_zero(loopback: Any) -> None:
    """A request exactly one interval after the last one needs no wait.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_9
    """
    server = loopback(reply)
    now = [100.0]
    waits: list[float] = []
    config = TransportConfig(policy=NetworkPolicy(**(LOCAL | {"min_interval_ms": 500})), engine_version="1")
    subject = PolicyTransport(config, FrozenClock(NOW), sleep=waits.append, monotonic=lambda: now[0])
    subject.fetch(Request("GET", f"{server.origin}/ok"))
    now[0] = 100.5
    subject.fetch(Request("GET", f"{server.origin}/ok"))
    assert waits == []


class _FakeTimer:
    """Stands in for threading.Timer. The deadline passes at once, on a socket that cannot be shut down."""

    instances: ClassVar[list[_FakeTimer]] = []

    def __init__(self, interval: float, function: Callable[..., None], args: tuple[Any, ...] = ()) -> None:
        self.function = function
        self.daemon: bool | None = None
        _FakeTimer.instances.append(self)

    def start(self) -> None:
        class Closed:
            def shutdown(self, how: int) -> None:
                raise OSError("the socket is closed")

        self.function(Closed())

    def cancel(self) -> None:
        return


def test_a_deadline_on_a_closed_socket_is_a_timeout_and_the_timer_is_a_daemon(
    loopback: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timer shuts the socket down and ignores an error of the shutdown. It does not hold the process.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_send__mutmut_54, 66, 67
    """
    server = loopback(reply)
    _FakeTimer.instances = []
    monkeypatch.setattr(threading, "Timer", _FakeTimer)
    record = _waiting([]).fetch(Request("GET", f"{server.origin}/x"))
    assert record.error == "timeout"
    assert [timer.daemon for timer in _FakeTimer.instances] == [True]


def test_a_role_with_a_credential_for_another_origin_and_no_client_gets_no_secret() -> None:
    """The secret is for the origin of its credential. A role without a client has no other source.

    Kills:
    dppce.infrastructure.transport.xǁPolicyTransportǁ_secret_of__mutmut_12
    """
    settings = TransportConfig(
        policy=NetworkPolicy(**LOCAL),
        engine_version="1",
        credentials={"auditor": ("http://127.0.0.1:1", "TEST-ONLY-secret-0123456789")},
    )
    subject = PolicyTransport(settings, FrozenClock(NOW))
    assert subject._secret_of("auditor", "http://127.0.0.1:1") == "TEST-ONLY-secret-0123456789"
    assert subject._secret_of("auditor", "http://127.0.0.1:2") is None


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
    # A renamed header would add a name on the wire, so the set of names is pinned too.
    assert set(sent) == {
        "Accept",
        "Accept-Encoding",
        "Authorization",
        "Content-Length",
        "Content-Type",
        "Host",
        "User-Agent",
    }


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


def test_a_form_of_a_credential_that_is_part_of_a_longer_form_comes_after_it() -> None:
    """The plain form of a token that starts with "/" is part of its JSON-escaped form ("\\\\/...").
    Replacing the short one first would leave a backslash. Longer forms come first.

    Kills:
    dppce.infrastructure.transport.x__forms__mutmut_31, 34, 35
    """
    forms = _forms("/TEST-ONLY-slash-token-0123456789")
    assert forms.index("\\/TEST-ONLY-slash-token-0123456789") < forms.index(
        "/TEST-ONLY-slash-token-0123456789"
    )
    assert not any(a in b for i, a in enumerate(forms) for b in forms[i + 1 :])


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
    dppce.infrastructure.transport.xǁPolicyTransportǁ_request_token__mutmut_20, 26, 27
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


class _RecordingPath(type(Path())):  # type: ignore[misc]  # a Path whose open() records each read size
    reads: ClassVar[list[int | None]] = []

    def open(self, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        handle = super().open(mode, *args, **kwargs)
        real = handle.read

        def read(size: int | None = -1) -> bytes:
            _RecordingPath.reads.append(size)
            return real(size)  # type: ignore[no-any-return]  # handle is Any, so its read() is untyped

        handle.read = read
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
    dppce.verifier.verify.x__signers__mutmut_25, 30, 39, 75, 76
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
    dppce.verifier.verify.x__lifecycle__mutmut_2, 3, 7, 10
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


# -- evidence: disclosure files and the layout of a body ------------------------------------------

ROOTS = {"results": True, "records": True}


def test_a_refused_disclosure_gives_its_code_and_its_message() -> None:
    """The error holds the text that it is given. A record that is not in the report, or that
    differs from its commitment, and a result that is not in the report, each have their own message.

    Kills:
    dppce.evidence.disclosure.xǁDisclosureErrorǁ__init____mutmut_1
    dppce.evidence.disclosure.x_prove__mutmut_8
    dppce.evidence.disclosure.x_open_record__mutmut_3, 4, 5, 6, 7, 8, 18, 19, 20, 21, 22, 23
    """
    decision = make_envelope().decision
    with pytest.raises(disclosure.DisclosureError) as unknown:
        disclosure.prove(decision, "T:TP-999")
    assert (unknown.value.code, str(unknown.value)) == (
        "PROVE.RESULT.UNKNOWN",
        "the report holds no result with the key 'T:TP-999'",
    )
    committed = make_record(1)
    with_commitment = decision.model_copy(
        update={"record_commitments": record_commitments([committed]), "records_root": "0" * 64}
    )
    with pytest.raises(disclosure.DisclosureError) as absent:
        disclosure.open_record(with_commitment, make_record(2))
    assert (absent.value.code, str(absent.value)) == (
        "OPEN.RECORD.NOT_IN_REPORT",
        "the report holds no commitment to the record 'r0002'",
    )
    with pytest.raises(disclosure.DisclosureError) as differs:
        disclosure.open_record(with_commitment, make_record(1))  # the same record, with a new salt
    assert (differs.value.code, str(differs.value)) == (
        "OPEN.RECORD.NOT_IN_REPORT",
        "the commitment of the record 'r0001' differs from the commitment in the report",
    )


def test_a_proof_file_of_exactly_the_limit_is_read_and_one_byte_more_is_refused(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
) -> None:
    """Kills:
    dppce.evidence.disclosure.x__parse__mutmut_1, 3
    """
    envelope, _, proof = disclosing
    limit = disclosure.MAX_PROOF_BYTES
    at_limit = proof + b" " * (limit - len(proof))
    assert len(at_limit) == limit
    assert disclosure.check_proof_file(at_limit, envelope.decision, ROOTS, ordered=True)[0] == "pass"
    assert disclosure.check_proof_file(at_limit + b" ", envelope.decision, ROOTS, ordered=True) == (
        "fail",
        f"PROOF.FILE.TOO_LARGE: the file is larger than {limit} bytes.",
    )


def test_a_proof_file_that_is_not_a_document_says_how(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
) -> None:
    """Kills:
    dppce.evidence.disclosure.x__parse__mutmut_11, 14, 15, 16, 19, 21, 22, 26, 37, 40, 41, 42, 43
    """
    envelope, _, proof = disclosing

    def checked(raw: bytes) -> tuple[str, str]:
        return disclosure.check_proof_file(raw, envelope.decision, ROOTS, ordered=True)

    assert checked(b"{") == ("fail", "PROOF.FILE.MALFORMED: the file is not strict JSON.")
    assert checked(b"{}") == (
        "fail",
        "PROOF.FILE.MALFORMED: the file is not a valid document: missing at 'schema_version'.",
    )
    nested = json.loads(proof)
    nested["leaf"] = {}
    assert checked(json.dumps(nested).encode()) == (
        "fail",
        "PROOF.FILE.MALFORMED: the file is not a valid document: "
        "missing at 'leaf.RequirementResult.requirement_id'.",
    )
    inexact = json.loads(proof)
    inexact["index"] = float(inexact["index"])
    assert checked(json.dumps(inexact).encode()) == (
        "fail",
        "PROOF.FILE.MALFORMED: the document is not in the exact canonical form of the schema "
        "(a field is missing, a type differs, or a number is not an integer).",
    )


def test_a_proof_for_another_report_or_a_wrong_path_says_which(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
) -> None:
    """Kills:
    dppce.evidence.disclosure.x__check_proof__mutmut_13, 18, 19, 37
    """
    envelope, _, proof = disclosing
    document = json.loads(proof)

    def checked(change: dict[str, Any]) -> tuple[str, str]:
        raw = json.dumps(document | change).encode()
        return disclosure.check_proof_file(raw, envelope.decision, ROOTS, ordered=True)

    digest = document["decision_digest"]
    other_digest = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    assert checked({"decision_digest": other_digest}) == (
        "fail",
        "PROOF.REPORT.MISMATCH: the decision digest, the root, or the size differs from the report.",
    )
    key = document["key"]
    assert checked({"index": document["index"] + 1 if document["size"] > 1 else 0, "path": ["0" * 64]}) == (
        "fail",
        f"PROOF.PATH.INVALID: the path does not lead from the leaf {key!r} to the root of the report.",
    )


def test_the_detail_of_a_passing_proof_names_the_kind_of_leaf_and_its_verdict(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes],
) -> None:
    """Kills:
    dppce.evidence.disclosure.x_check_proof_file__mutmut_29, 30, 31, 32, 34, 35
    """
    envelope, opening, proof = disclosing
    decision = envelope.decision
    detail = disclosure.check_proof_file(proof, decision, ROOTS, ordered=True)[1]
    assert detail.startswith(
        "PROOF.LEAF.OK: the results tree of the report holds the result 'T:TP-001' at index "
    )
    assert detail.endswith(f", with the verdict {decision.test_results[0].verdict.value}.")
    committed = json.loads(opening)["proof"]
    detail = disclosure.check_proof_file(json.dumps(committed).encode(), decision, ROOTS, ordered=True)[1]
    assert (
        detail
        == "PROOF.LEAF.OK: the records tree of the report holds the commitment 'r0001' at index 0 of 1."
    )


def test_an_opening_with_a_bad_salt_or_a_wrong_plaintext_or_too_long_says_which(
    disclosing: tuple[EvidenceEnvelope, bytes, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kills:
    dppce.evidence.disclosure.x_check_opening_file__mutmut_5, 12, 13, 28, 33, 34, 58, 63, 64, 73, 74
    """
    envelope, opening, _ = disclosing
    decision = envelope.decision

    def checked(raw: bytes) -> tuple[str, str]:
        return disclosure.check_opening_file(raw, decision, ROOTS, ordered=True)

    document = json.loads(opening)
    assert checked(opening) == (
        "pass",
        "OPENING.RECORD.OK: the record 'r0001' opens its commitment, and the records tree of the report "
        "holds that commitment.",
    )
    # The last character of a 32 byte salt carries two bits that no byte uses. Another character
    # with the same byte value is another spelling of one salt.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    salt = document["salt"]
    spare = salt[-2]
    other = alphabet[(alphabet.index(spare) ^ 1)]
    respelled = document | {"salt": salt[:-2] + other + salt[-1]}
    assert checked(json.dumps(respelled).encode()) == (
        "fail",
        "OPENING.FILE.MALFORMED: the salt is not the canonical base64 of 32 bytes.",
    )
    forged = json.loads(opening)
    forged["record"]["body"] = "AA=="
    assert checked(json.dumps(forged).encode()) == (
        "fail",
        "OPENING.COMMITMENT.MISMATCH: the salt and the plaintext do not give the commitment of the proof.",
    )
    monkeypatch.setattr(disclosure, "MAX_OPENING_BYTES", 10)
    assert checked(opening) == ("fail", "OPENING.FILE.TOO_LARGE: the file is larger than 10 bytes.")


def test_a_body_of_the_same_version_is_returned_as_it_is_and_an_older_layout_drops_the_fields() -> None:
    """A /2 body asked for in the /2 layout is the same object. The /1 layout has no bound_files.

    Kills:
    dppce.evidence.envelope.x_in_layout_of__mutmut_1, 10, 11, 12, 13, 14
    """
    v3 = make_envelope().decision
    v2 = in_layout_of(v3, "dppce.decision/2")
    assert v2.schema_version == "dppce.decision/2"
    assert in_layout_of(v2, "dppce.decision/2") is v2
    assert v2.manifest.bound_files == {}
    v1 = in_layout_of(v3, "dppce.decision/1")
    assert v1.schema_version == "dppce.decision/1"
    assert v1.manifest.bound_files is None


# -- evidence: report status lists ---------------------------------------------------------------


def _gzip_list(size: int, *, wbits: int = 31) -> str:
    packer = zlib.compressobj(wbits=wbits)
    data = packer.compress(b"\x01" * size) + packer.flush()
    return "u" + base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _error_of(call: Callable[..., Any], *args: Any) -> tuple[str, str]:
    with pytest.raises(StatusError) as caught:
        call(*args)
    return caught.value.code, str(caught.value)


def test_encode_list_sets_every_bit_of_a_byte() -> None:
    """Two bits of one byte are both set.

    Kills:
    dppce.evidence.status.x_encode_list__mutmut_17
    """
    assert decode_list(encode_list({0, 1, 7}))[0] == 0b11000001


def test_a_list_size_that_is_not_a_multiple_of_eight_is_refused() -> None:
    """Kills:
    dppce.evidence.status.x_encode_list__mutmut_6
    """
    with pytest.raises(ValueError, match=r"^the number of bits of a status list is a multiple of 8$"):
        encode_list(set(), MIN_BITS + 1)


def test_decode_list_asks_for_one_byte_more_than_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap on the output is what stops a GZIP bomb. The decoder asks for the limit plus one byte.

    Kills:
    dppce.evidence.status.x_decode_list__mutmut_36, 38
    """
    asked: list[int] = []
    real = zlib.decompressobj

    class Spy:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._inner = real(*args, **kwargs)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            asked.append(max_length)
            return self._inner.decompress(data, max_length)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    monkeypatch.setattr(zlib, "decompressobj", Spy)
    decode_list(encode_list({1}))
    assert asked == [MAX_BITSTRING_BYTES + 1]


def test_decode_list_refuses_each_kind_of_bad_list_with_its_own_message() -> None:
    """Kills:
    dppce.evidence.status.xǁStatusErrorǁ__init____mutmut_1
    dppce.evidence.status.x_decode_list__mutmut_4, 9, 10, 22, 27, 28, 31, 40, 45, 46, 47, 61, 66, 67, 68
    """
    malformed = "STATUSLIST.FILE.MALFORMED"
    assert _error_of(decode_list, "u!") == (malformed, "the list is not base64url after the prefix 'u'")
    assert _error_of(decode_list, "uA") == (malformed, "the list is not base64url")
    assert _error_of(decode_list, "uAAA") == (malformed, "the list is not GZIP data")
    # A zlib stream is not a GZIP stream.
    assert _error_of(decode_list, _gzip_list(16384, wbits=15)) == (malformed, "the list is not GZIP data")
    complete = _gzip_list(20000)
    data = base64.urlsafe_b64decode(complete[1:] + "=" * (-len(complete[1:]) % 4))
    for broken in (data[:-4], data + b"x"):
        text = "u" + base64.urlsafe_b64encode(broken).rstrip(b"=").decode("ascii")
        assert _error_of(decode_list, text) == (malformed, "the list is not one complete GZIP stream of bits")


def test_a_list_of_exactly_the_limit_is_read_and_a_longer_one_is_refused() -> None:
    """Kills:
    dppce.evidence.status.x_decode_list__mutmut_37, 49, 51
    """
    assert len(decode_list(_gzip_list(MAX_BITSTRING_BYTES))) == MAX_BITSTRING_BYTES
    assert _error_of(decode_list, _gzip_list(MAX_BITSTRING_BYTES + 1)) == (
        "STATUSLIST.FILE.TOO_LARGE",
        f"the list expands to more than {MAX_BITSTRING_BYTES} bytes",
    )


def test_an_index_outside_the_list_names_the_index_and_the_size() -> None:
    """Kills:
    dppce.evidence.status.x_bit_is_set__mutmut_8, 13, 14
    """
    assert _error_of(bit_is_set, b"\x00", 8) == (
        "STATUSLIST.INDEX.OUT_OF_RANGE",
        "index 8 is outside a list of 8 bits",
    )


def test_a_status_list_file_is_read_at_its_limit_and_refused_with_the_reason(trust: TrustBundle) -> None:
    """Kills:
    dppce.evidence.status.x_read_status_list__mutmut_1, 3, 15, 20, 21, 22, 32, 41, 61, 74, 81
    dppce.evidence.status.x_read_status_list__mutmut_91, 96, 97, 100, 105, 106
    dppce.evidence.status.x_read_status_list__mutmut_54, 55
    """
    key = _status_key(STATUS_SIGNER, ("status",))
    bundle = trust.model_copy(update={"keys": (*trust.keys, key)})

    def read(raw: bytes, at: datetime = AT, keys: TrustBundle = bundle) -> tuple[str, str]:
        return _error_of(read_status_list, raw, keys, at)

    not_a_jws = "the file is not one compact JWS in ASCII"
    assert read(b"A" * MAX_TOKEN_BYTES) == ("STATUSLIST.FILE.MALFORMED", not_a_jws)
    assert read(b"\xff") == ("STATUSLIST.FILE.MALFORMED", not_a_jws)
    assert read(b"A" * (MAX_TOKEN_BYTES + 1)) == (
        "STATUSLIST.FILE.TOO_LARGE",
        f"the file is larger than {MAX_TOKEN_BYTES} bytes",
    )
    canonical = canonical_bytes({"a": 1})
    signed = sign_compact(canonical, STATUS_SIGNER, typ=STATUS_LIST_TYP).encode("ascii")
    stranger = LocalSigner.generate("TEST-ONLY-status-key-9")
    unknown = sign_compact(canonical, stranger, typ=STATUS_LIST_TYP).encode("ascii")
    assert read(unknown) == (
        "STATUSLIST.KEY.UNKNOWN",
        "key 'TEST-ONLY-status-key-9' of the list is not in the trust bundle",
    )
    without_purpose = trust.model_copy(
        update={"keys": (*trust.keys, _status_key(STATUS_SIGNER, ("report",)))}
    )
    assert read(signed, keys=without_purpose) == (
        "STATUSLIST.KEY.PURPOSE",
        "key 'TEST-ONLY-status-key-1' does not have the purpose 'status'",
    )
    # The first and the last instant of the validity period of the key are inside it.
    for edge in ("not_before", "not_after"):
        edged = trust.model_copy(
            update={"keys": (*trust.keys, key.model_copy(update={edge: "2026-10-14T00:00:00Z"}))}
        )
        assert read(signed, keys=edged) == (
            "STATUSLIST.FILE.MALFORMED",
            "the payload is not dppce.statuslist/1",
        )
    late = datetime(2027, 1, 2, tzinfo=UTC)
    assert read(signed, at=late) == (
        "STATUSLIST.KEY.NOT_TRUSTED",
        "key 'TEST-ONLY-status-key-1' is outside its validity or revoked at the evaluation time",
    )
    other_type = sign_compact(canonical, STATUS_SIGNER, typ="other").encode("ascii")
    assert read(other_type) == (
        "STATUSLIST.SIGNATURE.INVALID",
        "the signature of the list does not verify: type 'other' is not 'dppce-status-list+jws'",
    )
    huge = sign_compact(b"x" * (MAX_PAYLOAD_BYTES + 1), STATUS_SIGNER, typ=STATUS_LIST_TYP).encode("ascii")
    assert read(huge) == (
        "STATUSLIST.FILE.TOO_LARGE",
        "the signature of the list does not verify: the token is larger than this engine accepts",
    )
    valid = StatusList(
        schema_version="dppce.statuslist/1",
        id=LIST_ID,
        status_purpose="revocation",
        issued_at=ISSUED_AT,
        encoded_list=encode_list(set()),
    )
    spaced = json.dumps(json.loads(canonical_bytes(valid)), indent=1).encode()
    loose = sign_compact(spaced, STATUS_SIGNER, typ=STATUS_LIST_TYP).encode("ascii")
    assert read(loose) == ("STATUSLIST.FILE.MALFORMED", "the payload is not in its canonical form")


# -- evidence: timestamps -------------------------------------------------------------------------

AUTHORITY = "the TSA certificate has no path to a timestamp anchor"
ONLY_PURPOSE = "the TSA certificate does not have time stamping as its only critical purpose"
NOT_DER = "the token is not a DER TimeStampToken"
TOKEN_DETAILS = {
    "wrong imprint": (
        "TIMESTAMP.IMPRINT.MISMATCH: token 0: the imprint is not that of a signature that verifies"
    ),
    "no timestamp anchor": f"TIMESTAMP.TSA.UNTRUSTED: token 0: {AUTHORITY}",
    "the CA only in the passport anchors": f"TIMESTAMP.TSA.UNTRUSTED: token 0: {AUTHORITY}",
    "EKU serverAuth": f"TIMESTAMP.TSA.EKU: token 0: {ONLY_PURPOSE}",
    "no EKU": f"TIMESTAMP.TSA.EKU: token 0: {ONLY_PURPOSE}",
    "non-critical EKU": f"TIMESTAMP.TSA.EKU: token 0: {ONLY_PURPOSE}",
    "two purposes": f"TIMESTAMP.TSA.EKU: token 0: {ONLY_PURPOSE}",
    "no digital signature usage": (
        "TIMESTAMP.TSA.KEY_USAGE: token 0: the key usage of the TSA certificate does not permit signing"
    ),
    "flipped signature byte": (
        "TIMESTAMP.CMS.SIGNATURE_INVALID: token 0: the signature of the token does not verify"
    ),
    "TSTInfo changed after signing": (
        "TIMESTAMP.CMS.SIGNATURE_INVALID: token 0: the content type or the message digest does not verify"
    ),
    "genTime after the evaluation time": (
        "TIMESTAMP.TIME.FUTURE: token 0: genTime 2026-10-15T00:00:00Z is after the evaluation time"
    ),
    "genTime half a second after the evaluation time": (
        "TIMESTAMP.TIME.FUTURE: token 0: genTime 2026-10-14T00:00:00.500000Z is after the evaluation time"
    ),
    "sha512 imprint": "TIMESTAMP.IMPRINT.ALGORITHM: token 0: the imprint does not use SHA-256",
    "not base64": "TIMESTAMP.TOKEN.MALFORMED: token 0: the token is not standard base64",
    "random DER": f"TIMESTAMP.TOKEN.MALFORMED: token 0: {NOT_DER} (ValueError)",
    "a certificate that does not load": f"TIMESTAMP.TOKEN.MALFORMED: token 0: {NOT_DER} (ValueError)",
    "a signer certificate with an invalid X.509 version": (
        f"TIMESTAMP.TOKEN.MALFORMED: token 0: {NOT_DER} (InvalidVersion)"
    ),
    "a TSA certificate with a repeated extension": f"TIMESTAMP.TSA.EKU: token 0: {ONLY_PURPOSE}",
    "six certificates": "TIMESTAMP.TOKEN.TOO_LARGE: token 0: the token holds more than 5 certificates",
    "a critical TSTInfo extension": (
        "TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION: token 0: the TSTInfo has a critical extension"
    ),
    "no ESS attribute": (
        "TIMESTAMP.CMS.SIGNING_CERT: token 0: the signing certificate attribute does not identify "
        "the TSA certificate"
    ),
    "the signer certificate is absent": (
        "TIMESTAMP.TSA.UNKNOWN: token 0: no certificate matches the signer of the token"
    ),
    "expired at genTime": (
        "TIMESTAMP.TSA.EXPIRED: token 0: a certificate of the TSA path is not valid at 2026-10-13T12:06:00Z"
    ),
    "genTime 0.9 s after not_after": (
        "TIMESTAMP.TSA.EXPIRED: token 0: a certificate of the TSA path is not valid at "
        "2026-10-13T12:06:00.900000Z"
    ),
    "revoked under its issuer": (
        "TIMESTAMP.TSA.REVOKED: token 0: a certificate of the TSA path is revoked at 2026-10-13T12:06:00Z"
    ),
    "Ed25519 key": "TIMESTAMP.CMS.UNSUPPORTED: token 0: the CMS signer is outside the timestamp profile",
    "Ed25519 key declared as ECDSA": (
        "TIMESTAMP.CMS.UNSUPPORTED: token 0: the TSA key is outside the timestamp profile"
    ),
    "a combined signature OID that names another hash": (
        "TIMESTAMP.CMS.UNSUPPORTED: token 0: the CMS signer is outside the timestamp profile"
    ),
    "17 tokens": "TIMESTAMP.EVIDENCE.TOO_MANY: the envelope holds 17 tokens; the limit is 16.",
    "a token of MAX_TOKEN_BYTES + 1 bytes": (
        "TIMESTAMP.TOKEN.TOO_LARGE: token 0: the token is larger than 65536 bytes"
    ),
    "text of MAX_TOKEN_TEXT + 1 characters": (
        "TIMESTAMP.TOKEN.TOO_LARGE: token 0: the token is longer than 87384 characters"
    ),
}


@pytest.fixture(scope="module")
def tsa() -> Tsa:
    authority = tsa_ca()
    return Tsa(authority, tsa_cert(authority))


@pytest.mark.parametrize("name", list(FAULTS))
def test_each_fault_of_a_timestamp_token_gives_its_detail(
    name: str, signed: EvidenceEnvelope, trust: TrustBundle, tsa: Tsa
) -> None:
    """The detail is what the reader of the verification report sees.

    Kills:
    dppce.evidence.timestamp.xǁTimestampErrorǁ__init____mutmut_1
    dppce.evidence.timestamp.x__malformed__mutmut_2
    dppce.evidence.timestamp.x_parse_token__mutmut_86, 117, 118
    dppce.evidence.timestamp.x__check_cms__mutmut_27, 32, 33, 34, 59, 64, 65, 66, 75, 80, 81, 100, 105, 106
    dppce.evidence.timestamp.x__check_tsa__mutmut_16, 21, 22, 23, 34, 39, 40, 41
    dppce.evidence.timestamp.x_verify_token__mutmut_3, 14, 15, 16, 19, 27, 32, 33, 34, 45, 50, 51, 52
    dppce.evidence.timestamp.x_verify_token__mutmut_74, 79, 80, 92, 97, 98, 99, 102, 107, 108, 123, 128
    dppce.evidence.timestamp.x_verify_token__mutmut_129, 130, 142, 153, 166
    """
    build, _ = FAULTS[name]
    tokens, bundle, at = build(signed, trust, tsa)
    report = check(with_tokens(signed, *tokens), bundle.model_copy(update={"require_timestamp": True}), at)
    assert dim(report, "timestamp") == ("fail", TOKEN_DETAILS[name])


# -- authorization -------------------------------------------------------------------------------


def test_each_refusal_of_an_authorization_gives_its_code_and_its_message(
    signer: LocalSigner, trust: TrustBundle
) -> None:
    """The CLI shows the message to the operator, who decides what to correct.

    Kills:
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_8, 13, 25, 41, 68, 73
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_84, 89, 90, 91, 94, 99, 100, 101
    dppce.infrastructure.authorization.x_validate_authorization__mutmut_108, 113, 114, 115
    """
    at = datetime(2026, 10, 14, tzinfo=UTC)
    origin = "http://127.0.0.1:1"
    token = issue_authorization(_authorization(origin), signer)

    def refused(text: str, **changes: Any) -> tuple[str, str]:
        arguments: dict[str, Any] = {"trust": trust, "at": at, "sut_identifier": "urn:example:sut"}
        with pytest.raises(AuthorizationError) as caught:
            validate_authorization(text, **(arguments | changes))
        return caught.value.code, str(caught.value)

    assert validate_authorization(token, trust, at, "urn:example:sut").sut_identifier == "urn:example:sut"
    assert refused("x") == ("AUTHZ.MALFORMED", "a compact JWS is three base64url parts")
    stranger = LocalSigner.generate("TEST-ONLY-unknown-key")
    assert refused(issue_authorization(_authorization(origin), stranger)) == (
        "AUTHZ.ISSUER.UNTRUSTED",
        "Key 'TEST-ONLY-unknown-key' is not trusted to authorize tests.",
    )
    assert refused(token, at=datetime(2028, 1, 1, tzinfo=UTC)) == (
        "AUTHZ.ISSUER.KEY_NOT_VALID",
        f"Key '{KID}' is revoked or outside its validity.",
    )
    head, body, _ = token.split(".")
    assert refused(f"{head}.{body}.{_b64(bytes(64))}") == (
        "AUTHZ.SIGNATURE.INVALID",
        "the signature does not verify",
    )
    assert refused(issue_authorization(_authorization(origin, issuer="urn:example:other"), signer)) == (
        "AUTHZ.ISSUER.MISMATCH",
        "The authorization names a different issuer than the key.",
    )
    assert refused(token, sut_identifier="urn:example:other-sut") == (
        "AUTHZ.SUT.MISMATCH",
        "The authorization is for a different system under test.",
    )
    assert refused(token, at=datetime(2026, 11, 15, tzinfo=UTC)) == (
        "AUTHZ.EXPIRED",
        "The authorization is not valid at the evaluation time.",
    )


# -- evidence: certificate paths, the Merkle tree, and strict JSON ---------------------------------


def _certificate(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    *extensions: tuple[x509.ExtensionType, bool],
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1))
        .not_valid_after(datetime(2027, 1, 1))
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return builder.sign(signer, hashes.SHA256())


def test_a_path_with_a_constraint_that_the_engine_cannot_evaluate_says_which(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kills:
    dppce.evidence.x509path.x_path_gap__mutmut_4, 5, 6, 7, 8, 9, 12, 13, 14
    """
    key = ec.generate_private_key(ec.SECP256R1())
    plain = _certificate("TEST-ONLY-plain", key, "TEST-ONLY-plain", key)
    assert path_gap([plain]) is None
    constrained = _certificate(
        "TEST-ONLY-constrained",
        key,
        "TEST-ONLY-constrained",
        key,
        (
            x509.NameConstraints(permitted_subtrees=[x509.DNSName("example.test")], excluded_subtrees=None),
            False,
        ),
    )
    assert path_gap([plain, constrained]) == (
        "A certificate of the chain has NameConstraints, which this engine does not evaluate."
    )
    critical = _certificate(
        "TEST-ONLY-critical",
        key,
        "TEST-ONLY-critical",
        key,
        (x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), True),
    )
    assert path_gap([critical]) == (
        "A certificate of the chain has a critical extension that this engine does not evaluate."
    )
    monkeypatch.setattr(x509path, "extensions", lambda certificate: None)
    assert path_gap([plain]) == "A certificate of the chain has extensions that this engine cannot read."


def _authority(
    name: str, key: ec.EllipticCurvePrivateKey, parent: str, parent_key: ec.EllipticCurvePrivateKey
) -> Any:
    return _certificate(
        name,
        key,
        parent,
        parent_key,
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (x509.KeyUsage(*[name_ == "key_cert_sign" for name_ in _USAGES]), True),
    )


_USAGES = (
    "digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
    "key_cert_sign", "crl_sign", "encipher_only", "decipher_only",
)  # fmt: skip


def _chain(intermediates: int) -> tuple[x509.Certificate, list[x509.Certificate], TrustAnchor]:
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(intermediates + 2)]
    names = [f"TEST-ONLY-ca-{i}" for i in range(intermediates + 1)]
    root = _authority(names[0], keys[0], names[0], keys[0])
    authorities = [
        _authority(names[i], keys[i], names[i - 1], keys[i - 1]) for i in range(1, intermediates + 1)
    ]
    leaf = _certificate("TEST-ONLY-leaf", keys[-1], names[-1], keys[intermediates])
    pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return leaf, authorities, TrustAnchor(name="TEST-ONLY-root", certificate_pem=pem)


def test_a_path_may_hold_five_authorities_below_the_anchor_and_not_six() -> None:
    """The leaf, then the intermediates, then the anchor: MAX_CHAIN is the number below the anchor.

    Kills:
    dppce.evidence.x509path.x_trust_path__mutmut_12
    """
    leaf, authorities, anchor = _chain(MAX_CHAIN - 1)
    path = trust_path(leaf, authorities, [anchor])
    assert path is not None
    assert len(path) == MAX_CHAIN + 1
    leaf, authorities, anchor = _chain(MAX_CHAIN)
    assert trust_path(leaf, authorities, [anchor]) is None


def test_the_merkle_tree_refuses_an_index_that_equals_the_size() -> None:
    """Kills:
    dppce.evidence.merkle.x_inclusion_proof__mutmut_5, 6, 7
    dppce.evidence.merkle.x_verify_inclusion__mutmut_4
    """
    with pytest.raises(IndexError, match=r"^leaf index is outside the tree$"):
        merkle.inclusion_proof("results", [b"a", b"b"], 2)
    # A one-leaf tree: its root is the hash of the leaf. Index 1 is not in it.
    only = merkle.root("results", [b"a"])
    assert merkle.verify_inclusion("results", b"a", index=0, size=1, proof=[], expected_root=only)
    assert not merkle.verify_inclusion("results", b"a", index=1, size=1, proof=[], expected_root=only)


def test_a_constant_that_is_not_json_is_named() -> None:
    """Kills:
    dppce.evidence.canonical.x__reject_constant__mutmut_1
    """
    with pytest.raises(CanonicalizationError, match=r"^NaN is not JSON$"):
        parse_strict(b"NaN")


# -- evidence: manual results ---------------------------------------------------------------------

REFUSED = "The manual result is refused: "
MANUAL_MESSAGES = {
    "another-purpose": REFUSED + "The result names a different test purpose.",
    "another-sut": REFUSED + "The result names a different system under test.",
    "untrusted-kid": REFUSED + "No key of the trust bundle signs manual results.",
    "report-purpose-key": REFUSED + "No key of the trust bundle signs manual results.",
    "expired-key": REFUSED + "The key is revoked or not valid at the evaluation time.",
    "revoked-kid": REFUSED + "The key is revoked or not valid at the evaluation time.",
    "performed-before-the-key-was-valid": REFUSED + "The review is outside the validity period of the key.",
    "digest-of-another-method": REFUSED + "The result answers a different version of the test purpose.",
    "version-that-the-ics-does-not-declare": REFUSED
    + "The result does not name the SUT version that the ICS declares.",
    "performed-after-evaluation": REFUSED + "The review is later than the evaluation time.",
    "impossible-date": REFUSED + "The payload is not a canonical manual result.",
    "alg-none": REFUSED + "The algorithm is not on the allowlist.",
    "empty-signature": REFUSED + "The signature does not verify with the trusted key.",
    "tampered-payload": REFUSED + "The signature does not verify with the trusted key.",
    "attestation-typ": REFUSED + "The header is not that of a manual result.",
    "x5c-header": REFUSED + "The header is not that of a manual result.",
    "wrong-typ-and-bad-signature": REFUSED + "The header is not that of a manual result.",
    "non-canonical-payload": REFUSED + "The payload is not a canonical manual result.",
    "payload-without-outcome": REFUSED + "The payload is not a canonical manual result.",
}


@pytest.mark.parametrize(
    ("body", "error", "trust", "code", "message"),
    [(*refusal[1:], MANUAL_MESSAGES[refusal[0]]) for refusal in REFUSALS if refusal[0] in MANUAL_MESSAGES],
    ids=[refusal[0] for refusal in REFUSALS if refusal[0] in MANUAL_MESSAGES],
)
def test_each_refusal_of_a_manual_result_gives_its_message(
    body: Callable[[], bytes], error: Any, trust: TrustBundle, code: str, message: str
) -> None:
    """The message is part of the test result, so it is part of the decision digest.

    Kills:
    dppce.evidence.manual.xǁManualResultErrorǁ__init____mutmut_1
    dppce.evidence.manual.x__trusted_key__mutmut_14, 19, 20, 21, 36, 41, 42, 43
    dppce.evidence.manual.x_verify_manual_result__mutmut_19, 24, 25, 26, 31, 36, 37, 38, 61, 64, 65, 66
    dppce.evidence.manual.x_verify_manual_result__mutmut_78, 83, 84, 85, 88, 93, 94, 95
    dppce.evidence.manual.x_verify_manual_result__mutmut_98, 103, 104, 105, 108, 113, 114, 115
    dppce.evidence.manual.x_verify_manual_result__mutmut_119, 124, 125, 126, 129, 134, 135
    dppce.evidence.manual.x_verify_manual_result__mutmut_136, 143, 148, 149, 150
    """
    refused = run_check(body(), error=error, trust=trust)
    assert (refused.reason_code, refused.message) == (code, message)


def _verify_manual(token: str, trust: TrustBundle, **changes: Any) -> tuple[ManualResult, TrustedKey]:
    arguments: dict[str, Any] = {
        "test_purpose_id": "T-MAN",
        "test_purpose_digest": PURPOSE_DIGEST,
        "sut": core_builders.ics().sut,
        "evaluation_time": datetime(2026, 10, 14, tzinfo=UTC),
        "key_valid_at": datetime(2026, 10, 13, 8, 0, tzinfo=UTC),
    }
    return verify_manual_result(token, trust, **(arguments | changes))


def _manual_refusal(token: str, trust: TrustBundle, **changes: Any) -> tuple[str, str]:
    with pytest.raises(ManualResultError) as caught:
        _verify_manual(token, trust, **changes)
    assert str(caught.value) == str(caught.value.args[0])
    return caught.value.code, str(caught.value)


def test_a_manual_result_that_is_not_a_jws_or_is_signed_with_a_bad_part_says_which() -> None:
    """Kills:
    dppce.evidence.manual.x_verify_manual_result__mutmut_3, 4, 5, 6, 7, 8, 9, 10, 11
    dppce.evidence.manual.x_verify_manual_result__mutmut_55, 57, 58, 59
    """
    assert _manual_refusal("a.b.c", UNIT_TRUST) == (
        "MANUAL.RESULT.MALFORMED",
        "The text is not a compact JWS.",
    )
    parts = _token().decode("ascii").split(".")
    # A payload part that cannot be decoded is a malformed result, not a bad signature.
    assert _manual_refusal(".".join([parts[0], "A", parts[2]]), UNIT_TRUST) == (
        "MANUAL.RESULT.MALFORMED",
        "The signature does not verify with the trusted key.",
    )


def test_the_first_and_the_last_instant_are_inside_the_validity_of_a_key_and_a_result() -> None:
    """The key, the performing time, and the evaluation time may equal their limits.

    Kills:
    dppce.evidence.manual.x__trusted_key__mutmut_24, 25
    dppce.evidence.manual.x_verify_manual_result__mutmut_127, 139, 140
    """
    token = _token().decode("ascii")
    performed = datetime(2026, 10, 13, 8, 0, tzinfo=UTC)  # the performed_at of the result
    one_instant = _manual_key(
        MANUAL, ("manual",), not_before="2026-10-13T08:00:00Z", not_after="2026-10-13T08:00:00Z"
    )
    trust = UNIT_TRUST.model_copy(update={"keys": (one_instant,)})
    result_, key = _verify_manual(token, trust, evaluation_time=performed, key_valid_at=performed)
    assert (result_.test_purpose_id, key.kid) == ("T-MAN", MANUAL.key_id)


def test_a_key_with_a_stamp_that_is_no_time_is_not_valid() -> None:
    """Kills:
    dppce.evidence.manual.x__trusted_key__mutmut_28
    """
    broken = UNIT_TRUST.keys[0].model_copy(update={"not_before": "yesterday"})
    trust = UNIT_TRUST.model_copy(update={"keys": (broken,)})
    assert _manual_refusal(_token().decode("ascii"), trust) == (
        "MANUAL.KEY.NOT_VALID",
        "The key is revoked or not valid at the evaluation time.",
    )


def test_the_purpose_that_a_result_claims_is_read_without_verifying_it() -> None:
    """Kills:
    dppce.evidence.manual.x_claimed_test_purpose__mutmut_18, 19, 20, 23, 24, 25, 26, 27
    dppce.evidence.manual.x_claimed_test_purpose__mutmut_30, 35, 36, 37, 38, 39, 40, 41, 42, 43
    """
    assert claimed_test_purpose(_token().decode("ascii")) == "T-MAN"
    malformed = "MANUAL.RESULT.MALFORMED"

    def claim(token: str) -> tuple[str, str]:
        with pytest.raises(ManualResultError) as caught:
            claimed_test_purpose(token)
        return caught.value.code, str(caught.value)

    assert claim("not a token") == (malformed, "The text is not a compact JWS.")
    for payload in ({}, [1], {"test_purpose_id": 5}):
        assert claim(f"e30.{_part(payload)}.AAAA") == (malformed, "The payload names no test purpose.")
    # A payload text whose length needs two padding characters, and is a multiple of five: the
    # padding is the amount that makes a multiple of four, not of five.
    for size in range(1, 40):
        named = "T" * size
        part = _part({"test_purpose_id": named})
        if len(part) % 4 == 2 and len(part) % 5 == 0:
            assert claimed_test_purpose(f"e30.{part}.AAAA") == named
            break
    else:
        pytest.fail("no payload length needs two padding characters and is a multiple of five")


# -- evidence: recordings -------------------------------------------------------------------------


class _Keys:
    def data_key(self, key_id: str) -> bytes:
        return bytes(range(32))

    def default_key_id(self) -> str:
        return "TEST-ONLY-data-key"


def _recording(path: Path, records: int = 1) -> None:
    write_recording(
        path,
        [make_record(i + 1) for i in range(records)],
        _Keys(),
        created=date(2026, 1, 1),
        retention_days=30,
    )


TODAY = date(2026, 10, 13)


def _reseal(path: Path, record_id: str, plaintext: bytes) -> None:
    """Replace one record by another that authenticates with the data key, as its owner could."""
    nonce = bytes(12)
    sealed = nonce + AESGCM(bytes(range(32))).encrypt(nonce, plaintext, _aad(record_id))
    (path / "records" / f"{record_id}.enc").write_bytes(sealed)


def _failure(call: Callable[..., Any], *args: Any) -> str:
    with pytest.raises(RecordingError) as caught:
        call(*args)
    return str(caught.value)


def test_a_record_form_refuses_a_non_canonical_base64_text_and_a_wrong_hop_list() -> None:
    """Kills:
    dppce.evidence.recording.x_record_from_json__mutmut_54, 56, 59, 70, 72, 75
    dppce.evidence.recording.x__hop_statuses__mutmut_11, 12, 13, 20
    """
    data = record_to_json(make_record(1), with_salt=True)
    assert record_from_json(data).record_id == "r0001"
    for name in ("body", "salt"):
        assert _failure(record_from_json, data | {name: data[name] + "\n"}).startswith(
            "a record is malformed: "
        )
    lone = data | {"redirects": ["http://h/x"]}
    assert _failure(record_from_json, lone | {"redirect_statuses": [200]}) == (
        f"a record is malformed: each redirect status must be one of {REDIRECT_STATUSES}"
    )
    assert _failure(record_from_json, lone | {"redirect_statuses": []}) == (
        "a record is malformed: redirect_statuses must hold one status for each redirect target"
    )


def test_a_damaged_recording_says_where_and_what(tmp_path: Path) -> None:
    """Kills:
    dppce.evidence.recording.x_read_index__mutmut_2
    dppce.evidence.recording.x_read_recording__mutmut_11
    dppce.evidence.recording.x__verified_index_from__mutmut_3, 8, 13, 20, 21
    dppce.evidence.recording.x__open__mutmut_1, 2, 3
    dppce.evidence.recording.x__records_from__mutmut_7, 15, 24, 25, 33
    """
    absent = tmp_path / "absent"
    assert _failure(read_index, absent) == f"{absent}: the recording index is missing or not valid"
    assert (
        _failure(read_recording, absent, _Keys()) == f"{absent}: the recording index is missing or not valid"
    )

    unsealed = tmp_path / "unsealed"
    _recording(unsealed)
    (unsealed / "recording.sealed").unlink()
    assert _failure(read_recording, unsealed, _Keys()) == f"{unsealed}: the sealed index is missing"

    short = tmp_path / "short"
    _recording(short)
    (short / "recording.sealed").write_bytes(b"12345")
    assert _failure(read_recording, short, _Keys()) == "the sealed index: too short to be a sealed file"
    (short / "recording.sealed").write_bytes(bytes(28))
    assert _failure(read_recording, short, _Keys()) == "the sealed index: missing or does not authenticate"

    damaged = tmp_path / "damaged"
    _recording(damaged)
    original = (damaged / "records" / "r0001.enc").read_bytes()
    (damaged / "records" / "r0001.enc").write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    assert _failure(read_recording, damaged, _Keys()) == "r0001: missing or does not authenticate"

    garbage = tmp_path / "garbage"
    _recording(garbage)
    _reseal(garbage, "r0001", b"{")
    assert _failure(read_recording, garbage, _Keys()) == "r0001: a record is malformed"

    named = tmp_path / "named"
    _recording(named)
    index = read_index(named).model_copy(
        update={"records": (RecordCommitment(record_id="r1/../x", commitment="0" * 64),)}
    )
    (named / "recording.json").write_bytes(canonical_bytes(index) + b"\n")
    (named / "recording.sealed").write_bytes(
        bytes(12) + AESGCM(bytes(range(32))).encrypt(bytes(12), canonical_bytes(index), _INDEX_AAD)
    )
    assert _failure(read_recording, named, _Keys()) == "record identifier 'r1/../x' is not valid"

    other = tmp_path / "other"
    _recording(other)
    changed = record_to_json(replace(make_record(1), body=b"another body"), with_salt=True)
    _reseal(other, "r0001", canonical_bytes(changed))
    assert _failure(read_recording, other, _Keys()) == "r0001: does not match the commitment in the index"


def test_a_purge_keeps_what_it_cannot_authenticate_and_says_why(tmp_path: Path) -> None:
    """Kills:
    dppce.evidence.recording.x__purge_one__mutmut_8
    dppce.evidence.recording.x__descriptor_reader__mutmut_2, 3, 22
    dppce.evidence.recording.x__is_only_a_recording__mutmut_14
    dppce.evidence.recording.x_purge_expired__mutmut_10
    """
    runs = tmp_path / "runs"
    _recording(runs / "unsealed")
    (runs / "unsealed" / "recording.sealed").unlink()
    # The records directory is a link to a copy: a link is never followed in a recording.
    _recording(runs / "linked-dir")
    copy = tmp_path / "copy"
    shutil.copytree(runs / "linked-dir" / "records", copy)
    shutil.rmtree(runs / "linked-dir" / "records")
    os.symlink(copy, runs / "linked-dir" / "records")
    # One record is a link to a copy of itself.
    _recording(runs / "linked-file")
    record = runs / "linked-file" / "records" / "r0001.enc"
    elsewhere = tmp_path / "r0001.enc"
    shutil.copy(record, elsewhere)
    record.unlink()
    os.symlink(elsewhere, record)
    # A recording with no record, and a records directory that is a link.
    _recording(runs / "empty", records=0)
    shutil.rmtree(runs / "empty" / "records")
    os.symlink(tmp_path / "copy", runs / "empty" / "records")
    result = purge_expired(runs, TODAY, _Keys())
    assert result.expired == ()
    reasons = {path.name: reason for path, reason in result.kept}
    assert reasons == {
        "unsealed": "not an authentic recording: unsealed: the sealed index is missing",
        "linked-dir": "not an authentic recording: r0001: missing or does not authenticate",
        "linked-file": "not an authentic recording: r0001: missing or does not authenticate",
        "empty": "holds files that are not part of the recording",
    }

    # A link to the directory that holds the recordings is followed: the operator named it.
    real = tmp_path / "real"
    _recording(real / "old")
    os.symlink(real, tmp_path / "root-link")
    assert purge_expired(tmp_path / "root-link", TODAY, _Keys()).expired == (tmp_path / "root-link" / "old",)


def test_the_last_step_of_a_purge_refuses_a_name_that_was_replaced(tmp_path: Path) -> None:
    """The directory that was checked and emptied is the one that is removed, not a link in its place.

    Kills:
    dppce.evidence.recording.x__delete_recording__mutmut_29, 30
    """
    root = tmp_path / "runs"
    _recording(root / "old")
    index = read_index(root / "old")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    directory_fd = os.open("old", os.O_RDONLY | os.O_DIRECTORY, dir_fd=root_fd)
    try:
        os.rename(root / "old", root / "moved")
        os.symlink(root / "moved", root / "old")
        with pytest.raises(OSError, match=r"^old was replaced during the purge; it is not removed$"):
            _delete_recording(root_fd, "old", directory_fd, index)
    finally:
        os.close(directory_fd)
        os.close(root_fd)


# -- evidence: JOSE profiles and public keys ------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _part(document: object) -> str:
    return _b64(json.dumps(document).encode())


def _refused(call: Callable[..., Any], *args: Any) -> tuple[str, str]:
    with pytest.raises(jose.JoseError) as caught:
        call(*args)
    # The text that Python shows for the exception is the message.
    assert str(caught.value) == caught.value.message
    return caught.value.code, caught.value.message


def _signature_with(header: dict[str, Any], protected: set[str]) -> jose.Signature:
    return jose.Signature(header=header, protected=frozenset(protected), signing_input=b"", value=b"")


HEADER_CASES = [
    ("jws", {}, set(), ("INTEGRITY.JOSE.MALFORMED", "The header names no algorithm.")),
    (
        "jws",
        {"alg": "none"},
        {"alg"},
        ("INTEGRITY.JOSE.ALGORITHM", "The header names an algorithm that every profile refuses (RFC 8725)."),
    ),
    (
        "jws",
        {"alg": "ES256", "crit": "b64"},
        {"alg", "crit"},
        ("INTEGRITY.JOSE.MALFORMED", "The member crit is not a list of protected header member names."),
    ),
    (
        "jws",
        {"alg": "ES256", "crit": ["x"], "x": 1},
        {"alg", "crit"},
        ("INTEGRITY.JOSE.MALFORMED", "The member crit is not a list of protected header member names."),
    ),
    (
        "jws",
        {"alg": "ES256", "crit": ["exp"], "exp": 1},
        {"alg", "crit", "exp"},
        ("INTEGRITY.JOSE.HEADER", "The token needs a header extension that the profile does not define."),
    ),
    (
        "jws",
        {"alg": "ES256", "b64": False},
        {"alg", "b64"},
        ("INTEGRITY.JOSE.MALFORMED", "The member b64 is not protected and named in crit."),
    ),
    (
        "jws",
        {"alg": "ES256", "crit": ["b64"], "b64": "no"},
        {"alg", "crit", "b64"},
        ("INTEGRITY.JOSE.MALFORMED", "The member b64 is not a boolean."),
    ),
    (
        "vc-jose",
        {"alg": "ES256", "crit": ["b64"], "b64": False},
        {"alg", "crit", "b64"},
        ("INTEGRITY.JOSE.HEADER", "A credential of the vc-jose profile has a base64url payload."),
    ),
    (
        "jws",
        {"alg": "ES256", "crit": ["b64"], "b64": False},
        {"alg", "crit", "b64"},
        ("INTEGRITY.JOSE.UNSUPPORTED", "This engine does not verify an unencoded payload (RFC 7797)."),
    ),
    (
        "vc-jose",
        {"alg": "ES256", "typ": "JWT"},
        {"alg", "typ"},
        ("INTEGRITY.JOSE.TYPE", "The header typ of a vc-jose credential is not vc+jwt."),
    ),
]


@pytest.mark.parametrize(("profile", "header", "protected", "refusal"), HEADER_CASES)
def test_each_header_rule_refuses_with_its_code_and_its_message(
    profile: Any, header: dict[str, Any], protected: set[str], refusal: tuple[str, str]
) -> None:
    """Kills:
    dppce.evidence.jose_profiles.xǁJoseErrorǁ__init____mutmut_1
    dppce.evidence.jose_profiles.x_check_header__mutmut_8, 13, 15, 18, 23, 24, 25, 41, 46, 47, 48
    dppce.evidence.jose_profiles.x_check_header__mutmut_55, 60, 61, 62, 76, 81, 82, 83, 86, 91, 92, 93
    dppce.evidence.jose_profiles.x_check_header__mutmut_102, 107, 108, 109, 116, 117, 118, 134
    """
    assert _refused(jose.check_header, _signature_with(header, protected), profile) == refusal


def test_a_vc_jose_typ_may_leave_out_the_media_type_prefix_and_the_case() -> None:
    """RFC 7515, section 4.1.9: the type is compared without case, and "application/" may be left out."""
    for typ in ("vc+jwt", "VC+JWT", "application/vc+jwt"):
        jose.check_header(_signature_with({"alg": "ES256", "typ": typ}, {"alg", "typ"}), "vc-jose")


def test_a_token_with_an_unprotected_header_only_is_read() -> None:
    """A flattened JWS may have a header and no protected header.

    Kills:
    dppce.evidence.jose_profiles.x__is_signature__mutmut_11, 12, 23
    dppce.evidence.jose_profiles.x__signature__mutmut_3
    dppce.evidence.jose_profiles.x_parse__mutmut_85, 87, 90
    """
    body = json.dumps({"payload": _part({"a": 1}), "header": {"alg": "ES256"}, "signature": "AAAA"}).encode()
    token = jose.parse(body)
    assert token.serialization == "flattened"
    assert token.signatures[0].header == {"alg": "ES256"}
    assert token.signatures[0].protected == frozenset()
    # The signing input of RFC 7515 is the (empty) protected header, a dot, and the payload.
    assert token.signatures[0].signing_input == f".{_part({'a': 1})}".encode()


def test_a_token_that_is_not_a_jws_is_refused_with_one_message() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x_parse__mutmut_43, 48, 49, 50, 56, 61, 62, 63
    dppce.evidence.jose_profiles.x_is_jws_json__mutmut_21, 22, 23, 24
    """
    neither = ("INTEGRITY.JOSE.MALFORMED", "The body is neither a compact JWS nor a JWS JSON serialization.")
    member = {"protected": _part({"alg": "ES256"}), "signature": "AAAA"}
    assert _refused(jose.parse, b"not a token") == neither
    assert _refused(jose.parse, b"[1]") == neither
    general = {"payload": _part({}), "signatures": [member]}
    assert jose.parse(json.dumps(general).encode()).serialization == "general"
    for top in ("signature", "protected", "header"):
        assert (
            _refused(
                jose.parse,
                json.dumps(general | {top: member.get(top, "AAAA") if top != "header" else {}}).encode(),
            )
            == neither
        )


def test_a_part_that_is_not_base64url_and_a_header_that_is_not_an_object_are_refused() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x__decode__mutmut_8, 9, 10, 11, 12, 13, 14, 15, 16
    dppce.evidence.jose_profiles.x__signature__mutmut_6, 11, 12, 13, 19, 24, 25, 26, 27, 28, 31, 36, 37, 38
    """
    assert _refused(jose.parse, f"{_part({'alg': 'ES256'})}.e30.A".encode()) == (
        "INTEGRITY.JOSE.MALFORMED",
        "A part of the token is not base64url.",
    )
    assert _refused(jose.parse, f"{_part([1])}.e30.AAAA".encode()) == (
        "INTEGRITY.JOSE.MALFORMED",
        "The protected header is not a JSON object.",
    )
    shared = {
        "payload": "e30",
        "protected": _part({"alg": "ES256"}),
        "header": {"alg": "ES384"},
        "signature": "AAAA",
    }
    assert _refused(jose.parse, json.dumps(shared).encode()) == (
        "INTEGRITY.JOSE.MALFORMED",
        "The protected and the unprotected header share a member name.",
    )
    critical = {
        "payload": "e30",
        "protected": _part({"alg": "ES256"}),
        "header": {"crit": ["b64"]},
        "signature": "AAAA",
    }
    assert _refused(jose.parse, json.dumps(critical).encode()) == (
        "INTEGRITY.JOSE.MALFORMED",
        "The member crit is in the unprotected header.",
    )


def test_a_token_of_exactly_the_body_limit_is_read() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x_parse__mutmut_1
    """
    head = f"{_part({'alg': 'ES256'})}."
    tail = ".AAAA"
    payload = "A" * (jose.MAX_BODY_BYTES - len(head) - len(tail))
    assert jose.parse(f"{head}{payload}{tail}".encode()).serialization == "compact"
    assert _refused(jose.parse, b"A" * (jose.MAX_BODY_BYTES + 1))[0] == "INTEGRITY.JOSE.TOO_LARGE"


def _p256_jwk(**changes: Any) -> dict[str, str]:
    jwk = LocalSigner.generate("TEST-ONLY-jose-key").public_jwk()
    return {**jwk, **changes}


def _jwk_with_short_x() -> dict[str, str]:
    """A valid P-256 point whose x coordinate has a leading zero byte, spelled in 31 bytes."""
    for _ in range(20000):
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        if numbers.x < 2**248:
            return {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64(numbers.x.to_bytes(31, "big")),
                "y": _b64(numbers.y.to_bytes(32, "big")),
            }
    pytest.fail("no P-256 key with a leading zero byte in x")


UNTRUSTED_KEY = (
    "INTEGRITY.JOSE.UNSUPPORTED",
    "The trusted key is not a public key that this engine verifies.",
)


def test_a_trusted_jwk_of_another_type_or_with_a_private_member_is_not_used() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x_public_key_from_jwk__mutmut_2, 3, 19, 38, 59, 94, 95, 96
    dppce.evidence.jose_profiles.x_public_key_from_jwk__mutmut_97, 101, 102, 106, 107, 108, 109, 110
    dppce.evidence.jose_profiles.x_public_key_from_jwk__mutmut_111, 112, 113, 114
    """
    good = _p256_jwk()
    assert jose.key_algorithm(jose.public_key_from_jwk(good)) == "ES256"
    assert _refused(jose.public_key_from_jwk, good | {"d": "AAAA"}) == UNTRUSTED_KEY
    assert _refused(jose.public_key_from_jwk, good | {"use": "enc"}) == UNTRUSTED_KEY
    # An EC point under another key type, and a curve that this engine does not know.
    assert _refused(jose.public_key_from_jwk, good | {"kty": "OKP"}) == UNTRUSTED_KEY
    assert _refused(jose.public_key_from_jwk, good | {"crv": "P-521"}) == UNTRUSTED_KEY
    assert (
        _refused(jose.public_key_from_jwk, {"kty": "OKP", "crv": "X25519", "x": _b64(bytes(32))})
        == UNTRUSTED_KEY
    )
    assert _refused(jose.public_key_from_jwk, _jwk_with_short_x()) == UNTRUSTED_KEY
    assert _refused(jose.public_key_from_jwk, good | {"alg": "ES384"}) == (
        "INTEGRITY.JOSE.UNSUPPORTED",
        "The trusted key names an algorithm that does not fit its type.",
    )
    assert jose.public_key_from_jwk(good | {"alg": "ES256"}) is not None


def test_a_key_of_an_unknown_type_has_no_algorithm_and_a_signature_is_judged_by_its_key() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x_key_algorithm__mutmut_5, 6, 7, 8, 9, 10, 11, 12, 13
    dppce.evidence.jose_profiles.x_verify__mutmut_5, 10, 11, 12, 17, 22, 23, 24, 54, 59, 60, 61
    """
    assert _refused(jose.key_algorithm, object()) == (
        "INTEGRITY.JOSE.UNSUPPORTED",
        "The key is of a type that this engine does not verify.",
    )
    signer = ec.generate_private_key(ec.SECP256R1())
    signature = jose.Signature(
        header={"alg": "ES256"}, protected=frozenset({"alg"}), signing_input=b"a.b", value=bytes(64)
    )
    assert _refused(jose.verify, signature, signer.public_key(), ("ES384",)) == (
        "INTEGRITY.JOSE.ALGORITHM",
        "The key type needs an algorithm outside the allowlist of the test.",
    )
    other = jose.Signature(
        header={"alg": "ES384"}, protected=frozenset(), signing_input=b"a.b", value=bytes(64)
    )
    assert _refused(jose.verify, other, signer.public_key(), ("ES256",)) == (
        "INTEGRITY.JOSE.ALGORITHM",
        "The header names an algorithm that the key type does not give.",
    )
    assert _refused(jose.verify, signature, signer.public_key(), ("ES256",)) == (
        "INTEGRITY.JOSE.SIGNATURE",
        "The signature does not verify with the key.",
    )


def _credential(**claims: Any) -> bytes:
    return json.dumps({"issuer": "urn:example:issuer"} | claims).encode()


NOW_UTC = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)
CLAIMS = "INTEGRITY.JOSE.CLAIMS"


def test_each_claim_rule_refuses_with_its_code_and_its_message() -> None:
    """Kills:
    dppce.evidence.jose_profiles.x_credential_issuer__mutmut_8, 13, 14, 15, 18, 23, 24, 25, 36, 40, 45, 46, 47
    dppce.evidence.jose_profiles.x_credential_issuer__mutmut_56, 61, 62, 63, 91, 96, 97, 98
    dppce.evidence.jose_profiles.x_credential_issuer__mutmut_111, 116, 117, 118
    dppce.evidence.jose_profiles.x__moment__mutmut_1, 2, 3, 4, 7, 14, 29, 31, 32, 33, 34, 35, 36
    dppce.evidence.jose_profiles.x__seconds__mutmut_4, 9, 10, 11
    """
    assert _refused(jose.credential_issuer, b"{", NOW_UTC) == (CLAIMS, "The payload is not one JSON object.")
    assert _refused(jose.credential_issuer, b"[1]", NOW_UTC) == (
        CLAIMS,
        "The payload is not one JSON object.",
    )
    for issuer in (5, "", None):
        assert _refused(jose.credential_issuer, json.dumps({"issuer": issuer}).encode(), NOW_UTC) == (
            CLAIMS,
            "The credential names no issuer identifier.",
        )
    assert _refused(jose.credential_issuer, _credential(iss="urn:example:other"), NOW_UTC) == (
        "INTEGRITY.JOSE.ISSUER_MISMATCH",
        "The claim iss differs from the issuer of the credential.",
    )
    not_a_moment = (CLAIMS, "A validity member is not an RFC 3339 date-time with an offset.")
    for bad in (5, "2026-10-14", "2026-13-45T00:00:00Z", "2026-10-13T12:00:60+02:00x"):
        assert _refused(jose.credential_issuer, _credential(validFrom=bad), NOW_UTC) == not_a_moment
    # A leap second with an offset longer than "Z" is read as the second before it.
    assert jose.credential_issuer(_credential(validFrom="2026-10-13T12:00:60+02:00"), NOW_UTC)
    assert _refused(jose.credential_issuer, _credential(nbf="x"), NOW_UTC) == (
        CLAIMS,
        "A NumericDate claim is not a number.",
    )
    not_yet = ("INTEGRITY.JOSE.NOT_YET_VALID", "The credential is not yet valid at the evaluation time.")
    assert _refused(jose.credential_issuer, _credential(validFrom="2026-10-14T12:00:01Z"), NOW_UTC) == not_yet
    assert _refused(jose.credential_issuer, _credential(nbf=int(NOW_UTC.timestamp()) + 1), NOW_UTC) == not_yet
    expired = ("INTEGRITY.JOSE.EXPIRED", "The credential is expired at the evaluation time.")
    assert (
        _refused(jose.credential_issuer, _credential(validUntil="2026-10-14T11:59:59Z"), NOW_UTC) == expired
    )
    assert _refused(jose.credential_issuer, _credential(exp=int(NOW_UTC.timestamp())), NOW_UTC) == expired


def test_a_validity_period_includes_its_first_and_its_last_moment() -> None:
    """validFrom and nbf may equal the evaluation time. validUntil may equal it. exp may not.

    Kills:
    dppce.evidence.jose_profiles.x_credential_issuer__mutmut_81, 89, 101
    """
    now = int(NOW_UTC.timestamp())
    stamp = "2026-10-14T12:00:00Z"
    assert jose.credential_issuer(
        _credential(validFrom=stamp, nbf=now, validUntil=stamp, exp=now + 1), NOW_UTC
    )


def _jwk_for(**changes: Any) -> dict[str, Any]:
    return _p256_jwk() | changes


PRIVATE = ("PRIVATE", "the JWK holds the private member 'd'; give the public key only")
NOT_STRINGS = ("KEY", "a public key is a JSON object of strings")


def test_public_jwk_from_refuses_each_bad_key_with_its_code_and_its_message() -> None:
    """Kills:
    dppce.evidence.jws.x_public_jwk_from__mutmut_2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 18, 19, 20
    dppce.evidence.jws.x_public_jwk_from__mutmut_25, 26, 27, 28, 29, 30, 31, 32, 33, 43, 44, 45, 46, 47, 48
    dppce.evidence.jws.x_public_jwk_from__mutmut_49, 50, 51, 52, 63, 64, 65, 66, 67, 68, 69, 70, 71
    dppce.evidence.jws.x_public_jwk_from__mutmut_84, 88, 89, 93, 94, 95, 96, 97, 98, 99, 100, 101, 108
    dppce.evidence.jws.x_public_jwk_from__mutmut_136, 137, 138, 139, 140, 141, 142, 143, 144, 156, 157
    dppce.evidence.jws.x_public_jwk_from__mutmut_158, 159, 160, 161, 162, 163, 164
    """

    def refused(document: object) -> tuple[str, str]:
        with pytest.raises(SignatureError) as caught:
            public_jwk_from(document)
        return caught.value.code, str(caught.value)

    good = _jwk_for()
    assert public_jwk_from(good) == good
    assert refused([good]) == NOT_STRINGS
    assert refused(good | {"x": 5}) == NOT_STRINGS
    assert refused(good | {"d": "AAAA"}) == PRIVATE
    assert refused({"kty": "EC"}) == ("KEY", "the JWK is not an EC public key with kty, crv, x, and y")
    assert refused(good | {"kty": "OKP"}) == ("KEY", "the JWK is not a P-256 key")
    assert refused(good | {"crv": "P-384"}) == ("KEY", "the JWK is not a P-256 key")
    for change in ({"use": "enc"}, {"alg": "RS256"}):
        assert refused(good | change) == ("KEY", "the JWK is not a signing key for ES256")
    assert refused(good | {"x": _b64(bytes(32)), "y": _b64(bytes(32))}) == (
        "KEY",
        "the JWK is not a point on P-256",
    )
    assert refused(_jwk_with_short_x()) == ("KEY", "the JWK is not a point on P-256")
    respelled = good["x"][:-1] + _URLSAFE[_URLSAFE.index(good["x"][-1]) ^ 1]
    assert refused(good | {"x": respelled}) == (
        "KEY",
        "a coordinate of the JWK is not the unpadded base64url of 32 bytes",
    )


_URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def test_a_compact_token_part_check_and_a_signer_check_name_their_reason() -> None:
    """Kills:
    dppce.evidence.jws.x_payload_of__mutmut_3, 4, 5, 6
    dppce.evidence.jws.x_signature_value__mutmut_3, 4, 5, 6
    dppce.evidence.jws.x_sign_compact__mutmut_2
    dppce.evidence.jws.x_public_jwk_of__mutmut_2
    """
    for read in (payload_of, signature_value):
        with pytest.raises(SignatureError, match=r"^a compact JWS is three base64url parts$"):
            read("a.b")

    class Weak:
        algorithm = "RS256"
        key_id = "TEST-ONLY-weak"

        def sign(self, data: bytes) -> bytes:
            return b""

    with pytest.raises(SignatureError, match=r"^algorithm 'RS256' is not in the allowlist$") as caught:
        sign_compact(b"{}", Weak(), typ="x")
    assert caught.value.code == "ALGORITHM"
    with pytest.raises(SignatureError, match=r"^the key is on curve secp384r1, not on P-256$") as curve:
        public_jwk_of(ec.generate_private_key(ec.SECP384R1()).public_key())
    assert curve.value.code == "KEY"


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
    dppce.verifier.verify.x__ordering__mutmut_2, 3, 4, 5, 18
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
