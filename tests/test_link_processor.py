"""The processor model of Link reading: the linear scanner, the gate, the target parameter, joined lines.

The agreement check compares the engine reading with a model of the Link parsers of jsonld.js 8.3.3
and pyld 3.0.0. A system under test must not get a false pass, or turn a fail into blocked, with a
value that these parsers read differently. A common valid value keeps its pass. Architecture
sections 8 and 10. No test contacts a host.
"""

from __future__ import annotations

import json
import random
import re
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import pytest

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.adapters.resolver import _advertised
from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import (
    _JS_SPACE,
    _PY_SPACE,
    REMOVED,
    _processor_links,
    _processor_read,
    parse_link,
    redact_link,
    redact_response_headers,
    resolutions,
)
from tests.support import make_record, reply
from tests.test_data_document_source import ALLOWED, blocked, failed, passed, verdict
from tests.test_review_findings import transport
from tests.test_rulepack_v2 import BODY, JSONLD_CONTEXT, PLAIN, Linked, contexts, pin

CTX = f'rel="{JSONLD_CONTEXT}"'
EVIL = "https://evil.test/ctx"
SECRET = "S3CRET"
PLACEHOLDER = f"<%3Cremoved%3E>, {REMOVED}"

# The three regular expressions of jsonld.js 8.3.3 (lib/util.js, parseLinkHeader) and pyld 3.0.0
# (parse_link_header), in Python syntax. They are the reference of the scanner. In Python, "\s" also
# matches "\x85", and "." also matches "\r". The JavaScript forms below replace both.
PART = re.compile(r'(?:<[^>]*>|"[^"]*"|[^,])+')
LINK = re.compile(r"\s*<([^>]*)>\s*(?:;\s*(.*))?")
PARAMETER = re.compile(r'(.*?)=(?:"([^"]*)"|([^"]*?))\s*(?:;\s*|\Z)')


def javascript(pattern: re.Pattern[str]) -> re.Pattern[str]:
    return re.compile(pattern.pattern.replace(r"\s", r"[\t\n\x0b\x0c\r \xa0]").replace(".", r"[^\n\r]"))


JS = (javascript(PART), javascript(LINK), javascript(PARAMETER))
PY = (PART, LINK, PARAMETER)


def reference(
    value: str, regexes: tuple[re.Pattern[str], ...]
) -> list[tuple[str, list[tuple[str, str, bool]]]]:
    """Each target and its parameters as the three regular expressions read them."""
    part, link, parameter = regexes
    out: list[tuple[str, list[tuple[str, str, bool]]]] = []
    for text in part.findall(value):
        if (found := link.search(text)) is None:
            continue
        pairs = [
            (m[1], m[3] if m[2] is None else m[2], m[2] is not None)
            for m in parameter.finditer(found[2] or "")
        ]
        out.append((found[1], pairs))
    return out


# The alphabet of the differential tests: every character that the three expressions treat apart,
# the two spaces that only one language reads as white space, and one plain letter.
ALPHABET = '<>",;= \t\xa0\x85a'


# Most samples start with a link, so that the parameter expression sees many inputs.
PREFIXES = ("", "<a>", "<a>;", "<a>; ", "<a>, <a>;")


def samples(seed: int, count: int = 20000) -> list[str]:
    rng = random.Random(seed)  # noqa: S311 - fixed test samples, not a secret
    return [
        rng.choice(PREFIXES) + "".join(rng.choice(ALPHABET) for _ in range(rng.randrange(16)))
        for _ in range(count)
    ]


# -- the linear scanner ------------------------------------------------------------------------------


def test_the_scanner_reads_as_the_python_regular_expressions() -> None:
    for value in samples(20261027):
        assert _processor_read(value, _PY_SPACE) == reference(value, PY), repr(value)


def test_the_scanner_reads_as_the_javascript_regular_expressions() -> None:
    for value in samples(20261028):
        assert _processor_read(value, _JS_SPACE) == reference(value, JS), repr(value)


def test_the_two_space_models_differ_and_each_is_checked() -> None:
    # Python skips "\x85" after ";", so pyld reads the relation. JavaScript keeps it in the name.
    value = f"<{EVIL}>; \x85rel={JSONLD_CONTEXT}"
    assert _processor_links(value, _PY_SPACE) == [(EVIL, True)]
    assert _processor_links(value, _JS_SPACE) == [(EVIL, False)]
    assert not parse_link(value).complete


# Values of 64 KiB in each shape that made a backtracking expression slow, and their mixes.
SIZE = 64 * 1024
ADVERSARIAL = (
    "<https://a.test/>, " + " " * SIZE + "x",
    "<x>; " + "a=" * (SIZE // 2) + '"',
    "<x>; " + "=" * SIZE,
    "<" * SIZE,
    "<x>; t=" + "<" * SIZE,
    '"' * SIZE,
    "<x>; " + '="' * (SIZE // 2),
    "<x>; a=" + '"' * SIZE,
    "<x>" + ";" * SIZE,
    "<x>; a=" + ";" * SIZE,
    "," * SIZE,
    "<x>," * (SIZE // 4),
    '<x>; a="b"' + " " * SIZE + "c",
    "<x>; " + 'a="b" ' * (SIZE // 6),
    "<x>; " + "a=b \xa0\x85" * (SIZE // 6),
    "<x>; a=" + "\xa0" * SIZE + "b",
    "<" + "a" * SIZE + ">",
    "<" + "%" * SIZE + ">",
    "<https://" + "@" * SIZE + ">",
    "<" + ":" * SIZE + ">",
    "<https://x.test/?" + "token=a&" * (SIZE // 8) + ">",
    "<x>; title=" + '\\"' * (SIZE // 2),
    '<x>; title="' + "\\" * SIZE,
    f"{REMOVED}," * (SIZE // 10),
)


def test_the_link_path_is_linear_on_adversarial_values() -> None:
    start = time.perf_counter()
    for value in ADVERSARIAL:
        recorded = redact_response_headers((("Link", value), ("Link", value)))
        parse_link(value)
        for _, kept in recorded:
            parse_link(kept)
    # The scanner takes milliseconds per value. A backtracking expression took seconds on one.
    assert time.perf_counter() - start < 5


def test_the_link_checks_are_linear_on_adversarial_records(tmp_path: Path) -> None:
    start = time.perf_counter()
    lines = tuple(("Link", value) for value in ADVERSARIAL)
    record = replace(make_record(1), headers=redact_response_headers(lines))
    _advertised([record])
    contexts(tmp_path, Linked(BODY, redact_response_headers(lines)))
    assert time.perf_counter() - start < 5


# -- the record-time gate ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "character", ["\x00", "\x01", "\x08", "\n", "\x0b", "\r", "\x1c", "\x1f", "\x7f", "\u0100", "\u2028"]
)
def test_a_character_that_a_field_value_cannot_hold_stops_reading(tmp_path: Path, character: str) -> None:
    value = f'<{ALLOWED[0]}>; {CTX}; title="a{character}b"'
    assert redact_link(value) == f"<{ALLOWED[0]}>; {CTX}; {REMOVED}, {REMOVED}"
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == failed("DATA.CONTEXT.LINK_MALFORMED")


def test_an_obs_fold_line_break_left_in_a_value_stops_reading(tmp_path: Path) -> None:
    value = f"<{ALLOWED[0]}>;\r\n {CTX}"
    assert not parse_link(recorded(value)[0][1]).complete
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == failed("DATA.CONTEXT.LINK_MALFORMED")


def recorded(*values: str) -> tuple[tuple[str, str], ...]:
    return redact_response_headers(tuple(("Link", v) for v in values))


# Common valid values. Each keeps its pass, and its record is complete. A header value arrives as
# latin-1 text, so UTF-8 text such as u-umlaut (C3 BC) or A-ring (C3 85) arrives as two characters.
COMMON = (
    '</doc>; rel="alternate"; title="f\xc3\xbcr"',
    '</doc>; rel="alternate"; title="\xc3\x85r"',
    "</doc>; rel=alternate; title=\xc3\x85r",
    "</doc>; rel=alternate; title=a\tb",
    "</s.css>; rel=preload; as=style, </f.woff2>; rel=preload; as=font; type=font/woff2; crossorigin",
    '<https://x.test/p?page=2>; rel="next", <https://x.test/p?page=9>; rel="last"',
    '<https://x.test/ls>; rel="linkset"; type="application/linkset+json"',
    '</x>; rel="related"; title="say \\"hi\\""',
    "</x>; rel=related; title*=UTF-8''f%C3%BCr",
    f'<{ALLOWED[0]}>; {CTX}; type="application/ld+json"',
)


@pytest.mark.parametrize("value", COMMON)
def test_a_common_value_keeps_a_pass_and_records_complete(tmp_path: Path, value: str) -> None:
    kept = recorded(value)
    assert parse_link(kept[0][1]).complete
    assert verdict(contexts(tmp_path, Linked(BODY, kept))) == passed("DATA.CONTEXT.OK")


def test_paging_on_two_lines_and_several_lines_keep_a_pass(tmp_path: Path) -> None:
    lines = recorded(*COMMON)
    assert all(parse_link(kept).complete for _, kept in lines)
    assert verdict(contexts(tmp_path, Linked(BODY, lines))) == passed("DATA.CONTEXT.OK")
    paging = recorded('<https://x.test/p?page=2>; rel="next"', '<https://x.test/p?page=1>; rel="prev"')
    assert paging == (
        ("Link", '<https://x.test/p?page=2>; rel="next"'),
        ("Link", '<https://x.test/p?page=1>; rel="prev"'),
    )


# -- a parameter named target ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        f'<{ALLOWED[0]}>; {CTX}; target="{EVIL}"',
        f'<{ALLOWED[0]}>; target="{EVIL}"; {CTX}',
        f"<{ALLOWED[0]}>; {CTX}; target={EVIL}",
        f"<{ALLOWED[0]}>; rel={JSONLD_CONTEXT};target={EVIL}",
    ],
)
def test_a_parameter_named_target_that_replaces_the_target_fails(tmp_path: Path, value: str) -> None:
    # jsonld.js and pyld assign each parameter to the link, so "target" replaces the target.
    assert _processor_links(value, _JS_SPACE) == [(EVIL, True)]
    assert not parse_link(value).complete
    assert recorded(value)[0][1].endswith(f", {REMOVED}")
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == failed("DATA.CONTEXT.LINK_MALFORMED")
    assert verdict(contexts(tmp_path, Linked(PLAIN, recorded(value)))) == failed(
        "DATA.CONTEXT.LINK_MALFORMED"
    )


@pytest.mark.parametrize(
    "value",
    [
        f"<{ALLOWED[0]}>; {CTX}; target={ALLOWED[0]}",
        f"<{ALLOWED[0]}>; target={ALLOWED[0]}; {CTX}",
        f'<{ALLOWED[0]}>; {CTX}; target="{ALLOWED[0]}"; target={ALLOWED[0]}',
    ],
)
def test_an_unquoted_target_parameter_that_pyld_reads_as_empty_fails(tmp_path: Path, value: str) -> None:
    # pyld 3.0.0 reads parameters with re.findall, which gives "" for the quoted group of an unquoted
    # value. So the target is "", and pyld loads the URL of the answer itself as the context.
    assert _processor_links(value, _JS_SPACE) == [(ALLOWED[0], True)]
    assert _processor_links(value, _PY_SPACE, pyld=True) == [("", True)]
    assert not parse_link(value).complete
    for body in (BODY, PLAIN):
        outcome = contexts(tmp_path, Linked(body, recorded(value)))
        assert verdict(outcome) == failed("DATA.CONTEXT.LINK_MALFORMED")


def test_pyld_reads_an_unquoted_rel_as_empty_but_the_model_keeps_the_context(tmp_path: Path) -> None:
    # pyld then finds no context link. The engine judges the context that jsonld.js reads: the safe side.
    value = f"<{ALLOWED[0]}>; rel={JSONLD_CONTEXT}"
    assert _processor_links(value, _PY_SPACE, pyld=True) == [(ALLOWED[0], True)]
    assert parse_link(value).complete
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize("name", ["target ", "Target", "TARGET", "targets", "xtarget"])
def test_only_the_exact_name_target_replaces_the_target(tmp_path: Path, name: str) -> None:
    value = f'<{ALLOWED[0]}>; {CTX}; {name}="{EVIL}"'
    assert _processor_links(value, _JS_SPACE) == [(ALLOWED[0], True)]
    assert parse_link(value).complete
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == passed("DATA.CONTEXT.OK")


def test_a_target_parameter_never_reaches_the_record() -> None:
    kept = recorded(f'<{ALLOWED[0]}>; {CTX}; target="https://{SECRET}.test/ctx"')
    assert SECRET not in repr(kept)


# -- Link lines joined ------------------------------------------------------------------------------

# Each line reads the same alone in the engine and in the model. Joined with ", ", as every HTTP
# client hands the value to the application, the model reads the foreign context.
QUOTE_SHIFT = (f'<{EVIL}>; title="x', f'<{ALLOWED[0]}>; t="p, <{EVIL}>; rel={JSONLD_CONTEXT}, q"')
ANGLE_SWALLOW = (f"<{EVIL}>; title=x<", f"<{ALLOWED[0]}>; {CTX}")


@pytest.mark.parametrize("lines", [QUOTE_SHIFT, ANGLE_SWALLOW])
def test_lines_that_read_differently_once_joined_fail(tmp_path: Path, lines: tuple[str, str]) -> None:
    assert all(parse_link(line).complete for line in lines)
    assert any(context for _, context in _processor_links(", ".join(lines), _JS_SPACE))
    kept = recorded(*lines)
    assert [parse_link(value).complete for _, value in kept] == [True, False]
    assert kept[-1][1] == redact_link(lines[-1]) + f", {REMOVED}"
    assert verdict(contexts(tmp_path, Linked(BODY, kept))) == failed("DATA.CONTEXT.LINK_MALFORMED")


def test_the_joined_check_reads_the_header_name_without_case_and_in_wire_order() -> None:
    kept = redact_response_headers(
        (("link", QUOTE_SHIFT[0]), ("Content-Type", "application/json"), ("LINK", QUOTE_SHIFT[1]))
    )
    assert [name for name, _ in kept] == ["link", "Content-Type", "LINK"]
    assert kept[2][1].endswith(f", {REMOVED}")
    # In the other order the lines read the same joined, so nothing stops.
    swapped = recorded(QUOTE_SHIFT[1], QUOTE_SHIFT[0])
    assert all(parse_link(value).complete for _, value in swapped)


def test_a_last_line_without_a_link_records_as_the_placeholder(tmp_path: Path) -> None:
    kept = recorded(*QUOTE_SHIFT, "")
    assert kept[-1] == ("Link", PLACEHOLDER)
    assert verdict(contexts(tmp_path, Linked(BODY, kept))) == failed("DATA.CONTEXT.LINK_MALFORMED")


def test_the_joined_check_is_skipped_when_a_line_already_stopped() -> None:
    junk = f"<https://a.example/x> junk, <{EVIL}>; {CTX}"
    kept = recorded(junk, QUOTE_SHIFT[1])
    assert kept[1][1] == redact_link(QUOTE_SHIFT[1])
    assert kept[0][1].endswith(f", {REMOVED}")


def test_a_recorded_value_is_read_line_by_line_so_an_old_record_keeps_its_reading(tmp_path: Path) -> None:
    # A recorded value holds stop markers that a comma-splitting model reads as a target. So data.context
    # never joins recorded lines: each recorded line is canonical and reads the same alone.
    kept = (("Link", f"<{ALLOWED[0]}>; {CTX}"), ("Link", f"<https://x.test/a>; {REMOVED}"))
    assert verdict(contexts(tmp_path, Linked(BODY, kept))) == passed("DATA.CONTEXT.OK")


def test_resolver_linkset_reads_each_recorded_line_after_a_joined_disagreement() -> None:
    # Joined, a comma-splitting reader takes the first target with the relation linkset. The engine
    # reads each recorded line, so it takes the target of the second line. The record shows the stop.
    lines = ("</other>; title=x<", '</linksets/EV0001>; rel="linkset"')
    record = replace(make_record(1, url="https://id.example.test/01/1"), headers=recorded(*lines))
    assert not parse_link(record.headers[-1][1]).complete
    assert _advertised([record]) == "https://id.example.test/linksets/EV0001"
    joined = _processor_read(", ".join(lines), _JS_SPACE)
    assert [(target, {n: v for n, v, _ in pairs}.get("rel")) for target, pairs in joined] == [
        ("/other", "linkset")
    ]


# -- a special scheme without "//" ------------------------------------------------------------------------

SCHEME_ONLY = ("https:user:pw@example.test/ctx", "https:/contexts/battery/v1", "https:contexts/battery/v1")


@pytest.mark.parametrize("target", SCHEME_ONLY)
@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_special_scheme_target_without_an_authority_is_not_allowed(
    tmp_path: Path, target: str, body: bytes
) -> None:
    # Python urljoin resolves such a target against the host of the answer. pyld 3.0.0 keeps it as it is.
    assert recorded(f"<{target}>; {CTX}") == (("Link", f"<%3Cremoved%3E>; {CTX}"),)
    first = contexts(tmp_path, Linked(body, recorded(f"<{target}>; {CTX}")))
    assert verdict(first) == failed("DATA.CONTEXT.NOT_ALLOWED")
    # Even with the URL that urljoin gives on the allowlist, the marker is not allowed.
    resolved = urljoin(first.observations[0].summary["not_allowed"][0], target)
    outcome = contexts(
        tmp_path, Linked(body, recorded(f"<{target}>; {CTX}")), allowed_contexts=[ALLOWED[0], resolved]
    )
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert "user:pw" not in repr(outcome)


# -- a target that Python urljoin changes ----------------------------------------------------------------

# urljoin drops an empty ";" parameter and an empty "?" query, and removes empty segments of a relative
# path. pyld 3.0.0 drops the first "." of a relative path such as ".well-known". WHATWG URL and pyld
# keep the others, so the engine would judge a URL that a processor does not load. The readers also
# differ on dot segments, so only a leading run of "." and ".." segments is kept.
NORMALIZED = (
    "https://example.test/ctx;",
    "https://example.test/ctx?",
    "https://example.test/ctx;?",
    "/contexts/battery/v1;",
    "contexts//battery/v1",
    ".well-known/ctx",
    # Found by a fuzzer that compares urljoin with WHATWG URL and pyld: dot segments read differently.
    "contexts/..;x",
    "%2e%2e/contexts/battery/v1",
    "a/../contexts/battery/v1",
    "contexts/.?v=1",
    "/..//contexts/battery/v1",
    "https://example.test/a/../ctx",
)


@pytest.mark.parametrize("target", NORMALIZED)
@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_target_that_urljoin_changes_is_not_allowed(tmp_path: Path, target: str, body: bytes) -> None:
    assert recorded(f"<{target}>; {CTX}") == (("Link", f"<%3Cremoved%3E>; {CTX}"),)
    first = contexts(tmp_path, Linked(body, recorded(f"<{target}>; {CTX}")))
    assert verdict(first) == failed("DATA.CONTEXT.NOT_ALLOWED")
    resolved = urljoin(first.observations[0].summary["not_allowed"][0], target)
    outcome = contexts(
        tmp_path, Linked(body, recorded(f"<{target}>; {CTX}")), allowed_contexts=[ALLOWED[0], resolved]
    )
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


@pytest.mark.parametrize("target", ["/linksets/EV0001;", "/linksets/EV0001?", "linksets//EV0001"])
def test_resolver_linkset_does_not_fetch_a_target_that_urljoin_changes(target: str) -> None:
    lines = recorded(f'<{target}>; rel="linkset"')
    assert _advertised([replace(make_record(1, url="https://id.example.test/01/1"), headers=lines)]) is None


@pytest.mark.parametrize(
    "target",
    [
        "https://example.test/ctx",
        "HTTPS://example.test/ctx",
        "urn:x:ctx",
        "/ctx",
        "ctx",
        "../ctx",
        "./ctx",
        ".a",
        "..a/ctx",
        "/a//ctx",
        "https://example.test/a//ctx",
        "?page=2",
        "/ctx;v=1",
    ],
)
def test_a_target_with_an_authority_or_another_scheme_is_kept(target: str) -> None:
    assert recorded(f"<{target}>; {CTX}") == (("Link", f"<{target}>; {CTX}"),)


@pytest.mark.parametrize("target", ["https:/linksets/EV0001", "https:linksets/EV0001"])
def test_resolver_linkset_does_not_fetch_a_special_scheme_target_without_an_authority(target: str) -> None:
    lines = recorded(f'<{target}>; rel="linkset"')
    assert _advertised([replace(make_record(1, url="https://id.example.test/01/1"), headers=lines)]) is None


# -- an echoed credential in a Link line ---------------------------------------------------------------

TOKEN = "TEST-ONLY-S3CRET-token"


@pytest.mark.parametrize(
    "line",
    [
        # The token takes the place of the ">" of a target. Scrubbed in place, the marker would close it.
        f"<{EVIL}{TOKEN}, <{ALLOWED[0]}>; {CTX}",
        f'<{ALLOWED[0]}>; {CTX}; title="{TOKEN}"',
    ],
)
@pytest.mark.parametrize(("body", "code"), [(BODY, "LINK_MALFORMED"), (PLAIN, "MISSING")])
def test_a_link_line_that_echoes_a_credential_records_as_the_placeholder(
    tmp_path: Path, loopback: Any, line: str, body: bytes, code: str
) -> None:
    server = loopback(lambda r: reply(r, headers={"Link": line}))
    engine = transport(credentials={"authority": (server.origin, TOKEN)})
    record = engine.fetch(Request("GET", f"{server.origin}/dpp/1", role="anonymous"))
    assert "Authorization" not in server.seen[-1], "an anonymous request carries no credential"
    assert [v for k, v in record.headers if k.lower() == "link"] == [PLACEHOLDER]
    assert TOKEN not in repr(record)
    headers = tuple((k, v) for k, v in record.headers if k.lower() != "content-type")
    assert verdict(contexts(tmp_path, Linked(body, headers))) == failed(f"DATA.CONTEXT.{code}")


# -- a relative target against a base path with an empty or dot segment ----------------------------------

BATTERY = "https://dppce.example.test/contexts/battery/v1"


class Redirected(Linked):
    """Linked whose answer came after a redirect to ``final``."""

    def __init__(self, body: bytes, headers: tuple[tuple[str, str], ...], final: str) -> None:
        super().__init__(body, headers)
        self._final = final

    def fetch(self, request: Request) -> Record:
        record = replace(super().fetch(request), redirects=(self._final,))
        self._records[-1] = record
        return record


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_on_a_base_with_an_empty_segment_is_judged_as_the_consumers_resolve_it(
    tmp_path: Path, body: bytes
) -> None:
    # urljoin gives BATTERY. WHATWG URL and pyld 3.0.0 keep the empty segment: .../x/contexts/battery/v1.
    acquirer = Redirected(
        body, recorded(f"<../../contexts/battery/v1>; {CTX}"), "https://dppce.example.test/x//y/z"
    )
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [
        "https://dppce.example.test/x/contexts/battery/v1"
    ]


def test_a_relative_target_that_the_consumers_resolve_outside_the_allowlist_fails(tmp_path: Path) -> None:
    acquirer = Redirected(
        BODY, recorded(f"<../contexts/battery/v1>; {CTX}"), "https://dppce.example.test/x//y/z"
    )
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_target_that_only_urljoin_resolves_outside_the_allowlist_passes(
    tmp_path: Path, body: bytes
) -> None:
    # urljoin gives .../battery/v1. WHATWG URL and pyld 3.0.0 keep the empty segment and give BATTERY.
    acquirer = Redirected(
        body, recorded(f"<../battery/v1>; {CTX}"), "https://dppce.example.test/contexts//v0"
    )
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize("target", ["../../contexts/battery/v1", "/contexts/battery/v1", BATTERY])
def test_a_context_target_on_a_plain_base_or_without_a_relative_path_keeps_its_pass(
    tmp_path: Path, target: str
) -> None:
    final = (
        "https://dppce.example.test/x/y/z" if target.startswith("..") else "https://dppce.example.test/x//y/z"
    )
    acquirer = Redirected(PLAIN, recorded(f"<{target}>; {CTX}"), final)
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_target_on_a_base_with_a_percent_encoded_dot_segment_fails_if_one_reading_is_foreign(
    tmp_path: Path, body: bytes
) -> None:
    # WHATWG URL reads "%2e%2e" as "..": BATTERY. pyld 3.0.0 keeps it: .../x/%2e%2e/contexts/battery/v1.
    final = "https://dppce.example.test/x/%2e%2e/contexts/v0"
    acquirer = Redirected(body, recorded(f"<battery/v1>; {CTX}"), final)
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [
        "https://dppce.example.test/x/%2e%2e/contexts/battery/v1"
    ]
    both = [ALLOWED[0], BATTERY, "https://dppce.example.test/x/%2e%2e/contexts/battery/v1"]
    assert verdict(contexts(tmp_path, acquirer, allowed_contexts=both)) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize(
    ("base", "target", "readings"),
    [
        ("https://h.test/x//y/z", "../../a", ("https://h.test/x/a",)),
        ("https://h.test/x//y/z", "", ("https://h.test/x//y/z",)),
        ("https://h.test/x//y/z?q", "?r", ("https://h.test/x//y/z?r",)),
        ("https://h.test/x/%2E%2e/y/z", "a", ("https://h.test/x/%2E%2e/y/a", "https://h.test/y/a")),
        ("https://h.test/x/.%2e/y/z", "a", ("https://h.test/x/.%2e/y/a", "https://h.test/y/a")),
        ("https://h.test/a/..", "a", ("https://h.test/a/a", "https://h.test/a")),
        ("https://h.test/a/b//", "..", ("https://h.test/a/b/",)),
        # A target with an authority or an absolute path does not read the base path.
        ("https://h.test/x//y/z", "/c", ("https://h.test/c",)),
        ("https://h.test/x//y/z", "https://h.test/c", ("https://h.test/c",)),
        # The WHATWG URL parser reads "\" in the path of an https URL as "/". pyld keeps it.
        (
            "https://h.example/a\\b/c/doc",
            "../../contexts/battery/v1",
            ("https://h.example/contexts/battery/v1", "https://h.example/a/contexts/battery/v1"),
        ),
        (
            "https://h.example/contexts\\x/doc",
            "v1",
            ("https://h.example/contexts\\x/v1", "https://h.example/contexts/x/v1"),
        ),
        ("https://h.example/x\\..\\contexts/doc", "../battery/v1", ("https://h.example/battery/v1",)),
        # No reader decodes "%5c", so this base is plain.
        ("https://h.example/a%5cb/c/doc", "../../ctx", ("https://h.example/ctx",)),
    ],
)
def test_the_consumer_readings_of_a_relative_target_on_an_odd_base(
    base: str, target: str, readings: tuple[str, ...]
) -> None:
    # Each expected value is what pyld 3.0.0 (iri_resolver.resolve) and Node.js 22 new URL() printed.
    assert resolutions(base, target) == readings


def test_on_a_plain_base_the_consumer_reading_is_urljoin() -> None:
    rng = random.Random(7)  # noqa: S311 - fixed test samples, not a secret
    segments = ["a", "b", "x.y", "a;p", "..a"]
    targets = ["", "/", "ctx", ".", "..", "./", "../", "?q", "a", "x/", "../../c", "/c/d", "//h.test/c"]
    checked = 0
    for _ in range(5000):
        base = "https://id.test/" + "/".join(rng.choice(segments) for _ in range(rng.randint(0, 4)))
        target = "".join(rng.choice(targets) for _ in range(rng.randint(1, 3)))
        if redact_link(f"<{target}>") != f"<{target}>":
            continue
        assert resolutions(base, target) == (urljoin(base, target),), (base, target)
        checked += 1
    assert checked > 1000


def test_resolver_linkset_fetches_a_relative_target_on_a_base_with_an_empty_segment_as_the_consumers_do() -> (
    None
):
    lines = recorded('<../linksets/EV0001>; rel="linkset"')
    odd = replace(make_record(1), headers=lines, redirects=("https://id.example.test/dpp//x/y",))
    plain = replace(odd, redirects=("https://id.example.test/dpp/x/y",))
    assert _advertised([odd]) == "https://id.example.test/dpp//linksets/EV0001"
    assert _advertised([plain]) == "https://id.example.test/dpp/linksets/EV0001"
    # The readers resolve it to two URLs, so it is not fetched.
    dotted = replace(odd, redirects=("https://id.example.test/dpp/%2e%2e/x/y",))
    assert _advertised([dotted]) is None


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_on_a_base_with_a_backslash_is_judged_as_the_consumers_resolve_it(
    tmp_path: Path, body: bytes
) -> None:
    # urljoin and pyld 3.0.0 give BATTERY. Node.js 22 new URL() reads "\" as "/": .../a/contexts/battery/v1.
    final = "https://dppce.example.test/a\\b/c/doc"
    acquirer = Redirected(body, recorded(f"<../../contexts/battery/v1>; {CTX}"), final)
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [
        "https://dppce.example.test/a/contexts/battery/v1"
    ]
    both = [ALLOWED[0], BATTERY, "https://dppce.example.test/a/contexts/battery/v1"]
    assert verdict(contexts(tmp_path, acquirer, allowed_contexts=both)) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_target_that_both_readers_resolve_to_an_allowed_context_on_a_backslash_base_passes(
    tmp_path: Path, body: bytes
) -> None:
    # pyld 3.0.0 keeps "x\..\y" as one segment. WHATWG URL reads it as "x/../y". Both give BATTERY.
    final = "https://dppce.example.test/contexts/x\\..\\y/doc"
    acquirer = Redirected(body, recorded(f"<../battery/v1>; {CTX}"), final)
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


def test_resolver_linkset_does_not_fetch_a_target_that_the_readers_resolve_apart_on_a_backslash_base() -> (
    None
):
    lines = recorded('<../../linksets/EV0001>; rel="linkset"')
    apart = replace(make_record(1), headers=lines, redirects=("https://id.example.test/a\\b/c/1",))
    assert _advertised([apart]) is None
    alike = replace(apart, redirects=("https://id.example.test/a\\..\\b/c/1",))
    assert _advertised([alike]) == "https://id.example.test/linksets/EV0001"


# -- a relative target against a redirect path that held an echoed credential -----------------------------


@pytest.mark.parametrize(
    "secret",
    [
        # The scrub replaces "ab/cd/S3CRET" with one marker segment, so urljoin of the record gives the
        # allowed context. Every reader of the fetched URL gives .../x/TEST-ONLY-ab/contexts/battery/v1.
        "TEST-ONLY-ab/cd/S3CRET",
        # Without "/" the record keeps the segments. The engine cannot tell the two apart, and the
        # system put the engine credential into its own redirect target, so this fails too.
        "TEST-ONLY-abcdS3CRET",
    ],
)
@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_on_a_redirect_path_with_an_echoed_credential_fails(
    tmp_path: Path, loopback: Any, secret: str, body: bytes
) -> None:
    def answer(request: Any) -> None:
        if request.path == "/dpp/1":
            reply(request, 302, b"", {"Location": f"/x/{secret}/doc"})
        else:
            reply(request, headers={"Link": f"<../../contexts/battery/v1>; {CTX}"})

    server = loopback(answer)
    engine = transport(credentials={"authority": (server.origin, secret)})
    record = engine.fetch(Request("GET", f"{server.origin}/dpp/1", role="authority"))
    assert server.seen[-1]["path"] == f"/x/{secret}/doc"
    assert secret not in repr(record)
    assert record.redirects == (f"{server.origin}/x/{REMOVED}/doc",)
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    acquirer = Redirected(body, links, record.redirects[-1])
    allowed = [ALLOWED[0], f"{server.origin}/contexts/battery/v1"]
    outcome = contexts(tmp_path, acquirer, allowed_contexts=allowed)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [
        f"{server.origin}/x/{REMOVED}/doc/../../contexts/battery/v1"
    ]


@pytest.mark.parametrize(
    ("final", "target"),
    [
        # A target with an absolute path or an authority does not read the base path.
        (f"https://dppce.example.test/x/{REMOVED}/doc", "/contexts/battery/v1"),
        (f"https://dppce.example.test/x/{REMOVED}/doc", BATTERY),
        # Redaction of a credential-like query parameter does not change the base path.
        ("https://dppce.example.test/x/y/doc?session=%3Cremoved%3E", "../../contexts/battery/v1"),
    ],
)
def test_a_context_target_that_does_not_read_a_scrubbed_base_path_keeps_its_pass(
    tmp_path: Path, final: str, target: str
) -> None:
    acquirer = Redirected(PLAIN, recorded(f"<{target}>; {CTX}"), final)
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


def test_resolver_linkset_does_not_fetch_a_relative_target_on_a_redirect_path_with_an_echoed_credential() -> (
    None
):
    lines = recorded('<../../linksets/EV0001>; rel="linkset"')
    final = f"https://id.example.test/x/Bearer {REMOVED}/doc"
    scrubbed = replace(make_record(1), headers=lines, redirects=(final,))
    assert _advertised([scrubbed]) is None
    absolute = replace(scrubbed, headers=recorded('</linksets/EV0001>; rel="linkset"'))
    assert _advertised([absolute]) == "https://id.example.test/linksets/EV0001"


# -- a redirect Location that urljoin reads as another URL than the consumers do --------------------------

# The transport records such a hop, and each later hop, with this suffix. A fragment is never recorded
# otherwise, because redact_url removes it.
UNKNOWN = f"#{REMOVED}"


# Each case: the Locations, the context target, the recorded hops, and the context that WHATWG URL loads.
@pytest.mark.parametrize(
    "case",
    [
        # urljoin removes "a\b/..". Node.js 22 new URL() reads "\" as "/": base /a/doc.
        (["/a\\b/../doc"], "contexts/battery/v1", ["/doc"], "/a/contexts/battery/v1"),
        # urljoin removes the empty segment of a relative path. WHATWG URL keeps it: base /dpp/x//y/doc.
        (["x//y/doc"], "../../../contexts/battery/v1", ["/dpp/x/y/doc"], "/dpp/contexts/battery/v1"),
        # The next hop joins the quoted path /a%5Cb/c/x. WHATWG URL joins /a/b/c/x: base /a/doc.
        (["/a\\b/c/x", "../../doc"], "contexts/battery/v1", ["/a\\b/c/x", "/doc"], "/a/contexts/battery/v1"),
        # urljoin keeps "%2e%2e" as a segment. WHATWG URL and requests read it as "..": base /doc.
        (
            ["/contexts/%2e%2e/y/z", "../../doc"],
            "battery/v1",
            ["/contexts/%2e%2e/y/z", "/contexts/doc"],
            "/battery/v1",
        ),
        # The ".." of urljoin removes "%2e%2e". WHATWG URL and requests read both as "..": base /doc.
        (["/contexts/x/%2e%2e/../doc"], "../battery/v1", ["/contexts/x/doc"], "/battery/v1"),
    ],
)
@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_after_a_location_that_the_consumers_read_apart_fails(
    tmp_path: Path, loopback: Any, case: tuple[list[str], str, list[str], str], body: bytes
) -> None:
    locations, target, recorded_hops, consumer = case

    def answer(request: Any) -> None:
        hop = len(server.seen) - 1
        if hop < len(locations):
            reply(request, 302, b"", {"Location": locations[hop]})
        else:
            reply(request, headers={"Link": f"<{target}>; {CTX}"})

    server = loopback(answer)
    record = transport().fetch(Request("GET", f"{server.origin}/dpp/1", role="anonymous"))
    assert record.status == 200
    assert record.redirects == tuple(f"{server.origin}{hop}{UNKNOWN}" for hop in recorded_hops)
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    # The allowlist holds the urljoin reading of the record and not the URL that the consumer loads.
    allowed = [ALLOWED[0], urljoin(f"{server.origin}{recorded_hops[-1]}", target)]
    assert f"{server.origin}{consumer}" not in allowed
    outcome = contexts(tmp_path, Redirected(body, links, record.redirects[-1]), allowed_contexts=allowed)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [f"{record.redirects[-1]}/{target}"]


@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_after_a_plain_redirect_keeps_its_pass(
    tmp_path: Path, loopback: Any, body: bytes
) -> None:
    def answer(request: Any) -> None:
        if request.path == "/dpp/1":
            reply(request, 302, b"", {"Location": "/x/y/z"})
        else:
            reply(request, headers={"Link": f"<../../contexts/battery/v1>; {CTX}"})

    server = loopback(answer)
    record = transport().fetch(Request("GET", f"{server.origin}/dpp/1", role="anonymous"))
    assert record.redirects == (f"{server.origin}/x/y/z",)
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    allowed = [ALLOWED[0], f"{server.origin}/contexts/battery/v1"]
    outcome = contexts(tmp_path, Redirected(body, links, record.redirects[-1]), allowed_contexts=allowed)
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize(
    ("base", "location", "apart"),
    [
        ("https://h.example/dpp/1", "/a\\b/../doc", True),
        ("https://h.example/dpp/1", "x//y/doc", True),
        ("https://h.example/dpp/1", "/contexts/x/%2e%2e/../doc", True),
        ("https://h.example/dpp/1", "/contexts/%2E./y", True),
        ("https://h.example/dpp/1", "..;x/doc", True),
        # urljoin removes the empty segment of the base path for a relative path. WHATWG URL keeps it.
        ("https://h.example/dpp//1", "doc", True),
        ("https://h.example/a\\b/1", "../doc", True),
        # A Location that every reader reads alike is plain.
        ("https://h.example/dpp//1", "/doc", False),
        ("https://h.example/dpp/1", "/x/y/z", False),
        ("https://h.example/dpp/1", "../x/doc", False),
        ("https://h.example/dpp/1", "/a//b", False),
        ("https://h.example/dpp/1", "https://h.example/a//b", False),
        ("https://h.example/dpp/1", "x/", False),
        ("https://h.example/dpp/1", "?q", False),
        ("https://h.example/dpp/1", "%5c/doc", False),
    ],
)
def test_the_locations_that_the_readers_resolve_apart(base: str, location: str, apart: bool) -> None:
    from dppce.infrastructure.redaction import reads_apart  # noqa: PLC0415 - red until the code lands

    assert reads_apart(base, location) is apart


@pytest.mark.parametrize(
    ("target", "result"),
    [
        # A query or an empty target also reads the base path, which the record does not hold.
        ("?v1", failed("DATA.CONTEXT.NOT_ALLOWED")),
        ("", failed("DATA.CONTEXT.NOT_ALLOWED")),
        # An absolute path does not read the base path.
        ("/contexts/battery/v1", passed("DATA.CONTEXT.OK")),
        (BATTERY, passed("DATA.CONTEXT.OK")),
    ],
)
def test_a_context_target_on_a_base_that_the_consumers_read_apart(
    tmp_path: Path, target: str, result: Any
) -> None:
    final = f"https://dppce.example.test/doc?v=1{UNKNOWN}"
    acquirer = Redirected(PLAIN, recorded(f"<{target}>; {CTX}"), final)
    allowed = [ALLOWED[0], BATTERY, "https://dppce.example.test/doc?v1", "https://dppce.example.test/doc?v=1"]
    assert verdict(contexts(tmp_path, acquirer, allowed_contexts=allowed)) == result


def test_resolver_linkset_does_not_fetch_a_relative_target_on_a_base_that_the_consumers_read_apart() -> None:
    final = f"https://id.example.test/contexts/x/doc{UNKNOWN}"
    lines = recorded('<../linksets/EV0001>; rel="linkset"')
    apart = replace(make_record(1), headers=lines, redirects=(final,))
    assert _advertised([apart]) is None
    assert _advertised([replace(apart, headers=recorded('<?linkset>; rel="linkset"'))]) is None
    absolute = replace(apart, headers=recorded('</linksets/EV0001>; rel="linkset"'))
    assert _advertised([absolute]) == "https://id.example.test/linksets/EV0001"


# The suffix after a Location whose empty ";" parameter urljoin drops: only a query or an empty target
# reads the part of the base that the record does not hold.
QUERY_UNKNOWN = f"#?{REMOVED}"


def _follow(loopback: Any, locations: list[str], link: str) -> tuple[Any, Record]:
    """The transport record of a chain of 302 answers with ``locations``, then a 200 answer with ``link``."""

    def answer(request: Any) -> None:
        hop = len(server.seen) - 1
        if hop < len(locations):
            reply(request, 302, b"", {"Location": locations[hop]})
        else:
            reply(request, headers={"Link": link})

    server = loopback(answer)
    return server, transport().fetch(Request("GET", f"{server.origin}/dpp/1", role="anonymous"))


@pytest.mark.parametrize(
    "locations",
    [
        # Node.js 22 new URL() reads the next segment as the host: http://h2.example/x/doc. urljoin keeps
        # the engine host, and RFC 9110, section 4.2.1, says that a recipient rejects an empty http host.
        ["http:///h2.example/x/doc"],
        ["HTTP:///h2.example/x/doc"],
        ["////h2.example/x/doc"],
        ["/dpp/2", "http:///h2.example/x/doc"],
        # WHATWG URL reads "\" as "/": http://h2.example/doc.
        ["/\\h2.example/doc"],
        ["\\\\h2.example/doc"],
        ["http:/\\h2.example/doc"],
    ],
)
def test_a_location_that_a_consumer_reads_with_another_host_is_not_followed(
    loopback: Any, locations: list[str]
) -> None:
    server, record = _follow(loopback, locations, f"</contexts/battery/v1>; {CTX}")
    assert record.error == "redirect_out_of_scope"
    assert record.status == 302
    assert len(server.seen) == len(locations), "the engine fetches no answer of another URL"
    assert len(record.redirects) == len(locations) - 1


@pytest.mark.parametrize(
    "locations",
    [
        # urljoin drops an empty query or fragment. Node.js 22 and requests read the same base.
        ["/x/y/z?"],
        ["/x/y/z#"],
        ["/x/y/z;"],
        # A later hop with an absolute path does not read the path of an earlier hop.
        ["/a?", "/x/y/z"],
        ["/a\\b/../c", "/x/y/z"],
        ["x//y/doc", "/x/y/z"],
    ],
)
@pytest.mark.parametrize("body", [BODY, PLAIN])
def test_a_relative_context_target_after_a_location_that_every_reader_reads_alike_keeps_its_pass(
    tmp_path: Path, loopback: Any, locations: list[str], body: bytes
) -> None:
    server, record = _follow(loopback, locations, f"<../../contexts/battery/v1>; {CTX}")
    assert record.status == 200
    assert record.redirects[-1] in (f"{server.origin}/x/y/z", f"{server.origin}/x/y/z{QUERY_UNKNOWN}")
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    allowed = [ALLOWED[0], f"{server.origin}/contexts/battery/v1"]
    outcome = contexts(tmp_path, Redirected(body, links, record.redirects[-1]), allowed_contexts=allowed)
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize(
    ("locations", "suffix"),
    [
        # Node.js 22 reads the base /x/y/z; and then a query target as /x/y/z;?v1. urljoin gives /x/y/z?v1.
        (["/x/y/z;"], QUERY_UNKNOWN),
        (["/x/y/z;?a=1"], QUERY_UNKNOWN),
        # A query hop reads the query of the earlier hop.
        (["/x/y/z;", "?a=1"], QUERY_UNKNOWN),
        # A relative hop reads the path of the earlier hop, which the record does not hold.
        (["/a\\b/x", "y/z"], UNKNOWN),
        (["/x/y/z;", "/a\\b/x", "?a=1"], UNKNOWN),
    ],
)
def test_a_query_target_after_a_dropped_empty_parameter_counts_unresolved(
    tmp_path: Path, loopback: Any, locations: list[str], suffix: str
) -> None:
    server, record = _follow(loopback, locations, f"<?v1>; {CTX}")
    assert record.status == 200
    assert record.redirects[-1].endswith(suffix)
    assert all(hop.count("#") <= 1 for hop in record.redirects)
    links = tuple((k, v) for k, v in record.headers if k.lower() == "link")
    base = record.redirects[-1].partition("#")[0]
    allowed = [ALLOWED[0], urljoin(base, "?v1"), urljoin(base, "")]
    for target in ("?v1", ""):
        lines = tuple((k, v.replace("<?v1>", f"<{target}>")) for k, v in links)
        outcome = contexts(tmp_path, Redirected(PLAIN, lines, record.redirects[-1]), allowed_contexts=allowed)
        assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    # A relative path or an absolute path target does not read the query.
    if suffix == QUERY_UNKNOWN:
        allowed += [f"{server.origin}/x/y/v1", f"{server.origin}/contexts/battery/v1"]
        for target in ("v1", "/contexts/battery/v1"):
            lines = tuple((k, v.replace("<?v1>", f"<{target}>")) for k, v in links)
            outcome = contexts(
                tmp_path, Redirected(PLAIN, lines, record.redirects[-1]), allowed_contexts=allowed
            )
            assert verdict(outcome) == passed("DATA.CONTEXT.OK")


def test_resolver_linkset_reads_a_relative_target_after_a_dropped_empty_parameter() -> None:
    final = f"https://id.example.test/x/doc{QUERY_UNKNOWN}"
    record = replace(
        make_record(1), headers=recorded('<../linksets/EV0001>; rel="linkset"'), redirects=(final,)
    )
    assert _advertised([record]) == "https://id.example.test/linksets/EV0001"
    assert _advertised([replace(record, headers=recorded('<?linkset>; rel="linkset"'))]) is None


@pytest.mark.parametrize("suffix", [UNKNOWN, QUERY_UNKNOWN])
def test_the_access_check_reads_a_marked_redirect_as_the_url_that_the_engine_fetched(
    tmp_path: Path, suffix: str
) -> None:
    from tests.test_review_round2 import _POLICY, _context, _Redirected, restricted_fields  # noqa: PLC0415

    # The suffix removed nothing from the URL, so a canary cannot hide there.
    acquirer = _Redirected(b"<p>clean</p>", redirects=(f"http://sut.example/dpp/x{suffix}",))
    outcome = restricted_fields(_context(tmp_path, _POLICY, acquirer))
    assert (outcome.passed, outcome.reason_code) == (True, "ACCESS.POLICY.ENFORCED")
    leaked = _Redirected(b"<p>clean</p>", redirects=(f"http://sut.example/dpp/CANARY-test{suffix}",))
    outcome = restricted_fields(_context(tmp_path, _POLICY, leaked))
    assert (outcome.passed, outcome.reason_code) == (False, "ACCESS.LEAK.FETCH")


# One Link line of about 64 KiB with distinct relative context targets, on a base path of about 60 KiB.
_MANY = ", ".join(f'<a{i}>; rel="{JSONLD_CONTEXT}"' for i in range(1200))
_LONG_BASES = (
    "https://h.example" + "/" * 60000 + "doc",
    "https://h.example" + "/." * 30000 + "/doc",
    "https://h.example/" + "\\" * 60000 + "/doc",
    "https://h.example" + "/a" * 30000 + "/doc" + UNKNOWN,
)
_LONG_IDS = ("empty-segments", "dot-segments", "backslashes", "marked")


@pytest.mark.parametrize("base", _LONG_BASES, ids=_LONG_IDS)
def test_the_context_links_of_one_answer_on_a_long_odd_base_cost_little(base: str) -> None:
    from dppce.adapters.data import _link_contexts  # noqa: PLC0415 - a private reader of one record

    lines = redact_response_headers((("Link", _MANY), ("Content-Type", "application/json")))
    record = replace(make_record(1, b"{}", "https://h.example/dpp/1"), headers=lines, redirects=(base,))
    start = time.perf_counter()
    found = _link_contexts(record, ["https://h.example/ctx"], {}).found
    # The bound is wide, so a slow machine passes. Before the fix, one line took from 8 s to 19 s.
    assert time.perf_counter() - start < 3
    assert len(found) >= 1200


@pytest.mark.parametrize("base", _LONG_BASES, ids=_LONG_IDS)
def test_the_linkset_links_of_one_answer_on_a_long_odd_base_cost_little(base: str) -> None:
    many = ", ".join(f'<a{i}>; rel="next"' for i in range(1200)) + ', <a>; rel="linkset"'
    record = replace(make_record(1), headers=redact_response_headers((("Link", many),)), redirects=(base,))
    start = time.perf_counter()
    _advertised([record])
    assert time.perf_counter() - start < 3


# -- an application/ld+json answer whose Content-Type value pyld reads as another type -----------------

FOREIGN = f"<{EVIL}>; {CTX}"


@pytest.mark.parametrize(
    "headers",
    [
        (("Content-Type", "application/ld+json; charset=utf-8"),),
        (("Content-Type", "Application/LD+JSON"),),
        (("Content-Type", 'application/ld+json;profile="x"'),),
        (("Content-Type", "application/ld+json"), ("Content-Type", "text/html")),
    ],
)
def test_pyld_reads_the_link_of_an_ld_json_answer_with_another_content_type_value(
    tmp_path: Path, headers: tuple[tuple[str, str], ...]
) -> None:
    # pyld 3.0.0 compares the whole value, with the lines joined, with "application/ld+json".
    acquirer = Linked(BODY, (*headers[1:], *recorded(FOREIGN)), media=headers[0][1])
    assert verdict(contexts(tmp_path, acquirer)) == blocked("DATA.CONTEXT.LINK_UNREADABLE")
    # pyld can read a context after the part where the engine stopped.
    stopped = recorded(f'<{ALLOWED[0]}>; {CTX}; title="a\x01b"')
    assert not parse_link(stopped[0][1]).complete
    malformed = Linked(BODY, (*headers[1:], *stopped), media=headers[0][1])
    assert verdict(contexts(tmp_path, malformed)) == blocked("DATA.CONTEXT.LINK_UNREADABLE")
    # An allowed context link whose pinned copy imports a context outside the allowlist.
    other = "https://example.test/b"
    files = {ALLOWED[0]: pin(tmp_path, "a.json", {"@context": {"@import": "https://other.test/ctx"}})}
    body = json.dumps({"@context": other}).encode()
    imported = Linked(body, (*headers[1:], *recorded(f"<{ALLOWED[0]}>; {CTX}")), media=headers[0][1])
    outcome = contexts(tmp_path, imported, allowed_contexts=[ALLOWED[0], other], context_files=files)
    assert verdict(outcome) == blocked("DATA.CONTEXT.LINK_UNREADABLE")


def test_an_ld_json_answer_keeps_an_allowed_link_and_its_fails(tmp_path: Path) -> None:
    media = "application/ld+json; charset=utf-8"
    allowed = Linked(BODY, recorded(f"<{ALLOWED[0]}>; {CTX}"), media=media)
    assert verdict(contexts(tmp_path, allowed)) == passed("DATA.CONTEXT.OK")
    # The header does not count as a context for an application/ld+json answer, so it hides no fail.
    assert verdict(contexts(tmp_path, Linked(PLAIN, recorded(FOREIGN), media=media))) == failed(
        "DATA.CONTEXT.MISSING"
    )
    foreign = b'{"@context": "https://other.test/ctx"}'
    assert verdict(contexts(tmp_path, Linked(foreign, recorded(FOREIGN), media=media))) == failed(
        "DATA.CONTEXT.NOT_ALLOWED"
    )


def test_an_exact_ld_json_answer_ignores_the_link_header(tmp_path: Path) -> None:
    acquirer = Linked(BODY, recorded(FOREIGN), media="application/ld+json")
    assert verdict(contexts(tmp_path, acquirer)) == passed("DATA.CONTEXT.OK")


# -- an alternate JSON-LD document of an answer without a JSON media type --------------------------------

ALTERNATE = '<https://evil.test/doc>; rel="alternate"; type="application/ld+json"'
LATER_ALTERNATE = '<https://evil.test/doc>; rel="next"; rel="alternate"; type="application/ld+json"'


@pytest.mark.parametrize(
    "media", ["text/html", "text/plain", "application/octet-stream", "", "application/json; charset=utf-8"]
)
@pytest.mark.parametrize("line", [ALTERNATE, LATER_ALTERNATE])
def test_an_alternate_json_ld_document_of_an_answer_that_pyld_reads_as_not_json_is_blocked(
    tmp_path: Path, media: str, line: str
) -> None:
    # pyld 3.0.0 loads the alternate document if the whole Content-Type value is not a JSON type.
    outcome = contexts(tmp_path, Linked(BODY, recorded(line), media=media))
    assert verdict(outcome) == blocked("DATA.CONTEXT.LINK_UNREADABLE")


@pytest.mark.parametrize("media", ["application/json", "application/problem+json", "application/ld+json"])
def test_an_alternate_link_of_a_json_answer_keeps_its_pass(tmp_path: Path, media: str) -> None:
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(ALTERNATE), media=media))) == passed(
        "DATA.CONTEXT.OK"
    )


def test_the_alternate_limit_never_hides_a_fail(tmp_path: Path) -> None:
    lines = recorded(ALTERNATE)
    assert verdict(contexts(tmp_path, Linked(PLAIN, lines, media="text/html"))) == failed(
        "DATA.CONTEXT.MISSING"
    )
    foreign = b'{"@context": "https://other.test/ctx"}'
    assert verdict(contexts(tmp_path, Linked(foreign, lines, media="text/html"))) == failed(
        "DATA.CONTEXT.NOT_ALLOWED"
    )


def test_an_alternate_link_recorded_by_the_transport_is_blocked(tmp_path: Path, loopback: Any) -> None:
    server = loopback(lambda r: reply(r, body=BODY, headers={"Content-Type": "text/html", "Link": ALTERNATE}))
    record = transport().fetch(Request("GET", f"{server.origin}/dpp/1"))
    assert record.header("link") == ALTERNATE
    others = tuple((k, v) for k, v in record.headers if k.lower() != "content-type")
    acquirer = Linked(record.body, others, media=record.header("content-type") or "")
    assert verdict(contexts(tmp_path, acquirer)) == blocked("DATA.CONTEXT.LINK_UNREADABLE")


# -- a later type parameter that a processor reads -------------------------------------------------------

# jsonld.js and pyld assign each parameter to the link, so the last parameter named exactly "type"
# counts. The record keeps the first kept type. So a later type="application/ld+json" stops reading.
LATER_TYPES = (
    '<https://evil.test/doc>; rel="alternate"; type="application/json"; type="application/ld+json"',
    '<https://evil.test/doc>; rel="alternate"; TYPE="application/json"; type="application/ld+json"',
    '<https://evil.test/doc>; rel="alternate"; Type="application/json"; type="application/ld+json"',
    '<https://evil.test/doc>; rel="alternate"; type="application/linkset+json"; type="application/ld+json"',
    '<https://evil.test/doc>; rel="alternate"; type=application/json; type="application/ld+json"',
    '<https://evil.test/doc>; rel="next"; type="application/json"; rel="alternate"; '
    'type="application/ld+json"',
    '<https://evil.test/doc>; rel="next"; rel="alternate"; type="application/json"; '
    'type="application/ld+json"',
)


@pytest.mark.parametrize("media", ["application/json; charset=utf-8", "text/html"])
@pytest.mark.parametrize("line", LATER_TYPES)
def test_a_later_type_that_a_processor_reads_as_json_ld_fails(tmp_path: Path, media: str, line: str) -> None:
    lines = recorded(line)
    assert lines[0][1].endswith(f", {REMOVED}")
    assert redact_link(lines[0][1]) == lines[0][1]
    assert verdict(contexts(tmp_path, Linked(BODY, lines, media=media))) == failed(
        "DATA.CONTEXT.LINK_MALFORMED"
    )
    assert verdict(contexts(tmp_path, Linked(PLAIN, lines, media=media))) == failed("DATA.CONTEXT.MISSING")


@pytest.mark.parametrize(
    "line",
    [
        '<https://x.test/a>; rel="alternate"; type="application/json"; title="x"',
        '<https://x.test/a>; rel="alternate"; type="application/json"; type="application/json"',
        '<https://r.example/x>; rel="gs1:pip"; type="text/html"; hreflang="en"; title="Product"',
    ],
)
def test_a_type_that_no_processor_reads_as_json_ld_keeps_its_pass(tmp_path: Path, line: str) -> None:
    lines = recorded(line)
    assert parse_link(lines[0][1]).complete
    outcome = contexts(tmp_path, Linked(BODY, lines, media="application/json; charset=utf-8"))
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        (ALTERNATE, ALTERNATE),
        (
            '<https://evil.test/doc>; rel="alternate foo"; type="application/ld+json"',
            f'<https://evil.test/doc>; rel="alternate"; type="application/ld+json"; {REMOVED}',
        ),
        (
            '<https://r.example/x>; rel="gs1:pip"; type="text/html"; hreflang="en"; title="Product"',
            f'<https://r.example/x>; rel="gs1:pip"; {REMOVED}',
        ),
    ],
)
def test_a_link_with_at_most_one_json_ld_type_records_complete(line: str, kept: str) -> None:
    # Only a later type that differs from the kept one stops reading.
    assert recorded(line) == (("Link", kept),)
    assert parse_link(kept).complete
    assert redact_link(kept) == kept


def test_a_later_type_recorded_by_the_transport_fails(tmp_path: Path, loopback: Any) -> None:
    headers = {"Content-Type": "application/json; charset=utf-8", "Link": LATER_TYPES[0]}
    server = loopback(lambda r: reply(r, body=BODY, headers=headers))
    record = transport().fetch(Request("GET", f"{server.origin}/dpp/1"))
    kept = '<https://evil.test/doc>; rel="alternate"; type="application/json"'
    assert record.header("link") == f"{kept}; {REMOVED}, {REMOVED}"
    others = tuple((k, v) for k, v in record.headers if k.lower() != "content-type")
    acquirer = Linked(record.body, others, media=record.header("content-type") or "")
    assert verdict(contexts(tmp_path, acquirer)) == failed("DATA.CONTEXT.LINK_MALFORMED")
