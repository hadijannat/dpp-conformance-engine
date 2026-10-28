"""The processor model of Link reading: the linear scanner, the gate, the target parameter, joined lines.

The agreement check compares the engine reading with a model of the Link parsers of jsonld.js 8.3.3
and pyld 3.0.0. A system under test must not get a false pass, or turn a fail into blocked, with a
value that these parsers read differently. A common valid value keeps its pass. Architecture
sections 8 and 10. No test contacts a host.
"""

from __future__ import annotations

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
)
from tests.support import make_record, reply
from tests.test_data_document_source import ALLOWED, blocked, failed, passed, verdict
from tests.test_review_findings import transport
from tests.test_rulepack_v2 import BODY, JSONLD_CONTEXT, PLAIN, Linked, contexts

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
def test_a_relative_context_target_on_a_base_with_an_empty_segment_is_blocked(
    tmp_path: Path, body: bytes
) -> None:
    # urljoin gives BATTERY. WHATWG URL and pyld 3.0.0 keep the empty segment: .../x/contexts/battery/v1.
    acquirer = Redirected(
        body, recorded(f"<../../contexts/battery/v1>; {CTX}"), "https://dppce.example.test/x//y/z"
    )
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == blocked("DATA.CONTEXT.LINK_UNREADABLE")


def test_the_base_path_limit_never_hides_a_fail(tmp_path: Path) -> None:
    acquirer = Redirected(
        BODY, recorded(f"<../contexts/battery/v1>; {CTX}"), "https://dppce.example.test/x//y/z"
    )
    outcome = contexts(tmp_path, acquirer, allowed_contexts=[ALLOWED[0], BATTERY])
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


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


def test_resolver_linkset_does_not_fetch_a_relative_target_on_a_base_with_an_empty_segment() -> None:
    lines = recorded('<../linksets/EV0001>; rel="linkset"')
    odd = replace(make_record(1), headers=lines, redirects=("https://id.example.test/dpp//x/y",))
    plain = replace(odd, redirects=("https://id.example.test/dpp/x/y",))
    assert _advertised([odd]) is None
    assert _advertised([plain]) == "https://id.example.test/dpp/linksets/EV0001"
