"""Link values: RFC 8288 reading, redaction, and the checks that read the recorded form.

A system under test must not turn a fail or a pass into blocked with a common valid Link value or
with a malformed value of its own. Architecture sections 8 and 10. No test contacts a host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.infrastructure.redaction import REMOVED, parse_link, redact_link, redact_response_headers
from dppce.models import ExecutionStatus
from tests.test_adapters_resolver import LINKSET_TYPE
from tests.test_data_document_source import ALLOWED, blocked, failed, passed, verdict
from tests.test_link_relations import ADVERTISED, _advertised_linkset, _advertising_run, _outcome
from tests.test_rulepack_v2 import BODY, JSONLD_CONTEXT, PLAIN, Linked, contexts

CTX = f'rel="{JSONLD_CONTEXT}"'
SECRET = "S3CRET"

# -- parse_link --------------------------------------------------------------------------------------


def test_a_quoted_comma_or_semicolon_does_not_split() -> None:
    parsed = parse_link('<https://a.test/x>; rel="next"; title="a, b; c", <https://a.test/y>; rel=prev')
    assert parsed.complete
    assert [(x.target, x.relations, x.media_type, x.other) for x in parsed.links] == [
        ("https://a.test/x", ("next",), None, True),
        ("https://a.test/y", ("prev",), None, False),
    ]


def test_a_quoted_string_can_hold_an_escaped_quote() -> None:
    parsed = parse_link(r'<https://a.test/x>; title="a \", b"; rel="next"')
    assert parsed.complete
    assert [x.relations for x in parsed.links] == [("next",)]


def test_a_kept_type_parameter_is_read_in_lower_case() -> None:
    links = parse_link('<https://a.test/x>; rel="linkset"; type="Application/Linkset+JSON"').links
    assert (links[0].media_type, links[0].other) == ("application/linkset+json", False)
    other = parse_link('<https://a.test/x>; rel="linkset"; type="text/css"').links
    assert (other[0].media_type, other[0].other) == (None, True)
    # RFC 8288, appendix B.3: an unquoted value is read up to the next ";" or ",".
    unquoted = parse_link("<https://a.test/x>; rel=linkset; type=application/linkset+json").links
    assert (unquoted[0].media_type, unquoted[0].other) == ("application/linkset+json", False)


def test_the_marker_of_redaction_reads_as_another_parameter() -> None:
    assert parse_link(f'<https://a.test/x>; rel="next"; {REMOVED}').links[0].other


def test_the_first_rel_counts_and_a_later_rel_is_another_parameter() -> None:
    # RFC 8288, section 3.3: a parser ignores each rel after the first.
    links = parse_link('<https://a.test/x>; rel="next"; REL="prev"').links
    assert [(x.relations, x.other) for x in links] == [(("next",), True)]


def test_a_relation_is_compared_without_case() -> None:
    # RFC 8288, section 2.1.2: an extension relation is compared without case, too.
    value = f'<https://a.test/x>; rel="NEXT {JSONLD_CONTEXT.upper()} GS1:ACTIVITYIDEAS"'
    assert parse_link(value).links[0].relations == ("next", JSONLD_CONTEXT, "gs1:activityIdeas")


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        # RFC 8288, appendix B.2: reading stops where a link-value does not start with a target.
        ("", REMOVED),
        (SECRET, REMOVED),
        (f'<https://a.test/x>; rel="next", {SECRET}', f'<https://a.test/x>; rel="next", {REMOVED}'),
        (f"<https://a.test/x> {SECRET}", f"<https://a.test/x>, {REMOVED}"),
        (f"<https://a.test/{SECRET}", REMOVED),  # a target without ">"
        # The links before the stop are kept, whatever follows.
        (
            f'<https://a.test/x>; rel="next", <https://a.test/y>; rel=prev, {SECRET} <https://a.test/z>',
            f'<https://a.test/x>; rel="next", <https://a.test/y>; rel="prev", {REMOVED}',
        ),
    ],
)
def test_reading_stops_where_a_link_value_is_not_well_formed(value: str, kept: str) -> None:
    assert redact_link(value) == kept
    assert not parse_link(value).complete or not value


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ('<https://a.test/x>; rel="next"; rel="prev"', f'<https://a.test/x>; rel="next"; {REMOVED}'),
        (f'<https://a.test/x>; title="{SECRET}', f"<https://a.test/x>; {REMOVED}"),  # B.4: to the end
        (f"<https://a.test/x>; ={SECRET}", f"<https://a.test/x>; {REMOVED}"),
        ("<https://a.test/x>; rel=gs1:pip", '<https://a.test/x>; rel="gs1:pip"'),
        ("<https://a.test/x>; type=application/json", '<https://a.test/x>; type="application/json"'),
        # A target that is not a URI reference gets the marker, and the other links are kept.
        (
            f"<http://[{SECRET}>; rel=next, <https://a.test/y>",
            '<%3Cremoved%3E>; rel="next", <https://a.test/y>',
        ),
    ],
)
def test_a_lenient_link_value_is_read_as_appendix_b_reads_it(value: str, kept: str) -> None:
    assert redact_link(value) == kept
    assert parse_link(value).complete


# -- redact_link ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("<https://x.test/s.css>; rel=preload; as=style", f"<https://x.test/s.css>; {REMOVED}"),
        ('<https://x.test/a>; rel="linkset preload"', f'<https://x.test/a>; rel="linkset"; {REMOVED}'),
        (
            '<https://x.test/a>; rel="linkset"; type="application/linkset+json"',
            '<https://x.test/a>; rel="linkset"; type="application/linkset+json"',
        ),
        (
            f'<https://x.test/c>; {CTX}; type="Application/LD+JSON"',
            f'<https://x.test/c>; {CTX}; type="application/ld+json"',
        ),
        (
            '<https://x.test/a>; type="application/json"; type="application/json"; rel=next',
            f'<https://x.test/a>; rel="next"; type="application/json"; {REMOVED}',
        ),
        (
            '<https://x.test/a>; rel="next"; title="a, b"; anchor="#x; y"',
            f'<https://x.test/a>; rel="next"; {REMOVED}',
        ),
    ],
)
def test_an_unknown_relation_is_dropped_by_word_and_its_link_gets_the_marker(value: str, kept: str) -> None:
    assert redact_link(value) == kept


@pytest.mark.parametrize(
    "value",
    [
        f'<https://x.test/a>; rel="next {SECRET}"',
        f'<https://x.test/a>; rel="https://x.test/{SECRET}"',
        f"<https://x.test/a>; rel={SECRET}",
        f'<https://x.test/a>; rel=next; title="{SECRET}, {SECRET}; x"',
        f"<https://x.test/a>; rel=next; type={SECRET}",
        f'<https://x.test/a?token={SECRET}>; rel="linkset"',
        f'<https://x.test/c?api_key={SECRET}>; {CTX}; type="application/ld+json"',
        f'<https://x.test/a>; rel="next"; {SECRET}',
        f'<https://x.test/a>; rel="next"; rel="{SECRET}"',
        f"<https://x.test/a>; rel=next {SECRET}; title={SECRET}",
        f'<https://x.test/a>; rel="next", {SECRET}',
        f"<https://x.test/a>; {CTX}, <http://[::1/{SECRET}>; rel=next",
        f'<https://x.test/a>; rel="{SECRET.lower()}:{SECRET}"',
    ],
)
def test_a_secret_never_reaches_the_record(value: str) -> None:
    recorded = dict(redact_response_headers((("Link", value),)))["Link"]
    assert SECRET not in recorded
    assert recorded != REMOVED, "a well-formed value keeps its targets"


@pytest.mark.parametrize(
    "value",
    [
        "<https://x.test/s.css>; rel=preload; as=style, <https://x.test/a>; rel=next",
        f'<https://x.test/c?token=1&page=2#f>; {CTX}; type="application/ld+json"; title="t, u"',
        '<https://x.test/a>; rel="linkset preload"; type="text/css"',
        '<https://x.test/a>; rel="Next LAST gs1:pip"; type="application/json"; hreflang=de',
        REMOVED,
        f"<https://x.test/a>; {REMOVED}",
        f'<https://x.test/a>; rel="next", {SECRET}',
        "<http://[::1>; REL=Next; rel=prev, <https://x.test/b>; rel=HTTP://WWW.W3.ORG/NS/JSON-LD#CONTEXT",
    ],
)
def test_redaction_is_idempotent_and_its_output_parses(value: str) -> None:
    once = redact_link(value)
    assert redact_link(once) == once
    assert parse_link(once) == parse_link(redact_link(once))
    # The record shows whether reading stopped before the end of the value.
    assert parse_link(once).complete is parse_link(value).complete


# -- data.context reads the recorded form --------------------------------------------------------------


def recorded(*values: str) -> tuple[tuple[str, str], ...]:
    return redact_response_headers(tuple(("Link", v) for v in values))


COMMON = (
    "<https://x.test/s.css>; rel=preload; as=style",
    '<https://x.test/a>; rel="linkset preload"',
)


@pytest.mark.parametrize("value", COMMON)
def test_a_common_link_keeps_a_pass(tmp_path: Path, value: str) -> None:
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == passed("DATA.CONTEXT.OK")


@pytest.mark.parametrize("value", COMMON)
def test_a_common_link_keeps_the_fail_of_a_missing_context(tmp_path: Path, value: str) -> None:
    assert verdict(contexts(tmp_path, Linked(PLAIN, recorded(value)))) == failed("DATA.CONTEXT.MISSING")


def test_the_standard_context_link_of_json_ld_1_1_is_read(tmp_path: Path) -> None:
    value = f'<{ALLOWED[0]}>; {CTX}; type="application/ld+json"'
    outcome = contexts(tmp_path, Linked(PLAIN, recorded(value)))
    assert verdict(outcome) == passed("DATA.CONTEXT.OK")
    assert outcome.observations[0].summary["contexts"] == 1


@pytest.mark.parametrize("title", ['"ctx"', '"a, b"', '"a; b"', "x"])
def test_a_context_link_with_another_parameter_names_its_target(tmp_path: Path, title: str) -> None:
    allowed = contexts(tmp_path, Linked(PLAIN, recorded(f"<{ALLOWED[0]}>; {CTX}; title={title}")))
    assert verdict(allowed) == passed("DATA.CONTEXT.OK")
    other = contexts(tmp_path, Linked(PLAIN, recorded(f"<https://other.test/ctx>; {CTX}; title={title}")))
    assert verdict(other) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert other.observations[0].summary["not_allowed"] == ["https://other.test/ctx"]


@pytest.mark.parametrize(
    "value",
    [
        SECRET,
        f"{SECRET}, <{ALLOWED[0]}>; {CTX}",  # reading stops before the first target
        f"<{ALLOWED[0]}> {SECRET}; {CTX}",  # reading stops after a target without parameters
        f"<{ALLOWED[0]}; {CTX}",  # a target without ">"
    ],
)
def test_a_malformed_link_names_no_context_and_cannot_hide_a_missing_context(
    tmp_path: Path, value: str
) -> None:
    assert verdict(contexts(tmp_path, Linked(PLAIN, recorded(value)))) == failed("DATA.CONTEXT.MISSING")
    assert verdict(contexts(tmp_path, Linked(BODY, recorded(value)))) == passed("DATA.CONTEXT.OK")


EVIL = "https://evil.test/ctx"


@pytest.mark.parametrize(
    "value",
    [
        # RFC 8288, appendix B.2: the links before a malformed link-value are read.
        f"<{EVIL}>; {CTX}, <http://[::1>; rel=next",
        f"<{EVIL}>; {CTX}, {SECRET}",
        # A target that is not a URI reference does not hide the links after it.
        f"<http://[::1>; rel=next, <{EVIL}>; {CTX}",
        # RFC 8288, section 3.3: the first rel counts.
        f'<{EVIL}>; {CTX}; rel="next"',
        # RFC 8288, appendix B.3: an unquoted value is read up to ";" or ",".
        f"<{EVIL}>; {CTX}; type=application/ld+json",
        f"<{EVIL}>; rel={JSONLD_CONTEXT}",
        # RFC 8288, section 2.1.2: a relation is compared without case.
        f'<{EVIL}>; rel="{JSONLD_CONTEXT.upper()}"',
    ],
)
def test_a_reshaped_context_link_to_a_foreign_target_still_fails(tmp_path: Path, value: str) -> None:
    outcome = contexts(tmp_path, Linked(BODY, recorded(value)))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [EVIL]


def test_a_second_rel_keeps_an_allowed_context_link(tmp_path: Path) -> None:
    value = f'<{ALLOWED[0]}>; {CTX}; rel="next"'
    assert verdict(contexts(tmp_path, Linked(PLAIN, recorded(value)))) == passed("DATA.CONTEXT.OK")


def test_a_context_link_whose_target_is_not_a_uri_reference_is_not_allowed(tmp_path: Path) -> None:
    outcome = contexts(tmp_path, Linked(BODY, recorded(f"<http://[{SECRET}>; {CTX}")))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert SECRET not in repr(outcome)


def test_a_context_target_that_redaction_changed_is_not_on_the_allowlist(tmp_path: Path) -> None:
    value = f"<{ALLOWED[0]}?token={SECRET}>; {CTX}"
    outcome = contexts(tmp_path, Linked(PLAIN, recorded(value)))
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")
    assert outcome.observations[0].summary["not_allowed"] == [f"{ALLOWED[0]}?token=%3Cremoved%3E"]
    assert SECRET not in repr(outcome)


def test_a_changed_target_equal_to_a_changed_allowed_url_is_blocked(tmp_path: Path) -> None:
    # The engine cannot tell the two credential values apart, so it cannot compare them exactly.
    allowed = [f"{ALLOWED[0]}?token=TEST-ONLY-1"]
    value = f"<{ALLOWED[0]}?token={SECRET}>; {CTX}"
    outcome = contexts(tmp_path, Linked(PLAIN, recorded(value)), allowed_contexts=allowed)
    assert verdict(outcome) == blocked("DATA.CONTEXT.LINK_UNREADABLE")
    # A limit never hides a fail found in the body.
    foreign = b'{"@context": "https://other.test/ctx"}'
    outcome = contexts(tmp_path, Linked(foreign, recorded(value)), allowed_contexts=allowed)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


def test_an_unchanged_target_is_never_blocked_by_a_changed_allowed_url(tmp_path: Path) -> None:
    # Redaction drops the fragment of the allowed URL, but the recorded target has no marker.
    allowed = [f"{ALLOWED[0]}#v1"]
    outcome = contexts(tmp_path, Linked(PLAIN, recorded(f"<{ALLOWED[0]}>; {CTX}")), allowed_contexts=allowed)
    assert verdict(outcome) == failed("DATA.CONTEXT.NOT_ALLOWED")


def test_a_value_that_redaction_removed_names_no_context(tmp_path: Path) -> None:
    assert verdict(contexts(tmp_path, Linked(PLAIN, (("Link", REMOVED),)))) == failed("DATA.CONTEXT.MISSING")
    assert verdict(contexts(tmp_path, Linked(BODY, (("Link", REMOVED),)))) == passed("DATA.CONTEXT.OK")


# -- resolver.linkset reads a kept type parameter --------------------------------------------------------


def test_resolver_linkset_reads_a_linkset_link_with_a_kept_type(tmp_path: Path, loopback: Any) -> None:
    advertised = (200, _advertised_linkset(), {"Content-Type": LINKSET_TYPE})
    link = f'<{ADVERTISED}>; rel="linkset"; type="application/linkset+json"'
    outcome, api, _ = _advertising_run(tmp_path, loopback, advertised, link=link)
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert api.hits(ADVERTISED) == 1
    assert len(outcome.observations) == 3


def test_resolver_linkset_still_skips_a_linkset_link_with_a_marker(tmp_path: Path, loopback: Any) -> None:
    advertised = (200, _advertised_linkset(anchor="/elsewhere"), {"Content-Type": LINKSET_TYPE})
    link = f'<{ADVERTISED}>; rel="linkset"; type="application/linkset+json"; title="x"'
    outcome, api, _ = _advertising_run(tmp_path, loopback, advertised, link=link)
    assert _outcome(outcome) == (ExecutionStatus.COMPLETED, True, "RESOLVER.LINKSET.OK")
    assert api.hits(ADVERTISED) == 0
