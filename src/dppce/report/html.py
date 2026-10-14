"""Render an evidence envelope as one self-contained, accessible HTML page.

Target: WCAG 2.2 level AA. The page has no script and loads nothing from the network.
Every value from the envelope is escaped. A verdict is always shown as text, never by color
alone. Automated checks do not establish full accessibility conformance: see
docs/reference/accessibility.md for the manual review record.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from html import escape

from dppce.evidence.envelope import decision_digest
from dppce.models import EvidenceEnvelope, Ratio, VerificationReport

_CSS = """
:root { color-scheme: light dark; --fg: #1a1a1a; --bg: #ffffff; --muted: #4a4a4a; --line: #767676;
  --panel: #f3f3f3; --link: #0b4f9e; }
@media (prefers-color-scheme: dark) { :root { --fg: #f2f2f2; --bg: #121212; --muted: #c8c8c8;
  --line: #9a9a9a; --panel: #1f1f1f; --link: #9cc7ff; } }
body { font: 1rem/1.55 system-ui, sans-serif; color: var(--fg); background: var(--bg); margin: 0; }
main, header, footer { max-width: 70rem; margin: 0 auto; padding: 1rem; }
h1 { font-size: 1.8rem; } h2 { font-size: 1.35rem; margin-top: 2rem; border-bottom: 1px solid var(--line); }
a { color: var(--link); } a:focus, summary:focus { outline: 3px solid var(--link); outline-offset: 2px; }
.skip { position: absolute; left: -999rem; } .skip:focus { position: static; }
.notice { border: 2px solid var(--line); background: var(--panel); padding: .75rem 1rem; }
.scroll { overflow-x: auto; } table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
caption { text-align: left; font-weight: 600; padding: .4rem 0; }
th, td { border: 1px solid var(--line); padding: .4rem .55rem; text-align: left; vertical-align: top; }
th { background: var(--panel); } code { overflow-wrap: anywhere; }
.verdict { font-weight: 700; white-space: nowrap; } dt { font-weight: 600; } dd { margin: 0 0 .6rem 0; }
"""

# A text symbol goes with each verdict word, so that meaning never depends on color.
_SYMBOL = {"pass": "✓", "fail": "✗", "inconclusive": "?", "not_applicable": "-", "error": "!"}


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _verdict(value: str) -> str:
    return f'<span class="verdict">{_SYMBOL.get(value, "")} {_e(value.replace("_", " "))}</span>'


def _ratio(ratio: Ratio) -> str:
    """A count with its denominator. A percentage is shown only together with both."""
    text = f"{ratio.numerator} of {ratio.denominator} {_e(ratio.of)}"
    if ratio.denominator == 0:
        return f"{text} (no percentage: the denominator is zero)"
    percent = (200 * ratio.numerator + ratio.denominator) // (2 * ratio.denominator)
    return f"{text} ({percent}%)"


def _table(caption: str, head: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    """Cells are trusted HTML fragments. Callers escape every value with ``_e``."""
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    if not body:
        return f"<p>{_e(caption)}: none.</p>"
    heads = "".join(f'<th scope="col">{_e(h)}</th>' for h in head)
    return (
        f'<div class="scroll" role="region" aria-label="{_e(caption)}" tabindex="0"><table>'
        f"<caption>{_e(caption)}</caption><thead><tr>{heads}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{_e(k.replace('_', ' '))}: {v}" for k, v in counts.items()) or "none"


def _summary(envelope: EvidenceEnvelope) -> str:
    decision, manifest = envelope.decision, envelope.decision.manifest
    counts = decision.verdict_counts
    assessed = len(decision.requirement_results)

    def n(verdict: str) -> int:
        return counts.get(verdict, 0)

    return (
        '<section aria-labelledby="summary"><h2 id="summary">Summary in plain language</h2>'
        f"<p>The engine tested the system <strong>{_e(manifest.sut.name)}</strong> with the profile "
        f"<strong>{_e(manifest.profile_id)}</strong> in <strong>{_e(manifest.mode.value)}</strong> mode.</p>"
        f"<p>Overall outcome for the selected catalogue: {_verdict(decision.overall.value)}. "
        f"{_e(decision.overall_reason)}</p>"
        f"<p>Of {assessed} requirement results: {n('pass')} passed, {n('fail')} failed, "
        f"{n('inconclusive')} are inconclusive, {n('not_applicable')} do not apply, and "
        f"{n('error')} had an execution error. "
        f"{decision.coverage.excluded} more requirements were excluded and are listed below.</p>"
        '<p class="notice"><strong>This is a conformance test report. It is not a certificate.</strong> '
        "It does not show that product data are true, that a product is safe, or that all legal "
        "obligations are met.</p></section>"
    )


def _scope(envelope: EvidenceEnvelope) -> str:
    manifest = envelope.decision.manifest
    issuer = manifest.issuer
    rows = [
        ("Issuer", _e(issuer.name)),
        ("Issuer identifier", f"<code>{_e(issuer.identifier)}</code>"),
        ("Accreditation status of the issuer", _e(issuer.accreditation_status)),
        ("Accreditation reference", _e(issuer.accreditation_reference or "none")),
        ("System under test", f"{_e(manifest.sut.name)} (<code>{_e(manifest.sut.identifier)}</code>)"),
        ("System version", _e(manifest.sut.version)),
        ("System operator", _e(manifest.sut.operator)),
        ("Execution mode", _e(manifest.mode.value)),
        ("Profile", f"<code>{_e(manifest.profile_id)}</code>"),
        ("Evaluation time", _e(manifest.evaluation_time)),
        (
            "First and last acquisition",
            f"{_e(manifest.acquisition.first)} to {_e(manifest.acquisition.last)}",
        ),
        ("Engine version", _e(manifest.engine_version)),
        ("Container image digest", _e(manifest.image_digest or "not recorded")),
        ("Authorization reference", _e(manifest.authorization_ref or "none")),
        ("Trust policy version", _e(manifest.trust_policy_version)),
        (
            "Requirement packs",
            "<br>".join(f"<code>{_e(k)}</code> {_e(v)}" for k, v in manifest.pack_hashes.items()),
        ),
        (
            "Test packs",
            "<br>".join(f"<code>{_e(k)}</code> {_e(v)}" for k, v in manifest.testpack_hashes.items()),
        ),
        ("Source catalogue hash", f"<code>{_e(manifest.sources_hash)}</code>"),
        ("ICS hash", f"<code>{_e(manifest.ics_hash)}</code>"),
        ("Sanitized IXIT hash", f"<code>{_e(manifest.ixit_sanitized_hash)}</code>"),
        ("Dependencies", ", ".join(f"{_e(k)} {_e(v)}" for k, v in manifest.dependency_versions.items())),
    ]
    items = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    heading = '<h2 id="scope">Issuer, scope, and versions</h2>'
    return f'<section aria-labelledby="scope">{heading}<dl>{items}</dl></section>'


def _coverage(envelope: EvidenceEnvelope) -> str:
    c = envelope.decision.coverage
    rows = [
        ("Scope of these figures", _e(c.scope_statement)),
        ("Known requirements", str(c.total_requirements)),
        ("Implementation coverage", _ratio(c.implementation)),
        ("Execution coverage", _ratio(c.execution)),
        ("Passing outcomes", _ratio(c.passing)),
        ("By authority class", _counts(c.by_authority_class)),
        ("By review status", _counts(c.by_review_status)),
        ("By applicability", _counts(c.by_applicability)),
        ("By testability", _counts(c.by_testability)),
        ("By verdict", _counts(c.by_verdict)),
        ("Placeholders with no interpretation", str(c.placeholders)),
        ("Unknown applicability", str(c.unknown_applicability)),
        ("Excluded", str(c.excluded)),
        ("Manual assessment missing", str(c.manual_missing)),
    ]
    items = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return (
        '<section aria-labelledby="coverage"><h2 id="coverage">Coverage of the selected catalogue</h2>'
        "<p>These figures count requirements in the selected catalogue. They are not coverage of a law "
        f"or of a whole standard.</p><dl>{items}</dl></section>"
    )


def _results(envelope: EvidenceEnvelope) -> str:
    d = envelope.decision
    requirements = _table(
        "Requirement results",
        (
            "Requirement",
            "Authority class",
            "Modality",
            "Review status",
            "Applies",
            "Verdict",
            "Claim level",
            "Reason",
        ),
        (
            (
                f"<code>{_e(r.requirement_id)}</code>",
                _e(r.authority_class.value.replace("_", " ")),
                _e(r.modality.value),
                _e(r.review_status.value),
                f"{_e(r.applicability.value)}<br><small>{_e(r.applicability_reason)}</small>",
                _verdict(r.verdict.value),
                _e(r.claim_level.value),
                _e(r.verdict_reason)
                + (
                    "<br><small>Also: " + "; ".join(_e(x) for x in r.retained) + "</small>"
                    if r.retained
                    else ""
                ),
            )
            for r in d.requirement_results
        ),
    )
    tests = _table(
        "Test step results",
        ("Test purpose", "Check", "Execution", "Verdict", "Reason code", "Message"),
        (
            (
                f"<code>{_e(t.test_purpose_id)}</code>",
                f"<code>{_e(t.check)}</code>",
                _e(t.execution_status.value.replace("_", " ")),
                _verdict(t.verdict.value),
                f"<code>{_e(t.reason_code)}</code>",
                _e(t.message),
            )
            for t in d.test_results
        ),
    )
    exclusions = _table(
        "Exclusions",
        ("Kind", "Identifier", "Reason code", "Reason"),
        (
            (
                _e(x.kind.replace("_", " ")),
                f"<code>{_e(x.id)}</code>",
                f"<code>{_e(x.reason_code)}</code>",
                _e(x.reason),
            )
            for x in d.exclusions
        ),
    )
    conflicts = _table(
        "Conflicts between declarations and applicable requirements",
        ("Requirement", "Declared", "Explanation"),
        ((f"<code>{_e(c.requirement_id)}</code>", _e(c.declared), _e(c.explanation)) for c in d.conflicts),
    )
    return (
        f'<section aria-labelledby="results"><h2 id="results">Results</h2>{requirements}{tests}</section>'
        f'<section aria-labelledby="left-out"><h2 id="left-out">Exclusions and conflicts</h2>'
        f"<p>Nothing in the selected catalogue is left out silently.</p>{exclusions}{conflicts}</section>"
    )


def _evidence(envelope: EvidenceEnvelope, verification: VerificationReport | None) -> str:
    d = envelope.decision
    rows = [
        ("Decision digest", f"<code>{_e(decision_digest(d))}</code>"),
        ("Results root", f"<code>{_e(d.results_root)}</code> over {d.results_count} results"),
        (
            "Records root",
            f"<code>{_e(d.records_root)}</code> over {len(d.record_commitments)} record commitments",
        ),
        ("Signatures", str(len(envelope.signatures))),
    ]
    items = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    if verification is None:
        checked = (
            "<p>This page does not verify the report. Run <code>dppce verify</code> with an explicit trust "
            "bundle and an explicit evaluation time.</p>"
        )
    else:
        state = "complete" if verification.complete else "not complete"
        checked = (
            f"<p>Verification at {_e(verification.evaluation_time)} is <strong>{state}</strong>. "
            + _e(verification.note)
            + "</p>"
            + _table(
                "Verification dimensions",
                ("Dimension", "Outcome", "Detail"),
                (
                    (_e(x.name.replace("_", " ")), _e(x.outcome.replace("_", " ")), _e(x.detail))
                    for x in verification.dimensions
                ),
            )
        )
    return (
        f'<section aria-labelledby="evidence"><h2 id="evidence">Evidence</h2><dl>{items}</dl>{checked}'
        "<p>The report holds commitments to the raw observations, not the observations.</p></section>"
    )


def render(envelope: EvidenceEnvelope, verification: VerificationReport | None = None) -> str:
    """Return the complete HTML document."""
    manifest = envelope.decision.manifest
    title = f"Conformance test report: {manifest.sut.name}, {manifest.profile_id}"
    limits = "".join(f"<li>{_e(x)}</li>" for x in manifest.limitations)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>"
        '<a class="skip" href="#main">Skip to the report</a>'
        f'<header><h1>{_e(title)}</h1></header><main id="main">'
        f"{_summary(envelope)}{_scope(envelope)}{_coverage(envelope)}{_results(envelope)}"
        f'<section aria-labelledby="limits"><h2 id="limits">Limitations</h2><ul>{limits}</ul></section>'
        f"{_evidence(envelope, verification)}</main>"
        f"<footer><p>Generated by dppce {_e(manifest.engine_version)}.</p></footer></body></html>\n"
    )
