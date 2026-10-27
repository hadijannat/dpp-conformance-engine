"""Redirect hop statuses in the record and the redirect rules of resolver.conformance (P2-25, OD-08).

Expected values come from docs/explanation/architecture.md, sections 8 to 10, and from the fault
catalogue entries F-78 and E-17, which were written before this change. Loopback servers and local
fixtures only. The fixture tests/fixtures/recording-f114b50 was made by `dppce run` at f114b50.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from validation import evidence_cases
from validation.rig import TRUST, ReferenceRig

import dppce.adapters  # noqa: F401 - importing the package registers every check
from dppce.evidence import disclosure
from dppce.evidence.canonical import canonical_bytes, parse_strict
from dppce.evidence.envelope import decision_digest, records_root
from dppce.evidence.recording import (
    RecordingError,
    commit,
    read_recording,
    record_commitments,
    record_from_json,
    record_to_json,
)
from dppce.infrastructure.interfaces import Acquirer, Record, Request
from dppce.infrastructure.keys import FileDataKeyProvider
from dppce.infrastructure.replay import ReplayAcquirer
from dppce.infrastructure.transport import origin_of
from dppce.models import CheckOutcome, EvidenceEnvelope, ExecutionStatus, OpenedRecord, TrustBundle
from dppce.verifier import verify
from tests.support import make_envelope, make_record, reply
from tests.test_adapters_resolver import INVALID, LINKTYPE, OUT_OF_SCOPE, _linkset
from tests.test_resolved_target import ITEM_PATH, RESOLVER_PATH, Origin, resolved_context, served
from tests.test_transport import LOCAL, Start, transport
from tests.test_url_templates import run

BASE = Path(__file__).resolve().parent / "fixtures" / "recording-f114b50"
# Printed by `dppce run` at f114b50 for this fixture (see its README).
BASE_DIGEST = "sha256:6bb7dfe16661e291f291b7d548e482f72484eacd8c2728ad6e7838d08dbf6997"
LINKSET_TYPE = "application/linkset+json"
CODES = (301, 302, 303, 307, 308)


# -- the transport ----------------------------------------------------------------------------------


def _chain(routes: dict[str, tuple[int, str]]) -> Any:
    """A handler: each path in ``routes`` redirects with its status to its target; others answer 200."""

    def handler(request: http.server.BaseHTTPRequestHandler) -> None:
        if request.path in routes:
            status, target = routes[request.path]
            reply(request, status, b"", {"Location": target})
        else:
            reply(request)

    return handler


def test_each_followed_hop_records_its_status(loopback: Start) -> None:
    server = loopback(_chain({"/a": (301, "/b"), "/b": (307, "/c")}))
    record = transport().fetch(Request("GET", f"{server.origin}/a"))
    assert (record.status, record.error) == (200, None)
    assert record.redirects == (f"{server.origin}/b", f"{server.origin}/c")
    assert record.redirect_statuses == (301, 307)


def test_an_answer_without_a_redirect_has_no_hop_status(loopback: Start) -> None:
    server = loopback(_chain({}))
    record = transport().fetch(Request("GET", f"{server.origin}/a"))
    assert (record.redirects, record.redirect_statuses) == ((), ())


def test_a_refused_hop_keeps_its_status(loopback: Start) -> None:
    server = loopback(_chain({"/a": (308, OUT_OF_SCOPE)}))
    record = transport().fetch(Request("GET", f"{server.origin}/a"))
    assert record.error == "redirect_out_of_scope"
    assert (record.redirects, record.redirect_statuses) == ((OUT_OF_SCOPE,), (308,))


def test_a_loop_keeps_one_status_per_followed_hop(loopback: Start) -> None:
    server = loopback(_chain({"/again": (302, "/again")}))
    record = transport(LOCAL | {"max_redirects": 2}).fetch(Request("GET", f"{server.origin}/again"))
    assert record.error == "too_many_redirects"
    assert record.redirect_statuses == (302, 302)
    assert len(record.redirects) == len(record.redirect_statuses)


def test_follow_redirects_false_returns_the_first_answer(loopback: Start) -> None:
    server = loopback(_chain({"/a": (303, "/b")}))
    record = transport().fetch(Request("GET", f"{server.origin}/a", follow_redirects=False))
    assert (record.status, record.error, record.header("location")) == (303, None, "/b")
    assert (record.redirects, record.redirect_statuses) == ((), ())
    assert [seen["path"] for seen in server.seen] == ["/a"]


def test_a_request_follows_redirects_by_default() -> None:
    assert Request("GET", "http://127.0.0.1/").follow_redirects is True


# -- the record form --------------------------------------------------------------------------------


def _hopped(index: int = 1, statuses: tuple[int, ...] = (303,)) -> Record:
    redirects = tuple(f"http://127.0.0.1/hop{n}" for n in range(len(statuses)))
    return dataclasses.replace(make_record(index), redirects=redirects, redirect_statuses=statuses)


def test_an_empty_hop_status_list_is_left_out_of_the_record_form() -> None:
    plain = record_to_json(make_record(1), with_salt=True)
    assert "redirect_statuses" not in plain
    assert record_from_json(plain).redirect_statuses == ()


def test_hop_statuses_are_in_the_record_form_and_in_the_commitment() -> None:
    record = _hopped(statuses=(301, 307))
    plain = record_to_json(record, with_salt=True)
    assert plain["redirect_statuses"] == [301, 307]
    assert record_from_json(plain) == record
    changed = dataclasses.replace(record, redirect_statuses=(302, 307))
    assert commit(changed) != commit(record)


@pytest.mark.parametrize(
    "statuses",
    [[], [303, 303], [200], [399], ["303"], [True], 303],
    ids=["empty", "too_many", "not_3xx", "not_a_redirect", "text", "boolean", "not_a_list"],
)
def test_a_malformed_hop_status_list_is_a_recording_error(statuses: object) -> None:
    plain = record_to_json(_hopped(), with_salt=True)
    plain["redirect_statuses"] = statuses
    with pytest.raises(RecordingError):
        record_from_json(plain)


@pytest.mark.parametrize("statuses", [(), (303,), (301, 308)], ids=len)
def test_the_opening_has_the_bytes_of_the_committed_plaintext(statuses: tuple[int, ...]) -> None:
    record = _hopped(statuses=statuses) if statuses else make_record(1)
    plain = record_to_json(record, with_salt=False)
    assert canonical_bytes(OpenedRecord.model_validate(plain)) == canonical_bytes(plain)
    assert OpenedRecord.model_validate(plain).redirect_statuses == statuses


def _decision_of(*records: Record) -> Any:
    commitments = record_commitments(records)
    return make_envelope().decision.model_copy(
        update={"record_commitments": commitments, "records_root": records_root(commitments)}
    )


def _opening_outcome(raw: bytes, decision: Any) -> tuple[str, str]:
    return disclosure.check_opening_file(raw, decision, {"results": True, "records": True}, ordered=True)


def test_an_opening_of_a_record_with_hop_statuses_verifies() -> None:
    record = _hopped(statuses=(303,))
    decision = _decision_of(record, make_record(2))
    outcome, detail = _opening_outcome(canonical_bytes(disclosure.open_record(decision, record)), decision)
    assert (outcome, detail.split(":")[0]) == ("pass", "OPENING.RECORD.OK")


def test_e17_a_changed_hop_status_in_an_opening_fails_the_opening() -> None:
    record = _hopped(statuses=(303,))
    decision = _decision_of(make_record(2), record)
    raw = evidence_cases.change_redirect_status(decision, [make_record(2), record])
    assert json.loads(raw)["record"]["redirect_statuses"] != [303]
    outcome, detail = _opening_outcome(raw, decision)
    assert (outcome, detail.split(":")[0]) == ("fail", "OPENING.COMMITMENT.MISMATCH")


# The baseline run reaches the resolver redirect only after the QR carrier step decodes the
# qr_image sample, and that step needs the qr extra.
@pytest.mark.qr
def test_e17_runs_on_the_signed_baseline_control(tmp_path: Path) -> None:
    """The method validation seeds E-17 into the first control, battery/ev on the reference system."""
    trust = TrustBundle.model_validate(parse_strict(TRUST.read_bytes()))
    with ReferenceRig(tmp_path / "rig", "ev") as rig:
        run_result = rig.run()
        signed = EvidenceEnvelope.model_validate_json(rig.sign(run_result).read_bytes())
    keys = FileDataKeyProvider(run_result.run_dir.parent / "keys")
    records = read_recording(run_result.run_dir / "recording", keys)
    raw = evidence_cases.change_redirect_status(signed.decision, records)
    document = json.loads(signed.model_dump_json(by_alias=True))
    report = verify(document, trust, datetime(2026, 10, 14, tzinfo=UTC), opening=raw)
    outcome = next(d for d in report.dimensions if d.name == "opening")
    assert (outcome.outcome, report.complete) == ("fail", False)
    assert outcome.detail.startswith("OPENING.COMMITMENT.MISMATCH"), outcome.detail


def test_e17_needs_a_record_with_a_hop_status() -> None:
    with pytest.raises(LookupError):
        evidence_cases.change_redirect_status(_decision_of(make_record(1)), [make_record(1)])


# -- a recording made at f114b50, before hop statuses -------------------------------------------------


def _base() -> tuple[EvidenceEnvelope, tuple[Record, ...]]:
    envelope = EvidenceEnvelope.model_validate_json((BASE / "envelope.json").read_bytes())
    # read_recording checks every record against its commitment in the index.
    records = read_recording(BASE / "recording", FileDataKeyProvider(BASE / "TEST-ONLY-keys"))
    return envelope, records


def test_a_recording_from_f114b50_keeps_its_commitments_and_roots() -> None:
    envelope, records = _base()
    decision = envelope.decision
    assert decision_digest(decision) == BASE_DIGEST
    assert record_commitments(records) == decision.record_commitments
    assert records_root(record_commitments(records)) == decision.records_root
    hopped = [r for r in records if r.redirects]
    assert hopped, "the fixture must hold a record that followed a redirect"
    assert all(r.redirect_statuses == () for r in records)


def test_a_record_from_f114b50_opens_and_its_opening_verifies() -> None:
    envelope, records = _base()
    record = next(r for r in records if r.redirects)
    opening = disclosure.open_record(envelope.decision, record)
    raw = canonical_bytes(opening)
    assert b"redirect_statuses" not in raw
    outcome, detail = _opening_outcome(raw, envelope.decision)
    assert (outcome, detail.split(":")[0]) == ("pass", "OPENING.RECORD.OK")


def test_a_recording_from_f114b50_gives_the_same_conformance_result(tmp_path: Path) -> None:
    # TestResult.message is in the decision body: a changed text changes the replay digest.
    envelope, records = _base()
    stored = next(t for t in envelope.decision.test_results if t.check == "resolver.conformance")
    used = {i for o in stored.observations for i in o.record_ids}
    replayed = [r for r in records if r.record_id in used]
    carrier = replayed[0].url
    acquirer = ReplayAcquirer(replayed)
    ctx = resolved_context(
        tmp_path,
        "resolver.conformance",
        origin_of(carrier),
        samples={"identifier": carrier},
        acquirer=acquirer,
    )
    outcome = run(ctx)
    assert (outcome.passed, outcome.reason_code, outcome.message) == (
        True,
        stored.reason_code,
        stored.message,
    )
    assert [o.summary for o in outcome.observations] == [o.summary for o in stored.observations]
    assert acquirer.complete()


# -- resolver.conformance ---------------------------------------------------------------------------


def _resolver(api: Origin, status: int = 303, target: str | None = None) -> None:
    api.routes.update(
        {
            RESOLVER_PATH: (status, b"", {"Location": target or api.origin + ITEM_PATH}),
            ITEM_PATH: served(),
            LINKTYPE: (200, _linkset(api.origin), {"Content-Type": LINKSET_TYPE}),
            INVALID: (404, b"{}", {}),
        }
    )


def _conformance(tmp_path: Path, api: Origin, **params: Any) -> CheckOutcome:
    return run(resolved_context(tmp_path, "resolver.conformance", api.origin, params=params or None))


@pytest.mark.parametrize("status", CODES)
def test_the_default_set_accepts_each_redirect_status(status: int, tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    _resolver(api, status)
    outcome = _conformance(tmp_path, api)
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.CONFORMANCE.OK"), outcome.message


def test_a_declared_status_passes(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    _resolver(api, 307)
    outcome = _conformance(tmp_path, api, expected_redirect_statuses=[307, 308])
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.CONFORMANCE.OK")


@pytest.mark.parametrize(
    ("target", "status"),
    [(None, 302), (OUT_OF_SCOPE, 302), (RESOLVER_PATH, 302)],
    ids=["followed", "out_of_scope", "loop"],
)
def test_an_undeclared_first_hop_status_fails(
    target: str | None, status: int, tmp_path: Path, loopback: Any
) -> None:
    # Neither a refused hop nor a loop turns the fail into blocked: the first hop status is recorded.
    api = Origin(loopback)
    _resolver(api, status, target)
    outcome = _conformance(tmp_path, api, expected_redirect_statuses=[307])
    assert outcome.status is ExecutionStatus.COMPLETED
    assert (outcome.passed, outcome.reason_code) == (False, "RESOLVER.CONFORMANCE.REDIRECT_STATUS")
    assert api.hits(LINKTYPE) == 0, "the check stops at the first rule that breaks"


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        ((500, b"", {}), "TRANSPORT.SERVER_ERROR"),
        ((503, b"", {}), "TRANSPORT.SERVER_ERROR"),
        (None, "TRANSPORT.UNREACHABLE"),
    ],
    ids=["500", "503", "connect"],
)
def test_a_followed_hop_to_a_target_without_an_answer_is_no_answer(
    answer: tuple[int, bytes, dict[str, str]] | None, code: str, tmp_path: Path, loopback: Any
) -> None:
    # A declared first hop status does not make up for a final answer that is missing: no false pass.
    api = Origin(loopback)
    if answer is None:
        _resolver(api, 303, "http://127.0.0.1:1/dpp/x")
    else:
        _resolver(api, 303)
        api.routes[ITEM_PATH] = answer
    outcome = _conformance(tmp_path, api)
    assert (outcome.status, outcome.passed, outcome.unreachable, outcome.reason_code) == (
        ExecutionStatus.COMPLETED,
        False,
        True,
        code,
    ), outcome.message


@pytest.mark.parametrize("target", [OUT_OF_SCOPE, RESOLVER_PATH], ids=["out_of_scope", "loop"])
def test_a_declared_first_hop_is_judged_also_when_the_hop_is_not_followed(
    target: str, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    _resolver(api, 307, target)
    outcome = _conformance(tmp_path, api, expected_redirect_statuses=[307])
    assert (outcome.passed, outcome.reason_code) == (True, "RESOLVER.CONFORMANCE.OK")


def test_a_redirect_status_is_judged_before_the_other_probes(tmp_path: Path, loopback: Any) -> None:
    api = Origin(loopback)
    _resolver(api, 301)
    api.routes[INVALID] = served()
    outcome = _conformance(tmp_path, api, expected_redirect_statuses=[303])
    assert (outcome.passed, outcome.reason_code) == (False, "RESOLVER.CONFORMANCE.REDIRECT_STATUS")


@pytest.mark.parametrize(
    "value",
    [[], [200], [304], ["303"], [True], [303, 303], 303, [301, 302, 303, 307, 308, 301]],
    ids=["empty", "200", "304", "text", "boolean", "repeated", "not_a_list", "too_many"],
)
def test_an_invalid_status_set_blocks_before_any_request(
    value: object, tmp_path: Path, loopback: Any
) -> None:
    api = Origin(loopback)
    _resolver(api)
    outcome = _conformance(tmp_path, api, expected_redirect_statuses=value)
    assert (outcome.status, outcome.reason_code) == (ExecutionStatus.BLOCKED, "RESOLVER.PARAMS.INVALID")
    assert api.server.seen == []


class _WithoutHopStatus:
    """An acquirer that drops the hop statuses, as a recording made before f114b50 holds none."""

    def __init__(self, inner: Acquirer) -> None:
        self._inner = inner

    def fetch(self, request: Request) -> Record:
        return dataclasses.replace(self._inner.fetch(request), redirect_statuses=())

    def artifact(self, name: str) -> Record:
        return self._inner.artifact(name)

    def records(self) -> tuple[Record, ...]:
        return tuple(dataclasses.replace(r, redirect_statuses=()) for r in self._inner.records())


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({}, (ExecutionStatus.COMPLETED, "RESOLVER.CONFORMANCE.OK")),
        (
            {"expected_redirect_statuses": [303]},
            (ExecutionStatus.BLOCKED, "RESOLVER.CONFORMANCE.HOP_STATUS_NOT_RECORDED"),
        ),
    ],
    ids=["default_set", "declared_set"],
)
def test_a_record_without_hop_statuses(
    params: dict[str, Any], expected: tuple[ExecutionStatus, str], tmp_path: Path, loopback: Any
) -> None:
    # The transport follows a redirect status only, so a followed hop meets the default set.
    # A declared subset cannot be judged without the status.
    api = Origin(loopback)
    _resolver(api)
    plain = resolved_context(tmp_path, "resolver.conformance", api.origin, params=params or None)
    ctx = dataclasses.replace(plain, acquirer=_WithoutHopStatus(plain.acquirer))
    outcome = run(ctx)
    assert (outcome.status, outcome.reason_code) == expected
