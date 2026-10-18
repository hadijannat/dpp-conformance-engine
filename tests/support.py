"""Shared builders for tests. Nothing here is a real key or a real system."""

from __future__ import annotations

import dataclasses
import http.server
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from dppce.evidence.envelope import build_decision
from dppce.evidence.recording import new_salt, record_commitments
from dppce.infrastructure.interfaces import Record, Request, TransportError
from dppce.models import (
    CoverageSummary,
    EvidenceEnvelope,
    ExecutionMode,
    Ratio,
    RequirementResult,
    ReviewStatus,
    RunManifest,
    SutIdentity,
    TestResult,
    Tri,
    Verdict,
)
from dppce.verdicts import overall_verdict, requirement_verdict
from dppce.verdicts.coverage import RATIO_LABELS

ISSUER = "urn:example:test-lab"
KID = "TEST-ONLY-report-key-1"
AT = datetime(2026, 10, 14, tzinfo=UTC)


def make_record(index: int, body: bytes = b"{}", url: str | None = None) -> Record:
    return Record(
        record_id=f"r{index:04d}",
        kind="http",
        acquired_at="2026-10-13T12:00:00Z",
        method="GET",
        url=url or f"http://127.0.0.1/dpp/{index}",
        role="anonymous",
        request_headers=(("User-Agent", "dppce/test"),),
        status=200,
        headers=(("Content-Type", "application/json"),),
        body=body,
        truncated=False,
        error=None,
        redirects=(),
        attempts=1,
        salt=new_salt(),
    )


def make_artifact(name: str, body: bytes = b"", error: TransportError | None = None, index: int = 1) -> Record:
    """A local input artifact as the transport records it."""
    return Record(
        record_id=f"r{index:04d}",
        kind="artifact",
        acquired_at="2026-10-13T12:00:00Z",
        method="READ",
        url=f"artifact:{name}",
        role="local",
        request_headers=(),
        status=None,
        headers=(),
        body=body,
        truncated=False,
        error=error,
        redirects=(),
        attempts=1,
        salt=new_salt(),
    )


class ArtifactAcquirer:
    """Serves prepared input artifacts by name. An unknown name is ``artifact_unavailable``. No transport."""

    def __init__(self, artifacts: dict[str, Record] | None = None) -> None:
        self._artifacts = dict(artifacts or {})
        self._served: list[Record] = []

    def fetch(self, request: Request) -> Record:
        raise AssertionError(f"no network in this test: {request.url}")

    def artifact(self, name: str) -> Record:
        record = self._artifacts.get(name) or make_artifact(name, error="artifact_unavailable")
        record = dataclasses.replace(record, record_id=f"r{len(self._served) + 1:04d}")
        self._served.append(record)
        return record

    def records(self) -> tuple[Record, ...]:
        return tuple(self._served)


def make_requirement_result(index: int, verdict: str, **changes: Any) -> RequirementResult:
    fields: dict[str, Any] = {
        "requirement_id": f"ILL-{index:03d}",
        "pack_id": "illustrative/core",
        "authority_class": "illustrative",
        "modality": "mandatory",
        "review_status": "draft-needs-review",
        "testability": "automated",
        "applicability": "true",
        "applicability_reason": "always",
        "verdict": verdict,
        # The reason that the published rules give for this verdict; the verifier derives it again.
        "verdict_reason": requirement_verdict(
            Tri.TRUE, False, [Verdict(verdict)], ExecutionMode.ILLUSTRATIVE, ReviewStatus.DRAFT
        )[1],
        "claim_level": "illustrative",
        "paths": [
            {"path_id": "default", "applicability": "true", "verdict": verdict, "steps": [f"TP-{index:03d}"]}
        ],
    }
    return RequirementResult.model_validate(fields | changes)


def make_test_result(index: int, verdict: str) -> TestResult:
    return TestResult.model_validate(
        {
            "test_purpose_id": f"TP-{index:03d}",
            "requirement_ids": [f"ILL-{index:03d}"],
            "check": "data.rules",
            "applicability": "true",
            "applicability_reason": "always",
            "execution_status": "completed",
            "verdict": verdict,
            "severity": "major",
            "reason_code": "DATA.RULES.OK" if verdict == "pass" else "DATA.RANGE.VIOLATED",
            "message": "test",
        }
    )


def make_manifest(**changes: Any) -> RunManifest:
    """A manifest for a dppce.decision/2 body. ``bound_files=None`` gives one for a /1 body."""
    fields: dict[str, Any] = {"bound_files": {}} | changes
    return RunManifest(
        engine_version="0.0.0-test",
        dependency_versions={},
        mode="illustrative",
        profile_id="battery/ev",
        profile_hash="h",
        catalogue_hash="h",
        pack_hashes={},
        testpack_hashes={},
        sources_hash="h",
        ics_hash="h",
        ixit_sanitized_hash="h",
        sut=SutIdentity(name="Reference", identifier="urn:example:sut"),
        evaluation_time="2026-10-13T12:00:00Z",
        trust_policy_version="test-1",
        limitations=("test",),
        **fields,
    )


def make_envelope(verdicts: tuple[str, ...] = ("pass", "fail", "pass")) -> EvidenceEnvelope:
    """An unsigned envelope with one requirement and one test result per verdict, and two records."""
    requirements = [make_requirement_result(i, v) for i, v in enumerate(verdicts, start=1)]
    tests = [make_test_result(i, v) for i, v in enumerate(verdicts, start=1)]
    passed = sum(1 for v in verdicts if v == "pass")
    counts = {v: verdicts.count(v) for v in sorted(set(verdicts))}
    total = len(verdicts)
    coverage = CoverageSummary(
        scope_statement="test scope",
        total_requirements=total,
        by_authority_class={"illustrative": total},
        by_review_status={"draft-needs-review": total},
        by_applicability={"true": total},
        by_testability={"automated": total},
        by_verdict=counts,
        implementation=Ratio(numerator=total, denominator=total, of=RATIO_LABELS["implementation"]),
        execution=Ratio(numerator=total, denominator=total, of=RATIO_LABELS["execution"]),
        passing=Ratio(numerator=passed, denominator=total, of=RATIO_LABELS["passing"]),
        placeholders=0,
        unknown_applicability=0,
        excluded=0,
        manual_missing=0,
    )
    overall, reason = overall_verdict(requirements)
    decision = build_decision(
        manifest=make_manifest(),
        overall=overall,
        overall_reason=reason,
        requirement_results=requirements,
        test_results=tests,
        exclusions=(),
        conflicts=(),
        coverage=coverage,
        record_commitments=record_commitments([make_record(1), make_record(2)]),
    )
    return EvidenceEnvelope(schema_version="dppce.envelope/1", decision=decision)


Handler = Callable[[http.server.BaseHTTPRequestHandler], None]


class LoopbackServer:
    """A loopback HTTP server whose behavior a test sets with one function. No external network."""

    def __init__(self, handler: Handler) -> None:
        seen: list[dict[str, str]] = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def do_GET(self) -> None:
                seen.append({"path": self.path, **dict(self.headers.items())})
                handler(self)

            do_POST = do_GET

        self.seen = seen
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def reply(
    request: http.server.BaseHTTPRequestHandler,
    status: int = 200,
    body: bytes = b'{"ok":true}',
    headers: dict[str, str] | None = None,
) -> None:
    request.send_response(status)
    for name, value in ({"Content-Type": "application/json"} | (headers or {})).items():
        request.send_header(name, value)
    request.send_header("Content-Length", str(len(body)))
    request.end_headers()
    request.wfile.write(body)
