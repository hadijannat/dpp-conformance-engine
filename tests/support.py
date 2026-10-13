"""Shared builders for tests. Nothing here is a real key or a real system."""

from __future__ import annotations

import http.server
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from dppce.evidence.envelope import build_decision
from dppce.evidence.recording import new_salt, record_commitments
from dppce.infrastructure.interfaces import Record
from dppce.models import (
    CoverageSummary,
    EvidenceEnvelope,
    Ratio,
    RequirementResult,
    RunManifest,
    SutIdentity,
    TestResult,
)
from dppce.verdicts import overall_verdict

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
        "verdict_reason": "test",
        "claim_level": "illustrative",
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


def make_manifest() -> RunManifest:
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
        implementation=Ratio(numerator=total, denominator=total, of="requirements"),
        execution=Ratio(numerator=total, denominator=total, of="requirements"),
        passing=Ratio(numerator=passed, denominator=total, of="requirements"),
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
