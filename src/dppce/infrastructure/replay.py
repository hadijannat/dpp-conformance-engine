"""Replay ``Acquirer``: serves the records of a recording instead of the network.

Replay with the same recording, evaluation time, catalogue, profile, and test pack must give
the same verdicts and the same decision digest. Records are served in sequence. A request
that differs from the recorded one means that the inputs changed: that is an execution error.
"""

from __future__ import annotations

from collections.abc import Sequence

from dppce.infrastructure.interfaces import Record, Request
from dppce.infrastructure.redaction import redact_url


class ReplayAcquirer:
    def __init__(self, recorded: Sequence[Record]) -> None:
        self._recorded = tuple(recorded)
        self._served: list[Record] = []

    def records(self) -> tuple[Record, ...]:
        return tuple(self._served)

    def _next(self, kind: str, method: str, url: str, role: str) -> Record:
        position = len(self._served)
        template: Record | None
        if position < len(self._recorded):
            record = self._recorded[position]
            if (record.kind, record.method, record.url, record.role) == (kind, method, url, role):
                self._served.append(record)
                return record
            template = record
        else:
            template = self._recorded[-1] if self._recorded else None
        mismatch = Record(
            record_id=f"r{position + 1:04d}",
            kind="http" if kind == "http" else "artifact",
            acquired_at=template.acquired_at if template else "1970-01-01T00:00:00Z",
            method=method,
            url=url,
            role=role,
            request_headers=(),
            status=None,
            headers=(),
            body=b"",
            truncated=False,
            error="recording_mismatch",
            redirects=(),
            attempts=0,
            # Not secret and not random: this record is never committed, because the run ends in an error.
            salt=bytes(32),
        )
        self._served.append(mismatch)
        return mismatch

    def fetch(self, request: Request) -> Record:
        # The recording holds the redacted URL, so compare in the same form.
        return self._next("http", request.method.upper(), redact_url(request.url), request.role)

    def artifact(self, name: str) -> Record:
        return self._next("artifact", "READ", f"artifact:{name}", "local")

    def complete(self) -> bool:
        """True if every recorded record was served and none mismatched."""
        return len(self._served) == len(self._recorded) and all(
            r.error != "recording_mismatch" for r in self._served
        )
