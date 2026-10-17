"""Status documents must agree with the open questions."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _status_cells(name: str, prefix: str) -> dict[str, str]:
    """Map each table row whose first cell starts with ``prefix`` to its last cell."""
    rows: dict[str, str] = {}
    for line in (ROOT / "docs" / name).read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells[0].startswith(prefix):
            rows[cells[0]] = cells[-1]
    return rows


def test_no_backlog_item_is_blocked_by_a_closed_question() -> None:
    questions = _status_cells("open-questions.md", "OQ-")
    closed = {qid for qid, status in questions.items() if status.lower().startswith("closed")}
    assert closed, "the parser found no closed question"
    blockers = {
        qid
        for status in _status_cells("backlog.md", "BL-").values()
        if "blocked" in status.lower()
        for qid in re.findall(r"OQ-\d{3}", status)
    }
    assert sorted(blockers & closed) == []
