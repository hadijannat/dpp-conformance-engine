"""The method-validation record holds a field for a person's review that the engine never fills."""

from __future__ import annotations

import json
from pathlib import Path

from validation.run import HUMAN_REVIEW

RECORDS = Path(__file__).resolve().parent.parent / "validation" / "records"


def test_the_engine_never_fills_the_human_review() -> None:
    assert HUMAN_REVIEW["human_review_and_signature"] is None
    assert "never fills" in HUMAN_REVIEW["human_review_and_signature_note"]
    assert set(HUMAN_REVIEW) == {"human_review_and_signature", "human_review_and_signature_note"}


def test_the_newest_written_record_holds_an_empty_human_review() -> None:
    # The written record, not the constant, is what a laboratory keeps.
    newest = sorted(RECORDS.glob("method-validation-*.json"))[-1]
    record = json.loads(newest.read_text(encoding="utf-8"))
    assert "human_review_and_signature" in record
    assert record["human_review_and_signature"] is None
