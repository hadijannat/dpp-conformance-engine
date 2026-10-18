"""The method-validation record holds a field for a person's review that the engine never fills."""

from __future__ import annotations

from validation.run import HUMAN_REVIEW


def test_the_engine_never_fills_the_human_review() -> None:
    assert HUMAN_REVIEW["human_review_and_signature"] is None
    assert "never fills" in HUMAN_REVIEW["human_review_and_signature_note"]
    assert set(HUMAN_REVIEW) == {"human_review_and_signature", "human_review_and_signature_note"}
