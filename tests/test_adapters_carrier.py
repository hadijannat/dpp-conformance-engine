"""carrier.qr_decode on TEST-ONLY degraded synthetic QR images.

The images come from scripts/gen_fixtures.py. Their expected outcomes are in expected.json next
to them. The engine does not grade print quality; these cases only fix what the decoder reports.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from dppce.adapters.carrier import qr_decode
from dppce.infrastructure.interfaces import Record
from tests.support import make_record
from tests.test_adapters_security import _POLICY, _Canned, _context

pytest.importorskip("zxingcpp", reason="needs the optional 'qr' extra (zxing-cpp)")
pytest.importorskip("PIL", reason="needs the optional 'qr' extra (Pillow)")
pytestmark = pytest.mark.qr

DEGRADED = Path(__file__).resolve().parent.parent / "fixtures" / "reference" / "qr" / "degraded"
CASES: dict[str, dict[str, Any]] = json.loads((DEGRADED / "expected.json").read_text(encoding="utf-8"))[
    "cases"
]


class _Sample(_Canned):
    """An acquirer that returns one image as the QR sample."""

    def artifact(self, name: str) -> Record:
        return make_record(1, self._body)


def test_every_degraded_image_has_an_expected_outcome() -> None:
    assert {p.name for p in DEGRADED.glob("*.png")} == set(CASES)


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_degraded_image_gives_the_expected_outcome(name: str, tmp_path: Path) -> None:
    expected = CASES[name]
    outcome = qr_decode(_context(tmp_path, _POLICY, _Sample((DEGRADED / name).read_bytes(), "image/png")))
    assert (outcome.status.value, outcome.passed, outcome.reason_code) == (
        expected["status"],
        expected["passed"],
        expected["reason_code"],
    )
    if expected["summary"] is None:
        assert outcome.observations == ()
    else:
        summary = outcome.observations[0].summary
        assert {key: summary.get(key) for key in expected["summary"]} == expected["summary"]
    if "two-symbols" in name:
        # Rule 7, independent of the data file: an image with two symbols never passes.
        assert outcome.passed is not True


def test_qr_decode_of_an_image_above_the_pixel_limit_is_blocked(tmp_path: Path) -> None:
    from PIL import Image  # noqa: PLC0415 - optional dependency, skipped above when missing

    image = io.BytesIO()
    Image.new("1", (4097, 4097), 1).save(image, format="PNG")
    outcome = qr_decode(_context(tmp_path, _POLICY, _Sample(image.getvalue(), "image/png")))
    assert (outcome.status.value, outcome.passed, outcome.reason_code) == (
        "blocked",
        None,
        "CARRIER.SAMPLE.TOO_LARGE",
    )
