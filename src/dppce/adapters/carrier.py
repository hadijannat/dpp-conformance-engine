"""Carrier adapter: QR image decoding. NFC and RFID are interfaces only (see the capability manifest)."""

from __future__ import annotations

from pydantic import Field

from dppce.adapters.common import completed, decode_qr
from dppce.models import CheckOutcome, Model
from dppce.testdefs.registry import CheckContext, register


class QrDecodeParams(Model):
    artifact: str = Field(
        default="qr_image", min_length=1, description="Name of the IXIT sample that holds the QR image."
    )


@register("carrier.qr_decode", capability="carrier.qr", params=QrDecodeParams)
def qr_decode(ctx: CheckContext) -> CheckOutcome:
    artifact = str(ctx.params.get("artifact", "qr_image"))
    text, record, problem = decode_qr(ctx, artifact)
    if problem is not None or text is None or record is None:
        assert problem is not None  # noqa: S101 - decode_qr returns a text or an outcome
        return problem
    # The payload length is recorded, not the payload: an identifier can be commercially sensitive.
    summary = {"qr_symbols": 1, "payload_characters": len(text)}
    observation = ctx.observation(
        0, kind="artifact", records=[record], summary=summary, transformations=("qr_decode",)
    )
    message = "The image decodes to one QR symbol with text. The engine does not grade print quality."
    return completed(True, "CARRIER.QR.OK", message, [observation])
