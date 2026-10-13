"""Clocks and the one timestamp format that canonical bodies use."""

from __future__ import annotations

from datetime import UTC, datetime

STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_stamp(moment: datetime) -> str:
    """Format an aware datetime as ``YYYY-MM-DDTHH:MM:SSZ``. A naive datetime is an error."""
    if moment.tzinfo is None:
        raise ValueError("a timestamp needs a time zone")
    return moment.astimezone(UTC).strftime(STAMP_FORMAT)


def parse_stamp(text: str) -> datetime:
    return datetime.strptime(text, STAMP_FORMAT).replace(tzinfo=UTC)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """A clock that always returns the same moment. Used for replay and for tests."""

    def __init__(self, moment: datetime) -> None:
        utc_stamp(moment)  # rejects a naive datetime
        self._moment = moment

    def now(self) -> datetime:
        return self._moment
