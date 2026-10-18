"""Clocks and the one timestamp format that canonical bodies use."""

from __future__ import annotations

import re
from datetime import UTC, datetime

STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Explicit ASCII digits: strptime reads any Unicode digit and accepts unpadded fields.
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# RFC 3339 section 5.6 lets T and Z be lower case. IGNORECASE affects nothing else here.
_RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})",
    re.IGNORECASE,
)


def utc_stamp(moment: datetime) -> str:
    """Format an aware datetime as ``YYYY-MM-DDTHH:MM:SSZ``. A naive datetime is an error."""
    if moment.tzinfo is None:
        raise ValueError("a timestamp needs a time zone")
    return moment.astimezone(UTC).strftime(STAMP_FORMAT)


def parse_stamp(text: str) -> datetime:
    """Parse exactly the form that ``utc_stamp`` writes. Anything else is a ValueError."""
    if not _STAMP.fullmatch(text):
        raise ValueError("not a canonical timestamp")
    return datetime.strptime(text, STAMP_FORMAT).replace(tzinfo=UTC)


def parse_instant(text: str) -> datetime:
    """Parse an RFC 3339 date-time with an explicit offset, as a system under test may write it.

    ponytail: datetime keeps microseconds, so a step back of less than a microsecond is not seen.
    """
    if not _RFC3339.fullmatch(text):
        raise ValueError("not an RFC 3339 date-time with an offset")
    return datetime.fromisoformat(text.upper())


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
