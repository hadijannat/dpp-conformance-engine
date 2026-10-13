"""The allowlisted registry of executable checks.

A test purpose can name only a check that is registered here. There is no plugin loading:
a check exists because code in ``dppce.adapters`` registers it at import time.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from dppce.infrastructure.interfaces import Acquirer, Record
from dppce.models import (
    ICS,
    IXIT,
    Authorization,
    CheckOutcome,
    JsonValue,
    Observation,
    Profile,
    TestPurpose,
    TrustBundle,
)


@dataclass(frozen=True)
class CheckContext:
    """Everything a check may use. A check reads the clock and the outside world only from here."""

    purpose: TestPurpose
    ics: ICS
    ixit: IXIT
    profile: Profile
    acquirer: Acquirer
    evaluation_time: datetime
    data_root: Path
    trust: TrustBundle | None = None
    authorization: Authorization | None = None

    @property
    def params(self) -> Mapping[str, JsonValue]:
        return self.purpose.stimulus.params

    def observation(
        self,
        index: int,
        *,
        kind: Literal["exchange", "artifact", "declaration", "derived"],
        records: Sequence[Record] = (),
        summary: Mapping[str, Any] | None = None,
        transformations: Sequence[str] = (),
    ) -> Observation:
        """Build an observation with a deterministic identifier.

        ``summary`` holds only what the verdict needs, such as field names and status codes.
        Never put a restricted payload value in it.
        """
        acquired = max(
            (r.acquired_at for r in records), default=self.evaluation_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        return Observation(
            id=f"{self.purpose.id}#{index}",
            test_purpose_id=self.purpose.id,
            kind=kind,
            acquired_at=acquired,
            record_ids=tuple(r.record_id for r in records),
            summary=dict(summary or {}),
            transformations=tuple(transformations),
            truncated=any(r.truncated for r in records),
        )


CheckFn = Callable[[CheckContext], CheckOutcome]


@dataclass(frozen=True)
class CheckSpec:
    name: str
    capability: str
    fn: CheckFn


_REGISTRY: dict[str, CheckSpec] = {}


def register(name: str, *, capability: str) -> Callable[[CheckFn], CheckFn]:
    """Decorator that adds a check to the registry under a dotted name."""

    def decorator(fn: CheckFn) -> CheckFn:
        if name in _REGISTRY:
            raise ValueError(f"check '{name}' is registered twice")
        _REGISTRY[name] = CheckSpec(name=name, capability=capability, fn=fn)
        return fn

    return decorator


def get(name: str) -> CheckSpec | None:
    return _REGISTRY.get(name)


def names() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))
