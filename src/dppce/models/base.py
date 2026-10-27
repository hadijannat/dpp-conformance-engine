"""Shared vocabulary for all data contracts.

The Pydantic models in this package are the single source of truth.
The JSON Schemas in ``dppce/schemas/v1`` are generated from them. See ADR 0003.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict


class Model(BaseModel):
    """Base for every contract: closed (no extra keys) and immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# Canonical bodies hold strings, integers, booleans, and null only. No floats. See ADR 0006.
type JsonScalar = str | int | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

Unknown = Literal["unknown"]
UNKNOWN: Unknown = "unknown"


class Tri(StrEnum):
    """Three-valued outcome. Missing information is UNKNOWN, never FALSE."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict name, not a credential
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class AuthorityClass(StrEnum):
    """Kept separate on purpose: a guidance item is never reported as a legal obligation."""

    LEGAL_OBLIGATION = "legal_obligation"
    STANDARD_METHOD = "standard_method"
    IMPLEMENTATION_CONTRACT = "implementation_contract"
    GUIDANCE = "guidance"
    ILLUSTRATIVE = "illustrative"


class Modality(StrEnum):
    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class ReviewStatus(StrEnum):
    PLACEHOLDER = "placeholder"
    DRAFT = "draft-needs-review"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ExecutionMode(StrEnum):
    ILLUSTRATIVE = "illustrative"
    EXPLORATORY = "exploratory"
    REVIEWED = "reviewed"


class Testability(StrEnum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    MIXED = "mixed"
    NOT_TESTABLE = "not_testable"


class ExecutionStatus(StrEnum):
    """What happened to one test step. Only COMPLETED can carry pass or fail."""

    COMPLETED = "completed"
    NOT_RUN = "not_run"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    MANUAL_UNAVAILABLE = "manual_unavailable"
    ERROR = "error"


class Severity(StrEnum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    INFO = "info"


class CapabilityState(StrEnum):
    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    INTERFACE_ONLY = "interface_only"
    UNSUPPORTED = "unsupported"


class ClaimLevel(StrEnum):
    """What a result may be cited as. Set by execution mode and review status."""

    NONE = "none"
    ILLUSTRATIVE = "illustrative"
    DIAGNOSTIC = "diagnostic"
    REVIEWED = "reviewed"


class Scope(StrEnum):
    """Permission needed by a test step. Anything above READ needs a signed authorization."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    TAMPER = "tamper"
    FUZZ = "fuzz"
    ACCESS_PROBE = "access_probe"
    # The token request of an OAuth 2.0 client credentials role (P2-28). No check can use it.
    CREDENTIAL = "credential"
