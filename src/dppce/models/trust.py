"""Explicit trust configuration. Nothing is trusted because a report or a passport says so."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from dppce.models.base import Model

STAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"


class TrustedKey(Model):
    """A public key that the verifier accepts for the listed purposes, inside its validity window."""

    kid: str
    issuer: str
    purposes: tuple[Literal["report", "authorization", "passport", "manual"], ...] = Field(min_length=1)
    public_jwk: dict[str, str]
    not_before: str = Field(pattern=STAMP)
    not_after: str = Field(pattern=STAMP)


class TrustAnchor(Model):
    """An X.509 certificate that ends a passport signature chain."""

    name: str
    certificate_pem: str


class TrustBundle(Model):
    schema_version: Literal["dppce.trust/1"]
    policy_version: str
    # When true, missing or stale evidence of that kind prevents a complete verification.
    require_status: bool = False
    require_timestamp: bool = False
    keys: tuple[TrustedKey, ...] = ()
    anchors: tuple[TrustAnchor, ...] = ()
    # A static snapshot of revocation status. The engine never fetches status at verification time.
    # Certificate serial numbers in hexadecimal. Colons are permitted. Compared as integers.
    revoked_serials: tuple[Annotated[str, Field(pattern=r"^[0-9A-Fa-f]+(:[0-9A-Fa-f]+)*$")], ...] = ()
    revoked_kids: tuple[str, ...] = ()
    status_as_of: str | None = Field(default=None, pattern=STAMP)
    status_max_age_days: int = Field(default=7, ge=0, le=3650)
