"""Explicit trust configuration. Nothing is trusted because a report or a passport says so."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Self

from cryptography import x509
from pydantic import Field, field_validator, model_validator

from dppce.models.base import Model

STAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
# Hexadecimal, colons permitted. Compared as an integer.
SERIAL = r"^[0-9A-Fa-f]+(:[0-9A-Fa-f]+)*$"


class TrustedKey(Model):
    """A public key that the verifier accepts for the listed purposes, inside its validity window."""

    kid: str
    issuer: str
    purposes: tuple[Literal["report", "authorization", "passport", "manual"], ...] = Field(min_length=1)
    public_jwk: dict[str, str]
    not_before: str = Field(pattern=STAMP)
    not_after: str = Field(pattern=STAMP)


class TrustAnchor(Model):
    """An X.509 certificate that ends a certificate path, or a pinned TSA certificate."""

    name: str
    certificate_pem: str

    @field_validator("certificate_pem")
    @classmethod
    def _one_certificate(cls, value: str) -> str:
        try:
            x509.load_pem_x509_certificate(value.encode("ascii"))
        # InvalidVersion is no ValueError, and pydantic re-raises any exception that is not one.
        except (ValueError, UnicodeEncodeError, x509.InvalidVersion) as exc:
            raise ValueError("certificate_pem is not a PEM X.509 certificate") from exc
        return value


class RevokedKey(Model):
    """A key of the bundle that the operator revoked."""

    kid: str = Field(min_length=1)
    # null: revoked at every time. A time: revoked at that time and later. No default: write null.
    revoked_at: str | None = Field(pattern=STAMP)


class RevokedCertificate(Model):
    """A certificate serial number scoped by its issuer. Both must match (gap D8-10)."""

    serial: str = Field(pattern=SERIAL)
    issuer_name: str | None = Field(
        default=None,
        min_length=1,
        description="RFC 4514 issuer name, compared attribute by attribute without case folding.",
    )
    issuer_key_id: str | None = Field(
        default=None,
        pattern=r"^([0-9A-Fa-f]{2})+$",
        description="Hex key identifier, compared with the authority key identifier of the certificate.",
    )
    revoked_at: str | None = Field(pattern=STAMP)

    @field_validator("issuer_name")
    @classmethod
    def _rfc4514(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                x509.Name.from_rfc4514_string(value)
            except ValueError as exc:
                raise ValueError("issuer_name is not an RFC 4514 name") from exc
        return value

    @model_validator(mode="after")
    def _one_issuer(self) -> Self:
        if (self.issuer_name is None) == (self.issuer_key_id is None):
            raise ValueError("name exactly one of issuer_name and issuer_key_id")
        return self


class TrustBundle(Model):
    schema_version: Literal["dppce.trust/2"]
    policy_version: str
    # When true, missing or stale evidence of that kind prevents a complete verification.
    require_status: bool = False
    require_timestamp: bool = False
    keys: tuple[TrustedKey, ...] = ()
    # Passport (x5c) paths only. An anchor here never ends a TSA path.
    anchors: tuple[TrustAnchor, ...] = ()
    # TSA paths only: a CA certificate, or the TSA certificate itself (ADR 0015).
    timestamp_anchors: tuple[TrustAnchor, ...] = ()
    # A static snapshot of revocation status. The engine never fetches status at verification time.
    revoked_certificates: tuple[RevokedCertificate, ...] = ()
    revoked_keys: tuple[RevokedKey, ...] = ()
    status_as_of: str | None = Field(default=None, pattern=STAMP)
    status_max_age_days: int = Field(default=7, ge=0, le=3650)

    def key_revoked(self, kid: str, at: datetime) -> bool:
        """True if an entry revokes ``kid`` at ``at``.

        revoked_at holds whole seconds, so comparing it with ``at`` floored to seconds gives the
        same result as comparing exact instants.
        """
        stamp = at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return any(
            r.kid == kid and (r.revoked_at is None or r.revoked_at <= stamp) for r in self.revoked_keys
        )
