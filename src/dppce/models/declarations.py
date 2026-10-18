"""What the system owner declares (ICS), what the tester needs (IXIT), and what the owner permits."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dppce.models.base import Model, Scope, Unknown

# No lookaround and no nested quantifier: pydantic checks these with its linear-time engine.
# Engine code applies them with re.fullmatch, because Python's `$` also matches before a "\n".
PLACEHOLDER_NAME = r"^[a-z][a-z0-9_]{0,31}$"
PLACEHOLDER_PATTERN = r"\{([a-z][a-z0-9_]{0,31})\}"
PATH_TEMPLATE_PATTERN = (
    r"^/(?:(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%?]|\{[a-z][a-z0-9_]{0,31}\})"
    r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%/?]|\{[a-z][a-z0-9_]{0,31}\})*)?$"
)

ResourceName = Literal["item", "model", "signed", "versions", "registry_record"]
ItemTarget = Literal["template", "resolved"]


class SutIdentity(Model):
    name: str
    version: str | Unknown = "unknown"
    operator: str | Unknown = "unknown"
    identifier: str = Field(description="Stable URI or URN of the system under test.")


class ApiDeclaration(Model):
    version: str | Unknown = "unknown"
    contract: str | Unknown = Field(default="unknown", description="Identifier of the pinned API contract.")


class AccessDeclaration(Model):
    tiers: tuple[str, ...] | Unknown = "unknown"
    policy: str | Unknown = Field(default="unknown", description="Identifier of the declared access policy.")


class ICS(Model):
    """Implementation Conformance Statement.

    The core is product-agnostic. Product facts such as a capacity or a market date go in
    ``characteristics``. The profile says which facts it reads. Any value may be ``"unknown"``.
    An ICS declaration cannot waive a mandatory requirement.
    """

    schema_version: Literal["dppce.ics/1"]
    sut: SutIdentity
    profile: str
    product_category: str | Unknown = "unknown"
    granularity: Literal["item", "model", "batch"] | Unknown = "unknown"
    identifier_scheme: str | Unknown = "unknown"
    carriers: tuple[str, ...] | Unknown = "unknown"
    api: ApiDeclaration = ApiDeclaration()
    access: AccessDeclaration = AccessDeclaration()
    signature_format: Literal["jws", "cose", "none"] | Unknown = "unknown"
    # Integers, booleans, and strings only. Dates are ISO 8601 strings. Quantities use integer units.
    characteristics: dict[str, str | int | bool] = Field(default_factory=dict)
    features: dict[str, bool | Unknown] = Field(default_factory=dict)


class RoleIdentity(Model):
    role: str
    # A reference such as "env:DPPCE_ROLE_AUDITOR". Never the secret itself.
    secret_ref: str | None = Field(default=None, pattern=r"^(env|file):.+$")
    description: str = ""


class NetworkPolicy(Model):
    """Destinations the transport may reach. Loopback and private ranges need an explicit entry."""

    allowed_hosts: tuple[str, ...] = ()
    allow_private_hosts: tuple[str, ...] = ()
    timeout_ms: int = Field(default=5000, ge=100, le=60000)
    total_timeout_ms: int = Field(
        default=30000, ge=100, le=600000, description="Limit for one complete request, not for one read."
    )
    max_body_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    max_redirects: int = Field(default=3, ge=0, le=5)
    max_requests: int = Field(default=200, ge=1, le=10000)
    min_interval_ms: int = Field(default=0, ge=0, le=60000)
    retries: int = Field(default=0, ge=0, le=3, description="Extra attempts for an idempotent read.")
    contact: str = Field(default="", description="Contact shown in the User-Agent header.")


class ObservationPolicy(Model):
    store_bodies: bool = True
    retention_days: int = Field(default=30, ge=0, le=3650)


class TrustConfig(Model):
    bundle: str | None = None
    policy_version: str = "unset"


class ResourceTemplate(Model):
    endpoint: str = Field(pattern=PLACEHOLDER_NAME, description="Key of IXIT.endpoints.")
    path: str = Field(
        max_length=512,
        pattern=PATH_TEMPLATE_PATTERN,
        description="Path template under the endpoint. It cannot change the scheme, the host, or the port.",
    )


class IdParts(Model):
    """Splits samples.passport_id at the first n-1 occurrences of the separator.

    The last part keeps any further separator. No part can be empty.
    """

    separator: str = Field(min_length=1, max_length=8)
    names: tuple[Annotated[str, Field(pattern=PLACEHOLDER_NAME)], ...] = Field(min_length=2, max_length=8)

    @model_validator(mode="after")
    def _distinct_names(self) -> Self:
        if len(set(self.names)) != len(self.names) or "id" in self.names:
            raise ValueError("the part names must be distinct and must not be 'id'")
        return self


class IXIT(Model):
    """Implementation eXtra Information for Testing."""

    schema_version: Literal["dppce.ixit/1"]
    endpoints: dict[str, str] = Field(default_factory=dict)
    samples: dict[str, str] = Field(default_factory=dict)
    # No default template and no default split: either would be a hidden layout assumption.
    resources: dict[ResourceName, ResourceTemplate] = Field(default_factory=dict)
    id_parts: IdParts | None = None
    item_target: ItemTarget = Field(
        default="template",
        description=(
            "Where api.contract, the data checks, and integrity.jws fetch the item-level passport: "
            "the 'item' template, or the final URL of the carrier resolution. "
            "The transport policy applies to that URL as to any other."
        ),
    )
    identities: tuple[RoleIdentity, ...] = (RoleIdentity(role="anonymous"),)
    authorization_ref: str | None = None
    network: NetworkPolicy = NetworkPolicy()
    trust: TrustConfig = TrustConfig()
    observation: ObservationPolicy = ObservationPolicy()

    @model_validator(mode="after")
    def _templates_are_complete(self) -> Self:
        declared = {"id", *(self.id_parts.names if self.id_parts else ())}
        for name in sorted(self.resources):
            template = self.resources[name]
            if template.endpoint not in self.endpoints:
                raise ValueError(
                    f"the resource '{name}' names the endpoint '{template.endpoint}', "
                    "which 'endpoints' does not give"
                )
            unknown = sorted(set(re.findall(PLACEHOLDER_PATTERN, template.path)) - declared)
            if unknown:
                raise ValueError(f"the resource '{name}' uses undeclared placeholders {unknown}")
        return self


class Authorization(Model):
    """Payload of a signed test authorization from the system owner or an authorized delegate."""

    schema_version: Literal["dppce.authorization/1"]
    authorization_id: str
    issuer: str
    subject: str
    sut_identifier: str
    endpoints: tuple[str, ...] = Field(min_length=1, description="Permitted URL origins.")
    methods: tuple[str, ...] = Field(min_length=1)
    roles: tuple[str, ...] = Field(min_length=1)
    scopes: tuple[Scope, ...] = Field(min_length=1)
    not_before: str
    not_after: str
    max_requests: int = Field(ge=1)
