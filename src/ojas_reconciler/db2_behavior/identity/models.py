from __future__ import annotations

from enum import StrEnum
from pydantic import Field, model_validator

from ..core.models import CanonicalModel


class IdentityMode(StrEnum):
    FIXED_LOCAL = "FIXED_LOCAL"
    SIGNED_TRUSTED_HEADERS = "SIGNED_TRUSTED_HEADERS"
    OIDC_JWT = "OIDC_JWT"


class EnterpriseRole(StrEnum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"
    ADMIN = "ADMIN"


class IdentityPrincipal(CanonicalModel):
    actor_ref: str
    tenant_ref: str
    roles: tuple[EnterpriseRole, ...]
    mode: IdentityMode
    issuer: str | None = None
    subject: str | None = None
    claims_digest: str | None = None
    evidence_refs: tuple[str, ...] = ()


class TrustedHeaderIdentityConfig(CanonicalModel):
    mode: IdentityMode = IdentityMode.SIGNED_TRUSTED_HEADERS
    shared_secret_env: str
    actor_header: str = "x-ojas-actor"
    tenant_header: str = "x-ojas-tenant"
    roles_header: str = "x-ojas-roles"
    timestamp_header: str = "x-ojas-timestamp"
    signature_header: str = "x-ojas-signature"
    max_clock_skew_seconds: int = Field(default=300, gt=0)


class OidcIdentityConfig(CanonicalModel):
    mode: IdentityMode = IdentityMode.OIDC_JWT
    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256",)
    public_key_file: str | None = None
    jwks_file: str | None = None
    actor_claim: str = "sub"
    tenant_claim: str = "tenant"
    roles_claim: str = "roles"
    role_mapping: dict[str, EnterpriseRole]
    required_claims: tuple[str, ...] = ("exp", "iat", "sub")

    @model_validator(mode="after")
    def validate_key_source(self) -> "OidcIdentityConfig":
        if bool(self.public_key_file) == bool(self.jwks_file):
            raise ValueError("OIDC identity requires exactly one of public_key_file or jwks_file.")
        return self
