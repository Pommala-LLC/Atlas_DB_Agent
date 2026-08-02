from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol

from ..core.canonical_json import canonical_digest
from .models import (
    EnterpriseRole,
    IdentityMode,
    IdentityPrincipal,
    OidcIdentityConfig,
    TrustedHeaderIdentityConfig,
)


class IdentityVerificationError(RuntimeError):
    pass


class IdentityProvider(Protocol):
    def authenticate(self, *, headers: Mapping[str, str]) -> IdentityPrincipal: ...


class FixedIdentityProvider:
    def __init__(self, *, actor_ref: str, tenant_ref: str, roles: tuple[EnterpriseRole, ...]) -> None:
        self.actor_ref = actor_ref
        self.tenant_ref = tenant_ref
        self.roles = roles

    def authenticate(self, *, headers: Mapping[str, str]) -> IdentityPrincipal:
        del headers
        return IdentityPrincipal(
            actor_ref=self.actor_ref,
            tenant_ref=self.tenant_ref,
            roles=self.roles,
            mode=IdentityMode.FIXED_LOCAL,
            evidence_refs=("LOCAL_CONFIGURATION",),
        )


class SignedTrustedHeaderIdentityProvider:
    """Verify reverse-proxy identity headers with an HMAC binding."""

    def __init__(self, config: TrustedHeaderIdentityConfig) -> None:
        self.config = config

    def authenticate(self, *, headers: Mapping[str, str]) -> IdentityPrincipal:
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        actor = normalized.get(self.config.actor_header.lower(), "")
        tenant = normalized.get(self.config.tenant_header.lower(), "")
        roles_raw = normalized.get(self.config.roles_header.lower(), "")
        timestamp = normalized.get(self.config.timestamp_header.lower(), "")
        signature = normalized.get(self.config.signature_header.lower(), "")
        if not all((actor, tenant, roles_raw, timestamp, signature)):
            raise IdentityVerificationError("Signed identity headers are incomplete.")
        secret = os.environ.get(self.config.shared_secret_env)
        if not secret:
            raise IdentityVerificationError(f"Missing trusted-header secret environment variable: {self.config.shared_secret_env}")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as exc:
            raise IdentityVerificationError("Invalid trusted-header timestamp.") from exc
        age = abs((datetime.now(timezone.utc) - parsed).total_seconds())
        if age > self.config.max_clock_skew_seconds:
            raise IdentityVerificationError("Trusted-header signature timestamp is outside the admitted clock-skew window.")
        message = "\n".join((actor, tenant, roles_raw, timestamp)).encode("utf-8")
        expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.removeprefix("sha256:")):
            raise IdentityVerificationError("Trusted-header signature is invalid.")
        try:
            roles = tuple(EnterpriseRole(value.strip().upper()) for value in roles_raw.split(",") if value.strip())
        except ValueError as exc:
            raise IdentityVerificationError("Trusted-header role is invalid.") from exc
        if not roles:
            raise IdentityVerificationError("At least one trusted-header role is required.")
        claims = {"actor": actor, "tenant": tenant, "roles": [item.value for item in roles], "timestamp": timestamp}
        return IdentityPrincipal(
            actor_ref=actor,
            tenant_ref=tenant,
            roles=roles,
            mode=IdentityMode.SIGNED_TRUSTED_HEADERS,
            claims_digest=canonical_digest(claims),
            evidence_refs=(self.config.signature_header,),
        )


class OidcJwtIdentityProvider:
    """Offline-verifiable OIDC/JWT adapter using a pinned public key or JWKS file."""

    def __init__(self, config: OidcIdentityConfig) -> None:
        self.config = config

    def _jwt(self):
        try:
            return importlib.import_module("jwt")
        except ModuleNotFoundError as exc:
            raise IdentityVerificationError(
                "AUTH_EXTRA_REQUIRED: install atlas-procedure-intelligence[auth]."
            ) from exc

    def authenticate(self, *, headers: Mapping[str, str]) -> IdentityPrincipal:
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        authorization = normalized.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            raise IdentityVerificationError("OIDC bearer token is required.")
        token = authorization.split(None, 1)[1]
        jwt = self._jwt()
        key: object
        evidence_ref: str
        if self.config.public_key_file:
            path = Path(self.config.public_key_file).resolve()
            key = path.read_text(encoding="utf-8")
            evidence_ref = path.as_posix()
        else:
            path = Path(self.config.jwks_file or "").resolve()
            jwks = json.loads(path.read_text(encoding="utf-8"))
            header = jwt.get_unverified_header(token)
            candidates = [item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")]
            if len(candidates) != 1:
                raise IdentityVerificationError("JWT kid does not resolve to exactly one pinned JWKS key.")
            key = jwt.PyJWK.from_dict(candidates[0]).key
            evidence_ref = path.as_posix() + "#kid=" + str(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self.config.algorithms),
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": list(self.config.required_claims)},
            )
        except Exception as exc:
            raise IdentityVerificationError(f"OIDC token verification failed: {exc}") from exc
        actor = str(claims.get(self.config.actor_claim) or "")
        tenant = str(claims.get(self.config.tenant_claim) or "")
        roles_claim = claims.get(self.config.roles_claim, [])
        if isinstance(roles_claim, str):
            raw_roles = [value.strip() for value in roles_claim.split(",") if value.strip()]
        elif isinstance(roles_claim, list):
            raw_roles = [str(value) for value in roles_claim]
        else:
            raw_roles = []
        roles = tuple(dict.fromkeys(self.config.role_mapping[value] for value in raw_roles if value in self.config.role_mapping))
        if not actor or not tenant or not roles:
            raise IdentityVerificationError("OIDC token lacks an admitted actor, tenant, or role mapping.")
        return IdentityPrincipal(
            actor_ref=actor,
            tenant_ref=tenant,
            roles=roles,
            mode=IdentityMode.OIDC_JWT,
            issuer=self.config.issuer,
            subject=str(claims.get("sub") or actor),
            claims_digest=canonical_digest(claims),
            evidence_refs=(evidence_ref,),
        )
