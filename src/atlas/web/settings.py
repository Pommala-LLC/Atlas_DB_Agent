from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class UiRole(StrEnum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    REVIEWER = "REVIEWER"
    ADMIN = "ADMIN"


@dataclass(frozen=True)
class AtlasUiSettings:
    workspace: Path
    tenant_ref: str = "tenant:local"
    actor_ref: str = "actor:local-ui"
    role: UiRole = UiRole.ADMIN
    trust_identity_headers: bool = False
    identity_config: Path | None = None
    title: str = "Atlas Procedure Intelligence"
    allowed_origins: tuple[str, ...] = ()
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls) -> "AtlasUiSettings":
        role_value = os.environ.get("ATLAS_UI_ROLE", UiRole.ADMIN.value)
        try:
            role = UiRole(role_value)
        except ValueError:
            role = UiRole.VIEWER
        config = os.environ.get("ATLAS_UI_IDENTITY_CONFIG")
        return cls(
            workspace=Path(os.environ.get("ATLAS_UI_WORKSPACE", "reports/atlas")),
            tenant_ref=os.environ.get("ATLAS_UI_TENANT", "tenant:local"),
            actor_ref=os.environ.get("ATLAS_UI_ACTOR", "actor:local-ui"), role=role,
            trust_identity_headers=os.environ.get("ATLAS_UI_TRUST_HEADERS", "").strip() == "1",
            identity_config=Path(config) if config else None,
            title=os.environ.get("ATLAS_UI_TITLE", "Atlas Procedure Intelligence"),
            allowed_origins=tuple(value.strip().rstrip("/") for value in
                os.environ.get("ATLAS_UI_ALLOWED_ORIGINS", "").split(",") if value.strip()),
            trust_proxy_headers=os.environ.get("ATLAS_UI_TRUST_PROXY_HEADERS", "").strip() == "1",
        )
