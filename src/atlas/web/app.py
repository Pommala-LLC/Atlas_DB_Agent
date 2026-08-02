from __future__ import annotations

from .api import register_api
from .settings import AtlasUiSettings


def create_app(settings: AtlasUiSettings):
    """Canonical Atlas web factory; legacy package remains a compatibility implementation bridge."""
    try:
        from ojas_reconciler.db2_behavior.commercial_ui.app import (
            CommercialUiSettings, UiRole as LegacyRole, create_app as create_legacy_app,
        )
    except ModuleNotFoundError as exc:
        raise RuntimeError("UI_EXTRA_REQUIRED: install atlas-procedure-intelligence[ui].") from exc
    legacy = CommercialUiSettings(
        workspace=settings.workspace, tenant_ref=settings.tenant_ref, actor_ref=settings.actor_ref,
        role=LegacyRole(settings.role.value), trust_identity_headers=settings.trust_identity_headers,
        identity_config=settings.identity_config, title=settings.title, allowed_origins=settings.allowed_origins,
        trust_proxy_headers=settings.trust_proxy_headers,
    )
    app = create_legacy_app(legacy)
    register_api(app)
    return app
