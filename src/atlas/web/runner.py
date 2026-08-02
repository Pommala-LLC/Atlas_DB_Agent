from __future__ import annotations

import argparse
from pathlib import Path

from atlas import __version__
from .app import create_app
from .settings import AtlasUiSettings, UiRole


def create_atlas_app(workspace: Path, tenant_ref: str, actor_ref: str, role: str):
    app = create_app(AtlasUiSettings(workspace=workspace, tenant_ref=tenant_ref,
        actor_ref=actor_ref, role=UiRole(role)))
    app.title = "Atlas Procedure Intelligence"
    app.version = __version__
    return app


def run(host: str, port: int, workspace: Path, tenant_ref: str, actor_ref: str, role: str) -> int:
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise SystemExit("UI_EXTRA_REQUIRED: install atlas-procedure-intelligence[ui].") from exc
    uvicorn.run(create_atlas_app(workspace, tenant_ref, actor_ref, role), host=host, port=port)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Atlas Procedure Intelligence")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--workspace", type=Path, default=Path("reports/atlas"))
    parser.add_argument("--tenant-ref", default="tenant:local")
    parser.add_argument("--actor-ref", default="actor:local-admin")
    parser.add_argument("--role", choices=tuple(item.value for item in UiRole), default=UiRole.ADMIN.value)
    args = parser.parse_args()
    return run(args.host, args.port, args.workspace, args.tenant_ref, args.actor_ref, args.role)
