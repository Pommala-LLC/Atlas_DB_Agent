from __future__ import annotations

from pathlib import Path


def handle(args) -> int | None:
    if args.command != "serve":
        return None
    from atlas.web.runner import run
    return run(args.host, args.port, Path(args.workspace), args.tenant_ref, args.actor_ref, args.role)
