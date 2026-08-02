from __future__ import annotations

import hashlib
import json
from datetime import datetime

from atlas import __version__ as atlas_version
from .models import DatabaseDescriptor


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def counts(sources: list[dict], routines: list[dict]) -> dict[str, int]:
    return {
        "sources": len(sources), "routines": len(routines),
        "complete": sum(item["status"] == "COMPLETE" for item in routines),
        "partial": sum(item["status"] == "PARTIAL" for item in routines),
        "blocked": sum(item["status"] == "BLOCKED" for item in routines),
        "file_errors": sum(item["status"] == "ERROR" for item in sources),
        "findings": sum(item["finding_count"] for item in routines)
        + sum(len(item["discovery_findings"]) for item in sources),
    }


def analysis_payload(analysis_id: str, run_name: str, created_at: datetime, database: DatabaseDescriptor,
                     actor_ref: str, tenant_ref: str, sources: list[dict], routines: list[dict]) -> dict:
    payload = {
        "schema_version": "atlas-procedure-analysis-1.0", "analysis_id": analysis_id,
        "run_name": run_name.strip() or "Stored procedure analysis",
        "created_at": created_at.isoformat().replace("+00:00", "Z"), "atlas_version": atlas_version,
        "tenant_ref": tenant_ref, "actor_ref": actor_ref,
        "database_type": database.database_type.value, "database_display_name": database.display_name,
        "declared_dialect": database.dialect.value, "dialect_selection_mode": "USER_EXPLICIT",
        "dialect_locked": True, "counts": counts(sources, routines), "sources": sources, "routines": routines,
    }
    payload["content_digest"] = sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return payload
