from __future__ import annotations

import json
from pathlib import Path

from .intake import safe_id
from .models import ProcedureAnalysisError

SUMMARY_KEYS = (
    "schema_version", "analysis_id", "run_name", "created_at", "atlas_version",
    "tenant_ref", "actor_ref", "database_type", "database_display_name",
    "declared_dialect", "dialect_selection_mode", "dialect_locked", "counts", "content_digest",
)


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    value = payload.model_dump(mode="json") if hasattr(payload, "model_dump") else payload
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ProcedureAnalysisRepository:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def create_directory(self, analysis_id: str) -> Path:
        path = self.root / analysis_id
        if path.exists():
            raise ProcedureAnalysisError(f"Analysis already exists: {analysis_id}")
        path.mkdir(parents=True)
        (path / "sources").mkdir()
        (path / "analysis").mkdir()
        return path

    def save(self, analysis_dir: Path, payload: dict[str, object]) -> None:
        write_json(analysis_dir / "analysis.json", payload)

    def list(self) -> list[dict[str, object]]:
        values = []
        for path in self.root.iterdir() if self.root.exists() else ():
            manifest = path / "analysis.json"
            if not path.is_dir() or not manifest.is_file():
                continue
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            values.append({key: payload[key] for key in SUMMARY_KEYS if key in payload})
        return sorted(values, key=lambda item: str(item.get("created_at", "")), reverse=True)

    def load(self, analysis_id: str) -> dict[str, object]:
        if safe_id(analysis_id) != analysis_id:
            raise ProcedureAnalysisError("Invalid analysis identifier.")
        candidate = (self.root / analysis_id / "analysis.json").resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ProcedureAnalysisError("Analysis path escapes the tenant workspace.") from exc
        if not candidate.is_file():
            raise ProcedureAnalysisError("Procedure analysis was not found.")
        return json.loads(candidate.read_text(encoding="utf-8"))
