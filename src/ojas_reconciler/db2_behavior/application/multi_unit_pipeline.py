from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from atlas import __version__ as atlas_version
from atlas.application import AtlasSourceSegmenter, AtlasSourceUnitService
from atlas.core.models import DialectId
from .pipeline import EndToEndPipeline


@dataclass(frozen=True)
class MultiUnitPipelineResult:
    manifest_path: Path
    routine_count: int
    failed: bool
    routine_outputs: tuple[str, ...]


class MultiUnitEndToEndPipeline:
    def run(self, *, source: Path, output_dir: Path, declared_dialect: str = "DB2_SQL_PL", **options) -> MultiUnitPipelineResult:
        if declared_dialect != "DB2_SQL_PL":
            raise ValueError("DIALECT_PROVIDER_MISMATCH: only DB2_SQL_PL is supported")
        text = source.resolve().read_text(encoding="utf-8")
        segmentation = AtlasSourceSegmenter().segment(text, source.name, DialectId.DB2_SQL_PL)
        if len(segmentation.candidates) <= 1:
            manifest = EndToEndPipeline().run(source=source, output_dir=output_dir, **options)
            failed = any(stage.status.value == "FAILED" for stage in manifest.stage_records)
            return MultiUnitPipelineResult(output_dir / "run-manifest.json", 1, failed, (output_dir.as_posix(),))
        output_dir.mkdir(parents=True, exist_ok=True)
        source_analysis = AtlasSourceUnitService(atlas_version).analyze(source.resolve(), DialectId.DB2_SQL_PL)
        (output_dir / "source-unit-analysis.json").write_text(
            source_analysis.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        runs, failed = [], False
        for index, candidate in enumerate(segmentation.candidates, start=1):
            routine_ref = source_analysis.routines[index - 1].routine_ref if index <= len(source_analysis.routines) else f"routine-{index}"
            routine_dir = output_dir / "routines" / f"{index:03d}-{_slug(routine_ref)}"
            routine_dir.mkdir(parents=True, exist_ok=True)
            routine_source = routine_dir / "source.sql"
            routine_source.write_text(candidate.text + "\n", encoding="utf-8")
            manifest = EndToEndPipeline().run(source=routine_source, output_dir=routine_dir, **options)
            routine_failed = any(stage.status.value == "FAILED" for stage in manifest.stage_records)
            failed = failed or routine_failed
            runs.append({"routine_ref": routine_ref, "output": routine_dir.relative_to(output_dir).as_posix(),
                         "manifest": "run-manifest.json", "failed": routine_failed})
        payload = {
            "schema_version": "atlas-multi-unit-e2e-run-1.0", "source": source.resolve().as_posix(),
            "declared_dialect": declared_dialect, "dialect_selection_mode": "USER_EXPLICIT",
            "routine_count": len(runs), "routines": runs, "failed": failed,
            "source_unit_analysis": "source-unit-analysis.json",
        }
        path = output_dir / "run-manifest.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return MultiUnitPipelineResult(path, len(runs), failed, tuple(item["output"] for item in runs))


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value).strip("-.") or "routine"
