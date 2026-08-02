from __future__ import annotations

from pathlib import Path

from atlas.application import AtlasSourceSegmenter
from atlas.core.models import SourceUnitAnalysis
from .findings import finding_view
from .payload import sha256_text
from .store import write_json
from .views import routine_view, source_status


def analyze_source(service, analysis_dir: Path, index: int, source, dialect):
    source_id = f"source-{index:04d}"
    source_dir = analysis_dir / "sources" / source_id
    source_dir.mkdir()
    source_path = source_dir / source.name
    source_path.write_text(source.text, encoding="utf-8", newline="\n")
    analysis: SourceUnitAnalysis = service.analyze(source_path, dialect)
    result_path = analysis_dir / "analysis" / f"{source_id}-source-unit-analysis.json"
    write_json(result_path, analysis)
    candidates = AtlasSourceSegmenter().segment(source.text, source.name, dialect).candidates
    views = [routine_view(bundle, candidates[i], source_id, source.name)
             for i, bundle in enumerate(analysis.routines) if i < len(candidates)]
    discovery = [finding_view(item, candidates[0]) if candidates else _file_finding(item)
                 for item in analysis.discovery_findings]
    source_view = {
        "source_id": source_id, "source_name": source.name, "intake_kind": source.intake_kind,
        "source_digest": sha256_text(source.text), "source_text": source.text, "start_line": 1,
        "size_bytes": len(source.text.encode("utf-8")), "status": source_status(analysis, views),
        "routine_count": len(views), "discovery_findings": discovery,
        "analysis_artifact": result_path.relative_to(analysis_dir).as_posix(),
    }
    return source_view, views


def _file_finding(finding) -> dict[str, object]:
    return {
        "code": finding.code, "severity": finding.severity, "message": finding.message,
        "consequence": finding.consequence, "finding_class": "FILE_LEVEL_REFUSAL",
        "attribution": "SOURCE_OR_ENVIRONMENT", "source_span": None,
    }
