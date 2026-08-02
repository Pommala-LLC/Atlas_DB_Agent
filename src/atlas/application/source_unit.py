from __future__ import annotations

import hashlib
from pathlib import Path

from atlas.core.canonical import canonical_digest
from atlas.core.models import DialectId, RoutineAnalysisBundle, SemanticFinding, SourceUnitAnalysis
from atlas.dialects.registry import AtlasDialectRegistry
from .segmentation import AtlasSourceSegmenter
from .service import AtlasSemanticService, routine_reference


class AtlasSourceUnitService:
    def __init__(self, atlas_version: str) -> None:
        self.atlas_version = atlas_version
        self.semantic = AtlasSemanticService(atlas_version)
        self.registry = AtlasDialectRegistry.default(atlas_version)
        self.segmenter = AtlasSourceSegmenter()

    def analyze(self, source: Path, dialect: DialectId) -> SourceUnitAnalysis:
        text = source.read_text(encoding="utf-8")
        segmentation = self.segmenter.segment(text, source.name, dialect)
        findings = list(segmentation.findings)
        bundles = self._bundles(segmentation.candidates, source.name, dialect, findings)
        if not segmentation.candidates:
            findings.append(SemanticFinding(code="SOURCE_UNIT_NO_ROUTINE_DISCOVERED", severity="ERROR",
                message=f"No {dialect.value} routine body was discovered in {source.name}.",
                consequence="The source unit cannot produce routine semantic evidence."))
        payload = {
            "schema_version": "atlas-source-unit-analysis-1.0",
            "atlas_version": self.atlas_version,
            "dialect": dialect,
            "source_name": source.name,
            "source_digest": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "routines": tuple(bundles),
            "discovery_findings": tuple(findings),
        }
        return SourceUnitAnalysis(**payload, content_digest=canonical_digest(payload))

    def _bundles(self, candidates, source_name: str, dialect: DialectId, findings: list[SemanticFinding]):
        adapter = self.registry.adapter(dialect)
        bundles: list[RoutineAnalysisBundle] = []
        for index, candidate in enumerate(candidates, start=1):
            try:
                ir = adapter.parse_text(candidate.text, f"{source_name}#routine-{index}")
            except Exception as exc:
                findings.append(SemanticFinding(code="SOURCE_UNIT_ROUTINE_ANALYSIS_BLOCKED", severity="ERROR",
                    message=f"Routine candidate {index} could not be analyzed: {exc}",
                    consequence="Other routines remain independently analyzable; this candidate is blocked."))
                continue
            report = self.semantic.report(ir)
            scenarios = self.semantic.scenarios(ir, report)
            payload = {"schema_version": "atlas-routine-analysis-bundle-1.0", "routine_ref": routine_reference(ir),
                "routine_ir": ir, "semantic_report": report, "scenario_candidates": scenarios}
            bundles.append(RoutineAnalysisBundle(**payload, content_digest=canonical_digest(payload)))
        return bundles
