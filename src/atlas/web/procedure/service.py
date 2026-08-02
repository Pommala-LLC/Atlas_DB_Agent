from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from atlas import __version__ as atlas_version
from atlas.application import AtlasSourceUnitService
from .intake import safe_id, validate_sources
from .models import DatabaseDescriptor, SourceInput
from .payload import analysis_payload
from .source import analyze_source
from .store import ProcedureAnalysisRepository


class ProcedureAnalysisService:
    def __init__(self, root: Path) -> None:
        self.repository = ProcedureAnalysisRepository(root)
        self.analyzer = AtlasSourceUnitService(atlas_version)

    @property
    def root(self) -> Path:
        return self.repository.root

    def create_analysis(self, *, run_name: str, database: DatabaseDescriptor,
                        sources: Iterable[SourceInput], actor_ref: str, tenant_ref: str):
        inputs = validate_sources(sources)
        now = datetime.now(timezone.utc)
        analysis_id = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{safe_id(run_name)}"
        analysis_dir = self.repository.create_directory(analysis_id)
        source_results, routine_results = [], []
        for index, source in enumerate(inputs, start=1):
            source_view, routines = analyze_source(self.analyzer, analysis_dir, index, source, database.dialect)
            source_results.append(source_view)
            routine_results.extend(routines)
        payload = analysis_payload(analysis_id, run_name, now, database, actor_ref, tenant_ref,
                                   source_results, routine_results)
        self.repository.save(analysis_dir, payload)
        return analysis_dir, payload

    def list_analyses(self):
        return self.repository.list()

    def load_analysis(self, analysis_id: str):
        return self.repository.load(analysis_id)
