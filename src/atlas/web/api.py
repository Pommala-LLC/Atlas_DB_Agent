from __future__ import annotations

from pathlib import Path

from atlas import __version__
from atlas.application import AtlasSemanticService, AtlasSourceUnitService
from atlas.core.models import DialectId
from atlas.product import load_semantic_coverage_manifest
from atlas.renderers import render_graph


def register_api(app) -> None:
    from fastapi import Body
    service = AtlasSemanticService(__version__)

    @app.get("/api/atlas/dialects")
    def dialects():
        return {"product": "Atlas", "dialects": [item.value for item in service.registry.dialects()]}

    @app.get("/api/atlas/coverage")
    def coverage():
        return load_semantic_coverage_manifest().model_dump(mode="json")

    @app.post("/api/atlas/analyze")
    def analyze(payload: dict = Body(...)):
        source = Path(str(payload["source_path"])).resolve()
        dialect = DialectId(str(payload["dialect"]))
        if not source.exists():
            return {"status": "BLOCKED", "blocker": "SOURCE_NOT_FOUND", "source_path": source.as_posix()}
        result = AtlasSourceUnitService(__version__).analyze(source, dialect)
        response = {
            "status": _status(result), "source_unit_analysis": result.model_dump(mode="json"),
            "routine_graphs": [render_graph(item.routine_ir) for item in result.routines],
        }
        if len(result.routines) == 1:
            bundle = result.routines[0]
            response.update(routine_ir=bundle.routine_ir.model_dump(mode="json"),
                semantic_report=bundle.semantic_report.model_dump(mode="json"),
                scenario_candidates=bundle.scenario_candidates.model_dump(mode="json"),
                graph=render_graph(bundle.routine_ir))
        return response


def _status(result) -> str:
    if not result.routines:
        return "BLOCKED"
    return "PARTIAL" if any(item.semantic_report.parse_status != "COMPLETE" for item in result.routines) else "COMPLETE"
