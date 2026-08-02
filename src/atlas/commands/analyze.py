from __future__ import annotations

from atlas import __version__
from atlas.application import AtlasSourceUnitService
from atlas.core.canonical import canonical_json_bytes
from atlas.renderers import render_gherkin, render_graph
from .common import slug, write


def handle(args) -> int | None:
    if args.command not in {"analyze", "analyze-unit"}:
        return None
    result = AtlasSourceUnitService(__version__).analyze(args.source.resolve(), args.dialect)
    output = args.output.resolve()
    if args.command == "analyze-unit":
        write(output, result)
    else:
        _write_analysis(output, result, args.emit_gherkin, args.emit_graph)
    summary = {
        "product": "Atlas", "version": __version__, "dialect": args.dialect.value,
        "source": result.source_name, "routines_analyzed": len(result.routines),
        "routine_refs": [item.routine_ref for item in result.routines],
        "parse_statuses": [item.semantic_report.parse_status for item in result.routines],
        "blocked_candidates": sum(item.severity == "ERROR" for item in result.discovery_findings),
        "output": output.as_posix(),
    }
    if len(result.routines) == 1:
        report = result.routines[0].semantic_report
        summary.update(parse_status=report.parse_status, routine=report.routine_ref,
                       decision_arms=len(report.decision_arms), effects=len(report.effects),
                       opaque_nodes=len(report.opaque_node_refs))
    print(canonical_json_bytes(summary).decode("utf-8"))
    return 0 if result.routines else 10


def _write_analysis(root, result, emit_gherkin: bool, emit_graph: bool) -> None:
    write(root / "source-unit-analysis.json", result)
    for index, bundle in enumerate(result.routines, start=1):
        target = root if len(result.routines) == 1 else root / "routines" / f"{index:03d}-{slug(bundle.routine_ref)}"
        write(target / "routine-ir.json", bundle.routine_ir)
        write(target / "semantic-report.json", bundle.semantic_report)
        write(target / "scenario-candidates.json", bundle.scenario_candidates)
        if emit_gherkin:
            write(target / "behavior-candidates.feature", render_gherkin(bundle.scenario_candidates))
        if emit_graph:
            write(target / "routine-graph.json", render_graph(bundle.routine_ir))
