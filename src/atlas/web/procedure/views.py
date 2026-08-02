from __future__ import annotations

from atlas.application import SourceCandidate
from atlas.core.models import RoutineAnalysisBundle, SemanticNodeKind, SourceUnitAnalysis
from .coverage import analysis_eligibility, composition_status, coverage, primary_status
from .findings import call_boundary, finding_view, opaque_view


def routine_view(bundle: RoutineAnalysisBundle, candidate: SourceCandidate, source_id: str, source_name: str):
    ir, report = bundle.routine_ir, bundle.semantic_report
    findings = [finding_view(item, candidate) for item in ir.findings]
    opaque_spans: list[dict[str, int]] = []
    for node in ir.nodes:
        if node.kind is SemanticNodeKind.OPAQUE:
            span, finding = opaque_view(node, candidate)
            opaque_spans.append(span)
            findings.append(finding)
    findings.extend(call_boundary(target) for target in report.call_targets)
    code_lines, opaque_lines, opacity = coverage(candidate, opaque_spans)
    return {
        "routine_ref": bundle.routine_ref, "routine_name": ir.routine_name,
        "schema_name": ir.schema_name, "routine_kind": ir.routine_kind.value,
        "source_id": source_id, "source_name": source_name, "source_text": candidate.text,
        "start_line": candidate.start_line, "end_line": candidate.end_line,
        "source_digest": ir.source_digest, "body_digest": ir.body_digest, "ir_digest": ir.content_digest,
        "status": report.parse_status, "primary_status": primary_status(report.parse_status, findings),
        "analysis_eligibility": analysis_eligibility(report.parse_status),
        "composition_completeness": composition_status(report.call_targets),
        "decision_arm_count": len(report.decision_arms), "effect_count": len(report.effects),
        "opaque_node_count": len(report.opaque_node_refs), "opaque_coverage_percent": opacity,
        "opaque_line_count": opaque_lines, "code_line_count": code_lines,
        "finding_count": len(findings), "findings": findings, "opaque_spans": opaque_spans,
        "decision_arms": [item.model_dump(mode="json") for item in report.decision_arms],
        "effects": [item.model_dump(mode="json") for item in report.effects],
        "scenarios": [item.model_dump(mode="json") for item in bundle.scenario_candidates.scenarios],
        "call_targets": list(report.call_targets), "relation_refs": list(report.relation_refs),
    }


def source_status(analysis: SourceUnitAnalysis, views: list[dict[str, object]]) -> str:
    if not views:
        return "ERROR"
    if any(item["status"] != "COMPLETE" for item in views):
        return "PARTIAL"
    return "PARTIAL" if any(item.severity in {"WARNING", "ERROR"} for item in analysis.discovery_findings) else "COMPLETE"
