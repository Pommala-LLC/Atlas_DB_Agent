from __future__ import annotations

from atlas.application import SourceCandidate
from atlas.core.models import SemanticFinding, SemanticNode, SemanticNodeKind


def finding_class(code: str) -> tuple[str, str]:
    upper = code.upper()
    if "UNCLOSED" in upper or "UNBALANCED" in upper or "SOURCE_UNIT_COUNT_MISMATCH" in upper:
        return "STRUCTURAL_BLOCKER", "ATLAS"
    if "OPAQUE" in upper or "UNSUPPORTED_CONSTRUCT" in upper:
        return "ANALYSER_GAP", "ATLAS"
    if "UNREACHABLE" in upper:
        return "CODE_FINDING", "UNRESOLVED"
    if upper.startswith("SOURCE_UNIT_") or upper in {
        "INCOMPLETE_ROUTINE_SOURCE", "MIXED_CONTENT_SOURCE_UNIT", "UNSUPPORTED_DIALECT",
        "INVALID_HEADER_FOR_DECLARED_DIALECT",
    }:
        return "FILE_LEVEL_REFUSAL", "SOURCE_OR_ENVIRONMENT"
    if upper == "UNRESOLVED_CALL_EFFECT_BOUNDARY":
        return "COMPOSITION_BOUNDARY", "ATLAS"
    return "CODE_FINDING", "ATLAS"


def global_span(span, candidate: SourceCandidate) -> dict[str, int] | None:
    if span is None:
        return None
    offset = candidate.start_line - 1
    return {
        "start_line": span.start_line + offset, "start_column": span.start_column,
        "end_line": span.end_line + offset, "end_column": span.end_column,
        "start_offset": span.start_offset, "end_offset": span.end_offset,
    }


def finding_view(finding: SemanticFinding, candidate: SourceCandidate) -> dict[str, object]:
    category, attribution = finding_class(finding.code)
    return {
        "code": finding.code, "severity": finding.severity, "message": finding.message,
        "consequence": finding.consequence, "finding_class": category,
        "attribution": attribution, "source_span": global_span(finding.source_span, candidate),
    }


def opaque_view(node: SemanticNode, candidate: SourceCandidate) -> tuple[dict[str, int], dict[str, object]]:
    if node.kind is not SemanticNodeKind.OPAQUE:
        raise ValueError("opaque_view requires an OPAQUE node")
    span = global_span(node.source_span, candidate)
    assert span is not None
    finding = {
        "code": "DIALECT_STATEMENT_OPAQUE", "severity": "WARNING",
        "message": "Atlas retained this source span as opaque rather than inventing semantics.",
        "consequence": "Behavior within this span is not included in complete semantic claims.",
        "finding_class": "ANALYSER_GAP", "attribution": "ATLAS", "source_span": span,
    }
    return span, finding


def call_boundary(target: str) -> dict[str, object]:
    return {
        "code": "UNRESOLVED_CALL_EFFECT_BOUNDARY", "severity": "INFO",
        "message": f"Call effects for {target} are not composed into this routine analysis.",
        "consequence": "Routine analysis is eligible, but composition completeness remains unresolved.",
        "finding_class": "COMPOSITION_BOUNDARY", "attribution": "ATLAS", "source_span": None,
    }
