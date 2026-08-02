from __future__ import annotations

import hashlib
import re

from ojas_reconciler.db2_behavior.parsing.models import ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    ConstraintAssessment,
    ConstraintAssessmentStatus,
    PredicateGraph,
    QueryBindingFact,
    QuerySourceSummary,
    SemanticFinding,
    SemanticFindingCode,
    WindowModelStatus,
)


class WindowReachabilityAnalyzer:
    """Propagates admitted window/cardinality facts into local reachability."""

    def analyze(
        self,
        ast: ProcedureAst,
        summaries: tuple[QuerySourceSummary, ...],
        bindings: tuple[QueryBindingFact, ...],
        graphs: tuple[PredicateGraph, ...],
        assessments: tuple[ConstraintAssessment, ...],
    ) -> tuple[tuple[ConstraintAssessment, ...], tuple[SemanticFinding, ...]]:
        summaries_by_id = {value.query_summary_id: value for value in summaries}
        always_null: dict[str, set[str]] = {}
        for binding in bindings:
            summary = summaries_by_id.get(binding.query_summary_ref or "")
            if summary is None:
                continue
            for model in summary.window_models:
                if (
                    model.function_name in {"LAG", "LEAD"}
                    and model.model_status == WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION
                ):
                    always_null.setdefault(binding.target_symbol.upper(), set()).update(
                        {summary.source_node_ref, *model.evidence_refs}
                    )

        by_graph = {value.predicate_graph_ref: value for value in assessments}
        findings: list[SemanticFinding] = []
        node_by_id = {value.node_id: value for value in ast.nodes}
        for graph in graphs:
            expression_by_id = {value.expression_id: value for value in graph.expressions}

            def positive_atoms(ref: str, polarity: bool = True) -> tuple[str, ...]:
                expression = expression_by_id[ref]
                if expression.node_kind.value == "NOT" and expression.operand_refs:
                    return positive_atoms(expression.operand_refs[0], not polarity)
                if expression.operand_refs:
                    return tuple(
                        atom
                        for child in expression.operand_refs
                        for atom in positive_atoms(child, polarity)
                    )
                if polarity and expression.technical_expression:
                    return (expression.technical_expression,)
                return ()

            atoms = positive_atoms(graph.root_ref)
            symbols = {
                symbol
                for symbol in always_null
                if any(
                    re.search(
                        rf"\b{re.escape(symbol)}\s+IS\s+NOT\s+NULL\b",
                        atom,
                        re.IGNORECASE,
                    )
                    for atom in atoms
                )
            }
            if not symbols:
                continue
            evidence_refs = tuple(
                sorted(
                    {
                        *graph.source_node_refs,
                        *(ref for symbol in symbols for ref in always_null[symbol]),
                    }
                )
            )
            reason = (
                "Window-derived symbol(s) "
                + ", ".join(sorted(symbols))
                + " are always NULL because LAG/LEAD is evaluated over an input constrained to at most one row."
            )
            current = by_graph.get(graph.predicate_graph_id)
            if current is not None:
                by_graph[graph.predicate_graph_id] = current.model_copy(
                    update={
                        "status": ConstraintAssessmentStatus.OBVIOUS_CONTRADICTION,
                        "reason": reason,
                        "evidence_refs": evidence_refs,
                    }
                )
            ranges = tuple(
                node_by_id[ref].source_range for ref in evidence_refs if ref in node_by_id
            )
            payload = f"{graph.predicate_graph_id}|{'|'.join(sorted(symbols))}"
            suffix = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
            findings.append(
                SemanticFinding(
                    finding_id="semantic-finding-window-unreachable-" + suffix,
                    code=SemanticFindingCode.UNREACHABLE_BRANCH,
                    message=reason,
                    evidence_node_refs=evidence_refs,
                    source_ranges=ranges,
                    consequence="Effects controlled by this branch are unreachable and cannot be promoted.",
                )
            )

        updated = tuple(
            sorted(
                (by_graph.get(value.predicate_graph_ref, value) for value in assessments),
                key=lambda value: value.assessment_id,
            )
        )
        return updated, tuple(sorted(findings, key=lambda value: value.finding_id))
