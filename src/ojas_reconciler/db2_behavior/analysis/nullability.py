from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ojas_reconciler.db2_behavior.analysis.models import (
    NullabilityStatus,
    QueryBindingFact,
    SemanticFinding,
    SemanticFindingCode,
    SymbolNullabilityFact,
)
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst


class DefiniteNullabilityAnalyzer:
    """Conservative symbol nullability derived from declarations and definitions."""

    def analyze(
        self,
        ast: ProcedureAst,
        query_bindings: tuple[QueryBindingFact, ...],
    ) -> tuple[tuple[SymbolNullabilityFact, ...], tuple[SemanticFinding, ...]]:
        nodes = {node.node_id: node for node in ast.nodes}
        query_by_node_and_target = {
            (binding.source_node_ref, binding.target_symbol.upper()): binding
            for binding in query_bindings
        }
        assignments: dict[str, list[tuple[str, str | None, NullabilityStatus]]] = defaultdict(list)

        for node in ast.nodes:
            if node.assignment_binding is not None:
                symbol = node.assignment_binding.target_name.upper()
                expr = node.assignment_binding.expression_text
                assignments[symbol].append(
                    (node.node_id, expr, self._expression_status(expr, symbol))
                )
            if node.select_into_binding is not None:
                for target in node.select_into_binding.target_names:
                    symbol = target.upper()
                    binding = query_by_node_and_target.get((node.node_id, symbol))
                    expression = binding.projection_expression if binding is not None else None
                    assignments[symbol].append(
                        (node.node_id, expression, self._query_projection_status(expression))
                    )
            if node.dynamic_execute_binding is not None:
                for target in node.dynamic_execute_binding.into_target_names:
                    assignments[target.upper()].append(
                        (node.node_id, None, NullabilityStatus.POSSIBLY_NULL)
                    )
            if node.fetch_binding is not None:
                for target in node.fetch_binding.target_names:
                    assignments[target.upper()].append(
                        (node.node_id, None, NullabilityStatus.POSSIBLY_NULL)
                    )

        facts: list[SymbolNullabilityFact] = []
        status_by_symbol: dict[str, NullabilityStatus] = {}
        for declared in ast.declared_symbol_types:
            symbol = declared.symbol_name.upper()
            default_status = self._default_status(declared.default_expression)
            values = assignments.get(symbol, [])
            statuses = [default_status, *(item[2] for item in values)]
            status = self._join(statuses)
            status_by_symbol[symbol] = status
            evidence = tuple(
                dict.fromkeys(
                    [declared.source_ref, *(item[0] for item in values)]
                )
            )
            payload = f"{symbol}|{status.value}|{'|'.join(evidence)}"
            facts.append(
                SymbolNullabilityFact(
                    fact_id="nullability-" + hashlib.sha256(payload.encode()).hexdigest()[:20],
                    symbol_name=symbol,
                    status=status,
                    declaration_default_ref=declared.source_ref,
                    assignment_refs=tuple(item[0] for item in values),
                    evidence_refs=evidence,
                    reason=self._reason(default_status, values, status),
                )
            )

        findings: list[SemanticFinding] = []
        for node in ast.nodes:
            if node.kind != NodeKind.IF_REGION or node.if_region is None:
                continue
            for arm in node.if_region.arms:
                condition = " ".join(str(arm.condition_text or "").split())
                for symbol in re.findall(
                    r"\b([A-Za-z_][A-Za-z0-9_.$]*)\s+IS\s+NULL\b",
                    condition,
                    flags=re.IGNORECASE,
                ):
                    normalized = symbol.upper()
                    if status_by_symbol.get(normalized) != NullabilityStatus.DEFINITELY_NON_NULL:
                        continue
                    payload = f"{node.node_id}|{arm.arm_id}|{normalized}|IMPOSSIBLE_NULL"
                    findings.append(
                        SemanticFinding(
                            finding_id="finding-" + hashlib.sha256(payload.encode()).hexdigest()[:20],
                            code=SemanticFindingCode.IMPOSSIBLE_NULL_PREDICATE,
                            message=(
                                f"Predicate {normalized} IS NULL is unreachable because all "
                                "declaration and assignment definitions are non-null."
                            ),
                            evidence_node_refs=tuple(
                                dict.fromkeys([node.node_id, *next(
                                    (fact.evidence_refs for fact in facts if fact.symbol_name == normalized),
                                    (),
                                )])
                            ),
                            source_ranges=(arm.source_range,),
                            consequence=(
                                "The null-case scenario must be suppressed or explicitly marked unreachable."
                            ),
                        )
                    )
        return (
            tuple(sorted(facts, key=lambda item: item.symbol_name)),
            tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    @staticmethod
    def _default_status(expression: str | None) -> NullabilityStatus:
        if expression is None or expression.strip().upper() == "NULL":
            return NullabilityStatus.DEFINITELY_NULL
        return NullabilityStatus.DEFINITELY_NON_NULL

    @staticmethod
    def _expression_status(expression: str | None, symbol: str) -> NullabilityStatus:
        text = " ".join(str(expression or "").strip().split())
        upper = text.upper()
        if not text:
            return NullabilityStatus.UNKNOWN
        if upper == "NULL":
            return NullabilityStatus.DEFINITELY_NULL
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?|'(?:''|[^'])*'", text):
            return NullabilityStatus.DEFINITELY_NON_NULL
        if upper.startswith(("CURRENT ", "NEXT VALUE FOR ", "COALESCE(", "COUNT(")):
            return NullabilityStatus.DEFINITELY_NON_NULL
        if re.search(rf"\b{re.escape(symbol)}\b\s*[+\-*/]", upper):
            return NullabilityStatus.DEFINITELY_NON_NULL
        if "NULLIF(" in upper or re.search(r"\b(AVG|SUM|MAX|MIN)\s*\(", upper):
            return NullabilityStatus.POSSIBLY_NULL
        return NullabilityStatus.POSSIBLY_NULL

    @staticmethod
    def _query_projection_status(expression: str | None) -> NullabilityStatus:
        text = " ".join(str(expression or "").strip().split()).upper()
        if not text:
            return NullabilityStatus.UNKNOWN
        if re.match(r"COUNT\s*\(", text) or text.startswith("COALESCE("):
            return NullabilityStatus.DEFINITELY_NON_NULL
        if re.match(r"(AVG|SUM|MAX|MIN)\s*\(", text):
            return NullabilityStatus.POSSIBLY_NULL
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?|'(?:''|[^'])*'", text):
            return NullabilityStatus.DEFINITELY_NON_NULL
        return NullabilityStatus.POSSIBLY_NULL

    @staticmethod
    def _join(statuses: list[NullabilityStatus]) -> NullabilityStatus:
        concrete = {value for value in statuses if value != NullabilityStatus.UNKNOWN}
        if not concrete:
            return NullabilityStatus.UNKNOWN
        if concrete == {NullabilityStatus.DEFINITELY_NON_NULL}:
            return NullabilityStatus.DEFINITELY_NON_NULL
        if concrete == {NullabilityStatus.DEFINITELY_NULL}:
            return NullabilityStatus.DEFINITELY_NULL
        return NullabilityStatus.POSSIBLY_NULL

    @staticmethod
    def _reason(default_status, values, status) -> str:
        return (
            f"Declaration starts {default_status.value}; {len(values)} assignment/binding "
            f"definition(s) yield {status.value}."
        )
