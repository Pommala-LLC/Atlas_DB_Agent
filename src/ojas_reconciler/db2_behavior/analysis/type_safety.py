from __future__ import annotations

import hashlib
import re

from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner
from ojas_reconciler.db2_behavior.parsing.models import ProcedureAst
from ojas_reconciler.db2_behavior.type_system.models import SqlTypeFamily
from ojas_reconciler.db2_behavior.analysis.models import SemanticFinding, SemanticFindingCode


class AssignmentTypeSafetyAnalyzer:
    """Conservative subset of DB2 assignment narrowing analysis.

    It reports only when declared DECIMAL domains prove the source can exceed the
    target domain. Unsupported expressions produce no finding.
    """

    _decimal_cast = re.compile(r"^\s*DECIMAL\s*\((.*),\s*(\d+)\s*,\s*(\d+)\s*\)\s*$", re.IGNORECASE | re.DOTALL)

    def __init__(self) -> None:
        self._scanner = Db2LexicalScanner()

    def analyze(self, ast: ProcedureAst) -> tuple[SemanticFinding, ...]:
        declared = {item.symbol_name.upper(): item for item in ast.declared_symbol_types if item.sql_type is not None}
        node_by_id = {node.node_id: node for node in ast.nodes}
        findings: list[SemanticFinding] = []
        for node in ast.nodes:
            binding = node.assignment_binding
            if binding is None:
                continue
            target_decl = declared.get(binding.target_name.upper())
            if target_decl is None or target_decl.sql_type is None or target_decl.sql_type.family is not SqlTypeFamily.DECIMAL:
                continue
            target = target_decl.sql_type
            source_symbols = [
                token.upper for token in self._scanner.scan(binding.expression_text).tokens
                if token.upper in declared and declared[token.upper].sql_type is not None
            ]
            cast = self._decimal_cast.match(binding.expression_text)
            compared_target = target
            if cast is not None:
                compared_target = target.model_copy(update={"precision": int(cast.group(2)), "scale": int(cast.group(3))})
            wider = []
            for symbol in sorted(set(source_symbols)):
                source = declared[symbol].sql_type
                if source is None or source.family is not SqlTypeFamily.DECIMAL:
                    continue
                if self._domain_wider(source.precision, source.scale, compared_target.precision, compared_target.scale):
                    wider.append(symbol)
            if not wider:
                continue
            refs = tuple(dict.fromkeys((node.node_id, target_decl.source_ref, *(declared[s].source_ref for s in wider))))
            payload = f"{SemanticFindingCode.NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW.value}|{node.node_id}|{'|'.join(wider)}"
            findings.append(
                SemanticFinding(
                    finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    code=SemanticFindingCode.NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW,
                    message=(
                        f"Assignment to {binding.target_name} narrows the declared DECIMAL domain of "
                        f"{', '.join(wider)} and may raise numeric overflow."
                    ),
                    evidence_node_refs=tuple(ref for ref in refs if ref in node_by_id),
                    source_ranges=tuple(node_by_id[ref].source_range for ref in refs if ref in node_by_id),
                    consequence="The assignment requires a proven value bound or an explicit overflow handler before executable test generation can treat it as safe.",
                )
            )
        return tuple(sorted(findings, key=lambda item: item.finding_id))

    @staticmethod
    def _domain_wider(source_p, source_s, target_p, target_s) -> bool:
        if None in {source_p, source_s, target_p, target_s}:
            return False
        return (source_p - source_s) > (target_p - target_s) or source_s > target_s
