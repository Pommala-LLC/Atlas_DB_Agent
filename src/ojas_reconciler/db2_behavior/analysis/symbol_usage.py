from __future__ import annotations

import hashlib
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import ProcedureAst, StateAccessKind
from ojas_reconciler.db2_behavior.analysis.models import SemanticFinding, SemanticFindingCode


class SymbolUsageAnalyzer:
    """Finds local declarations that are never assigned or never consumed."""

    def analyze(self, ast: ProcedureAst) -> tuple[SemanticFinding, ...]:
        defs = defaultdict(list)
        uses = defaultdict(list)
        node_by_id = {node.node_id: node for node in ast.nodes}
        for fact in ast.state_access_facts:
            (defs if fact.access_kind == StateAccessKind.DEF else uses)[fact.symbol_name.upper()].append(fact.source_node_ref)

        findings: list[SemanticFinding] = []
        for declared in ast.declared_symbol_types:
            if declared.symbol_kind != "LOCAL_VARIABLE":
                continue
            symbol = declared.symbol_name.upper()
            declaration = node_by_id.get(declared.source_ref)
            assigned_refs = set(defs.get(symbol, ()))
            if declared.default_expression is not None:
                assigned_refs.add(declared.source_ref)
            used_refs = set(uses.get(symbol, ()))
            if not assigned_refs:
                findings.append(self._finding(
                    SemanticFindingCode.DECLARED_SYMBOL_NEVER_ASSIGNED,
                    symbol,
                    tuple(ref for ref in (declared.source_ref,) if ref in node_by_id),
                    "The declaration contributes no value to any observed behavior and may indicate incomplete implementation.",
                    node_by_id,
                ))
            elif not used_refs:
                refs = tuple(dict.fromkeys((declared.source_ref, *sorted(assigned_refs))))
                findings.append(self._finding(
                    SemanticFindingCode.ASSIGNED_SYMBOL_NEVER_CONSUMED,
                    symbol,
                    tuple(ref for ref in refs if ref in node_by_id),
                    "Assignments and any queries feeding this symbol are dead with respect to the procedure's observable behavior.",
                    node_by_id,
                ))
        return tuple(sorted(findings, key=lambda item: item.finding_id))

    @staticmethod
    def _finding(code, symbol: str, refs: tuple[str, ...], consequence: str, node_by_id) -> SemanticFinding:
        payload = f"{code.value}|{symbol}|{'|'.join(refs)}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=(
                f"Local symbol {symbol} is declared but never assigned."
                if code == SemanticFindingCode.DECLARED_SYMBOL_NEVER_ASSIGNED
                else f"Local symbol {symbol} is assigned but never consumed."
            ),
            evidence_node_refs=refs,
            source_ranges=tuple(node_by_id[ref].source_range for ref in refs),
            consequence=consequence,
        )
