from __future__ import annotations

import hashlib
import re

from ojas_reconciler.db2_behavior.analysis.models import SemanticFinding, SemanticFindingCode
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst


class PathStateReconciliationAnalyzer:
    """Detects source-level state conflicts that local slices cannot safely flatten."""

    def analyze(self, ast: ProcedureAst) -> tuple[SemanticFinding, ...]:
        findings: list[SemanticFinding] = []
        findings.extend(self._cursor_state_conflicts(ast))
        findings.extend(self._conditional_savepoints(ast))
        return tuple(sorted(findings, key=lambda item: item.finding_id))

    def _cursor_state_conflicts(self, ast: ProcedureAst) -> list[SemanticFinding]:
        declarations: dict[str, object] = {}
        opens: list[tuple[str, object]] = []
        updates: list[object] = []
        for node in ast.nodes:
            if node.kind == NodeKind.DECLARE_CURSOR:
                match = re.search(r"\bDECLARE\s+([A-Za-z_][A-Za-z0-9_$]*)\b.*?\bCURSOR\b", node.text, re.I | re.S)
                if match:
                    declarations[match.group(1).upper()] = node
            elif node.kind == NodeKind.OPEN_CURSOR:
                match = re.search(r"\bOPEN\s+([A-Za-z_][A-Za-z0-9_$]*)\b", node.text, re.I)
                if match:
                    opens.append((match.group(1).upper(), node))
            elif node.kind == NodeKind.DML and re.match(r"\s*UPDATE\b", node.text, re.I):
                updates.append(node)

        result: list[SemanticFinding] = []
        for cursor_name, open_node in opens:
            declaration = declarations.get(cursor_name)
            if declaration is None:
                continue
            cursor_relation = self._relation_after(declaration.text, "FROM")
            cursor_equalities = self._literal_equalities(self._where_clause(declaration.text))
            if cursor_relation is None or not cursor_equalities:
                continue
            for update in updates:
                if update.source_range.start_offset >= open_node.source_range.start_offset:
                    continue
                update_relation = self._relation_after(update.text, "UPDATE")
                if update_relation != cursor_relation:
                    continue
                set_values = self._literal_assignments(self._set_clause(update.text))
                update_filters = self._literal_equalities(self._where_clause(update.text))
                conflicts: list[tuple[str, str, str]] = []
                for column, cursor_value in cursor_equalities.items():
                    new_value = set_values.get(column)
                    if new_value is None or new_value == cursor_value:
                        continue
                    if update_filters.get(column) == cursor_value:
                        conflicts.append((column, cursor_value, new_value))
                if not conflicts:
                    continue
                detail = ", ".join(
                    f"{column}: {old} -> {new}" for column, old, new in conflicts
                )
                result.append(
                    self._finding(
                        SemanticFindingCode.CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION,
                        (
                            f"Cursor {cursor_name} filters {cursor_relation} using a state that a prior "
                            f"UPDATE changes before OPEN ({detail})."
                        ),
                        (declaration.node_id, update.node_id, open_node.node_id),
                        (declaration.source_range, update.source_range, open_node.source_range),
                        (
                            "Cursor-body effects are conditional or potentially unreachable under isolated "
                            "execution; they must not be presented as unconditional procedure behavior."
                        ),
                    )
                )
        return result

    def _conditional_savepoints(self, ast: ProcedureAst) -> list[SemanticFinding]:
        savepoints: dict[str, object] = {}
        for node in ast.nodes:
            if node.kind == NodeKind.SAVEPOINT:
                match = re.search(r"\bSAVEPOINT\s+([A-Za-z_][A-Za-z0-9_$]*)", node.text, re.I)
                if match:
                    savepoints[match.group(1).upper()] = node
        if not savepoints:
            return []

        executable_before = [
            node
            for node in ast.nodes
            if node.kind in {
                NodeKind.SELECT_INTO,
                NodeKind.DML,
                NodeKind.CALL,
                NodeKind.PREPARE,
                NodeKind.EXECUTE,
                NodeKind.EXECUTE_IMMEDIATE,
                NodeKind.OPEN_CURSOR,
                NodeKind.FETCH_CURSOR,
                NodeKind.CLOSE_CURSOR,
                NodeKind.GET_DIAGNOSTICS,
            }
        ]
        result: list[SemanticFinding] = []
        for handler in ast.nodes:
            if handler.kind != NodeKind.HANDLER_REGION or handler.handler_region is None:
                continue
            for child_ref in handler.handler_region.body_node_refs:
                child = next((node for node in ast.nodes if node.node_id == child_ref), None)
                if child is None or child.kind != NodeKind.ROLLBACK:
                    continue
                match = re.search(r"\bTO\s+SAVEPOINT\s+([A-Za-z_][A-Za-z0-9_$]*)", child.text, re.I)
                if not match:
                    continue
                name = match.group(1).upper()
                savepoint = savepoints.get(name)
                if savepoint is None:
                    continue
                prior_risks = [
                    node
                    for node in executable_before
                    if node.source_range.start_offset < savepoint.source_range.start_offset
                    and node.lexical_scope_ref == savepoint.lexical_scope_ref
                ]
                if not prior_risks:
                    continue
                evidence = (handler.node_id, child.node_id, savepoint.node_id, prior_risks[-1].node_id)
                result.append(
                    self._finding(
                        SemanticFindingCode.HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT,
                        (
                            f"Handler rolls back to savepoint {name}, but executable statements can raise "
                            "before that savepoint is established."
                        ),
                        evidence,
                        tuple(next(node.source_range for node in ast.nodes if node.node_id == ref) for ref in evidence),
                        (
                            "A secondary savepoint error may mask the original exception; handler behavior "
                            "must be marked partial until establishment is proven on every activation path."
                        ),
                    )
                )
        return result

    @staticmethod
    def _relation_after(text: str, keyword: str) -> str | None:
        match = re.search(rf"\b{keyword}\s+([A-Za-z_][A-Za-z0-9_.$\"]*)", text, re.I)
        return match.group(1).strip('"').upper() if match else None

    @staticmethod
    def _where_clause(text: str) -> str:
        match = re.search(r"\bWHERE\b(.*?)(?:\bFOR\s+UPDATE\b|\bORDER\s+BY\b|;|$)", text, re.I | re.S)
        return match.group(1) if match else ""

    @staticmethod
    def _set_clause(text: str) -> str:
        match = re.search(r"\bSET\b(.*?)\bWHERE\b", text, re.I | re.S)
        return match.group(1) if match else ""

    @staticmethod
    def _literal_equalities(text: str) -> dict[str, str]:
        return {
            column.upper(): value.upper()
            for column, value in re.findall(
                r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:''|[^'])*'|[-+]?\d+(?:\.\d+)?)",
                text,
                re.I,
            )
        }

    @staticmethod
    def _literal_assignments(text: str) -> dict[str, str]:
        return PathStateReconciliationAnalyzer._literal_equalities(text)

    @staticmethod
    def _finding(code, message, refs, ranges, consequence) -> SemanticFinding:
        payload = f"{code.value}|{'|'.join(refs)}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode()).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=refs,
            source_ranges=ranges,
            consequence=consequence,
        )
