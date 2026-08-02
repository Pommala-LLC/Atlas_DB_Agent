from __future__ import annotations

import re
from dataclasses import dataclass

from atlas.core.models import DialectId, RoutineIR, RoutineKind, SemanticNode, SemanticNodeKind
from ..semantic_support import finding, merge_attributes


@dataclass(slots=True)
class _DeclarationState:
    last_rank: int = 0
    executable_seen: bool = False


class MySqlSemanticPolicy:
    dialect = DialectId.MYSQL_STORED_PROGRAM

    def enrich(self, ir: RoutineIR) -> RoutineIR:
        nodes: list[SemanticNode] = []
        findings = list(ir.findings)
        by_id = {node.node_id: node for node in ir.nodes}
        declared_locals = {
            node.text.split()[1].lstrip("@`").upper()
            for node in ir.nodes
            if node.kind is SemanticNodeKind.DECLARE and len(node.text.split()) > 1
        }
        declaration_rank = {
            SemanticNodeKind.DECLARE: 1,
            SemanticNodeKind.CONDITION_DECLARE: 1,
            SemanticNodeKind.CURSOR_DECLARE: 2,
            SemanticNodeKind.ERROR_HANDLER: 3,
        }
        states: dict[str, _DeclarationState] = {"<ROUTINE>": _DeclarationState()}

        def enclosing_block_ref(node: SemanticNode) -> str:
            current_ref = node.parent_ref
            seen: set[str] = set()
            while current_ref and current_ref not in seen:
                seen.add(current_ref)
                current = by_id.get(current_ref)
                if current is None:
                    break
                upper = re.sub(r"\s+", " ", current.text.upper()).strip()
                if current.kind is SemanticNodeKind.BLOCK and upper.startswith("BEGIN"):
                    return current.node_id
                current_ref = current.parent_ref
            return "<ROUTINE>"

        for original in ir.nodes:
            node = original
            upper = re.sub(r"\s+", " ", node.text.upper()).strip()
            scope_ref = enclosing_block_ref(node)
            state = states.setdefault(scope_ref, _DeclarationState())

            is_begin_block = node.kind is SemanticNodeKind.BLOCK and upper.startswith("BEGIN")
            is_end_block = node.kind is SemanticNodeKind.BLOCK and upper.startswith("END")
            if is_begin_block:
                # A nested compound statement is executable in its enclosing block,
                # while declarations inside it receive a fresh declaration phase.
                if scope_ref != node.node_id:
                    state.executable_seen = True
                states.setdefault(node.node_id, _DeclarationState())
            elif node.kind in declaration_rank:
                rank = declaration_rank[node.kind]
                if state.executable_seen:
                    findings.append(
                        finding(
                            "MYSQL_DECLARE_AFTER_EXECUTABLE_STATEMENT",
                            "A MySQL local declaration appears after an executable statement in the same block.",
                            "Every BEGIN...END block must place all declarations before its executable statements.",
                            node,
                        )
                    )
                if rank < state.last_rank:
                    findings.append(
                        finding(
                            "MYSQL_DECLARE_ORDER_INVALID",
                            "MySQL local declarations are not ordered as variables/conditions, cursors, then handlers.",
                            "The stored program is not valid under MySQL declaration ordering rules for this block.",
                            node,
                        )
                    )
                state.last_rank = max(state.last_rank, rank)
            elif node.kind not in {
                SemanticNodeKind.ENTRY,
                SemanticNodeKind.EXIT,
                SemanticNodeKind.LABEL,
            } and not is_end_block:
                state.executable_seen = True

            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                match = re.search(r"(?is)DECLARE\s+(CONTINUE|EXIT|UNDO)\s+HANDLER\s+FOR\s+(.+?)(?:\s+BEGIN|\s+SET|;|$)", node.text)
                action = match.group(1).upper() if match else "HANDLER_BRANCH"
                node = merge_attributes(
                    node,
                    handler_semantics="DECLARED_CONDITION_HANDLER",
                    handler_action=action,
                    handled_condition=match.group(2).strip() if match else node.condition_text,
                    scope="DECLARING_BLOCK",
                )
                if action == "UNDO":
                    findings.append(finding("MYSQL_UNDO_HANDLER_NOT_SUPPORTED", "An UNDO handler was declared.", "MySQL does not support UNDO handler execution.", node))
            elif node.kind in {SemanticNodeKind.CURSOR_DECLARE, SemanticNodeKind.CURSOR_OPEN, SemanticNodeKind.CURSOR_FETCH, SemanticNodeKind.CURSOR_CLOSE}:
                node = merge_attributes(node, cursor_sensitivity="ASENSITIVE", cursor_updatability="READ_ONLY", cursor_scrollability="NONSCROLLABLE", cursor_holdability="NONHOLDABLE")
            elif node.kind is SemanticNodeKind.DYNAMIC_SQL:
                node = merge_attributes(node, dynamic_semantics="SESSION_PREPARED_STATEMENT", statement_scope="SESSION", supports_local_prepared_statement_name=True)
                if upper.startswith("PREPARE") and any(re.search(rf"\b{re.escape(name)}\b", node.text, re.I) for name in declared_locals):
                    findings.append(finding("MYSQL_PREPARE_REFERENCES_LOCAL_VARIABLE", "MySQL prepared statement text references a local routine variable.", "Prepared statement text cannot directly depend on routine-local variable scope; use an admitted expression or user variable.", node))
                if ir.routine_kind in {RoutineKind.FUNCTION, RoutineKind.TRIGGER}:
                    findings.append(finding("MYSQL_DYNAMIC_SQL_NOT_ALLOWED_IN_FUNCTION_OR_TRIGGER", "Dynamic prepared-statement execution was found in a stored function or trigger.", "Prepared statements are admitted in stored procedures, not stored functions or triggers.", node))
            elif node.kind is SemanticNodeKind.CONDITION_DECLARE:
                node = merge_attributes(node, declaration_semantics="NAMED_CONDITION")
            elif node.kind is SemanticNodeKind.DIAGNOSTICS:
                node = merge_attributes(node, diagnostics_area=node.attributes.get("diagnostics_area", "STACKED" if "STACKED" in upper else "CURRENT"))
            elif node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK, SemanticNodeKind.TRANSACTION_BEGIN} and ir.routine_kind in {RoutineKind.FUNCTION, RoutineKind.TRIGGER}:
                findings.append(finding("MYSQL_TRANSACTION_CONTROL_NOT_ALLOWED_IN_FUNCTION_OR_TRIGGER", "Transaction control was found in a stored function or trigger.", "Stored functions and triggers cannot begin or end explicit transactions.", node))
            elif node.kind is SemanticNodeKind.RESULT_SET and ir.routine_kind is RoutineKind.FUNCTION:
                findings.append(finding("MYSQL_RESULT_SET_NOT_ALLOWED_IN_FUNCTION", "A result-set-producing SELECT was found in a stored function.", "Stored functions must return a scalar value and cannot return a client result set.", node))
            elif node.kind is SemanticNodeKind.LOCK:
                node = merge_attributes(node, explicit_table_lock=True)
            elif node.kind is SemanticNodeKind.UPSERT:
                node = merge_attributes(node, affected_rows_semantics="INSERT_OR_UPDATE_PATH", alias_or_values_reference_version_sensitive=True)
            nodes.append(node)
        return ir.model_copy(update={"nodes": tuple(nodes), "findings": tuple(findings)})
