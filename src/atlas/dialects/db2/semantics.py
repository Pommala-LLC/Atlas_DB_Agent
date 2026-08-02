from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineIR, RoutineKind, SemanticNode, SemanticNodeKind
from ..semantic_support import finding, merge_attributes


class Db2SemanticPolicy:
    dialect = DialectId.DB2_SQL_PL

    def enrich(self, ir: RoutineIR) -> RoutineIR:
        nodes: list[SemanticNode] = []
        findings = list(ir.findings)
        by_id = {node.node_id: node for node in ir.nodes}

        def inside_atomic_block(node: SemanticNode) -> bool:
            current: SemanticNode | None = node
            seen: set[str] = set()
            while current is not None and current.node_id not in seen:
                seen.add(current.node_id)
                if current.kind is SemanticNodeKind.BLOCK and "BEGIN ATOMIC" in current.text.upper():
                    return True
                current = by_id.get(current.parent_ref) if current.parent_ref else None
            return False

        for node in ir.nodes:
            upper = re.sub(r"\s+", " ", node.text.upper()).strip()
            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                action_match = re.search(r"\bDECLARE\s+(CONTINUE|EXIT|UNDO)\s+HANDLER\s+FOR\s+(.+?)(?:\s+BEGIN|\s+SET|;|$)", upper)
                action = action_match.group(1) if action_match else node.attributes.get("handler_action", "HANDLER_BRANCH")
                condition = action_match.group(2).strip() if action_match else node.condition_text
                node = merge_attributes(
                    node,
                    handler_semantics="COMPOUND_STATEMENT_CONDITION_HANDLER",
                    handler_action=action,
                    handled_condition=condition,
                    scope="DECLARING_COMPOUND_STATEMENT",
                )
                if action == "UNDO" and not inside_atomic_block(node):
                    findings.append(
                        finding(
                            "DB2_UNDO_HANDLER_REQUIRES_ATOMIC",
                            "An UNDO handler was declared outside a detected ATOMIC compound statement.",
                            "Db2 requires an UNDO handler to be declared in an ATOMIC compound statement.",
                            node,
                        )
                    )
            elif node.kind is SemanticNodeKind.SELECT_INTO:
                node = merge_attributes(
                    node,
                    cardinality_semantics="SINGLE_ROW_ASSIGNMENT_WITH_NOT_FOUND_AND_CARDINALITY_CONDITIONS",
                    sqlstate_not_found="02000",
                    sqlstate_multiple_rows="21000",
                )
            elif node.kind is SemanticNodeKind.DYNAMIC_SQL:
                if upper.startswith("EXECUTE IMMEDIATE"):
                    mechanism = "EXECUTE_IMMEDIATE"
                elif upper.startswith("PREPARE"):
                    mechanism = "PREPARE"
                elif upper.startswith("EXECUTE"):
                    mechanism = "EXECUTE_PREPARED"
                else:
                    mechanism = "DYNAMIC_SQL"
                node = merge_attributes(
                    node,
                    dynamic_semantics=mechanism,
                    supports_using=" USING " in f" {upper} ",
                    supports_into=" INTO " in f" {upper} ",
                )
            elif node.kind in {
                SemanticNodeKind.CURSOR_DECLARE,
                SemanticNodeKind.CURSOR_OPEN,
                SemanticNodeKind.CURSOR_FETCH,
                SemanticNodeKind.CURSOR_CLOSE,
            }:
                node = merge_attributes(
                    node,
                    with_hold="WITH HOLD" in upper,
                    with_return="WITH RETURN" in upper,
                    return_target="CALLER" if "TO CALLER" in upper else ("CLIENT" if "TO CLIENT" in upper else None),
                    scrollable="SCROLL" in upper and "NO SCROLL" not in upper,
                )
            elif node.kind is SemanticNodeKind.RESULT_SET:
                node = merge_attributes(
                    node,
                    result_set_semantics="WITH_RETURN_CURSOR_OR_LOCATOR",
                    with_return="WITH RETURN" in upper,
                )
            elif node.kind is SemanticNodeKind.DIAGNOSTICS:
                node = merge_attributes(node, diagnostics_semantics="DB2_GET_DIAGNOSTICS")
            elif node.kind is SemanticNodeKind.MERGE:
                node = merge_attributes(node, statement_atomicity="SINGLE_MERGE_STATEMENT")
            elif node.kind is SemanticNodeKind.SAVEPOINT:
                node = merge_attributes(
                    node,
                    retain_cursors="RETAIN CURSORS" in upper,
                    on_rollback_retain_locks="ON ROLLBACK RETAIN LOCKS" in upper,
                )
            elif node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK, SemanticNodeKind.TRANSACTION_BEGIN}:
                node = merge_attributes(node, transaction_semantics="DB2_UNIT_OF_WORK")
                if ir.routine_kind is not RoutineKind.PROCEDURE:
                    findings.append(
                        finding(
                            "DB2_TRANSACTION_CONTROL_OUTSIDE_PROCEDURE",
                            "Transaction control was found in a Db2 function or trigger.",
                            "Transaction-control statements are not admitted in the bounded function/trigger lane.",
                            node,
                        )
                    )
            if "NEXT VALUE FOR" in upper or "PREVIOUS VALUE FOR" in upper:
                node = merge_attributes(
                    node,
                    sequence_reference="NEXT" if "NEXT VALUE FOR" in upper else "PREVIOUS",
                    non_transactional_sequence_effect=True,
                )
            nodes.append(node)
        return ir.model_copy(update={"nodes": tuple(nodes), "findings": tuple(findings)})
