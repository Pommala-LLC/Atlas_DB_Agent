from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineIR, RoutineKind, SemanticNode, SemanticNodeKind
from ..semantic_support import finding, merge_attributes


class OracleSemanticPolicy:
    dialect = DialectId.ORACLE_PLSQL

    def enrich(self, ir: RoutineIR) -> RoutineIR:
        nodes: list[SemanticNode] = []
        findings = list(ir.findings)
        autonomous = bool(ir.routine_attributes.get("autonomous_transaction_declared"))
        for node in ir.nodes:
            upper = node.text.upper()
            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                node = merge_attributes(
                    node,
                    handler_semantics="EXIT_DECLARING_BLOCK",
                    sqlstate_source="SQLCODE_SQLERRM",
                    exception_matching="FIRST_MATCHING_WHEN_ARM",
                )
            elif node.kind is SemanticNodeKind.SELECT_INTO:
                node = merge_attributes(
                    node,
                    cardinality_semantics="EXACTLY_ONE_OR_NO_DATA_FOUND_OR_TOO_MANY_ROWS",
                    no_data_exception="NO_DATA_FOUND",
                    multiple_rows_exception="TOO_MANY_ROWS",
                )
            elif node.kind is SemanticNodeKind.DYNAMIC_SQL:
                node = merge_attributes(
                    node,
                    dynamic_semantics="EXECUTE_IMMEDIATE",
                    supports_into=" INTO " in f" {upper} ",
                    supports_using=" USING " in f" {upper} ",
                    supports_returning=" RETURNING " in f" {upper} ",
                    parse_and_execute_at_runtime=True,
                )
            elif node.kind is SemanticNodeKind.ERROR_RAISE:
                node = merge_attributes(
                    node,
                    reraises_current_exception=bool(re.match(r"(?is)^\s*RAISE\s*;?\s*$", node.text)),
                    raise_application_error="RAISE_APPLICATION_ERROR" in upper,
                )
            elif node.kind is SemanticNodeKind.PRAGMA:
                node = merge_attributes(
                    node,
                    autonomous_transaction="AUTONOMOUS_TRANSACTION" in upper,
                    exception_init="EXCEPTION_INIT" in upper,
                    serially_reusable="SERIALLY_REUSABLE" in upper,
                )
            elif node.kind is SemanticNodeKind.BULK_OPERATION:
                node = merge_attributes(
                    node,
                    bulk_semantics="FORALL" if upper.startswith("FORALL") else "BULK_COLLECT",
                    save_exceptions="SAVE EXCEPTIONS" in upper,
                    limit_clause=" LIMIT " in f" {upper} ",
                )
            elif node.kind in {
                SemanticNodeKind.CURSOR_DECLARE,
                SemanticNodeKind.CURSOR_OPEN,
                SemanticNodeKind.CURSOR_FETCH,
                SemanticNodeKind.CURSOR_CLOSE,
            }:
                node = merge_attributes(
                    node,
                    cursor_attributes=("%FOUND", "%NOTFOUND", "%ROWCOUNT", "%ISOPEN"),
                    cursor_parameters="CURSOR" in upper and "(" in node.text,
                )
            elif node.kind in {
                SemanticNodeKind.INSERT,
                SemanticNodeKind.UPDATE,
                SemanticNodeKind.DELETE,
                SemanticNodeKind.MERGE,
            }:
                node = merge_attributes(node, returning_into=" RETURNING " in f" {upper} " and " INTO " in f" {upper} ")
            elif node.kind is SemanticNodeKind.LOCK:
                node = merge_attributes(node, lock_scope="TRANSACTION", releases_on_commit_or_rollback=True)
            elif node.kind is SemanticNodeKind.RESULT_SET:
                node = merge_attributes(
                    node,
                    result_semantics=(
                        "PIPELINED_ROW" if upper.startswith("PIPE ROW") else "REF_CURSOR_OR_RETURN_VALUE"
                    ),
                )
            elif node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK}:
                node = merge_attributes(node, autonomous_transaction=autonomous)
                if ir.routine_kind is RoutineKind.TRIGGER and not autonomous:
                    findings.append(
                        finding(
                            "ORACLE_TRIGGER_TRANSACTION_CONTROL_REQUIRES_AUTONOMOUS_TRANSACTION",
                            "Transaction control was found in a non-autonomous Oracle trigger.",
                            "A trigger cannot commit or roll back the caller transaction; an autonomous transaction pragma is required for an independent unit of work.",
                            node,
                        )
                    )
            nodes.append(node)
        return ir.model_copy(update={"nodes": tuple(nodes), "findings": tuple(findings)})
