from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineIR, RoutineKind, SemanticNode, SemanticNodeKind
from ..semantic_support import finding, merge_attributes


class PostgreSqlSemanticPolicy:
    dialect = DialectId.POSTGRESQL_PLPGSQL

    def enrich(self, ir: RoutineIR) -> RoutineIR:
        nodes: list[SemanticNode] = []
        findings = list(ir.findings)
        found_updaters = {
            SemanticNodeKind.QUERY, SemanticNodeKind.SELECT_INTO, SemanticNodeKind.INSERT, SemanticNodeKind.UPDATE,
            SemanticNodeKind.DELETE, SemanticNodeKind.MERGE, SemanticNodeKind.UPSERT, SemanticNodeKind.CURSOR_FETCH,
            SemanticNodeKind.RESULT_SET,
        }
        for node in ir.nodes:
            upper = re.sub(r"\s+", " ", node.text.upper()).strip()
            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                node = merge_attributes(node, handler_semantics="EXCEPTION_BLOCK", block_changes_rolled_back_before_handler=True, diagnostics=("SQLSTATE", "SQLERRM", "GET STACKED DIAGNOSTICS"))
            elif node.kind is SemanticNodeKind.SELECT_INTO:
                node = merge_attributes(node, cardinality_semantics="STRICT_EXACTLY_ONE" if " INTO STRICT " in f" {upper} " else "FIRST_ROW_OR_NULL_ASSIGNMENT")
            if node.kind in found_updaters:
                node = merge_attributes(node, updates_found_register=True)
            if node.kind is SemanticNodeKind.DYNAMIC_SQL:
                node = merge_attributes(
                    node,
                    dynamic_semantics="PLPGSQL_EXECUTE",
                    updates_found_register=False,
                    supports_using=" USING " in f" {upper} ",
                    supports_into=" INTO " in f" {upper} ",
                    returns_rows=bool(node.attributes.get("returns_rows")) or upper.startswith("RETURN QUERY EXECUTE"),
                    opens_refcursor=bool(node.attributes.get("opens_refcursor")),
                )
            elif node.kind is SemanticNodeKind.ASSERT:
                node = merge_attributes(node, assertion_failure_sqlstate="P0004", enabled_by="plpgsql.check_asserts")
            elif node.kind is SemanticNodeKind.RESULT_SET:
                node = merge_attributes(node, result_semantics="RETURN_QUERY" if upper.startswith("RETURN QUERY") else "RETURN_NEXT_OR_REFCURSOR")
            elif node.kind is SemanticNodeKind.DIAGNOSTICS:
                node = merge_attributes(node, diagnostics_scope="STACKED" if "STACKED" in upper else "CURRENT")
            elif node.kind is SemanticNodeKind.LOCK:
                node = merge_attributes(node, lock_scope="TRANSACTION")
            elif node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK}:
                node = merge_attributes(node, chain="AND CHAIN" in upper, transaction_control_context="TOP_LEVEL_CALL_OR_DO_REQUIRED")

            if ir.routine_kind is not RoutineKind.PROCEDURE and node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK}:
                findings.append(finding("POSTGRES_TRANSACTION_CONTROL_OUTSIDE_PROCEDURE", "Transaction control was found in a PL/pgSQL function or trigger.", "COMMIT and ROLLBACK are only admitted for procedures or DO blocks in permitted top-level invocation contexts.", node))
            nodes.append(node)
        return ir.model_copy(update={"nodes": tuple(nodes), "findings": tuple(findings)})
