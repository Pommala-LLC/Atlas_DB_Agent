from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineIR, RoutineKind, SemanticNode, SemanticNodeKind
from ..semantic_support import finding, merge_attributes


class SqlServerSemanticPolicy:
    dialect = DialectId.SQLSERVER_TSQL

    def enrich(self, ir: RoutineIR) -> RoutineIR:
        nodes: list[SemanticNode] = []
        findings = list(ir.findings)
        for node in ir.nodes:
            upper = re.sub(r"\s+", " ", node.text.upper()).strip()
            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                node = merge_attributes(
                    node,
                    handler_semantics="TRY_CATCH",
                    diagnostics=("ERROR_NUMBER()", "ERROR_SEVERITY()", "ERROR_STATE()", "ERROR_PROCEDURE()", "ERROR_LINE()", "ERROR_MESSAGE()"),
                )
            elif node.kind in {SemanticNodeKind.BLOCK, SemanticNodeKind.DECLARE}:
                node = merge_attributes(node, lexical_scope=False)
            elif node.kind in {SemanticNodeKind.TRANSACTION_BEGIN, SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK, SemanticNodeKind.SAVEPOINT}:
                node = merge_attributes(node, transaction_registers=("@@TRANCOUNT", "XACT_STATE()"), nested_transaction_counter=True)
            elif node.kind is SemanticNodeKind.TRANSACTION_SETTING:
                node = merge_attributes(
                    node,
                    xact_abort="XACT_ABORT" in upper,
                    isolation_level=upper.split("ISOLATION LEVEL", 1)[1].strip().rstrip(";") if "ISOLATION LEVEL" in upper else None,
                    session_scoped=True,
                )
            elif node.kind is SemanticNodeKind.ERROR_RAISE:
                node = merge_attributes(
                    node,
                    reraises_current_exception=bool(re.match(r"(?is)^\s*THROW\s*;?\s*$", node.text)),
                    raise_mechanism="THROW" if upper.startswith("THROW") else "RAISERROR",
                )
            elif node.kind is SemanticNodeKind.DYNAMIC_SQL:
                node = merge_attributes(
                    node,
                    dynamic_semantics="EXEC_OR_SP_EXECUTESQL",
                    parameterized="SP_EXECUTESQL" in upper,
                    dynamic_scope="SEPARATE_BATCH_SCOPE",
                    local_variable_visibility="PARAMETER_BINDING_REQUIRED",
                )
            elif node.kind is SemanticNodeKind.SELECT_INTO:
                node = merge_attributes(node, assignment_cardinality="LAST_ROW_WINS_OR_UNCHANGED_ON_ZERO_ROWS")
            elif node.kind in {SemanticNodeKind.INSERT, SemanticNodeKind.UPDATE, SemanticNodeKind.DELETE, SemanticNodeKind.MERGE}:
                node = merge_attributes(node, output_clause=" OUTPUT " in f" {upper} ")
            elif node.kind is SemanticNodeKind.TEMP_OBJECT:
                table_variable = bool(node.attributes.get("table_variable")) or bool(re.match(r"(?is)^\s*DECLARE\s+@.+\bTABLE\b", node.text))
                node = merge_attributes(
                    node,
                    temp_scope="TABLE_VARIABLE_BATCH" if table_variable else ("GLOBAL_TEMPDB" if "##" in node.text else "SESSION_TEMPDB"),
                    table_variable=table_variable,
                )
            elif node.kind is SemanticNodeKind.GOTO:
                node = merge_attributes(node, transfer_semantics="SAME_BATCH_LABEL")

            if ir.routine_kind is RoutineKind.FUNCTION:
                if node.kind is SemanticNodeKind.DYNAMIC_SQL:
                    findings.append(finding("SQLSERVER_FUNCTION_DYNAMIC_SQL_NOT_ALLOWED", "Dynamic SQL was found in a T-SQL function.", "T-SQL user-defined functions cannot execute dynamic SQL.", node))
                elif node.kind is SemanticNodeKind.ERROR_HANDLER:
                    findings.append(finding("SQLSERVER_FUNCTION_TRY_CATCH_NOT_ALLOWED", "TRY/CATCH was found in a T-SQL function.", "T-SQL user-defined functions cannot contain TRY/CATCH error handling.", node))
                elif node.kind in {SemanticNodeKind.TRANSACTION_BEGIN, SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK, SemanticNodeKind.SAVEPOINT}:
                    findings.append(finding("SQLSERVER_FUNCTION_TRANSACTION_CONTROL_NOT_ALLOWED", "Transaction control was found in a T-SQL function.", "T-SQL user-defined functions cannot modify transaction state.", node))
                elif node.kind is SemanticNodeKind.TEMP_OBJECT and not bool(node.attributes.get("table_variable")):
                    findings.append(finding("SQLSERVER_FUNCTION_TEMP_TABLE_NOT_ALLOWED", "A temporary table was found in a T-SQL function.", "T-SQL user-defined functions may use table variables but cannot create temporary tables.", node))
                elif node.kind is SemanticNodeKind.ERROR_RAISE:
                    findings.append(finding("SQLSERVER_FUNCTION_ERROR_RAISE_NOT_ALLOWED", "THROW or RAISERROR was found in a T-SQL function.", "T-SQL user-defined functions cannot use side-effecting error-raising operators.", node))
            nodes.append(node)
        return ir.model_copy(update={"nodes": tuple(nodes), "findings": tuple(findings)})
