from __future__ import annotations

import hashlib
import re

from ojas_reconciler.db2_behavior.analysis.models import (
    ControlFlowGraph,
    HandlerSemanticsFact,
    SemanticFinding,
    SemanticFindingCode,
)
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst


class HandlerSemanticsAnalyzer:
    """Describe handler escape, propagation, and logging transaction semantics."""

    def analyze(
        self, ast: ProcedureAst, cfg: ControlFlowGraph
    ) -> tuple[tuple[HandlerSemanticsFact, ...], tuple[SemanticFinding, ...]]:
        del cfg  # The parsed handler region already carries its continuation contract.
        by_id = {node.node_id: node for node in ast.nodes}
        facts: list[HandlerSemanticsFact] = []
        findings: list[SemanticFinding] = []
        compatibility_nodes: set[str] = set()

        for handler in ast.nodes:
            region = handler.handler_region
            if region is None:
                continue
            descendants = self._descendants(region.body_node_refs, by_id)
            body_nodes = [by_id[ref] for ref in descendants if ref in by_id]
            resignal_refs = tuple(
                node.node_id for node in body_nodes if node.kind == NodeKind.RESIGNAL
            )
            dml_refs = tuple(node.node_id for node in body_nodes if node.kind == NodeKind.DML)
            transaction_refs = tuple(
                node.node_id
                for node in body_nodes
                if node.kind in {NodeKind.COMMIT, NodeKind.ROLLBACK}
            )
            is_exit = region.handler_kind.value in {"EXIT", "UNDO"}
            scope = region.lexical_scope_ref
            semantics_id = self._stable_id(
                "handler-semantics", handler.node_id, scope, *descendants
            )
            logging_scope = "NOT_APPLICABLE"
            rollback_visibility = "NOT_APPLICABLE"
            if dml_refs and transaction_refs:
                logging_scope = "HANDLER_MANAGED_TRANSACTION"
                rollback_visibility = "UNKNOWN"
            elif dml_refs:
                logging_scope = "CALLER_UNIT_OF_WORK"
                rollback_visibility = "ROLLS_BACK_WITH_CALLER"

            fact = HandlerSemanticsFact(
                semantics_id=semantics_id,
                handler_region_ref=handler.node_id,
                handler_scope_ref=scope,
                exited_compound_statement_ref=scope if is_exit else None,
                procedure_continues_after_scope=(scope != "procedure-body") if is_exit else True,
                resignal_present=bool(resignal_refs),
                original_condition_propagated=bool(resignal_refs),
                logging_transaction_scope=logging_scope,
                rollback_visibility=rollback_visibility,
                evidence_refs=tuple(dict.fromkeys((handler.node_id, *descendants))),
            )
            facts.append(fact)

            if not resignal_refs and region.handler_kind.value in {"EXIT", "UNDO"}:
                findings.append(
                    self._finding(
                        SemanticFindingCode.HANDLER_SWALLOWS_ORIGINAL_CONDITION,
                        (
                            f"{region.handler_kind.value} handler for {region.handled_condition_text} "
                            "does not RESIGNAL the original condition."
                        ),
                        (handler.node_id,),
                        (handler.source_range,),
                        (
                            "Control follows the handler continuation contract without propagating "
                            "the original SQL condition; callers may observe output state instead of an exception."
                        ),
                    )
                )
            if dml_refs and not transaction_refs:
                ranges = tuple(by_id[ref].source_range for ref in dml_refs)
                findings.append(
                    self._finding(
                        SemanticFindingCode.HANDLER_LOGGING_ROLLBACK_COUPLED,
                        "Handler DML executes in the caller-controlled unit of work.",
                        (handler.node_id, *dml_refs),
                        (handler.source_range, *ranges),
                        (
                            "Handler logging can be rolled back with the caller unless a separate "
                            "autonomous persistence mechanism is established."
                        ),
                    )
                )
                findings.append(
                    self._finding(
                        SemanticFindingCode.HANDLER_BODY_FAILURE_PROPAGATES,
                        (
                            "A SQL failure raised by DML inside the handler body is outside "
                            "the scope of that same handler."
                        ),
                        (handler.node_id, *dml_refs),
                        (handler.source_range, *ranges),
                        (
                            "A secondary failure from handler persistence can escape to the caller; "
                            "successful delivery of output assignments is not established without runtime evidence."
                        ),
                    )
                )
            for node in body_nodes:
                if re.search(r"\bSQLERRM\b", node.text, flags=re.IGNORECASE):
                    compatibility_nodes.add(node.node_id)
                if (
                    node.kind == NodeKind.GET_DIAGNOSTICS
                    and re.search(r"\bGET\s+DIAGNOSTICS\s+EXCEPTION\s+\d+\b", node.text, re.IGNORECASE)
                    and re.search(r"\bRETURNED_SQLSTATE\b", node.text, re.IGNORECASE)
                ):
                    findings.append(
                        self._finding(
                            SemanticFindingCode.DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM,
                            (
                                "RETURNED_SQLSTATE under GET DIAGNOSTICS EXCEPTION requires "
                                "verification against the configured Db2 LUW platform/version profile."
                            ),
                            (node.node_id,),
                            (node.source_range,),
                            (
                                "The EXCEPTION selector is not rejected, but the diagnostic-item "
                                "combination remains profile-unverified until target compilation or catalog evidence is supplied."
                            ),
                        )
                    )

        for ref in sorted(compatibility_nodes):
            node = by_id[ref]
            findings.append(
                self._finding(
                    SemanticFindingCode.DIALECT_SYMBOL_COMPATIBILITY_UNRESOLVED,
                    (
                        "SQLERRM compatibility is unresolved for the configured DB2_SQL_PL "
                        "dialect profile; verify the Db2 platform and compatibility mode or use GET DIAGNOSTICS."
                    ),
                    (ref,),
                    (node.source_range,),
                    "No compile failure or automatic rewrite is asserted without a platform-specific dialect profile.",
                )
            )

        return (
            tuple(sorted(facts, key=lambda item: item.semantics_id)),
            tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    @classmethod
    def _descendants(cls, refs: tuple[str, ...], by_id: dict[str, object]) -> tuple[str, ...]:
        result: list[str] = []

        def visit(ref: str) -> None:
            if ref in result or ref not in by_id:
                return
            result.append(ref)
            node = by_id[ref]
            for child in node.child_refs:
                visit(child)

        for ref in refs:
            visit(ref)
        return tuple(result)

    @staticmethod
    def _finding(code, message, refs, ranges, consequence) -> SemanticFinding:
        payload = f"{code.value}|{'|'.join(refs)}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=tuple(refs),
            source_ranges=tuple(ranges),
            consequence=consequence,
        )

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join((prefix, *parts))
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
