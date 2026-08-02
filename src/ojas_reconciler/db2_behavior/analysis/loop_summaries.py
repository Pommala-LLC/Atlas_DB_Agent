from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    ControlFlowGraph,
    LoopProofObligation,
    LoopProofObligationStatus,
    LoopSummaryCandidate,
    LoopSummarySoundness,
    LoopTerminationStatus,
    SemanticFinding,
    SemanticFindingCode,
)


class LoopSummaryAnalyzer:
    """Emits proof obligations and conservative loop-summary candidates."""

    def analyze(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
    ) -> tuple[tuple[LoopSummaryCandidate, ...], tuple[SemanticFinding, ...]]:
        by_id = {node.node_id: node for node in ast.nodes}
        parent_map = self._parent_map(ast)
        findings: list[SemanticFinding] = []
        summaries: list[LoopSummaryCandidate] = []

        for loop in sorted(
            (node for node in ast.nodes if node.kind == NodeKind.LOOP_REGION and node.loop_region is not None),
            key=lambda node: node.source_range.start_offset,
        ):
            region = loop.loop_region
            assert region is not None
            descendants = self._descendants(loop.node_id, by_id)
            fetches = tuple(
                sorted(
                    (ref for ref in descendants if by_id[ref].kind == NodeKind.FETCH_CURSOR),
                    key=lambda ref: by_id[ref].source_range.start_offset,
                )
            )
            leaves = tuple(
                sorted(
                    (
                        ref
                        for ref in descendants
                        if by_id[ref].kind in {NodeKind.LEAVE, NodeKind.RETURN, NodeKind.SIGNAL, NodeKind.RESIGNAL}
                    ),
                    key=lambda ref: by_id[ref].source_range.start_offset,
                )
            )
            iterates = tuple(
                sorted(
                    (ref for ref in descendants if by_id[ref].kind == NodeKind.ITERATE),
                    key=lambda ref: by_id[ref].source_range.start_offset,
                )
            )
            accumulators = tuple(
                sorted(
                    (
                        ref
                        for ref in descendants
                        if self._is_accumulator(by_id[ref])
                    ),
                    key=lambda ref: by_id[ref].source_range.start_offset,
                )
            )
            handler_bindings = tuple(
                sorted(
                    binding.binding_id
                    for binding in cfg.handler_bindings
                    if binding.source_ast_node_ref in descendants
                )
            )
            cursor_declarations = self._cursor_declarations(fetches, by_id, ast)
            initializations = self._accumulator_initializations(
                accumulators=accumulators,
                loop_ref=loop.node_id,
                parent_map=parent_map,
                by_id=by_id,
                ast=ast,
            )
            dml_refs = tuple(
                sorted(
                    (ref for ref in descendants if by_id[ref].kind == NodeKind.DML),
                    key=lambda ref: by_id[ref].source_range.start_offset,
                )
            )

            obligations = (
                LoopProofObligation(
                    obligation="CURSOR_POPULATION_IDENTIFIED",
                    status=(
                        LoopProofObligationStatus.SATISFIED
                        if not fetches or cursor_declarations
                        else LoopProofObligationStatus.UNSATISFIED
                    ),
                    evidence_refs=cursor_declarations,
                    note="Cursor declarations are structurally identified; query semantics remain Phase 2.",
                ),
                LoopProofObligation(
                    obligation="FETCH_BINDING_IDENTIFIED",
                    status=(
                        LoopProofObligationStatus.SATISFIED
                        if fetches
                        else LoopProofObligationStatus.NOT_APPLICABLE
                    ),
                    evidence_refs=fetches,
                ),
                LoopProofObligation(
                    obligation="ACCUMULATOR_INITIALIZATION_IDENTIFIED",
                    status=(
                        LoopProofObligationStatus.SATISFIED
                        if not accumulators or initializations
                        else LoopProofObligationStatus.PARTIAL
                    ),
                    evidence_refs=initializations,
                ),
                LoopProofObligation(
                    obligation="ACCUMULATOR_UPDATE_IDENTIFIED",
                    status=(
                        LoopProofObligationStatus.SATISFIED
                        if accumulators
                        else LoopProofObligationStatus.NOT_APPLICABLE
                    ),
                    evidence_refs=accumulators,
                ),
                LoopProofObligation(
                    obligation="EARLY_EXIT_RESOLVED",
                    status=(
                        LoopProofObligationStatus.PARTIAL
                        if leaves
                        else LoopProofObligationStatus.NOT_APPLICABLE
                    ),
                    evidence_refs=leaves,
                    note="Exit sites are identified; condition satisfiability is not yet proven.",
                ),
                LoopProofObligation(
                    obligation="HANDLER_INTERFERENCE_RESOLVED",
                    status=(
                        LoopProofObligationStatus.PARTIAL
                        if handler_bindings
                        else LoopProofObligationStatus.SATISFIED
                    ),
                    evidence_refs=handler_bindings,
                    note="Handler bindings are known; state interference remains conservative.",
                ),
                LoopProofObligation(
                    obligation="SOURCE_MUTATION_RESOLVED",
                    status=(
                        LoopProofObligationStatus.PARTIAL
                        if dml_refs and fetches
                        else LoopProofObligationStatus.NOT_APPLICABLE
                    ),
                    evidence_refs=dml_refs,
                    note="Query lineage is required to determine cursor-source mutation interference.",
                ),
                LoopProofObligation(
                    obligation="NULL_SEMANTICS_RESOLVED",
                    status=(
                        LoopProofObligationStatus.PARTIAL
                        if accumulators
                        else LoopProofObligationStatus.NOT_APPLICABLE
                    ),
                    evidence_refs=accumulators,
                    note="Typed query and column nullability are not yet available.",
                ),
                LoopProofObligation(
                    obligation="TERMINATION_RESOLVED",
                    status=(
                        LoopProofObligationStatus.PARTIAL
                        if leaves or region.condition_text
                        else LoopProofObligationStatus.UNSATISFIED
                    ),
                    evidence_refs=tuple([loop.node_id, *leaves]),
                ),
            )
            termination = self._termination_status(region.loop_kind.value, region.condition_text, leaves)
            soundness = LoopSummarySoundness.PARTIAL_SUMMARY
            summary_id = "loop-summary-" + hashlib.sha256(
                f"{loop.node_id}|{'|'.join(fetches)}|{'|'.join(accumulators)}".encode("utf-8")
            ).hexdigest()[:20]
            evidence_refs = tuple(
                dict.fromkeys(
                    [
                        loop.node_id,
                        *fetches,
                        *accumulators,
                        *leaves,
                        *iterates,
                        *cursor_declarations,
                        *initializations,
                        *dml_refs,
                    ]
                )
            )
            summary = LoopSummaryCandidate(
                loop_summary_id=summary_id,
                loop_region_ref=loop.node_id,
                loop_kind=region.loop_kind.value,
                label=region.label,
                condition_text=region.condition_text,
                cursor_fetch_refs=fetches,
                accumulator_assignment_refs=accumulators,
                early_exit_refs=leaves,
                iterate_refs=iterates,
                handler_binding_refs=handler_bindings,
                proof_obligations=obligations,
                termination_status=termination,
                cardinality_status="DATA_DEPENDENT" if fetches else "UNKNOWN",
                soundness=soundness,
                analysis_completeness="PARTIAL",
                evidence_refs=evidence_refs,
            )
            summaries.append(summary)
            findings.append(
                self._finding(
                    SemanticFindingCode.LOOP_SUMMARY_PARTIAL,
                    "Loop structure and proof obligations were extracted, but no exact loop summary was admitted.",
                    evidence_refs,
                    by_id,
                    "Loop effects remain MAY/UNKNOWN and cannot support mandatory behavior assertions.",
                )
            )
            if termination == LoopTerminationStatus.POSSIBLY_NON_TERMINATING:
                findings.append(
                    self._finding(
                        SemanticFindingCode.POSSIBLY_NON_TERMINATING_LOOP,
                        "No structural termination candidate was found for the loop.",
                        (loop.node_id,),
                        by_id,
                        "The loop remains an opaque or partial boundary for downstream behavior analysis.",
                    )
                )
            if any(obligation.status == LoopProofObligationStatus.UNSATISFIED for obligation in obligations):
                findings.append(
                    self._finding(
                        SemanticFindingCode.LOOP_EFFECT_UNRESOLVED,
                        "One or more required loop proof obligations are unsatisfied.",
                        evidence_refs,
                        by_id,
                        "No exact or conservative-must summary is emitted.",
                    )
                )

        return (
            tuple(sorted(summaries, key=lambda item: item.loop_summary_id)),
            tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    @staticmethod
    def _is_accumulator(node: object) -> bool:
        binding = getattr(node, "assignment_binding", None)
        if binding is None:
            return False
        target = re.escape(binding.target_name)
        return bool(re.search(rf"\b{target}\b\s*[+\-*/]", binding.expression_text, flags=re.IGNORECASE))

    def _cursor_declarations(
        self,
        fetch_refs: tuple[str, ...],
        by_id: dict[str, object],
        ast: ProcedureAst,
    ) -> tuple[str, ...]:
        cursor_names = {
            getattr(by_id[ref], "fetch_binding").cursor_name
            for ref in fetch_refs
            if getattr(by_id[ref], "fetch_binding", None) is not None
        }
        result: list[str] = []
        for node in ast.nodes:
            if node.kind != NodeKind.DECLARE_CURSOR:
                continue
            upper = node.text.upper()
            if any(re.search(rf"\b{re.escape(name)}\b", upper) for name in cursor_names):
                result.append(node.node_id)
        return tuple(sorted(result))

    def _accumulator_initializations(
        self,
        *,
        accumulators: tuple[str, ...],
        loop_ref: str,
        parent_map: dict[str, str],
        by_id: dict[str, object],
        ast: ProcedureAst,
    ) -> tuple[str, ...]:
        loop = by_id[loop_ref]
        loop_start = getattr(loop, "source_range").start_offset
        symbols = {
            getattr(by_id[ref], "assignment_binding").target_name
            for ref in accumulators
            if getattr(by_id[ref], "assignment_binding", None) is not None
        }
        result: list[str] = []
        for node in ast.nodes:
            if node.source_range.start_offset >= loop_start:
                continue
            binding = node.assignment_binding
            if binding is not None and binding.target_name in symbols:
                result.append(node.node_id)
                continue
            if node.kind == NodeKind.DECLARE_VARIABLE:
                upper = node.text.upper()
                if " DEFAULT " in f" {upper} " and any(re.search(rf"\b{re.escape(symbol)}\b", upper) for symbol in symbols):
                    result.append(node.node_id)
        return tuple(sorted(result))

    @staticmethod
    def _termination_status(
        loop_kind: str,
        condition_text: str | None,
        leaves: tuple[str, ...],
    ) -> LoopTerminationStatus:
        if leaves or condition_text:
            return LoopTerminationStatus.TERMINATION_CANDIDATE
        if loop_kind == "LOOP":
            return LoopTerminationStatus.POSSIBLY_NON_TERMINATING
        return LoopTerminationStatus.UNKNOWN

    def _parent_map(self, ast: ProcedureAst) -> dict[str, str]:
        result: dict[str, str] = {}
        for node in ast.nodes:
            for child in node.child_refs:
                result[child] = node.node_id
        return result

    def _descendants(self, root_ref: str, by_id: dict[str, object]) -> set[str]:
        result: set[str] = set()
        stack = [root_ref]
        while stack:
            current = stack.pop()
            node = by_id[current]
            for child in getattr(node, "child_refs"):
                if child not in result:
                    result.add(child)
                    stack.append(child)
        return result

    def _finding(
        self,
        code: SemanticFindingCode,
        message: str,
        evidence_refs: tuple[str, ...],
        by_id: dict[str, object],
        consequence: str,
    ) -> SemanticFinding:
        ranges = tuple(
            getattr(by_id[ref], "source_range")
            for ref in evidence_refs
            if ref in by_id
        )
        payload = f"{code.value}|{'|'.join(evidence_refs)}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=evidence_refs,
            source_ranges=ranges,
            consequence=consequence,
        )
