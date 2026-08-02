from __future__ import annotations

import hashlib
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    BehaviorEffectBundle,
    EffectCandidate,
    EffectKind,
    EffectModality,
    EffectObligation,
    EffectObservability,
    EffectRelationship,
    EffectTransactionAnalysis,
    LoopSummaryCandidate,
    TransactionSurvivalClassification,
    BehaviorActionScope,
)


class EffectModalityAnalyzer:
    """Propagates conservative MUST/MAY/UNKNOWN obligations for technical slices."""

    def analyze(
        self,
        ast: ProcedureAst,
        effects: tuple[EffectCandidate, ...],
        bundles: tuple[BehaviorEffectBundle, ...],
        transaction_analyses: tuple[EffectTransactionAnalysis, ...],
        loop_summaries: tuple[LoopSummaryCandidate, ...],
    ) -> tuple[EffectObligation, ...]:
        effect_by_id = {effect.effect_id: effect for effect in effects}
        transaction_by_id = {value.analysis_id: value for value in transaction_analyses}
        loop_by_ref = {value.loop_region_ref: value for value in loop_summaries}
        loop_ancestors = self._loop_ancestors(ast)
        obligations: list[EffectObligation] = []

        for bundle in bundles:
            for member in bundle.effect_members:
                effect = effect_by_id[member.effect_ref]
                modality, reasons = self._base(member.relationship)
                ancestor_loops = loop_ancestors.get(effect.source_node_ref, ())
                if ancestor_loops and bundle.action_scope != BehaviorActionScope.CURSOR_ITERATION:
                    # Procedure-level occurrence is data-dependent even with an exact loop body summary.
                    if modality == EffectModality.MUST:
                        modality = EffectModality.MAY
                    reasons.append("LOOP_EXECUTION_DATA_DEPENDENT")
                    for loop_ref in ancestor_loops:
                        summary = loop_by_ref.get(loop_ref)
                        if summary is None or summary.analysis_completeness == "PARTIAL":
                            modality = EffectModality.UNKNOWN
                            reasons.append("LOOP_SUMMARY_PARTIAL")
                elif ancestor_loops:
                    reasons.append("ITERATION_SCOPED_BEHAVIOR")

                if bundle.bundle_completeness == "PARTIAL" and modality == EffectModality.MUST:
                    modality = EffectModality.UNKNOWN
                    reasons.append("BUNDLE_PARTIAL")

                if effect.effect_kind == EffectKind.CALL:
                    modality = EffectModality.UNKNOWN
                    reasons.append("UNRESOLVED_EFFECT_BOUNDARY")
                elif (
                    effect.effect_kind == EffectKind.DYNAMIC_SQL
                    and effect.observability == EffectObservability.UNRESOLVED_EFFECT_BOUNDARY
                ):
                    modality = EffectModality.UNKNOWN
                    reasons.append("UNRESOLVED_DYNAMIC_SQL_EFFECT_BOUNDARY")

                if effect.observability in {
                    EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                    EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
                }:
                    modality = EffectModality.UNKNOWN
                    reasons.append(effect.observability.value)

                transaction = transaction_by_id.get(effect.transaction_analysis_ref or "")
                if transaction is not None:
                    if transaction.classification == TransactionSurvivalClassification.MUST_ROLLBACK:
                        modality = EffectModality.MUST_NOT
                        reasons.append("TRANSACTION_MUST_ROLLBACK")
                    elif transaction.classification == TransactionSurvivalClassification.CALLER_CONTRACT_COMMIT:
                        modality = EffectModality.MUST_IF_CALLER_CONTRACT_HOLDS
                        reasons.append("CALLER_TRANSACTION_CONTRACT")
                    elif transaction.classification != TransactionSurvivalClassification.MUST_COMMIT:
                        modality = EffectModality.UNKNOWN
                        reasons.append(f"TRANSACTION_{transaction.classification.value}")

                payload = f"{bundle.bundle_id}|{effect.effect_id}|{member.relationship.value}|{modality.value}|{'|'.join(sorted(set(reasons)))}"
                obligations.append(
                    EffectObligation(
                        obligation_id="effect-obligation-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                        bundle_ref=bundle.bundle_id,
                        effect_ref=effect.effect_id,
                        relationship=member.relationship,
                        modality=modality,
                        reason_codes=tuple(sorted(set(reasons))),
                    )
                )
        return tuple(sorted(obligations, key=lambda value: value.obligation_id))

    @staticmethod
    def _base(relationship: EffectRelationship) -> tuple[EffectModality, list[str]]:
        if relationship in {EffectRelationship.PRIMARY, EffectRelationship.REQUIRED_CO_EFFECT}:
            return EffectModality.MUST, [relationship.value]
        if relationship == EffectRelationship.ROLLED_BACK_EFFECT:
            return EffectModality.MUST_NOT, [relationship.value]
        return EffectModality.MAY, [relationship.value]

    @staticmethod
    def _loop_ancestors(ast: ProcedureAst) -> dict[str, tuple[str, ...]]:
        by_id = {node.node_id: node for node in ast.nodes}
        result: dict[str, set[str]] = defaultdict(set)

        def visit(ref: str, loops: tuple[str, ...]) -> None:
            node = by_id[ref]
            current = loops
            if node.kind == NodeKind.LOOP_REGION:
                current = (*loops, node.node_id)
            result[ref].update(current)
            if node.if_region is not None:
                children = tuple(child for arm in node.if_region.arms for child in arm.body_node_refs)
            elif node.handler_region is not None:
                children = node.handler_region.body_node_refs
            elif node.loop_region is not None:
                children = node.loop_region.body_node_refs
            else:
                children = node.child_refs
            for child in children:
                visit(child, current)

        for ref in ast.body_node_refs:
            visit(ref, ())
        return {key: tuple(sorted(value)) for key, value in result.items()}
