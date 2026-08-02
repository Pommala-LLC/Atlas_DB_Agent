from __future__ import annotations

import hashlib
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    CfgEdgeKind,
    ControlFlowGraph,
    EffectCandidate,
    EffectKind,
    EffectObservability,
    EffectTransactionAnalysis,
    SemanticFinding,
    SemanticFindingCode,
    TransactionPathOutcome,
    TransactionRegion,
    TransactionSurvivalClassification,
    CallerTransactionContract,
)


class TransactionSurvivalAnalyzer:
    """Conservative first-boundary transaction survival analysis for direct DML."""

    def analyze(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
        effects: tuple[EffectCandidate, ...],
        caller_transaction_contract: CallerTransactionContract | None = None,
    ) -> tuple[
        tuple[EffectCandidate, ...],
        tuple[TransactionRegion, ...],
        tuple[EffectTransactionAnalysis, ...],
        tuple[SemanticFinding, ...],
    ]:
        ast_by_id = {node.node_id: node for node in ast.nodes}
        cfg_by_ast = {
            node.ast_node_ref: node.cfg_node_id
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }
        edge_map: dict[str, list[tuple[str, CfgEdgeKind]]] = defaultdict(list)
        for edge in cfg.edges:
            edge_map[edge.source_ref].append((edge.target_ref, edge.edge_kind))
        for source in edge_map:
            edge_map[source].sort(key=lambda item: (item[1].value, item[0]))

        commit_refs = tuple(
            sorted(node.node_id for node in ast.nodes if node.kind == NodeKind.COMMIT)
        )
        rollback_refs = tuple(
            sorted(node.node_id for node in ast.nodes if node.kind == NodeKind.ROLLBACK)
        )
        dml_effects = tuple(
            effect
            for effect in effects
            if effect.effect_kind == EffectKind.DML
            or (
                effect.effect_kind == EffectKind.DYNAMIC_SQL
                and effect.observability == EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED
            )
        )
        region_id = "transaction-region-" + hashlib.sha256(ast.node_id.encode("utf-8")).hexdigest()[:20]
        region = TransactionRegion(
            transaction_region_id=region_id,
            procedure_ast_ref=ast.node_id,
            commit_on_return=self._commit_on_return(ast.commit_on_return),
            effect_refs=tuple(sorted(effect.effect_id for effect in dml_effects)),
            explicit_commit_refs=commit_refs,
            explicit_rollback_refs=rollback_refs,
            analysis_completeness="COMPLETE",
        )

        analyses: list[EffectTransactionAnalysis] = []
        findings: list[SemanticFinding] = []
        analysis_by_effect: dict[str, EffectTransactionAnalysis] = {}

        for effect in dml_effects:
            source_cfg = cfg_by_ast.get(effect.source_node_ref)
            if source_cfg is None:
                outcomes = (TransactionPathOutcome.NO_TERMINAL_PATH,)
                boundaries: tuple[str, ...] = ()
                completeness = "PARTIAL"
            else:
                outcome_set, boundary_set = self._first_boundaries(
                    source_cfg=source_cfg,
                    edge_map=edge_map,
                    cfg=cfg,
                    ast_by_id=ast_by_id,
                    commit_on_return=region.commit_on_return,
                    caller_transaction_contract=caller_transaction_contract,
                )
                outcomes = tuple(sorted(outcome_set, key=lambda value: value.value))
                boundaries = tuple(sorted(boundary_set))
                completeness = "COMPLETE" if outcomes else "PARTIAL"
                if not outcomes:
                    outcomes = (TransactionPathOutcome.NO_TERMINAL_PATH,)

            classification = self._classify(set(outcomes))
            analysis_id = "transaction-analysis-" + hashlib.sha256(
                f"{effect.effect_id}|{region_id}|{'|'.join(value.value for value in outcomes)}".encode("utf-8")
            ).hexdigest()[:20]
            analysis = EffectTransactionAnalysis(
                analysis_id=analysis_id,
                effect_ref=effect.effect_id,
                transaction_region_ref=region_id,
                reachable_outcomes=outcomes,
                classification=classification,
                boundary_node_refs=boundaries,
                analysis_completeness=completeness,
                evidence_refs=tuple(sorted({effect.source_node_ref, *boundaries, *(caller_transaction_contract.evidence_refs if caller_transaction_contract is not None else ())})),
                caller_transaction_contract_ref=(caller_transaction_contract.contract_id if caller_transaction_contract is not None else None),
                caller_transaction_contract_digest=(caller_transaction_contract.content_digest if caller_transaction_contract is not None else None),
            )
            analyses.append(analysis)
            analysis_by_effect[effect.effect_id] = analysis
            finding = self._finding_for_analysis(effect, analysis, ast_by_id)
            if finding is not None:
                findings.append(finding)

        updated_effects: list[EffectCandidate] = []
        for effect in effects:
            analysis = analysis_by_effect.get(effect.effect_id)
            if analysis is None:
                updated_effects.append(effect)
                continue
            observability = self._observability(analysis.classification)
            updated_effects.append(
                effect.model_copy(
                    update={
                        "observability": observability,
                        "transaction_analysis_ref": analysis.analysis_id,
                    }
                )
            )

        return (
            tuple(sorted(updated_effects, key=lambda item: item.effect_id)),
            (region,),
            tuple(sorted(analyses, key=lambda item: item.analysis_id)),
            tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    def _first_boundaries(
        self,
        *,
        source_cfg: str,
        edge_map: dict[str, list[tuple[str, CfgEdgeKind]]],
        cfg: ControlFlowGraph,
        ast_by_id: dict[str, object],
        commit_on_return: str,
        caller_transaction_contract: CallerTransactionContract | None,
    ) -> tuple[set[TransactionPathOutcome], set[str]]:
        outcomes: set[TransactionPathOutcome] = set()
        boundaries: set[str] = set()
        stack: list[tuple[str, bool]] = [(source_cfg, True)]
        visited: set[tuple[str, bool]] = set()
        cfg_ast = {
            node.cfg_node_id: node.ast_node_ref
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }

        while stack:
            current, is_source = stack.pop()
            state_key = (current, is_source)
            if state_key in visited:
                continue
            visited.add(state_key)

            if current == cfg.normal_exit_ref:
                if commit_on_return == "YES":
                    outcomes.add(TransactionPathOutcome.COMMIT_ON_RETURN)
                elif caller_transaction_contract is not None:
                    outcomes.add(TransactionPathOutcome.CALLER_CONTRACT_COMMIT)
                else:
                    outcomes.add(TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED)
                boundaries.add(current)
                continue
            if current == cfg.exceptional_exit_ref:
                if caller_transaction_contract is not None:
                    outcomes.add(TransactionPathOutcome.CALLER_CONTRACT_ROLLBACK)
                else:
                    outcomes.add(TransactionPathOutcome.EXCEPTIONAL_ESCAPE)
                boundaries.add(current)
                continue

            ast_ref = cfg_ast.get(current)
            if not is_source and ast_ref is not None:
                node = ast_by_id.get(ast_ref)
                kind = getattr(node, "kind", None)
                if kind == NodeKind.COMMIT:
                    outcomes.add(TransactionPathOutcome.EXPLICIT_COMMIT)
                    boundaries.add(ast_ref)
                    continue
                if kind == NodeKind.ROLLBACK:
                    outcomes.add(TransactionPathOutcome.EXPLICIT_ROLLBACK)
                    boundaries.add(ast_ref)
                    continue

            successors = edge_map.get(current, [])
            if not successors:
                continue
            for target, edge_kind in reversed(successors):
                # A handler edge raised by the DML itself represents statement failure,
                # not survival of a successfully completed DML effect.
                if is_source and edge_kind == CfgEdgeKind.HANDLER:
                    continue
                stack.append((target, False))

        return outcomes, boundaries

    @staticmethod
    def _commit_on_return(value: str | None) -> str:
        normalized = (value or "UNKNOWN").upper()
        return normalized if normalized in {"YES", "NO"} else "UNKNOWN"

    @staticmethod
    def _classify(outcomes: set[TransactionPathOutcome]) -> TransactionSurvivalClassification:
        meaningful = outcomes - {TransactionPathOutcome.NO_TERMINAL_PATH}
        if meaningful and meaningful <= {
            TransactionPathOutcome.EXPLICIT_COMMIT,
            TransactionPathOutcome.COMMIT_ON_RETURN,
        }:
            return TransactionSurvivalClassification.MUST_COMMIT
        if meaningful == {TransactionPathOutcome.EXPLICIT_ROLLBACK}:
            return TransactionSurvivalClassification.MUST_ROLLBACK
        if (
            TransactionPathOutcome.CALLER_CONTRACT_COMMIT in meaningful
            and meaningful <= {
                TransactionPathOutcome.CALLER_CONTRACT_COMMIT,
                TransactionPathOutcome.CALLER_CONTRACT_ROLLBACK,
            }
        ):
            return TransactionSurvivalClassification.CALLER_CONTRACT_COMMIT
        if meaningful == {TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED}:
            return TransactionSurvivalClassification.CALLER_CONTROLLED
        if meaningful <= {
            TransactionPathOutcome.EXPLICIT_COMMIT,
            TransactionPathOutcome.COMMIT_ON_RETURN,
            TransactionPathOutcome.EXPLICIT_ROLLBACK,
        } and TransactionPathOutcome.EXPLICIT_ROLLBACK in meaningful:
            return TransactionSurvivalClassification.MAY_COMMIT_OR_ROLLBACK
        if meaningful <= {
            TransactionPathOutcome.EXPLICIT_COMMIT,
            TransactionPathOutcome.COMMIT_ON_RETURN,
            TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED,
        } and TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED in meaningful:
            return TransactionSurvivalClassification.MAY_COMMIT_OR_CALLER_CONTROLLED
        if meaningful <= {
            TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED,
            TransactionPathOutcome.EXCEPTIONAL_ESCAPE,
        }:
            return TransactionSurvivalClassification.CALLER_CONTROLLED_OR_EXCEPTIONAL
        if {
            TransactionPathOutcome.EXPLICIT_COMMIT,
            TransactionPathOutcome.EXPLICIT_ROLLBACK,
            TransactionPathOutcome.NORMAL_EXIT_CALLER_CONTROLLED,
        } & meaningful:
            return TransactionSurvivalClassification.MAY_COMMIT_ROLLBACK_OR_CALLER_CONTROLLED
        return TransactionSurvivalClassification.UNRESOLVED

    @staticmethod
    def _observability(classification: TransactionSurvivalClassification) -> EffectObservability:
        if classification == TransactionSurvivalClassification.MUST_COMMIT:
            return EffectObservability.COMMITTED_EFFECT
        if classification == TransactionSurvivalClassification.CALLER_CONTRACT_COMMIT:
            return EffectObservability.CONDITIONALLY_COMMITTED_EFFECT
        if classification == TransactionSurvivalClassification.MUST_ROLLBACK:
            return EffectObservability.ROLLED_BACK_EFFECT
        return EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED

    def _finding_for_analysis(
        self,
        effect: EffectCandidate,
        analysis: EffectTransactionAnalysis,
        ast_by_id: dict[str, object],
    ) -> SemanticFinding | None:
        node = ast_by_id.get(effect.source_node_ref)
        source_range = getattr(node, "source_range", None)
        if source_range is None:
            return None
        if analysis.classification in {
            TransactionSurvivalClassification.MAY_COMMIT_OR_ROLLBACK,
            TransactionSurvivalClassification.MAY_COMMIT_ROLLBACK_OR_CALLER_CONTROLLED,
            TransactionSurvivalClassification.MAY_COMMIT_OR_CALLER_CONTROLLED,
        }:
            code = SemanticFindingCode.DML_MAY_COMMIT_OR_ROLLBACK
            message = "DML can reach more than one transaction-survival outcome."
            consequence = "The effect remains non-definitive and cannot be asserted as committed."
        elif analysis.classification == TransactionSurvivalClassification.CALLER_CONTRACT_COMMIT:
            return None
        elif analysis.classification in {
            TransactionSurvivalClassification.CALLER_CONTROLLED,
            TransactionSurvivalClassification.CALLER_CONTROLLED_OR_EXCEPTIONAL,
        }:
            code = SemanticFindingCode.DML_CALLER_CONTROLLED
            message = "DML reaches procedure exit without an explicit commit in the analyzed procedure."
            consequence = "Transaction survival remains controlled by the caller or external transaction context."
        elif analysis.classification == TransactionSurvivalClassification.UNRESOLVED:
            code = SemanticFindingCode.DML_TRANSACTION_SURVIVAL_UNRESOLVED
            message = "DML transaction survival could not be resolved."
            consequence = "The DML is not classified as committed or rolled back."
        else:
            return None

        payload = f"{code.value}|{effect.effect_id}|{analysis.analysis_id}"
        evidence_refs = tuple(
            dict.fromkeys(
                (
                    effect.source_node_ref,
                    *(ref for ref in analysis.evidence_refs if ref in ast_by_id),
                )
            )
        )
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=evidence_refs,
            source_ranges=tuple(getattr(ast_by_id[ref], "source_range") for ref in evidence_refs),
            consequence=consequence,
        )
