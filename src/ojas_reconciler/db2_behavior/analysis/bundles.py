from __future__ import annotations

import hashlib
from collections import defaultdict

import networkx as nx

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.dataflow import ReachingDefinitionAnalysis
from ojas_reconciler.db2_behavior.analysis.models import (
    BehaviorEffectBundle,
    BehaviorActionScope,
    BundleEffectMember,
    ControlFlowGraph,
    EffectCandidate,
    EffectKind,
    EffectObservability,
    EffectOrderingEdge,
    EffectRelationship,
    EffectTransactionAnalysis,
    TransactionRegion,
    TransactionSurvivalClassification,
)


class BehaviorEffectBundleBuilder:
    """Forms conservative effect bundles from control and transaction regions."""

    def build(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
        effects: tuple[EffectCandidate, ...],
        transaction_regions: tuple[TransactionRegion, ...],
        transaction_analyses: tuple[EffectTransactionAnalysis, ...],
    ) -> tuple[BehaviorEffectBundle, ...]:
        transaction_region_ref = transaction_regions[0].transaction_region_id
        analysis_by_ref = {analysis.analysis_id: analysis for analysis in transaction_analyses}
        control_regions = self._control_regions(ast)
        loop_scope_by_node = self._loop_scope_by_node(ast)
        cfg_by_ast = {
            node.ast_node_ref: node.cfg_node_id
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }
        graph, dominators, postdominators = self._graphs(cfg)
        reaching_definitions = ReachingDefinitionAnalysis(ast, cfg)

        admitted = [
            effect
            for effect in effects
            if not (
                effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT
                and effect.observability
                in {
                    EffectObservability.INTERMEDIATE_EFFECT,
                    EffectObservability.OVERWRITTEN_OUTPUT_ASSIGNMENT,
                }
            )
        ]
        grouped: dict[tuple[str, str], list[EffectCandidate]] = defaultdict(list)
        for effect in admitted:
            controlling = control_regions.get(effect.source_node_ref, f"effect-region:{effect.source_node_ref}")
            grouped[(controlling, transaction_region_ref)].append(effect)

        bundles: list[BehaviorEffectBundle] = []
        for (controlling, txn_ref), members in sorted(grouped.items()):
            base_members = sorted(
                members,
                key=lambda effect: self._source_offset(ast, effect.source_node_ref),
            )
            primary = min(base_members, key=lambda effect: self._primary_key(ast, effect))
            inherited = self._required_procedure_out_effects(
                primary=primary,
                base_members=base_members,
                admitted=admitted,
                control_regions=control_regions,
                cfg_by_ast=cfg_by_ast,
                dominators=dominators,
                postdominators=postdominators,
                reaching_definitions=reaching_definitions,
            )
            ordered_members = sorted(
                [*base_members, *inherited],
                key=lambda effect: self._source_offset(ast, effect.source_node_ref),
            )
            effect_members: list[BundleEffectMember] = []
            for effect in ordered_members:
                if effect.effect_id == primary.effect_id:
                    relationship = EffectRelationship.PRIMARY
                elif effect.observability == EffectObservability.ROLLED_BACK_EFFECT:
                    relationship = EffectRelationship.ROLLED_BACK_EFFECT
                elif effect.effect_kind == EffectKind.DML and effect.target and "AUDIT" in effect.target:
                    relationship = EffectRelationship.AUDIT_EFFECT
                elif self._is_required(
                    primary,
                    effect,
                    cfg_by_ast=cfg_by_ast,
                    dominators=dominators,
                    postdominators=postdominators,
                ):
                    relationship = EffectRelationship.REQUIRED_CO_EFFECT
                else:
                    relationship = EffectRelationship.CONDITIONAL_CO_EFFECT
                effect_members.append(
                    BundleEffectMember(
                        effect_ref=effect.effect_id,
                        relationship=relationship,
                    )
                )

            ordering_edges = self._ordering_edges(
                ordered_members,
                cfg_by_ast=cfg_by_ast,
                graph=graph,
                control_regions=control_regions,
            )
            loop_refs = tuple(sorted({loop_scope_by_node.get(effect.source_node_ref) for effect in ordered_members if loop_scope_by_node.get(effect.source_node_ref)}))
            if loop_refs:
                action_scope = BehaviorActionScope.CURSOR_ITERATION
                action_scope_ref = loop_refs[0]
            elif controlling.startswith("handler-region:"):
                action_scope = BehaviorActionScope.HANDLER_ACTIVATION
                action_scope_ref = controlling.split(":", 1)[1]
            else:
                action_scope = BehaviorActionScope.PROCEDURE_INVOCATION
                action_scope_ref = None
            completeness = "COMPLETE"
            for effect in ordered_members:
                if effect.effect_kind == EffectKind.CALL:
                    completeness = "PARTIAL"
                elif (
                    effect.effect_kind
                    in {EffectKind.DYNAMIC_SQL, EffectKind.SEQUENCE_VALUE_ACQUISITION}
                    and effect.observability == EffectObservability.UNRESOLVED_EFFECT_BOUNDARY
                ):
                    completeness = "PARTIAL"
                analysis = analysis_by_ref.get(effect.transaction_analysis_ref or "")
                if analysis is not None and analysis.classification not in {
                    TransactionSurvivalClassification.MUST_COMMIT,
                    TransactionSurvivalClassification.MUST_ROLLBACK,
                    TransactionSurvivalClassification.CALLER_CONTRACT_COMMIT,
                }:
                    completeness = "PARTIAL"

            payload = "|".join(
                [
                    controlling,
                    txn_ref,
                    primary.effect_id,
                    *(member.effect_id for member in ordered_members),
                ]
            )
            bundle_id = "behavior-bundle-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
            bundles.append(
                BehaviorEffectBundle(
                    bundle_id=bundle_id,
                    primary_effect_ref=primary.effect_id,
                    effect_members=tuple(effect_members),
                    transaction_region_ref=txn_ref,
                    controlling_region_ref=controlling,
                    action_scope=action_scope,
                    action_scope_ref=action_scope_ref,
                    ordering_edges=ordering_edges,
                    bundle_completeness=completeness,
                    evidence_refs=tuple(effect.source_node_ref for effect in ordered_members),
                )
            )
        return tuple(sorted(bundles, key=lambda item: item.bundle_id))

    def _control_regions(self, ast: ProcedureAst) -> dict[str, str]:
        by_id = {node.node_id: node for node in ast.nodes}
        result: dict[str, str] = {}

        def visit(ref: str, inherited: str | None) -> None:
            node = by_id[ref]
            own = inherited
            if node.kind == NodeKind.HANDLER_REGION:
                own = f"handler-region:{node.node_id}"
            elif node.kind == NodeKind.LOOP_REGION:
                own = f"loop-region:{node.node_id}"
            elif node.kind == NodeKind.COMPOUND and "BEGIN ATOMIC" in " ".join(node.text.upper().split()):
                own = f"atomic-region:{node.node_id}"
            result[node.node_id] = own or f"effect-region:{node.node_id}"

            if node.if_region is not None:
                for index, arm in enumerate(node.if_region.arms):
                    arm_region = f"if-arm:{node.node_id}:{index}:{arm.arm_kind}"
                    for child in arm.body_node_refs:
                        visit(child, arm_region)
            elif node.handler_region is not None:
                for child in node.handler_region.body_node_refs:
                    visit(child, f"handler-region:{node.node_id}")
            elif node.loop_region is not None:
                for child in node.loop_region.body_node_refs:
                    visit(child, f"loop-region:{node.node_id}")
            else:
                for child in node.child_refs:
                    visit(child, own)

        for ref in ast.body_node_refs:
            visit(ref, None)
        return result

    def _loop_scope_by_node(self, ast: ProcedureAst) -> dict[str, str]:
        by_id = {node.node_id: node for node in ast.nodes}
        result: dict[str, str] = {}

        def visit(ref: str, current_loop: str | None) -> None:
            node = by_id[ref]
            loop_ref = node.node_id if node.kind == NodeKind.LOOP_REGION else current_loop
            if loop_ref is not None:
                result[node.node_id] = loop_ref
            if node.if_region is not None:
                children = tuple(child for arm in node.if_region.arms for child in arm.body_node_refs)
            elif node.handler_region is not None:
                children = node.handler_region.body_node_refs
            elif node.loop_region is not None:
                children = node.loop_region.body_node_refs
            else:
                children = node.child_refs
            for child in children:
                visit(child, loop_ref)

        for ref in ast.body_node_refs:
            visit(ref, None)
        return result

    def _graphs(
        self,
        cfg: ControlFlowGraph,
    ) -> tuple[nx.DiGraph, dict[str, str], dict[str, str]]:
        graph = nx.DiGraph()
        graph.add_nodes_from(node.cfg_node_id for node in cfg.nodes)
        graph.add_edges_from((edge.source_ref, edge.target_ref) for edge in cfg.edges)
        try:
            dominators = nx.immediate_dominators(graph, cfg.entry_ref)
        except (nx.NetworkXError, nx.NetworkXException):
            dominators = {}

        post_graph = graph.reverse(copy=True)
        synthetic_sink = "cfg:synthetic-postdom-sink"
        post_graph.add_node(synthetic_sink)
        post_graph.add_edge(synthetic_sink, cfg.normal_exit_ref)
        post_graph.add_edge(synthetic_sink, cfg.exceptional_exit_ref)
        try:
            postdominators = nx.immediate_dominators(post_graph, synthetic_sink)
        except (nx.NetworkXError, nx.NetworkXException):
            postdominators = {}
        return graph, dominators, postdominators

    def _required_procedure_out_effects(
        self,
        *,
        primary: EffectCandidate,
        base_members: list[EffectCandidate],
        admitted: list[EffectCandidate],
        control_regions: dict[str, str],
        cfg_by_ast: dict[str, str],
        dominators: dict[str, str],
        postdominators: dict[str, str],
        reaching_definitions: ReachingDefinitionAnalysis,
    ) -> list[EffectCandidate]:
        """Attach only uniquely reaching OUT definitions to a branch bundle.

        Dominance alone is insufficient: an initialization may dominate a branch
        while a later SELECT INTO or guarded assignment kills it.  A co-effect is
        safe to assert only when exactly one definition reaches the primary node.
        Ambiguous values are deliberately omitted instead of being rendered with
        false certainty.
        """
        if not str(control_regions.get(primary.source_node_ref, "")).startswith("if-arm:"):
            return []
        if (
            primary.effect_kind != EffectKind.OUT_PARAMETER_ASSIGNMENT
            or not any(
                token in str(primary.target or "").upper()
                for token in ("DECISION", "STATUS", "RESULT")
            )
        ):
            return []
        member_ids = {effect.effect_id for effect in base_members}
        member_targets = {
            effect.target
            for effect in base_members
            if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT
        }
        effects_by_target_and_source = {
            (str(effect.target or "").upper(), effect.source_node_ref): effect
            for effect in admitted
            if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT
        }
        result: list[EffectCandidate] = []
        targets = {
            str(effect.target or "").upper()
            for effect in admitted
            if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT and effect.target
        }
        for target in sorted(targets):
            if target in member_targets:
                continue
            reaching_refs = reaching_definitions.definitions_before_ast(
                primary.source_node_ref, target
            )
            if len(reaching_refs) != 1:
                continue
            effect = effects_by_target_and_source.get((target, reaching_refs[0]))
            if effect is None or effect.effect_id in member_ids:
                continue
            if effect.observability != EffectObservability.ESCAPING_EFFECT:
                continue
            result.append(effect)
        return result

    def _is_required(
        self,
        primary: EffectCandidate,
        other: EffectCandidate,
        *,
        cfg_by_ast: dict[str, str],
        dominators: dict[str, str],
        postdominators: dict[str, str],
    ) -> bool:
        primary_cfg = cfg_by_ast.get(primary.source_node_ref)
        other_cfg = cfg_by_ast.get(other.source_node_ref)
        if primary_cfg is None or other_cfg is None:
            return False
        return self._dominates(other_cfg, primary_cfg, dominators) or self._dominates(
            other_cfg, primary_cfg, postdominators
        )

    @staticmethod
    def _dominates(candidate: str, target: str, immediate: dict[str, str]) -> bool:
        current = target
        seen: set[str] = set()
        while current in immediate and current not in seen:
            if current == candidate:
                return True
            seen.add(current)
            parent = immediate[current]
            if parent == current:
                break
            current = parent
        return current == candidate

    def _ordering_edges(
        self,
        members: list[EffectCandidate],
        *,
        cfg_by_ast: dict[str, str],
        graph: nx.DiGraph,
        control_regions: dict[str, str],
    ) -> tuple[EffectOrderingEdge, ...]:
        result: list[EffectOrderingEdge] = []
        for left_index, left in enumerate(members):
            left_cfg = cfg_by_ast.get(left.source_node_ref)
            if left_cfg is None:
                continue
            for right in members[left_index + 1 :]:
                right_cfg = cfg_by_ast.get(right.source_node_ref)
                if right_cfg is None:
                    continue
                left_region = control_regions.get(left.source_node_ref, "")
                right_region = control_regions.get(right.source_node_ref, "")
                same_atomic = (
                    left_region == right_region
                    and left_region.startswith("atomic-region:")
                )
                strictly_ordered = (
                    nx.has_path(graph, left_cfg, right_cfg)
                    and not nx.has_path(graph, right_cfg, left_cfg)
                )
                # Loop back-edges make both atomic statements mutually
                # reachable across iterations.  Source order still defines
                # their order within one BEGIN ATOMIC execution.
                if same_atomic or strictly_ordered:
                    result.append(
                        EffectOrderingEdge(
                            before_effect_ref=left.effect_id,
                            after_effect_ref=right.effect_id,
                            atomicity=(
                                "ATOMIC_COMPOUND"
                                if same_atomic
                                else "SAME_TRANSACTION_REGION"
                            ),
                        )
                    )
        return tuple(result)

    @staticmethod
    def _source_offset(ast: ProcedureAst, node_ref: str) -> int:
        by_id = {node.node_id: node for node in ast.nodes}
        return by_id[node_ref].source_range.start_offset

    def _primary_key(self, ast: ProcedureAst, effect: EffectCandidate) -> tuple[int, int, str]:
        priority = {
            EffectKind.RESIGNAL: 0,
            EffectKind.SIGNAL: 0,
            EffectKind.OUT_PARAMETER_ASSIGNMENT: 1,
            EffectKind.DML: 2,
            EffectKind.SEQUENCE_VALUE_ACQUISITION: 2,
            EffectKind.RESULT_SET_RETURN: 2,
            EffectKind.STATE_ASSIGNMENT: 2,
            EffectKind.CALL: 3,
            EffectKind.DYNAMIC_SQL: 3,
            EffectKind.COMMIT: 4,
            EffectKind.ROLLBACK: 4,
        }[effect.effect_kind]
        return (priority, self._source_offset(ast, effect.source_node_ref), effect.effect_id)
