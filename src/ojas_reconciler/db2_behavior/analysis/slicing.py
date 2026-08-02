from __future__ import annotations

import hashlib
from collections import defaultdict, deque

from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst, StateAccessKind
from ojas_reconciler.db2_behavior.analysis.symbol_resolution import ProceduralSymbolValidator
from ojas_reconciler.db2_behavior.analysis.models import (
    BehaviorEffectBundle,
    BehaviorSlice,
    ControlFlowGraph,
    ConstraintAssessment,
    EffectCandidate,
    EffectObligation,
    PredicateGraph,
    QueryBindingFact,
    QuerySourceSummary,
    SemanticFinding,
    SemanticFindingCode,
    StateDependencyEdge,
    UnresolvedInfluence,
)


class LocalBackwardSlicer:
    """Builds conservative local state slices for behavior-effect bundles."""

    def __init__(self) -> None:
        self._scanner = Db2LexicalScanner()

    def build(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
        effects: tuple[EffectCandidate, ...],
        bundles: tuple[BehaviorEffectBundle, ...],
        query_summaries: tuple[QuerySourceSummary, ...],
        query_bindings: tuple[QueryBindingFact, ...],
        predicate_graphs: tuple[PredicateGraph, ...] = (),
        constraint_assessments: tuple[ConstraintAssessment, ...] = (),
        effect_obligations: tuple[EffectObligation, ...] = (),
    ) -> tuple[tuple[BehaviorSlice, ...], tuple[SemanticFinding, ...]]:
        self._ast = ast
        self._cfg = cfg
        self._node_by_id = {node.node_id: node for node in ast.nodes}
        self._effect_by_id = {effect.effect_id: effect for effect in effects}
        self._summary_by_node = {summary.source_node_ref: summary for summary in query_summaries}
        self._binding_by_node: dict[str, list[QueryBindingFact]] = defaultdict(list)
        for binding in query_bindings:
            self._binding_by_node[binding.source_node_ref].append(binding)
        self._symbols = self._declared_symbols(ast)
        self._unresolved_symbols_by_node = ProceduralSymbolValidator().unresolved_symbols_by_node(ast)
        self._predicate_by_region = {graph.controlling_region_ref: graph for graph in predicate_graphs}
        self._assessment_by_graph: dict[str, list[ConstraintAssessment]] = defaultdict(list)
        for assessment in constraint_assessments:
            self._assessment_by_graph[assessment.predicate_graph_ref].append(assessment)
        self._obligations_by_bundle: dict[str, list[EffectObligation]] = defaultdict(list)
        for obligation in effect_obligations:
            self._obligations_by_bundle[obligation.bundle_ref].append(obligation)
        self._defs_by_node, self._uses_by_node = self._state_maps(ast)
        self._cfg_by_ast = {
            node.ast_node_ref: node.cfg_node_id
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }
        self._ast_by_cfg = {value: key for key, value in self._cfg_by_ast.items()}
        self._incoming_defs = self._reaching_definitions()

        slices: list[BehaviorSlice] = []
        findings: list[SemanticFinding] = []
        for bundle in bundles:
            behavior_slice = self._slice_bundle(bundle)
            slices.append(behavior_slice)
            if behavior_slice.analysis_completeness == "PARTIAL":
                ranges = tuple(
                    self._node_by_id[ref].source_range
                    for ref in behavior_slice.evidence_refs
                    if ref in self._node_by_id
                )
                payload = f"{SemanticFindingCode.BEHAVIOR_SLICE_PARTIAL.value}|{behavior_slice.slice_id}"
                findings.append(
                    SemanticFinding(
                        finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                        code=SemanticFindingCode.BEHAVIOR_SLICE_PARTIAL,
                        message="Local backward slice is partial: " + "; ".join(value.detail for value in behavior_slice.unresolved_influences),
                        evidence_node_refs=behavior_slice.evidence_refs,
                        source_ranges=ranges,
                        consequence="The slice remains technical and cannot support ScenarioSpec generation.",
                    )
                )
                ordered = tuple(
                    influence
                    for influence in behavior_slice.unresolved_influences
                    if influence.code == SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL.value
                )
                if ordered:
                    ordered_refs = tuple(dict.fromkeys(ref for item in ordered for ref in item.source_node_refs))
                    ordered_ranges = tuple(
                        self._node_by_id[ref].source_range for ref in ordered_refs if ref in self._node_by_id
                    )
                    ordered_payload = (
                        f"{SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL.value}|"
                        f"{behavior_slice.slice_id}"
                    )
                    findings.append(
                        SemanticFinding(
                            finding_id="semantic-finding-" + hashlib.sha256(ordered_payload.encode("utf-8")).hexdigest()[:20],
                            code=SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL,
                            message="; ".join(item.detail for item in ordered),
                            evidence_node_refs=ordered_refs,
                            source_ranges=ordered_ranges,
                            consequence=(
                                "The downstream arm cannot be admitted until every negated preceding-arm "
                                "dependency is summarized completely."
                            ),
                        )
                    )
        return tuple(sorted(slices, key=lambda item: item.slice_id)), tuple(sorted(findings, key=lambda item: item.finding_id))

    def _slice_bundle(self, bundle: BehaviorEffectBundle) -> BehaviorSlice:
        effect_refs = tuple(member.effect_ref for member in bundle.effect_members)
        seed_nodes = [self._effect_by_id[ref].source_node_ref for ref in effect_refs if ref in self._effect_by_id]
        control_nodes = self._control_predicate_nodes(bundle.controlling_region_ref)
        queue: deque[tuple[str, str]] = deque()
        for node_ref in [*seed_nodes, *control_nodes]:
            for symbol in self._symbols_used_by_node(node_ref):
                queue.append((node_ref, symbol))

        local_nodes: set[str] = set(seed_nodes) | set(control_nodes)
        parameter_sources: set[str] = set()
        declaration_default_refs: set[str] = set()
        query_summary_refs: set[str] = set()
        query_binding_refs: set[str] = set()
        unresolved_symbols: set[str] = set()
        unresolved_influences: dict[str, UnresolvedInfluence] = {}
        dependency_edges: dict[str, StateDependencyEdge] = {}
        visited: set[tuple[str, str]] = set()

        def add_influence(code: str, detail: str, source_refs: tuple[str, ...], related_refs: tuple[str, ...] = ()) -> None:
            payload = "|".join((code, detail, *source_refs, *related_refs))
            influence_id = "unresolved-influence-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
            unresolved_influences[influence_id] = UnresolvedInfluence(
                influence_id=influence_id,
                code=code,
                detail=detail,
                source_node_refs=source_refs,
                related_artifact_refs=related_refs,
            )

        current_control_ref = control_nodes[-1] if control_nodes else None
        preceding_control_refs = set(control_nodes[:-1])
        for control_ref in control_nodes:
            node = self._node_by_id.get(control_ref)
            condition = node.if_arm.condition_text if node is not None and node.if_arm is not None else None
            if condition and any(token.upper in {"SELECT", "WITH"} for token in self._scanner.scan(condition).tokens):
                if control_ref in preceding_control_refs:
                    code = SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL.value
                    detail = (
                        f"Negated preceding arm {control_ref} contains a predicate subquery "
                        "with no admitted query summary."
                    )
                else:
                    code = "PREDICATE_SUBQUERY_SUMMARY_UNAVAILABLE"
                    detail = f"Predicate subquery in ordered arm {control_ref} has no admitted query summary."
                add_influence(code, detail, (control_ref,))

        while queue:
            use_node_ref, symbol = queue.popleft()
            key = (use_node_ref, symbol)
            if key in visited:
                continue
            visited.add(key)
            if symbol in self._unresolved_symbols_by_node.get(use_node_ref, frozenset()):
                unresolved_symbols.add(symbol)
                add_influence(
                    SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE.value,
                    f"Procedural symbol {symbol} is not declared in the referencing lexical scope.",
                    (use_node_ref,),
                )
            definitions = self._definitions_reaching(use_node_ref, symbol)
            if not definitions:
                if symbol in {parameter.name.upper() for parameter in self._ast.parameters}:
                    parameter_sources.add(symbol)
                else:
                    default_ref = self._declaration_default_ref(symbol)
                    if default_ref is not None:
                        declaration_default_refs.add(default_ref)
                        local_nodes.add(default_ref)
                        for nested_symbol in self._symbols_used_by_node(default_ref):
                            queue.append((default_ref, nested_symbol))
                    else:
                        unresolved_symbols.add(symbol)
                        add_influence("UNRESOLVED_SYMBOL_DEFINITION", f"No reaching definition was found for {symbol}.", (use_node_ref,))
                continue
            for definition_ref in definitions:
                local_nodes.add(definition_ref)
                edge = self._dependency_edge(symbol, definition_ref, use_node_ref)
                dependency_edges[edge.edge_id] = edge
                summary = self._summary_by_node.get(definition_ref)
                if summary is not None:
                    query_summary_refs.add(summary.query_summary_id)
                    if summary.analysis_completeness != "COMPLETE":
                        unresolved_symbols.add(symbol)
                        add_influence(
                            "QUERY_SUMMARY_PARTIAL",
                            f"Query summary {summary.query_summary_id} feeding {symbol} is partial.",
                            (definition_ref,),
                            (summary.query_summary_id,),
                        )
                for binding in self._binding_by_node.get(definition_ref, []):
                    query_binding_refs.add(binding.binding_id)
                    if binding.query_summary_ref is not None:
                        query_summary_refs.add(binding.query_summary_ref)
                    if binding.analysis_completeness != "COMPLETE":
                        unresolved_symbols.add(symbol)
                        add_influence(
                            "QUERY_BINDING_PARTIAL",
                            f"Query binding {binding.binding_id} feeding {symbol} is partial.",
                            (definition_ref,),
                            (binding.binding_id,),
                        )
                for nested_symbol in self._symbols_used_by_node(definition_ref):
                    if nested_symbol != symbol:
                        queue.append((definition_ref, nested_symbol))

        # Fetch definitions inherit their cursor query summary even if the fetch itself has no state uses.
        for node_ref in tuple(local_nodes):
            for binding in self._binding_by_node.get(node_ref, []):
                query_binding_refs.add(binding.binding_id)
                if binding.query_summary_ref is not None:
                    query_summary_refs.add(binding.query_summary_ref)
                if binding.analysis_completeness != "COMPLETE":
                    unresolved_symbols.add(binding.target_symbol)
                    add_influence(
                        "QUERY_BINDING_PARTIAL",
                        f"Query binding {binding.binding_id} feeding {binding.target_symbol} is partial.",
                        (node_ref,),
                        (binding.binding_id,),
                    )

        predicate_graph = self._predicate_by_region.get(bundle.controlling_region_ref)
        assessments = (
            tuple(sorted(self._assessment_by_graph.get(predicate_graph.predicate_graph_id, []), key=lambda item: item.assessment_id))
            if predicate_graph is not None
            else ()
        )
        obligations = tuple(sorted(self._obligations_by_bundle.get(bundle.bundle_id, []), key=lambda item: item.obligation_id))
        completeness = "COMPLETE"
        if bundle.bundle_completeness == "PARTIAL":
            add_influence(
                "BEHAVIOR_BUNDLE_PARTIAL",
                f"Behavior bundle {bundle.bundle_id} is partial.",
                tuple(seed_nodes),
                (bundle.bundle_id,),
            )
        if unresolved_symbols or unresolved_influences or bundle.bundle_completeness == "PARTIAL":
            completeness = "PARTIAL"
        if predicate_graph is not None and predicate_graph.normalization_status == "PARTIAL":
            completeness = "PARTIAL"
        if any(value.status.value == "OBVIOUS_CONTRADICTION" for value in assessments):
            completeness = "PARTIAL"
        payload = "|".join(
            [
                bundle.bundle_id,
                *sorted(local_nodes),
                *sorted(query_summary_refs),
                *sorted(unresolved_symbols),
                *sorted(unresolved_influences),
            ]
        )
        slice_id = "behavior-slice-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        evidence_refs = tuple(sorted(local_nodes, key=self._source_offset))
        return BehaviorSlice(
            slice_id=slice_id,
            bundle_ref=bundle.bundle_id,
            local_influence_node_refs=evidence_refs,
            control_predicate_node_refs=tuple(sorted(control_nodes, key=self._source_offset)),
            state_dependency_edges=tuple(sorted(dependency_edges.values(), key=lambda item: item.edge_id)),
            query_summary_refs=tuple(sorted(query_summary_refs)),
            query_binding_refs=tuple(sorted(query_binding_refs)),
            parameter_source_names=tuple(sorted(parameter_sources)),
            declaration_default_refs=tuple(sorted(declaration_default_refs, key=self._source_offset)),
            unresolved_symbol_names=tuple(sorted(unresolved_symbols)),
            unresolved_influence_refs=tuple(sorted(unresolved_influences)),
            unresolved_influences=tuple(sorted(unresolved_influences.values(), key=lambda item: item.influence_id)),
            predicate_graph_ref=predicate_graph.predicate_graph_id if predicate_graph is not None else None,
            constraint_assessment_refs=tuple(value.assessment_id for value in assessments),
            effect_obligations=obligations,
            analysis_completeness=completeness,
            representation_mode="LOCAL_BACKWARD_SLICE",
            evidence_refs=evidence_refs,
        )

    def _state_maps(self, ast: ProcedureAst) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        defs: dict[str, set[str]] = defaultdict(set)
        uses: dict[str, set[str]] = defaultdict(set)
        for fact in ast.state_access_facts:
            target = defs if fact.access_kind == StateAccessKind.DEF else uses
            target[fact.source_node_ref].add(fact.symbol_name.upper())
        return defs, uses

    def _declared_symbols(self, ast: ProcedureAst) -> set[str]:
        result = {parameter.name.upper() for parameter in ast.parameters}
        for node in ast.nodes:
            if node.kind != NodeKind.DECLARE_VARIABLE:
                continue
            tokens = list(self._scanner.scan(node.text).tokens)
            if len(tokens) >= 2:
                result.add(tokens[1].upper)
        return result

    def _symbols_used_by_node(self, node_ref: str) -> tuple[str, ...]:
        result = set(self._uses_by_node.get(node_ref, set()))
        node = self._node_by_id.get(node_ref)
        if node is None:
            return tuple(sorted(result))
        # Effects such as DML, CALL, EXECUTE and SIGNAL are not fully covered by parser state facts.
        if node.kind in {
            NodeKind.DML,
            NodeKind.CALL,
            NodeKind.EXECUTE,
            NodeKind.EXECUTE_IMMEDIATE,
            NodeKind.SIGNAL,
            NodeKind.RESIGNAL,
        }:
            result.update(
                token.upper.strip('"')
                for token in self._scanner.scan(node.text).tokens
                if token.upper.strip('"') in self._symbols
                or token.upper.strip('"').startswith(("P_", "V_"))
            )
        return tuple(sorted(result))

    def _reaching_definitions(self) -> dict[str, dict[str, frozenset[str]]]:
        predecessors: dict[str, set[str]] = defaultdict(set)
        successors: dict[str, set[str]] = defaultdict(set)
        for edge in self._cfg.edges:
            predecessors[edge.target_ref].add(edge.source_ref)
            successors[edge.source_ref].add(edge.target_ref)

        initial_defs: dict[str, frozenset[str]] = {}
        for parameter in self._ast.parameters:
            if parameter.mode == "IN":
                initial_defs[parameter.name.upper()] = frozenset({f"parameter:{parameter.name.upper()}"})
        for node in self._ast.nodes:
            if node.kind != NodeKind.DECLARE_VARIABLE:
                continue
            symbol = self._declared_name(node.node_id)
            if symbol is not None and self._has_default(node.text):
                initial_defs[symbol] = frozenset({node.node_id})

        incoming: dict[str, dict[str, frozenset[str]]] = {self._cfg.entry_ref: initial_defs}
        outgoing: dict[str, dict[str, frozenset[str]]] = {}
        work = deque([self._cfg.entry_ref])
        queued = {self._cfg.entry_ref}
        while work:
            cfg_ref = work.popleft()
            queued.discard(cfg_ref)
            in_state = incoming.get(cfg_ref, {})
            out_state = dict(in_state)
            ast_ref = self._ast_by_cfg.get(cfg_ref)
            if ast_ref is not None:
                for symbol in self._defs_by_node.get(ast_ref, set()):
                    out_state[symbol] = frozenset({ast_ref})
            if out_state == outgoing.get(cfg_ref):
                continue
            outgoing[cfg_ref] = out_state
            for target in successors.get(cfg_ref, set()):
                merged: dict[str, frozenset[str]] = {}
                for predecessor in predecessors[target]:
                    for symbol, refs in outgoing.get(predecessor, {}).items():
                        merged[symbol] = merged.get(symbol, frozenset()) | refs
                if merged != incoming.get(target):
                    incoming[target] = merged
                    if target not in queued:
                        work.append(target)
                        queued.add(target)
        return incoming

    def _definitions_reaching(self, use_node_ref: str, symbol: str) -> tuple[str, ...]:
        cfg_ref = self._cfg_by_ast.get(use_node_ref)
        if cfg_ref is None:
            return ()
        refs = self._incoming_defs.get(cfg_ref, {}).get(symbol, frozenset())
        return tuple(sorted(ref for ref in refs if not ref.startswith("parameter:")))

    def _control_predicate_nodes(self, controlling_region_ref: str) -> tuple[str, ...]:
        if not controlling_region_ref.startswith("if-arm:"):
            return ()
        parts = controlling_region_ref.split(":")
        if len(parts) < 4:
            return ()
        node_ref = parts[1]
        try:
            arm_index = int(parts[2])
        except ValueError:
            return ()
        node = self._node_by_id.get(node_ref)
        if node is None or node.if_region is None or arm_index >= len(node.if_region.arms):
            return ()
        refs = tuple(arm.arm_id for arm in node.if_region.arms[: arm_index + 1])
        return tuple(ref for ref in refs if ref in self._node_by_id)

    def _declaration_default_ref(self, symbol: str) -> str | None:
        for node in self._ast.nodes:
            if node.kind == NodeKind.DECLARE_VARIABLE and self._declared_name(node.node_id) == symbol and self._has_default(node.text):
                return node.node_id
        return None

    def _declared_name(self, node_ref: str) -> str | None:
        node = self._node_by_id[node_ref]
        tokens = list(self._scanner.scan(node.text).tokens)
        return tokens[1].upper if len(tokens) >= 2 and tokens[0].upper == "DECLARE" else None

    @staticmethod
    def _has_default(text: str) -> bool:
        upper = " ".join(text.upper().split())
        return " DEFAULT " in f" {upper} "

    def _dependency_edge(self, symbol: str, definition_ref: str, use_ref: str) -> StateDependencyEdge:
        payload = f"{symbol}|{definition_ref}|{use_ref}"
        return StateDependencyEdge(
            edge_id="state-dependency-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            symbol_name=symbol,
            definition_ref=definition_ref,
            use_ref=use_ref,
        )

    def _source_offset(self, node_ref: str) -> int:
        node = self._node_by_id.get(node_ref)
        return node.source_range.start_offset if node is not None else 10**18
