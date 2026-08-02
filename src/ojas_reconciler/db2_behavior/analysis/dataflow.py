from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from ojas_reconciler.db2_behavior.analysis.models import CfgEdgeKind, ControlFlowGraph
from ojas_reconciler.db2_behavior.parsing.models import AstNode, NodeKind, ProcedureAst


@dataclass(frozen=True, slots=True)
class DefinitionSite:
    symbol_name: str
    source_node_ref: str
    expression_text: str | None
    definition_kind: str


class ReachingDefinitionAnalysis:
    """Edge-sensitive may-reaching definitions over the structural CFG.

    Query/fetch INTO bindings only take effect on the normal edge.  A handler edge
    represents failure before the output binding is established, so the incoming
    definition set is propagated unchanged along that edge.
    """

    def __init__(self, ast: ProcedureAst, cfg: ControlFlowGraph) -> None:
        self.ast = ast
        self.cfg = cfg
        self.node_by_id = {node.node_id: node for node in ast.nodes}
        self.ast_by_cfg = {
            node.cfg_node_id: node.ast_node_ref
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }
        self.definitions_by_cfg = self._definitions_by_cfg()
        self.predecessor_edges: dict[str, list] = defaultdict(list)
        self.successor_edges: dict[str, list] = defaultdict(list)
        for edge in cfg.edges:
            self.predecessor_edges[edge.target_ref].append(edge)
            self.successor_edges[edge.source_ref].append(edge)
        self.in_state, self.edge_state = self._solve()

    def definitions_before_ast(self, ast_node_ref: str, symbol_name: str) -> tuple[str, ...]:
        state = self.in_state.get(f"cfg:{ast_node_ref}", {})
        return tuple(sorted(state.get(symbol_name.upper(), frozenset())))

    def definitions_at_cfg(self, cfg_ref: str, symbol_name: str) -> tuple[str, ...]:
        state = self.in_state.get(cfg_ref, {})
        return tuple(sorted(state.get(symbol_name.upper(), frozenset())))

    def definitions_at_normal_exit(self, symbol_name: str) -> tuple[str, ...]:
        return self.definitions_at_cfg(self.cfg.normal_exit_ref, symbol_name)

    def definitions_at_exceptional_exit(self, symbol_name: str) -> tuple[str, ...]:
        return self.definitions_at_cfg(self.cfg.exceptional_exit_ref, symbol_name)

    def all_definition_sites(self) -> tuple[DefinitionSite, ...]:
        values = [site for sites in self.definitions_by_cfg.values() for site in sites]
        return tuple(sorted(values, key=lambda item: (item.source_node_ref, item.symbol_name)))

    def _definitions_by_cfg(self) -> dict[str, tuple[DefinitionSite, ...]]:
        result: dict[str, tuple[DefinitionSite, ...]] = {}
        for cfg_ref, ast_ref in self.ast_by_cfg.items():
            node = self.node_by_id[ast_ref]
            sites = self._node_definition_sites(node)
            if sites:
                result[cfg_ref] = sites
        return result

    @staticmethod
    def _node_definition_sites(node: AstNode) -> tuple[DefinitionSite, ...]:
        result: list[DefinitionSite] = []
        if node.assignment_binding is not None:
            result.append(
                DefinitionSite(
                    symbol_name=node.assignment_binding.target_name.upper(),
                    source_node_ref=node.node_id,
                    expression_text=node.assignment_binding.expression_text,
                    definition_kind="ASSIGNMENT",
                )
            )
        if node.select_into_binding is not None:
            for index, target in enumerate(node.select_into_binding.target_names):
                result.append(
                    DefinitionSite(
                        symbol_name=target.upper(),
                        source_node_ref=node.node_id,
                        expression_text=f"SELECT_INTO_PROJECTION_{index + 1}",
                        definition_kind="SELECT_INTO",
                    )
                )
        if node.fetch_binding is not None:
            for index, target in enumerate(node.fetch_binding.target_names):
                result.append(
                    DefinitionSite(
                        symbol_name=target.upper(),
                        source_node_ref=node.node_id,
                        expression_text=f"FETCH_{node.fetch_binding.cursor_name}_COLUMN_{index + 1}",
                        definition_kind="FETCH",
                    )
                )
        if node.dynamic_execute_binding is not None:
            for index, target in enumerate(node.dynamic_execute_binding.into_target_names):
                result.append(
                    DefinitionSite(
                        symbol_name=target.upper(),
                        source_node_ref=node.node_id,
                        expression_text=f"EXECUTE_INTO_PROJECTION_{index + 1}",
                        definition_kind="EXECUTE_INTO",
                    )
                )
        return tuple(result)

    def _solve(self):
        node_refs = {node.cfg_node_id for node in self.cfg.nodes}
        in_state: dict[str, dict[str, frozenset[str]]] = {ref: {} for ref in node_refs}
        edge_state: dict[str, dict[str, frozenset[str]]] = {
            edge.edge_id: {} for edge in self.cfg.edges
        }
        work = deque([self.cfg.entry_ref])
        queued = {self.cfg.entry_ref}
        reachable = {self.cfg.entry_ref}
        initialized_edges: set[str] = set()

        while work:
            current = work.popleft()
            queued.discard(current)
            merged = self._merge_predecessor_states(current, edge_state)
            if merged != in_state[current]:
                in_state[current] = merged

            for edge in self.successor_edges.get(current, []):
                propagated = self._transfer_for_edge(current, merged, edge.edge_kind)
                if (
                    edge.edge_id in initialized_edges
                    and propagated == edge_state[edge.edge_id]
                ):
                    continue
                initialized_edges.add(edge.edge_id)
                edge_state[edge.edge_id] = propagated
                reachable.add(edge.target_ref)
                if edge.target_ref not in queued:
                    work.append(edge.target_ref)
                    queued.add(edge.target_ref)
        return in_state, edge_state

    def _merge_predecessor_states(
        self,
        node_ref: str,
        edge_state: dict[str, dict[str, frozenset[str]]],
    ) -> dict[str, frozenset[str]]:
        merged: dict[str, frozenset[str]] = {}
        for edge in self.predecessor_edges.get(node_ref, []):
            for symbol, refs in edge_state[edge.edge_id].items():
                merged[symbol] = merged.get(symbol, frozenset()) | refs
        return merged

    def _transfer_for_edge(
        self,
        cfg_ref: str,
        incoming: dict[str, frozenset[str]],
        edge_kind: CfgEdgeKind,
    ) -> dict[str, frozenset[str]]:
        result = dict(incoming)
        sites = self.definitions_by_cfg.get(cfg_ref, ())
        ast_ref = self.ast_by_cfg.get(cfg_ref)
        node = self.node_by_id.get(ast_ref) if ast_ref is not None else None
        binding_can_fail = node is not None and node.kind in {
            NodeKind.SELECT_INTO,
            NodeKind.FETCH_CURSOR,
            NodeKind.EXECUTE,
            NodeKind.EXECUTE_IMMEDIATE,
        }
        if edge_kind == CfgEdgeKind.HANDLER and binding_can_fail:
            return result
        for site in sites:
            result[site.symbol_name] = frozenset({site.source_node_ref})
        return result
