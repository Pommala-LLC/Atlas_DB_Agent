from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import AstNode, HandlerKind, NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    CfgEdge,
    CfgEdgeKind,
    CfgNode,
    CfgNodeKind,
    ControlFlowGraph,
    HandlerFlowBinding,
)


@dataclass(frozen=True, slots=True)
class _ControlContext:
    exit_ref: str
    label: str | None
    loop_header_ref: str | None = None


class ControlFlowGraphBuilder:
    """Builds a compact structural CFG from the admitted procedural-shell AST."""

    _declaration_kinds = {
        NodeKind.DECLARE_VARIABLE,
        NodeKind.DECLARE_CURSOR,
        NodeKind.DECLARE_CONDITION,
        NodeKind.HANDLER_REGION,
    }

    _not_found_sources = {
        NodeKind.SELECT_INTO,
        NodeKind.FETCH_CURSOR,
    }

    _sql_exception_sources = {
        NodeKind.SELECT_INTO,
        NodeKind.DML,
        NodeKind.CALL,
        NodeKind.OPEN_CURSOR,
        NodeKind.FETCH_CURSOR,
        NodeKind.CLOSE_CURSOR,
        NodeKind.PREPARE,
        NodeKind.EXECUTE,
        NodeKind.EXECUTE_IMMEDIATE,
        NodeKind.COMMIT,
        NodeKind.ROLLBACK,
        NodeKind.GET_DIAGNOSTICS,
        NodeKind.SIGNAL,
    }

    def build(self, ast: ProcedureAst) -> ControlFlowGraph:
        self._ast = ast
        self._by_id = {node.node_id: node for node in ast.nodes}
        self._scope_parent: dict[str, str | None] = {"procedure-body": None}
        for node in ast.nodes:
            if node.compound_region is not None:
                self._scope_parent[node.node_id] = node.compound_region.lexical_scope_ref
            if node.handler_region is not None:
                self._scope_parent.setdefault(node.node_id, node.handler_region.lexical_scope_ref)
        self._cfg_nodes: dict[str, CfgNode] = {}
        self._edges: dict[str, CfgEdge] = {}
        self._handler_bindings: list[HandlerFlowBinding] = []
        self._excluded: list[str] = []

        self._entry = self._synthetic_node("entry", CfgNodeKind.ENTRY, "ENTRY")
        self._normal_exit = self._synthetic_node("normal-exit", CfgNodeKind.NORMAL_EXIT, "NORMAL_EXIT")
        self._exceptional_exit = self._synthetic_node(
            "exceptional-exit", CfgNodeKind.EXCEPTIONAL_EXIT, "EXCEPTIONAL_EXIT"
        )

        top_entry = self._build_sequence(ast.body_node_refs, self._normal_exit, ())
        self._add_edge(self._entry, top_entry, CfgEdgeKind.ENTRY)
        self._build_handler_subgraphs()
        self._bind_handlers()

        without_digest = {
            "schema_version": "db2-cfg-0.1",
            "procedure_ast_ref": ast.node_id,
            "entry_ref": self._entry,
            "normal_exit_ref": self._normal_exit,
            "exceptional_exit_ref": self._exceptional_exit,
            "nodes": tuple(sorted(self._cfg_nodes.values(), key=lambda n: n.cfg_node_id)),
            "edges": tuple(sorted(self._edges.values(), key=lambda e: e.edge_id)),
            "handler_bindings": tuple(sorted(self._handler_bindings, key=lambda b: b.binding_id)),
            "excluded_declaration_refs": tuple(sorted(self._excluded)),
        }
        return ControlFlowGraph(**without_digest, content_digest=canonical_digest(without_digest))

    def _build_sequence(
        self,
        refs: tuple[str, ...],
        continuation_ref: str,
        control_stack: tuple[_ControlContext, ...],
    ) -> str:
        current = continuation_ref
        for ref in reversed(refs):
            current = self._build_node(ref, current, control_stack)
        return current

    def _build_node(
        self,
        ast_ref: str,
        continuation_ref: str,
        control_stack: tuple[_ControlContext, ...],
    ) -> str:
        node = self._by_id[ast_ref]
        if node.kind in self._declaration_kinds:
            self._excluded.append(ast_ref)
            return continuation_ref

        cfg_ref = self._cfg_node_for_ast(node)

        if node.kind == NodeKind.COMPOUND and node.compound_region is not None:
            context = _ControlContext(
                exit_ref=continuation_ref,
                label=(node.compound_region.label or "").upper() or None,
            )
            body_entry = self._build_sequence(
                node.compound_region.body_node_refs,
                continuation_ref,
                control_stack + (context,),
            )
            self._add_edge(cfg_ref, body_entry, CfgEdgeKind.SEQUENTIAL)
            return cfg_ref

        if node.kind == NodeKind.IF_REGION and node.if_region is not None:
            has_else = False
            prior_arm_always_taken = False
            for index, arm in enumerate(node.if_region.arms):
                truth = True if arm.arm_kind == "ELSE" else self._literal_condition_truth(arm.condition_text)
                has_else = has_else or arm.arm_kind == "ELSE"
                arm_node = self._by_id[arm.arm_id]
                arm_cfg_ref = self._cfg_node_for_ast(arm_node)
                arm_entry = self._build_sequence(arm.body_node_refs, continuation_ref, control_stack)
                self._add_edge(arm_cfg_ref, arm_entry, CfgEdgeKind.SEQUENTIAL)
                if prior_arm_always_taken or truth is False:
                    continue
                self._add_edge(
                    cfg_ref,
                    arm_cfg_ref,
                    CfgEdgeKind.IF_ARM,
                    condition_text=arm.condition_text,
                    branch_index=index,
                )
                if truth is True:
                    prior_arm_always_taken = True
            if not has_else and not prior_arm_always_taken:
                self._add_edge(cfg_ref, continuation_ref, CfgEdgeKind.IF_NO_MATCH)
            return cfg_ref

        if node.kind == NodeKind.LOOP_REGION and node.loop_region is not None:
            context = _ControlContext(
                exit_ref=continuation_ref,
                label=(node.loop_region.label or "").upper() or None,
                loop_header_ref=cfg_ref,
            )
            body_entry = self._build_sequence(
                node.loop_region.body_node_refs,
                cfg_ref,
                control_stack + (context,),
            )
            self._add_edge(
                cfg_ref,
                body_entry,
                CfgEdgeKind.LOOP_BODY,
                condition_text=node.loop_region.condition_text,
            )
            if node.loop_region.loop_kind != "LOOP":
                self._add_edge(
                    cfg_ref,
                    continuation_ref,
                    CfgEdgeKind.LOOP_EXIT,
                    condition_text=self._negated_condition(node.loop_region.condition_text),
                )
            return cfg_ref

        if node.kind == NodeKind.RETURN:
            self._add_edge(cfg_ref, self._normal_exit, CfgEdgeKind.RETURN)
            return cfg_ref
        if node.kind == NodeKind.RESIGNAL:
            self._add_edge(cfg_ref, self._exceptional_exit, CfgEdgeKind.RESIGNAL)
            return cfg_ref
        if node.kind == NodeKind.SIGNAL:
            self._add_edge(cfg_ref, self._exceptional_exit, CfgEdgeKind.SIGNAL)
            return cfg_ref
        if node.kind == NodeKind.LEAVE:
            target = self._resolve_control_target(node, control_stack, iterate=False)
            self._add_edge(cfg_ref, target, CfgEdgeKind.LEAVE)
            return cfg_ref
        if node.kind == NodeKind.ITERATE:
            target = self._resolve_control_target(node, control_stack, iterate=True)
            self._add_edge(cfg_ref, target, CfgEdgeKind.ITERATE)
            return cfg_ref

        self._add_edge(cfg_ref, continuation_ref, CfgEdgeKind.SEQUENTIAL)
        return cfg_ref

    def _build_handler_subgraphs(self) -> None:
        for node in self._ast.nodes:
            if node.kind != NodeKind.HANDLER_REGION or node.handler_region is None:
                continue
            handler_cfg_ref = self._cfg_node_for_ast(node)
            exit_ref = self._synthetic_node(
                f"handler-exit:{node.node_id}",
                CfgNodeKind.HANDLER_EXIT,
                f"HANDLER_EXIT {node.handler_region.handled_condition_text}",
            )
            if node.handler_region.handler_kind == HandlerKind.CONTINUE:
                fallthrough = exit_ref
            else:
                fallthrough = self._normal_exit
            body_entry = self._build_sequence(node.handler_region.body_node_refs, fallthrough, ())
            self._add_edge(handler_cfg_ref, body_entry, CfgEdgeKind.HANDLER_BODY)
            if body_entry == fallthrough:
                self._add_edge(handler_cfg_ref, fallthrough, CfgEdgeKind.HANDLER_FALLTHROUGH)

    def _bind_handlers(self) -> None:
        handlers = [
            node
            for node in self._ast.nodes
            if node.kind == NodeKind.HANDLER_REGION and node.handler_region is not None
        ]
        handler_descendants = self._handler_descendants(handlers)
        normal_successors = self._normal_successors()

        for source in self._ast.nodes:
            if source.node_id in handler_descendants:
                continue
            grouped: dict[str, list[AstNode]] = {}
            for handler in handlers:
                region = handler.handler_region
                assert region is not None
                if not self._scope_contains(region.lexical_scope_ref, source.lexical_scope_ref):
                    continue
                if not self._handler_applies(region, source):
                    continue
                grouped.setdefault(self._handler_condition_key(region), []).append(handler)

            for candidates in grouped.values():
                handler = max(
                    candidates,
                    key=lambda value: self._scope_depth(value.handler_region.lexical_scope_ref if value.handler_region else None),
                )
                region = handler.handler_region
                assert region is not None
                handler_cfg = self._cfg_ref(handler.node_id)
                source_cfg = self._cfg_ref(source.node_id)
                if source_cfg not in self._cfg_nodes:
                    continue
                if region.handler_kind == HandlerKind.CONTINUE:
                    continuation = normal_successors.get(source_cfg, self._normal_exit)
                else:
                    continuation = self._normal_exit
                condition_label = region.resolved_sqlstate or region.handled_condition_text
                binding_payload = f"{source.node_id}|{handler.node_id}|{condition_label}|{continuation}"
                binding_id = "handler-binding-" + hashlib.sha256(binding_payload.encode("utf-8")).hexdigest()[:20]
                binding = HandlerFlowBinding(
                    binding_id=binding_id,
                    source_ast_node_ref=source.node_id,
                    handler_region_ref=handler.node_id,
                    handled_condition_text=region.handled_condition_text,
                    continuation_semantics=region.continuation_semantics,
                    continuation_target_ref=continuation,
                )
                self._handler_bindings.append(binding)
                self._add_edge(
                    source_cfg,
                    handler_cfg,
                    CfgEdgeKind.HANDLER,
                    condition_text=condition_label,
                    handler_region_ref=handler.node_id,
                    continuation_target_ref=continuation,
                )

    def _handler_applies(self, region, source: AstNode) -> bool:
        normalized = " ".join(region.handled_condition_text.upper().split())
        if region.resolved_sqlstate == "02000" or normalized == "NOT FOUND":
            if source.kind in self._not_found_sources:
                return True
            return source.kind == NodeKind.EXECUTE and " INTO " in f" {source.text.upper()} "
        if normalized in {"SQLEXCEPTION", "SQLWARNING"}:
            return source.kind in self._sql_exception_sources
        if region.resolved_sqlstate is not None or normalized.startswith("SQLSTATE"):
            return source.kind in self._sql_exception_sources
        return False

    @staticmethod
    def _handler_condition_key(region) -> str:
        if region.resolved_sqlstate is not None:
            return f"SQLSTATE:{region.resolved_sqlstate}"
        return " ".join(region.handled_condition_text.upper().split())

    def _scope_contains(self, handler_scope: str, source_scope: str | None) -> bool:
        current = source_scope or "procedure-body"
        seen: set[str] = set()
        while current not in seen:
            if current == handler_scope:
                return True
            seen.add(current)
            parent = self._scope_parent.get(current)
            if parent is None:
                break
            current = parent
        return handler_scope == "procedure-body"

    def _scope_depth(self, scope: str | None) -> int:
        current = scope or "procedure-body"
        depth = 0
        seen: set[str] = set()
        while current not in seen:
            seen.add(current)
            parent = self._scope_parent.get(current)
            if parent is None:
                break
            depth += 1
            current = parent
        return depth

    def _handler_descendants(self, handlers: list[AstNode]) -> set[str]:
        descendants: set[str] = set()

        def visit(ref: str) -> None:
            if ref in descendants:
                return
            descendants.add(ref)
            child = self._by_id.get(ref)
            if child is not None:
                for nested in child.child_refs:
                    visit(nested)

        for handler in handlers:
            for ref in handler.child_refs:
                visit(ref)
        return descendants

    def _normal_successors(self) -> dict[str, str]:
        result: dict[str, str] = {}
        excluded = {CfgEdgeKind.HANDLER, CfgEdgeKind.SIGNAL, CfgEdgeKind.RESIGNAL}
        for edge in self._edges.values():
            if edge.edge_kind in excluded:
                continue
            if edge.source_ref not in result:
                result[edge.source_ref] = edge.target_ref
        return result

    def _resolve_control_target(
        self,
        node: AstNode,
        control_stack: tuple[_ControlContext, ...],
        *,
        iterate: bool,
    ) -> str:
        label = self._jump_label(node.text)
        candidates = [
            context
            for context in reversed(control_stack)
            if (label is None or context.label == label)
            and (not iterate or context.loop_header_ref is not None)
        ]
        if candidates:
            context = candidates[0]
            if iterate and context.loop_header_ref is not None:
                return context.loop_header_ref
            return context.exit_ref
        # A labelled LEAVE from procedure-body exits the labelled outer
        # procedure compound.  The current AST does not retain that outer
        # label, so this is the only safe procedure-scope fallback.
        if not iterate and label is not None:
            return self._normal_exit
        return self._exceptional_exit

    @staticmethod
    def _jump_label(text: str) -> str | None:
        parts = text.strip().rstrip(";").split()
        return parts[1].strip('"').upper() if len(parts) > 1 else None

    _literal_comparison = re.compile(
        r"^\s*(-?\d+(?:\.\d+)?|'(?:''|[^'])*')\s*(=|<>|!=|<=|>=|<|>)\s*(-?\d+(?:\.\d+)?|'(?:''|[^'])*')\s*$",
        re.IGNORECASE,
    )

    @classmethod
    def _literal_condition_truth(cls, condition: str | None) -> bool | None:
        if condition is None:
            return None
        match = cls._literal_comparison.match(condition)
        if match is None:
            return None
        left_raw, operator, right_raw = match.groups()
        try:
            if left_raw.startswith("'") and right_raw.startswith("'"):
                left: object = left_raw[1:-1].replace("''", "'")
                right: object = right_raw[1:-1].replace("''", "'")
            elif not left_raw.startswith("'") and not right_raw.startswith("'"):
                left = Decimal(left_raw)
                right = Decimal(right_raw)
            else:
                return None
        except InvalidOperation:
            return None
        if operator == "=":
            return left == right
        if operator in {"<>", "!="}:
            return left != right
        if operator == "<":
            return left < right  # type: ignore[operator]
        if operator == "<=":
            return left <= right  # type: ignore[operator]
        if operator == ">":
            return left > right  # type: ignore[operator]
        if operator == ">=":
            return left >= right  # type: ignore[operator]
        return None

    @staticmethod
    def _negated_condition(condition: str | None) -> str | None:
        return f"NOT ({condition})" if condition else None

    def _cfg_node_for_ast(self, node: AstNode) -> str:
        ref = self._cfg_ref(node.node_id)
        if ref not in self._cfg_nodes:
            self._cfg_nodes[ref] = CfgNode(
                cfg_node_id=ref,
                node_kind=CfgNodeKind.AST,
                ast_node_ref=node.node_id,
                label=f"{node.kind.value}@{node.source_range.start_line}",
                source_range=node.source_range,
            )
        return ref

    def _synthetic_node(self, key: str, kind: CfgNodeKind, label: str) -> str:
        ref = "cfg-" + hashlib.sha256(f"{self._ast.node_id}|{key}".encode("utf-8")).hexdigest()[:20]
        self._cfg_nodes[ref] = CfgNode(cfg_node_id=ref, node_kind=kind, label=label)
        return ref

    @staticmethod
    def _cfg_ref(ast_ref: str) -> str:
        return f"cfg:{ast_ref}"

    def _add_edge(
        self,
        source_ref: str,
        target_ref: str,
        kind: CfgEdgeKind,
        *,
        condition_text: str | None = None,
        branch_index: int | None = None,
        handler_region_ref: str | None = None,
        continuation_target_ref: str | None = None,
    ) -> None:
        payload = "|".join(
            [
                source_ref,
                target_ref,
                kind.value,
                condition_text or "",
                str(branch_index) if branch_index is not None else "",
                handler_region_ref or "",
                continuation_target_ref or "",
            ]
        )
        edge_id = "edge-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        self._edges[edge_id] = CfgEdge(
            edge_id=edge_id,
            source_ref=source_ref,
            target_ref=target_ref,
            edge_kind=kind,
            condition_text=condition_text,
            branch_index=branch_index,
            handler_region_ref=handler_region_ref,
            continuation_target_ref=continuation_target_ref,
        )
