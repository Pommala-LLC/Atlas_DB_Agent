from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, cast

from lark import Lark

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token, TokenKind
from ojas_reconciler.db2_behavior.type_system.models import DeclaredSymbolType
from ojas_reconciler.db2_behavior.type_system.resolver import parse_declared_sql_type
from ojas_reconciler.db2_behavior.parsing.models import (
    AssignmentBinding,
    AstNode,
    CompoundRegion,
    ConditionDeclaration,
    DynamicExecuteBinding,
    DynamicPrepareBinding,
    FetchBinding,
    HandlerKind,
    HandlerRegion,
    IfArm,
    IfRegion,
    LoopKind,
    LoopRegion,
    MergeAction,
    MergeStructure,
    NodeKind,
    ParseFinding,
    ParseOutcome,
    ParserFindingCode,
    ProcedureAst,
    ProcedureParameter,
    ProcedureParseResult,
    SelectIntoBinding,
    SourceRange,
    StateAccessFact,
    StateAccessKind,
)

from .parser_types import _Header


class SymbolAnalysisMixin:
    def _resolve_named_conditions(
        self,
        nodes: list[AstNode],
    ) -> tuple[list[AstNode], list[ParseFinding]]:
        scope_parent: dict[str, str | None] = {"procedure-body": None}
        declarations: dict[str, dict[str, tuple[str, str]]] = {}
        for node in nodes:
            if node.compound_region is not None:
                scope_parent[node.node_id] = node.compound_region.lexical_scope_ref
            if node.kind == NodeKind.HANDLER_REGION and node.handler_region is not None:
                scope_parent.setdefault(node.node_id, node.handler_region.lexical_scope_ref)
            if node.condition_declaration is not None:
                declarations.setdefault(node.condition_declaration.lexical_scope_ref, {})[
                    node.condition_declaration.condition_name
                ] = (node.node_id, node.condition_declaration.sqlstate)

        findings: list[ParseFinding] = []
        resolved_nodes: list[AstNode] = []
        for node in nodes:
            region = node.handler_region
            if region is None:
                resolved_nodes.append(node)
                continue
            normalized = " ".join(region.handled_condition_text.upper().split())
            update: dict[str, object]
            if normalized == "NOT FOUND":
                update = {
                    "resolved_sqlstate": "02000",
                    "condition_resolution_status": "BUILTIN_CONDITION",
                }
            elif normalized.startswith("SQLSTATE"):
                parts = normalized.split(maxsplit=1)
                update = {
                    "resolved_sqlstate": parts[1].strip("'") if len(parts) > 1 else None,
                    "condition_resolution_status": "DIRECT_SQLSTATE",
                }
            elif normalized in {"SQLEXCEPTION", "SQLWARNING"}:
                update = {"condition_resolution_status": "CONDITION_CLASS"}
            else:
                current: str | None = region.lexical_scope_ref
                found: tuple[str, str] | None = None
                while current is not None:
                    found = declarations.get(current, {}).get(normalized)
                    if found is not None:
                        break
                    current = scope_parent.get(current)
                if found is None:
                    update = {"condition_resolution_status": "NAMED_CONDITION_UNRESOLVED"}
                    findings.append(
                        ParseFinding(
                            code=ParserFindingCode.NAMED_CONDITION_UNRESOLVED,
                            message=f"Named handler condition {normalized} was not declared in an enclosing compound scope.",
                            source_range=node.source_range,
                            consequence="Handler applicability remains unresolved.",
                        )
                    )
                else:
                    update = {
                        "named_condition_ref": found[0],
                        "resolved_sqlstate": found[1],
                        "condition_resolution_status": "NAMED_CONDITION_RESOLVED",
                    }
            resolved_region = region.model_copy(update=update)
            resolved_nodes.append(node.model_copy(update={"handler_region": resolved_region}))
        return resolved_nodes, findings

    def _build_declared_symbol_types(
        self,
        parameters: tuple[ProcedureParameter, ...],
        nodes: list[AstNode],
    ) -> tuple[DeclaredSymbolType, ...]:
        """Capture Phase 1 declared types without catalog inference."""
        declarations: list[DeclaredSymbolType] = []
        for parameter in parameters:
            source_ref = f"parameter:{parameter.name}:{parameter.source_range.start_offset}"
            declarations.append(
                DeclaredSymbolType(
                    symbol_name=parameter.name,
                    symbol_kind="PROCEDURE_PARAMETER",
                    parameter_mode=parameter.mode,
                    sql_type=parse_declared_sql_type(parameter.type_text, source_ref=source_ref),
                    lexical_scope_ref="procedure",
                    source_ref=source_ref,
                )
            )
        for node in nodes:
            if node.kind is not NodeKind.DECLARE_VARIABLE:
                continue
            tokens = [token for token in self._scanner.scan(node.text).tokens if token.value != ";"]
            if len(tokens) < 3:
                continue
            symbol_name = tokens[1].value.strip('"').upper()
            default_index = next((index for index, token in enumerate(tokens[2:], start=2) if token.upper == "DEFAULT"), None)
            type_tokens = tokens[2:default_index] if default_index is not None else tokens[2:]
            if not type_tokens:
                continue
            type_text = self._slice_text(
                node.text,
                type_tokens[0].offset,
                type_tokens[-1].offset + len(type_tokens[-1].value),
            ).strip()
            default_expression = None
            if default_index is not None and default_index + 1 < len(tokens):
                default_expression = self._slice_text(
                    node.text,
                    tokens[default_index + 1].offset,
                    tokens[-1].offset + len(tokens[-1].value),
                ).strip()
            declarations.append(
                DeclaredSymbolType(
                    symbol_name=symbol_name,
                    symbol_kind="LOCAL_VARIABLE",
                    sql_type=parse_declared_sql_type(type_text, source_ref=node.node_id),
                    default_expression=default_expression,
                    lexical_scope_ref=node.lexical_scope_ref,
                    source_ref=node.node_id,
                )
            )
        return tuple(declarations)

    def _build_state_access_facts(
        self,
        parameters: tuple[ProcedureParameter, ...],
        nodes: list[AstNode],
    ) -> tuple[StateAccessFact, ...]:
        symbol_names = {parameter.name.upper() for parameter in parameters}
        for node in nodes:
            if node.kind == NodeKind.DECLARE_VARIABLE:
                tokens = list(self._scanner.scan(node.text).tokens)
                if len(tokens) >= 2:
                    symbol_names.add(tokens[1].value.strip('"').upper())

        node_by_id = {node.node_id: node for node in nodes}
        handler_ancestor: dict[str, str] = {}

        def mark_descendants(parent_ref: str, child_refs: tuple[str, ...]) -> None:
            for child_ref in child_refs:
                handler_ancestor[child_ref] = parent_ref
                child = node_by_id.get(child_ref)
                if child is not None:
                    mark_descendants(parent_ref, child.child_refs)

        for node in nodes:
            if node.kind == NodeKind.HANDLER_REGION:
                mark_descendants(node.node_id, node.child_refs)

        facts: list[StateAccessFact] = []

        def add_fact(symbol: str, access: StateAccessKind, context: str, node: AstNode, region: str | None = None) -> None:
            payload = f"{symbol}|{access.value}|{context}|{node.node_id}|{region or ''}"
            facts.append(
                StateAccessFact(
                    fact_id="state-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    symbol_name=symbol,
                    access_kind=access,
                    context_kind=cast("Literal['ASSIGNMENT','HANDLER_ASSIGNMENT','FETCH_BINDING','SELECT_INTO_BINDING','IF_CONDITION','LOOP_CONDITION','PREPARE_SOURCE','EXECUTE_SOURCE','EXECUTE_INTO_BINDING','EXECUTE_USING']", context),
                    source_node_ref=node.node_id,
                    region_ref=region,
                )
            )

        for node in nodes:
            region = handler_ancestor.get(node.node_id)
            if node.assignment_binding is not None:
                context = "HANDLER_ASSIGNMENT" if region else "ASSIGNMENT"
                add_fact(node.assignment_binding.target_name, StateAccessKind.DEF, context, node, region)
                for symbol in self._symbol_uses(node.assignment_binding.expression_text, symbol_names):
                    add_fact(symbol, StateAccessKind.USE, context, node, region)
            if node.fetch_binding is not None:
                for target in node.fetch_binding.target_names:
                    add_fact(target, StateAccessKind.DEF, "FETCH_BINDING", node, region)
            if node.select_into_binding is not None:
                for target in node.select_into_binding.target_names:
                    add_fact(target, StateAccessKind.DEF, "SELECT_INTO_BINDING", node, region)
                for symbol in self._symbol_uses(node.select_into_binding.residual_query_text, symbol_names):
                    add_fact(symbol, StateAccessKind.USE, "SELECT_INTO_BINDING", node, region)
            if node.if_arm is not None and node.if_arm.condition_text:
                for symbol in self._symbol_uses(node.if_arm.condition_text, symbol_names):
                    add_fact(symbol, StateAccessKind.USE, "IF_CONDITION", node, region)
            if node.loop_region is not None and node.loop_region.condition_text:
                for symbol in self._symbol_uses(node.loop_region.condition_text, symbol_names):
                    add_fact(symbol, StateAccessKind.USE, "LOOP_CONDITION", node, region)
            if node.dynamic_prepare_binding is not None:
                for symbol in self._symbol_uses(node.dynamic_prepare_binding.source_expression, symbol_names):
                    add_fact(symbol, StateAccessKind.USE, "PREPARE_SOURCE", node, region)
            if node.dynamic_execute_binding is not None:
                if node.dynamic_execute_binding.source_expression:
                    for symbol in self._symbol_uses(node.dynamic_execute_binding.source_expression, symbol_names):
                        add_fact(symbol, StateAccessKind.USE, "EXECUTE_SOURCE", node, region)
                for target in node.dynamic_execute_binding.into_target_names:
                    add_fact(target, StateAccessKind.DEF, "EXECUTE_INTO_BINDING", node, region)
                for expression in node.dynamic_execute_binding.using_expressions:
                    for symbol in self._symbol_uses(expression, symbol_names):
                        add_fact(symbol, StateAccessKind.USE, "EXECUTE_USING", node, region)
        return tuple(sorted(facts, key=lambda fact: (fact.source_node_ref, fact.access_kind.value, fact.symbol_name, fact.context_kind)))

    def _symbol_uses(self, text: str, symbol_names: set[str]) -> tuple[str, ...]:
        tokens = self._scanner.scan(text).tokens
        return tuple(
            sorted(
                {
                    token.upper.strip('"')
                    for token in tokens
                    if token.upper.strip('"') in symbol_names
                    or token.upper.strip('"').startswith(("P_", "V_"))
                }
            )
        )

