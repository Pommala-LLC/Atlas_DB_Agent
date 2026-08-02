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


class RegionParsingMixin:
    def _parse_sequence(
        self,
        source: str,
        tokens: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[tuple[str, ...], list[AstNode], list[ParseFinding]]:
        top_refs: list[str] = []
        all_nodes: list[AstNode] = []
        findings: list[ParseFinding] = []
        for statement in self._split_regions(tokens):
            if not statement:
                continue
            node, descendants, node_findings = self._parse_region(
                source,
                statement,
                lexical_scope_ref=lexical_scope_ref,
            )
            if node.lexical_scope_ref is None:
                node = node.model_copy(update={"lexical_scope_ref": lexical_scope_ref})
            top_refs.append(node.node_id)
            all_nodes.append(node)
            all_nodes.extend(descendants)
            findings.extend(node_findings)
        return tuple(top_refs), all_nodes, findings

    def _parse_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        first = self._effective_first(statement)
        uppers = {token.upper for token in statement}
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)

        if first == "BEGIN":
            return self._parse_compound_region(source, statement, lexical_scope_ref=lexical_scope_ref)
        if first == "DECLARE" and "HANDLER" in uppers:
            return self._parse_handler_region(source, statement, lexical_scope_ref=lexical_scope_ref)
        if first == "DECLARE" and len(statement) > 2 and statement[2].upper == "CONDITION":
            return self._parse_condition_declaration(source, statement, lexical_scope_ref=lexical_scope_ref)
        if first in {"LOOP", "WHILE", "REPEAT", "FOR"}:
            return self._parse_loop_region(source, statement, lexical_scope_ref=lexical_scope_ref)
        if first == "IF":
            return self._parse_if_region(source, statement, lexical_scope_ref=lexical_scope_ref)
        if first == "CASE":
            return self._parse_case_region(source, statement, lexical_scope_ref=lexical_scope_ref)

        kind = NodeKind.OPAQUE
        binding: SelectIntoBinding | None = None
        assignment: AssignmentBinding | None = None
        fetch_binding: FetchBinding | None = None
        dynamic_prepare_binding: DynamicPrepareBinding | None = None
        dynamic_execute_binding: DynamicExecuteBinding | None = None
        merge_structure: MergeStructure | None = None
        opaque_reason: str | None = None
        findings: list[ParseFinding] = []

        if first == "DECLARE":
            kind = NodeKind.DECLARE_CURSOR if "CURSOR" in uppers else NodeKind.DECLARE_VARIABLE
        elif first == "SET":
            kind = NodeKind.SET
            assignment = self._assignment_binding(source, statement)
        elif first == "SIGNAL":
            kind = NodeKind.SIGNAL
        elif first == "RESIGNAL":
            kind = NodeKind.RESIGNAL
        elif first == "GET" and len(statement) > 1 and statement[1].upper == "DIAGNOSTICS":
            kind = NodeKind.GET_DIAGNOSTICS
        elif first == "CALL":
            kind = NodeKind.CALL
        elif first in {"INSERT", "UPDATE", "DELETE", "MERGE"}:
            kind = NodeKind.DML
            if first == "MERGE":
                merge_structure = self._merge_structure(source, statement)
                if merge_structure.analysis_completeness == "STRUCTURE_PARTIAL":
                    findings.append(
                        ParseFinding(
                            code=ParserFindingCode.MERGE_ACTIONS_PARTIAL,
                            message="MERGE was retained but one or more action arms were not structurally resolved.",
                            source_range=source_range,
                            consequence="No complete MERGE effect decomposition may be inferred.",
                        )
                    )
        elif first == "COMMIT":
            kind = NodeKind.COMMIT
        elif first == "ROLLBACK":
            kind = NodeKind.ROLLBACK
        elif first == "SAVEPOINT":
            kind = NodeKind.SAVEPOINT
        elif first == "RETURN":
            kind = NodeKind.RETURN
        elif first == "OPEN":
            kind = NodeKind.OPEN_CURSOR
        elif first == "FETCH":
            kind = NodeKind.FETCH_CURSOR
            fetch_binding = self._fetch_binding(statement)
            if fetch_binding is None:
                findings.append(
                    ParseFinding(
                        code=ParserFindingCode.FETCH_BINDING_NOT_FOUND,
                        message="FETCH cursor or INTO targets were not structurally resolved.",
                        source_range=source_range,
                        consequence="No FETCH definition facts were emitted.",
                    )
                )
        elif first == "CLOSE":
            kind = NodeKind.CLOSE_CURSOR
        elif first == "LEAVE":
            kind = NodeKind.LEAVE
        elif first == "ITERATE":
            kind = NodeKind.ITERATE
        elif first == "PREPARE":
            kind = NodeKind.PREPARE
            dynamic_prepare_binding = self._prepare_binding(source, statement)
        elif first == "EXECUTE":
            kind = NodeKind.EXECUTE_IMMEDIATE if len(statement) > 1 and statement[1].upper == "IMMEDIATE" else NodeKind.EXECUTE
            dynamic_execute_binding = self._execute_binding(source, statement)
        elif first in {"SELECT", "WITH", "VALUES"}:
            binding = self._select_into_binding(source, statement)
            if binding is not None:
                kind = NodeKind.SELECT_INTO
            else:
                opaque_reason = "Embedded query without an admitted SQL PL binding remains opaque."
        else:
            opaque_reason = f"Unsupported statement beginning with {first!r}."

        if kind == NodeKind.OPAQUE:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.OPAQUE_REGION_EMITTED,
                    message=opaque_reason or "Unsupported procedural region.",
                    source_range=source_range,
                    consequence="The region was retained as evidence but no CFG/DFG semantics were inferred.",
                )
            )
        node = AstNode(
            node_id=self._node_id(kind.value, source_range, text),
            kind=kind,
            source_range=source_range,
            text=text,
            select_into_binding=binding,
            assignment_binding=assignment,
            fetch_binding=fetch_binding,
            dynamic_prepare_binding=dynamic_prepare_binding,
            dynamic_execute_binding=dynamic_execute_binding,
            merge_structure=merge_structure,
            opaque_reason=opaque_reason,
            lexical_scope_ref=lexical_scope_ref,
        )
        return node, [], findings

    def _parse_compound_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        node_id = self._node_id(NodeKind.COMPOUND.value, source_range, text)
        findings: list[ParseFinding] = []
        label, begin_index = self._label_and_keyword(statement)
        if begin_index >= len(statement) or statement[begin_index].upper != "BEGIN":
            raise ValueError("Compound region does not begin with BEGIN.")
        end_index = self._matching_final_end_index(statement, expected_kind=None)
        if end_index is None or end_index <= begin_index:
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.OPAQUE,
                source_range=source_range,
                text=text,
                opaque_reason="Nested compound statement has no matching END.",
                lexical_scope_ref=lexical_scope_ref,
            )
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.UNBALANCED_COMPOUND_STATEMENT,
                    message="Nested compound statement has no matching END.",
                    source_range=source_range,
                    consequence="The nested scope remains opaque.",
                )
            )
            return node, [], findings
        body_start = begin_index + 1
        if body_start < end_index and statement[body_start].upper == "ATOMIC":
            body_start += 1
        body_tokens = statement[body_start:end_index]
        body_refs, child_nodes, child_findings = self._parse_sequence(
            source,
            body_tokens,
            lexical_scope_ref=node_id,
        )
        findings.extend(child_findings)
        direct_by_id = {child.node_id: child for child in child_nodes}
        declaration_kinds = {
            NodeKind.DECLARE_VARIABLE,
            NodeKind.DECLARE_CURSOR,
            NodeKind.DECLARE_CONDITION,
            NodeKind.HANDLER_REGION,
        }
        local_refs = tuple(ref for ref in body_refs if direct_by_id.get(ref) is not None and direct_by_id[ref].kind in declaration_kinds)
        condition_refs = tuple(ref for ref in body_refs if direct_by_id.get(ref) is not None and direct_by_id[ref].kind == NodeKind.DECLARE_CONDITION)
        region = CompoundRegion(
            label=label,
            lexical_scope_ref=lexical_scope_ref,
            body_node_refs=body_refs,
            local_declaration_refs=local_refs,
            condition_declaration_refs=condition_refs,
        )
        node = AstNode(
            node_id=node_id,
            kind=NodeKind.COMPOUND,
            source_range=source_range,
            text=text,
            child_refs=body_refs,
            compound_region=region,
            lexical_scope_ref=lexical_scope_ref,
        )
        return node, child_nodes, findings

    def _parse_condition_declaration(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        self._condition_parser.parse(text.strip())
        if len(statement) < 6:
            raise ValueError("Condition declaration is incomplete.")
        condition_index = next((i for i, token in enumerate(statement) if token.upper == "CONDITION"), None)
        sqlstate_index = next((i for i, token in enumerate(statement) if token.upper == "SQLSTATE"), None)
        if condition_index != 2 or sqlstate_index is None or sqlstate_index + 1 >= len(statement):
            raise ValueError("Expected DECLARE <name> CONDITION FOR SQLSTATE <string>.")
        name = statement[1].value.strip('"').upper()
        raw_sqlstate = statement[sqlstate_index + 1].value
        sqlstate = raw_sqlstate.strip("'").upper()
        declaration = ConditionDeclaration(
            condition_name=name,
            sqlstate=sqlstate,
            lexical_scope_ref=lexical_scope_ref,
        )
        node = AstNode(
            node_id=self._node_id(NodeKind.DECLARE_CONDITION.value, source_range, text),
            kind=NodeKind.DECLARE_CONDITION,
            source_range=source_range,
            text=text,
            condition_declaration=declaration,
            lexical_scope_ref=lexical_scope_ref,
        )
        return node, [], []

    def _parse_handler_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        node_id = self._node_id(NodeKind.HANDLER_REGION.value, source_range, text)
        findings: list[ParseFinding] = []

        try:
            handler_index = next(i for i, token in enumerate(statement) if token.upper == "HANDLER")
            kind_token = statement[handler_index - 1].upper
            handler_kind = HandlerKind(kind_token)
            for_index = next(i for i in range(handler_index + 1, len(statement)) if statement[i].upper == "FOR")
            condition_end = self._handler_condition_end(statement, for_index + 1)
            condition_tokens = statement[for_index + 1 : condition_end]
            body_tokens = self._trim_semicolon(statement[condition_end:])
            condition_text = self._text_for_tokens(source, condition_tokens)
            self._handler_condition_parser.parse(condition_text)
            if body_tokens and body_tokens[0].upper == "BEGIN":
                end_index = self._matching_final_end_index(body_tokens, expected_kind=None)
                if end_index is None:
                    raise ValueError("Handler compound body has no matching END.")
                nested_tokens = body_tokens[1:end_index]
            else:
                nested_tokens = body_tokens

            body_refs, child_nodes, child_findings = self._parse_sequence(
                source,
                nested_tokens,
                lexical_scope_ref=node_id,
            )
            findings.extend(child_findings)
            state_refs = tuple(
                child.node_id
                for child in child_nodes
                if child.assignment_binding is not None
            )
            continuation = {
                HandlerKind.CONTINUE: "AFTER_RAISING_STATEMENT",
                HandlerKind.EXIT: "EXIT_DECLARING_COMPOUND",
                HandlerKind.UNDO: "UNDO_AND_EXIT_DECLARING_COMPOUND",
            }[handler_kind]
            region = HandlerRegion(
                handler_kind=handler_kind,
                handled_condition_text=condition_text,
                lexical_scope_ref=lexical_scope_ref,
                body_node_refs=body_refs,
                continuation_semantics=continuation,
                state_assignment_refs=state_refs,
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.HANDLER_REGION,
                source_range=source_range,
                text=text,
                child_refs=body_refs,
                handler_region=region,
                lexical_scope_ref=lexical_scope_ref,
            )
            return node, child_nodes, findings
        except (StopIteration, ValueError) as exc:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.HANDLER_STRUCTURE_PARTIAL,
                    message=str(exc),
                    source_range=source_range,
                    consequence="Handler text was retained but continuation and body structure are incomplete.",
                )
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.OPAQUE,
                source_range=source_range,
                text=text,
                opaque_reason="Handler structure could not be resolved.",
            )
            return node, [], findings

    def _parse_loop_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        label, keyword_index = self._label_and_keyword(statement)
        loop_kind = LoopKind(statement[keyword_index].upper)
        node_id = self._node_id(NodeKind.LOOP_REGION.value, source_range, text)
        findings: list[ParseFinding] = []
        try:
            end_index = self._matching_final_end_index(statement, expected_kind=loop_kind.value)
            if end_index is None:
                raise ValueError(f"{loop_kind.value} region has no matching END {loop_kind.value}.")
            condition_text: str | None = None
            if loop_kind == LoopKind.LOOP:
                body_start = keyword_index + 1
                body_end = end_index
            elif loop_kind in {LoopKind.WHILE, LoopKind.FOR}:
                do_index = self._find_top_level_keyword(statement, "DO", keyword_index + 1, end_index)
                if do_index is None:
                    raise ValueError(f"{loop_kind.value} region has no top-level DO.")
                condition_text = self._text_for_tokens(source, statement[keyword_index + 1 : do_index])
                body_start = do_index + 1
                body_end = end_index
            else:  # REPEAT
                until_index = self._find_top_level_keyword(statement, "UNTIL", keyword_index + 1, end_index)
                if until_index is None:
                    raise ValueError("REPEAT region has no top-level UNTIL.")
                body_start = keyword_index + 1
                body_end = until_index
                condition_text = self._text_for_tokens(source, statement[until_index + 1 : end_index])

            body_tokens = self._trim_semicolon(statement[body_start:body_end])
            body_refs, child_nodes, child_findings = self._parse_sequence(
                source,
                body_tokens,
                lexical_scope_ref=lexical_scope_ref,
            )
            findings.extend(child_findings)
            region = LoopRegion(
                loop_kind=loop_kind,
                label=label,
                condition_text=condition_text,
                body_node_refs=body_refs,
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.LOOP_REGION,
                source_range=source_range,
                text=text,
                child_refs=body_refs,
                loop_region=region,
                lexical_scope_ref=lexical_scope_ref,
            )
            return node, child_nodes, findings
        except ValueError as exc:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.LOOP_STRUCTURE_PARTIAL,
                    message=str(exc),
                    source_range=source_range,
                    consequence="Loop text was retained but nested flow structure is incomplete.",
                )
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.OPAQUE,
                source_range=source_range,
                text=text,
                opaque_reason="Loop structure could not be resolved.",
            )
            return node, [], findings

    def _parse_if_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        node_id = self._node_id(NodeKind.IF_REGION.value, source_range, text)
        findings: list[ParseFinding] = []
        try:
            raw_arms = self._split_if_arms(statement)
            arms: list[IfArm] = []
            descendants: list[AstNode] = []
            arm_refs: list[str] = []
            for precedence, (arm_kind, condition_tokens, body_tokens) in enumerate(raw_arms):
                arm_tokens = [*condition_tokens, *self._trim_semicolon(body_tokens)]
                arm_range = (
                    self._range_from_tokens(source, arm_tokens)
                    if arm_tokens
                    else source_range
                )
                arm_text = self._slice_text(source, arm_range.start_offset, arm_range.end_offset)
                arm_id = self._node_id(
                    NodeKind.IF_ARM.value,
                    arm_range,
                    f"{node_id}|{precedence}|{arm_kind}|{arm_text}",
                )
                body_refs, child_nodes, child_findings = self._parse_sequence(
                    source,
                    self._trim_semicolon(body_tokens),
                    lexical_scope_ref=lexical_scope_ref,
                )
                findings.extend(child_findings)
                arm = IfArm(
                    arm_id=arm_id,
                    arm_kind=arm_kind,
                    ordered_precedence=precedence,
                    condition_text=self._text_for_tokens(source, condition_tokens) if condition_tokens else None,
                    body_node_refs=body_refs,
                    source_range=arm_range,
                )
                arm_node = AstNode(
                    node_id=arm_id,
                    kind=NodeKind.IF_ARM,
                    source_range=arm_range,
                    text=arm_text,
                    child_refs=body_refs,
                    if_arm=arm,
                    lexical_scope_ref=lexical_scope_ref,
                )
                arms.append(arm)
                arm_refs.append(arm_id)
                descendants.append(arm_node)
                descendants.extend(child_nodes)
            region = IfRegion(arms=tuple(arms), source_construct="IF")
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.IF_REGION,
                source_range=source_range,
                text=text,
                child_refs=tuple(arm_refs),
                if_region=region,
                lexical_scope_ref=lexical_scope_ref,
            )
            return node, descendants, findings
        except ValueError as exc:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.IF_STRUCTURE_PARTIAL,
                    message=str(exc),
                    source_range=source_range,
                    consequence="IF text was retained but branch structure is incomplete.",
                )
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.OPAQUE,
                source_range=source_range,
                text=text,
                opaque_reason="IF structure could not be resolved.",
            )
            return node, [], findings

    def _parse_case_region(
        self,
        source: str,
        statement: list[Token],
        *,
        lexical_scope_ref: str,
    ) -> tuple[AstNode, list[AstNode], list[ParseFinding]]:
        """Normalize Db2 simple/searched CASE into the ordered decision IR.

        Downstream Phase-1 analyses already consume IfRegion/IfArm as an
        ordered decision structure. CASE therefore shares that representation
        while retaining its original source form and selector metadata.
        """
        source_range = self._range_from_tokens(source, statement)
        text = self._slice_text(source, source_range.start_offset, source_range.end_offset)
        node_id = self._node_id(NodeKind.IF_REGION.value, source_range, text)
        findings: list[ParseFinding] = []
        try:
            selector_tokens, raw_arms = self._split_case_arms(statement)
            selector_text = self._text_for_tokens(source, selector_tokens) if selector_tokens else None
            source_construct = "SIMPLE_CASE" if selector_text else "SEARCHED_CASE"
            arms: list[IfArm] = []
            descendants: list[AstNode] = []
            arm_refs: list[str] = []
            when_count = 0
            for precedence, (arm_kind, condition_tokens, body_tokens) in enumerate(raw_arms):
                if arm_kind == "ELSE":
                    normalized_kind: Literal["IF", "ELSEIF", "ELSE"] = "ELSE"
                    condition_text = None
                else:
                    normalized_kind = "IF" if when_count == 0 else "ELSEIF"
                    when_count += 1
                    raw_condition = self._text_for_tokens(source, condition_tokens)
                    condition_text = (
                        f"({selector_text}) = ({raw_condition})"
                        if selector_text is not None
                        else raw_condition
                    )
                arm_tokens = [*condition_tokens, *self._trim_semicolon(body_tokens)]
                arm_range = self._range_from_tokens(source, arm_tokens) if arm_tokens else source_range
                arm_text = self._slice_text(source, arm_range.start_offset, arm_range.end_offset)
                arm_id = self._node_id(
                    NodeKind.IF_ARM.value,
                    arm_range,
                    f"{node_id}|CASE|{precedence}|{arm_kind}|{arm_text}",
                )
                body_refs, child_nodes, child_findings = self._parse_sequence(
                    source,
                    self._trim_semicolon(body_tokens),
                    lexical_scope_ref=lexical_scope_ref,
                )
                findings.extend(child_findings)
                arm = IfArm(
                    arm_id=arm_id,
                    arm_kind=normalized_kind,
                    ordered_precedence=precedence,
                    condition_text=condition_text,
                    body_node_refs=body_refs,
                    source_range=arm_range,
                )
                arm_node = AstNode(
                    node_id=arm_id,
                    kind=NodeKind.IF_ARM,
                    source_range=arm_range,
                    text=arm_text,
                    child_refs=body_refs,
                    if_arm=arm,
                    lexical_scope_ref=lexical_scope_ref,
                )
                arms.append(arm)
                arm_refs.append(arm_id)
                descendants.append(arm_node)
                descendants.extend(child_nodes)
            if not arms:
                raise ValueError("CASE region has no WHEN or ELSE arms.")
            region = IfRegion(
                arms=tuple(arms),
                source_construct=cast("Literal['SIMPLE_CASE','SEARCHED_CASE']", source_construct),
                selector_expression=selector_text,
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.IF_REGION,
                source_range=source_range,
                text=text,
                child_refs=tuple(arm_refs),
                if_region=region,
                lexical_scope_ref=lexical_scope_ref,
            )
            return node, descendants, findings
        except ValueError as exc:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.IF_STRUCTURE_PARTIAL,
                    message=f"CASE structure partial: {exc}",
                    source_range=source_range,
                    consequence="CASE text was retained but ordered arm semantics are incomplete.",
                )
            )
            node = AstNode(
                node_id=node_id,
                kind=NodeKind.OPAQUE,
                source_range=source_range,
                text=text,
                opaque_reason="CASE structure could not be resolved.",
                lexical_scope_ref=lexical_scope_ref,
            )
            return node, [], findings

    def _split_case_arms(
        self,
        statement: list[Token],
    ) -> tuple[list[Token], list[tuple[Literal["WHEN", "ELSE"], list[Token], list[Token]]]]:
        end_index = self._matching_final_end_index(statement, expected_kind="CASE")
        if end_index is None:
            raise ValueError("CASE region has no matching END CASE.")
        first_when = self._find_top_level_keyword(statement, "WHEN", 1, end_index)
        if first_when is None:
            raise ValueError("CASE region has no top-level WHEN.")
        selector_tokens = statement[1:first_when]
        result: list[tuple[Literal["WHEN", "ELSE"], list[Token], list[Token]]] = []
        i = first_when
        while i < end_index:
            token = statement[i]
            if token.upper == "WHEN":
                then_index = self._find_top_level_keyword(statement, "THEN", i + 1, end_index)
                if then_index is None:
                    raise ValueError("CASE WHEN arm has no THEN.")
                next_marker = self._next_case_marker(statement, then_index + 1, end_index)
                body_end = next_marker if next_marker is not None else end_index
                result.append(("WHEN", statement[i + 1:then_index], statement[then_index + 1:body_end]))
                i = body_end
                continue
            if token.upper == "ELSE":
                result.append(("ELSE", [], statement[i + 1:end_index]))
                break
            i += 1
        return selector_tokens, result

    @staticmethod
    def _next_case_marker(tokens: list[Token], start: int, end: int) -> int | None:
        stack: list[str] = []
        paren_depth = 0
        block_kinds = {"IF", "LOOP", "WHILE", "REPEAT", "FOR", "CASE", "BEGIN"}
        for index in range(start, end):
            token = tokens[index]
            previous = tokens[index - 1].upper if index > start else ""
            following = tokens[index + 1].upper if index + 1 < end else ""
            if token.value == "(":
                paren_depth += 1
                continue
            if token.value == ")":
                paren_depth = max(0, paren_depth - 1)
                continue
            if paren_depth:
                continue
            if not stack and token.upper in {"WHEN", "ELSE"}:
                return index
            if token.upper in block_kinds and previous != "END":
                if token.upper == "CASE" and not RegionParsingMixin._is_case_statement_start(tokens, index):
                    continue
                if token.upper != "FOR" or RegionParsingMixin._is_for_loop_start(tokens, index):
                    stack.append(token.upper)
            elif token.upper == "END" and stack:
                expected = following if following in block_kinds - {"BEGIN"} else "BEGIN"
                if expected in stack:
                    reverse = len(stack) - 1 - stack[::-1].index(expected)
                    del stack[reverse:]
        return None

    @staticmethod
    def _handler_condition_end(tokens: list[Token], start: int) -> int:
        if start >= len(tokens):
            raise ValueError("Handler condition is missing.")
        if tokens[start].upper == "NOT" and start + 1 < len(tokens) and tokens[start + 1].upper == "FOUND":
            return start + 2
        if tokens[start].upper == "SQLSTATE" and start + 1 < len(tokens):
            return start + 2
        return start + 1

    def _split_if_arms(
        self,
        statement: list[Token],
    ) -> list[tuple[Literal["IF", "ELSEIF", "ELSE"], list[Token], list[Token]]]:
        end_index = self._matching_final_end_index(statement, expected_kind="IF")
        if end_index is None:
            raise ValueError("IF region has no matching END IF.")
        then_index = self._find_top_level_keyword(statement, "THEN", 1, end_index)
        if then_index is None:
            raise ValueError("IF region has no top-level THEN.")
        result: list[tuple[Literal["IF", "ELSEIF", "ELSE"], list[Token], list[Token]]] = []
        current_kind: Literal["IF", "ELSEIF", "ELSE"] = "IF"
        current_condition = statement[1:then_index]
        body_start = then_index + 1
        i = body_start
        stack: list[str] = []
        paren_depth = 0
        while i < end_index:
            token = statement[i]
            following = statement[i + 1].upper if i + 1 < end_index else ""
            previous = statement[i - 1].upper if i > 0 else ""
            if token.value == "(":
                paren_depth += 1
            elif token.value == ")":
                paren_depth = max(0, paren_depth - 1)
            elif paren_depth == 0:
                if not stack and token.upper in {"ELSEIF", "ELSE"}:
                    result.append((current_kind, current_condition, statement[body_start:i]))
                    if token.upper == "ELSEIF":
                        next_then = self._find_top_level_keyword(statement, "THEN", i + 1, end_index)
                        if next_then is None:
                            raise ValueError("ELSEIF arm has no THEN.")
                        current_kind = "ELSEIF"
                        current_condition = statement[i + 1 : next_then]
                        body_start = next_then + 1
                        i = body_start
                        continue
                    current_kind = "ELSE"
                    current_condition = []
                    body_start = i + 1
                elif token.upper in {"IF", "LOOP", "WHILE", "REPEAT", "FOR", "BEGIN"} and previous != "END":
                    stack.append(token.upper)
                elif token.upper == "CASE" and previous != "END" and self._is_case_statement_start(statement, i):
                    stack.append("CASE")
                elif token.upper == "END" and stack:
                    expected = following if following in {"IF", "LOOP", "WHILE", "REPEAT", "FOR", "CASE"} else "BEGIN"
                    if expected in stack:
                        reverse_index = len(stack) - 1 - stack[::-1].index(expected)
                        del stack[reverse_index:]
            i += 1
        result.append((current_kind, current_condition, statement[body_start:end_index]))
        return result

    @staticmethod
    def _label_and_keyword(statement: list[Token]) -> tuple[str | None, int]:
        if len(statement) >= 3 and statement[1].value == ":":
            return statement[0].value.strip('"').upper(), 2
        return None, 0

    @staticmethod
    def _matching_final_end_index(tokens: list[Token], expected_kind: str | None) -> int | None:
        for i in range(len(tokens) - 1, -1, -1):
            if tokens[i].upper != "END":
                continue
            if expected_kind is None:
                following = tokens[i + 1].upper if i + 1 < len(tokens) else ""
                if following not in {"IF", "LOOP", "WHILE", "REPEAT", "FOR", "CASE"}:
                    return i
            elif i + 1 < len(tokens) and tokens[i + 1].upper == expected_kind:
                return i
        return None

    @staticmethod
    def _trim_semicolon(tokens: list[Token]) -> list[Token]:
        result = list(tokens)
        while result and result[-1].value == ";":
            result.pop()
        return result

    @staticmethod
    def _find_top_level_keyword(tokens: list[Token], keyword: str, start: int, end: int) -> int | None:
        paren_depth = 0
        block_stack: list[str] = []
        block_kinds = {"IF", "LOOP", "WHILE", "REPEAT", "FOR", "CASE", "BEGIN"}
        for i in range(start, end):
            token = tokens[i]
            previous = tokens[i - 1].upper if i > start else ""
            following = tokens[i + 1].upper if i + 1 < end else ""
            if token.value == "(":
                paren_depth += 1
                continue
            if token.value == ")":
                paren_depth = max(0, paren_depth - 1)
                continue
            if paren_depth:
                continue
            if not block_stack and token.upper == keyword:
                return i
            if token.upper in block_kinds and previous != "END":
                if token.upper == "CASE" and not RegionParsingMixin._is_case_statement_start(tokens, i):
                    continue
                if token.upper != "FOR" or RegionParsingMixin._is_for_loop_start(tokens, i):
                    block_stack.append(token.upper)
            elif token.upper == "END" and block_stack:
                expected = following if following in block_kinds - {"BEGIN"} else "BEGIN"
                if expected in block_stack:
                    reverse_index = len(block_stack) - 1 - block_stack[::-1].index(expected)
                    del block_stack[reverse_index:]
        return None

    @staticmethod
    def _effective_first(statement: list[Token]) -> str:
        # DB2 labels use `label:` immediately before LOOP/WHILE/REPEAT.
        if len(statement) >= 3 and statement[1].value == ":":
            return statement[2].upper
        return statement[0].upper

    @staticmethod
    def _split_regions(tokens: list[Token]) -> list[list[Token]]:
        regions: list[list[Token]] = []
        current: list[Token] = []
        block_stack: list[str] = []
        paren_depth = 0
        block_kinds = {"IF", "WHILE", "REPEAT", "LOOP", "FOR", "CASE"}

        for index, token in enumerate(tokens):
            current.append(token)
            previous = tokens[index - 1].upper if index > 0 else ""
            following = tokens[index + 1].upper if index + 1 < len(tokens) else ""

            if token.value == "(":
                paren_depth += 1
            elif token.value == ")":
                paren_depth = max(0, paren_depth - 1)
            elif paren_depth == 0:
                if token.upper == "BEGIN":
                    block_stack.append("BEGIN")
                elif token.upper in block_kinds and previous != "END":
                    if token.upper == "CASE" and not RegionParsingMixin._is_case_statement_start(tokens, index):
                        continue
                    if token.upper != "FOR" or RegionParsingMixin._is_for_loop_start(tokens, index):
                        block_stack.append(token.upper)
                elif token.upper == "END" and block_stack:
                    expected = following if following in block_kinds else "BEGIN"
                    if expected in block_stack:
                        reverse_index = len(block_stack) - 1 - block_stack[::-1].index(expected)
                        del block_stack[reverse_index:]
                elif token.value == ";" and not block_stack:
                    regions.append(current)
                    current = []

        if current:
            regions.append(current)
        return [region for region in regions if region]

    @staticmethod
    def _is_case_statement_start(tokens: list[Token], index: int) -> bool:
        if index == 0:
            return True
        previous = tokens[index - 1]
        if previous.value in {";", ":"}:
            return True
        return previous.upper in {"BEGIN", "THEN", "ELSE", "DO"}

    @staticmethod
    def _is_for_loop_start(tokens: list[Token], index: int) -> bool:
        # Distinguish SQL PL FOR loops from DECLARE ... CONDITION FOR and
        # DECLARE ... CURSOR FOR clauses. A loop has `FOR <row> AS ... CURSOR`.
        lookahead = [token.upper for token in tokens[index + 1 : index + 10]]
        return "AS" in lookahead and "CURSOR" in lookahead

    @staticmethod
    def _split_statements(tokens: list[Token]) -> list[list[Token]]:
        # Compatibility alias; the spike now preserves procedural regions.
        return LarkSqlPlSpikeParser._split_regions(tokens)

