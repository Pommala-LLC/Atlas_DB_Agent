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


class BindingParsingMixin:
    def _assignment_binding(self, source: str, statement: list[Token]) -> AssignmentBinding | None:
        equals_index = next((i for i, token in enumerate(statement) if token.value in {"=", ":="}), None)
        if equals_index is None or equals_index < 2:
            return None
        target = statement[1].value.strip('"').upper()
        expression = self._text_for_tokens(source, self._trim_semicolon(statement[equals_index + 1 :]))
        return AssignmentBinding(target_name=target, expression_text=expression)

    def _prepare_binding(self, source: str, statement: list[Token]) -> DynamicPrepareBinding | None:
        if len(statement) < 4 or statement[0].upper != "PREPARE":
            return None
        from_index = next((i for i, token in enumerate(statement) if token.upper == "FROM"), None)
        if from_index is None or from_index <= 1 or from_index + 1 >= len(statement):
            return None
        statement_name = statement[1].value.strip('"').upper()
        expression = self._text_for_tokens(source, self._trim_semicolon(statement[from_index + 1 :]))
        return DynamicPrepareBinding(statement_name=statement_name, source_expression=expression)

    def _execute_binding(self, source: str, statement: list[Token]) -> DynamicExecuteBinding | None:
        if len(statement) < 2 or statement[0].upper != "EXECUTE":
            return None
        trimmed = self._trim_semicolon(statement)
        if len(trimmed) >= 3 and trimmed[1].upper == "IMMEDIATE":
            source_tokens = trimmed[2:]
            return DynamicExecuteBinding(
                execution_kind="IMMEDIATE",
                source_expression=self._text_for_tokens(source, source_tokens),
            )
        statement_name = trimmed[1].value.strip('"').upper()
        into_index = next((i for i, token in enumerate(trimmed) if token.upper == "INTO"), None)
        using_index = next((i for i, token in enumerate(trimmed) if token.upper == "USING"), None)
        boundary = min(
            [value for value in (into_index, using_index, len(trimmed)) if value is not None]
        )
        into_targets: tuple[str, ...] = ()
        if into_index is not None:
            end = using_index if using_index is not None and using_index > into_index else len(trimmed)
            into_targets = tuple(
                token.value.strip('"').upper()
                for token in trimmed[into_index + 1 : end]
                if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
            )
        using_expressions: tuple[str, ...] = ()
        if using_index is not None:
            groups = self._split_top_level(trimmed[using_index + 1 :], ",")
            using_expressions = tuple(self._text_for_tokens(source, group) for group in groups if group)
        return DynamicExecuteBinding(
            execution_kind="PREPARED",
            statement_name=statement_name,
            source_expression=None,
            into_target_names=into_targets,
            using_expressions=using_expressions,
        )

    @staticmethod
    def _fetch_binding(statement: list[Token]) -> FetchBinding | None:
        if len(statement) < 4:
            return None
        into_index = next((i for i, token in enumerate(statement) if token.upper == "INTO"), None)
        if into_index is None or into_index <= 1:
            return None
        cursor_name = statement[1].value.strip('"').upper()
        targets = tuple(
            token.value.strip('"').upper()
            for token in statement[into_index + 1 :]
            if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
        )
        return FetchBinding(cursor_name=cursor_name, target_names=targets) if targets else None

    def _merge_structure(self, source: str, statement: list[Token]) -> MergeStructure:
        merge_index = next(i for i, token in enumerate(statement) if token.upper == "MERGE")
        target_start = merge_index + 1
        if target_start < len(statement) and statement[target_start].upper == "INTO":
            target_start += 1
        using_index = self._find_top_level_keyword(statement, "USING", target_start, len(statement))
        target_end = using_index if using_index is not None else min(target_start + 1, len(statement))
        target_text = self._text_for_tokens(source, statement[target_start:target_end])
        actions: list[MergeAction] = []
        i = 0
        while i < len(statement):
            if statement[i].upper != "WHEN":
                i += 1
                continue
            arm_start = i
            next_when = self._find_top_level_keyword(statement, "WHEN", i + 1, len(statement))
            arm_end = next_when if next_when is not None else len(statement)
            then_index = self._find_top_level_keyword(statement, "THEN", i + 1, arm_end)
            if then_index is None:
                i = arm_end
                continue
            cursor = i + 1
            if cursor < arm_end and statement[cursor].upper == "NOT":
                match_kind = "NOT_MATCHED"
                cursor += 1
            else:
                match_kind = "MATCHED"
            if cursor < arm_end and statement[cursor].upper == "MATCHED":
                cursor += 1
            condition_tokens = statement[cursor:then_index]
            if condition_tokens and condition_tokens[0].upper == "AND":
                condition_tokens = condition_tokens[1:]
            action_token = next(
                (token.upper for token in statement[then_index + 1 : arm_end] if token.upper in {"UPDATE", "INSERT", "DELETE", "SIGNAL"}),
                "UNKNOWN",
            )
            actions.append(
                MergeAction(
                    match_kind=cast("Literal['MATCHED', 'NOT_MATCHED']", match_kind),
                    condition_text=self._text_for_tokens(source, condition_tokens) or None,
                    action_kind=cast("Literal['UPDATE', 'INSERT', 'DELETE', 'SIGNAL', 'UNKNOWN']", action_token),
                )
            )
            i = arm_end if arm_end > arm_start else i + 1
        completeness = "STRUCTURE_COMPLETE" if actions and all(action.action_kind != "UNKNOWN" for action in actions) else "STRUCTURE_PARTIAL"
        return MergeStructure(
            target_text=target_text,
            actions=tuple(actions),
            analysis_completeness=cast("Literal['STRUCTURE_COMPLETE', 'STRUCTURE_PARTIAL']", completeness),
        )

    @staticmethod
    def _text_for_tokens(source: str, tokens: list[Token]) -> str:
        if not tokens:
            return ""
        start = tokens[0].offset
        end = tokens[-1].offset + len(tokens[-1].value)
        return source[start:end].strip()

    def _select_into_binding(self, source: str, statement: list[Token]) -> SelectIntoBinding | None:
        depth = 0
        into_index = None
        from_index = None
        for i, token in enumerate(statement):
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
            elif depth == 0 and token.upper == "INTO" and into_index is None:
                into_index = i
            elif depth == 0 and token.upper in {"FROM", "VALUES"} and into_index is not None:
                from_index = i
                break
        if into_index is None or from_index is None or from_index <= into_index + 1:
            return None
        target_tokens = statement[into_index + 1 : from_index]
        target_groups = self._split_top_level(target_tokens, ",")
        targets = tuple(
            group[0].value.strip('"').upper()
            for group in target_groups
            if group and group[0].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
        )
        projection_tokens = statement[1:into_index]
        projection_count = len(self._split_top_level(projection_tokens, ",")) if projection_tokens else 0
        if not targets:
            return None
        if projection_count == len(targets):
            arity = "ARITY_MATCHED"
        elif projection_count < len(targets):
            arity = "TOO_FEW_PROJECTIONS"
        else:
            arity = "TOO_MANY_PROJECTIONS"
        original_range = self._range_from_tokens(source, statement)
        removed_start = statement[into_index].offset
        removed_end = statement[from_index].offset
        residual = source[original_range.start_offset:removed_start] + source[removed_end:original_range.end_offset]
        removed_range = self._range_from_offsets(source, removed_start, removed_end)
        return SelectIntoBinding(
            target_names=targets,
            projection_count=projection_count,
            arity_status=cast("Literal[\"ARITY_MATCHED\", \"TOO_FEW_PROJECTIONS\", \"TOO_MANY_PROJECTIONS\", \"PROJECTION_COUNT_UNRESOLVED\"]", arity),
            original_statement_text=source[original_range.start_offset:original_range.end_offset],
            residual_query_text=residual,
            removed_range=removed_range,
        )

