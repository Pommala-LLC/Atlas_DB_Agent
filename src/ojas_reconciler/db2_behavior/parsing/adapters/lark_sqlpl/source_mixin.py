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


class SourceUtilitiesMixin:
    @staticmethod
    def _split_top_level(tokens: list[Token], separator: str) -> list[list[Token]]:
        groups: list[list[Token]] = [[]]
        depth = 0
        for token in tokens:
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
            if token.value == separator and depth == 0:
                groups.append([])
            else:
                groups[-1].append(token)
        return groups

    @staticmethod
    def _slice_text(source: str, start: int, end: int) -> str:
        return source[start:end]

    @staticmethod
    def _range_from_tokens(source: str, tokens: list[Token]) -> SourceRange:
        start = tokens[0].offset
        end = tokens[-1].offset + len(tokens[-1].value)
        return SourceUtilitiesMixin._range_from_offsets(source, start, end)

    @staticmethod
    def _range_from_offsets(source: str, start: int, end: int) -> SourceRange:
        prefix = source[:start]
        body = source[start:end]
        start_line = prefix.count("\n") + 1
        last_newline = prefix.rfind("\n")
        start_column = start - last_newline
        end_line = start_line + body.count("\n")
        end_last_newline = body.rfind("\n")
        if end_last_newline >= 0:
            end_column = len(body) - end_last_newline
        else:
            end_column = start_column + len(body)
        return SourceRange(
            start_line=start_line,
            start_column=start_column,
            start_offset=start,
            end_line=end_line,
            end_column=end_column,
            end_offset=end,
        )

    @staticmethod
    def _node_id(kind: str, source_range: SourceRange, text: str) -> str:
        payload = f"{kind}|{source_range.start_offset}|{source_range.end_offset}|{text}".encode("utf-8")
        return "node-" + hashlib.sha256(payload).hexdigest()[:20]

