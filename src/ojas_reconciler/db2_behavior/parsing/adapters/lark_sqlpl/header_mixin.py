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


class HeaderParsingMixin:
    def _parse_header(self, source: str, tokens: list[Token]) -> _Header:
        create_index = next(i for i, t in enumerate(tokens) if t.upper == "CREATE")
        proc_index = next(i for i in range(create_index + 1, len(tokens)) if tokens[i].upper == "PROCEDURE")
        lpar_index = next(i for i in range(proc_index + 1, len(tokens)) if tokens[i].value == "(")
        depth = 0
        rpar_index = None
        for i in range(lpar_index, len(tokens)):
            if tokens[i].value == "(":
                depth += 1
            elif tokens[i].value == ")":
                depth -= 1
                if depth == 0:
                    rpar_index = i
                    break
        if rpar_index is None:
            raise ValueError("Procedure parameter list is not balanced.")
        # Parse a comment-free token rendering rather than the raw source slice.
        # IBM samples legitimately place comments between the routine name and
        # parameter list; the scanner already removed trivia, so preserve only
        # semantic tokens at this grammar boundary.
        header_text = self._render_header_tokens(tokens[create_index : rpar_index + 1])
        tree = self._header_parser.parse(header_text)
        if any(subtree.data == "_ambig" for subtree in tree.iter_subtrees()):
            raise ValueError("Procedure header grammar is ambiguous.")
        name_tokens = tokens[proc_index + 1 : lpar_index]
        identifiers = [t.value.strip('"') for t in name_tokens if t.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}]
        if not identifiers:
            raise ValueError("Procedure name was not found.")
        schema = identifiers[-2] if len(identifiers) >= 2 else None
        name = identifiers[-1]
        parameters = self._extract_parameters(source, tokens[lpar_index + 1 : rpar_index])
        body_begin = self._find_body_begin(tokens)
        metadata_tokens = tokens[rpar_index + 1 : body_begin if body_begin is not None else len(tokens)]
        specific_name = self._value_after_sequence(metadata_tokens, ("SPECIFIC",))
        routine_version_id = self._value_after_sequence(metadata_tokens, ("VERSION",))
        commit_on_return = self._value_after_sequence(metadata_tokens, ("COMMIT", "ON", "RETURN"))
        declared_result_set_capacity = self._integer_after_sequence(
            metadata_tokens,
            (("DYNAMIC", "RESULT", "SETS"), ("RESULT", "SETS")),
        )
        return _Header(
            schema=schema,
            name=name,
            parameters=parameters,
            specific_name=specific_name,
            routine_version_id=routine_version_id,
            commit_on_return=commit_on_return,
            declared_result_set_capacity=declared_result_set_capacity,
        )

    def _extract_parameters(self, source: str, tokens: list[Token]) -> tuple[ProcedureParameter, ...]:
        groups = self._split_top_level(tokens, ",")
        params: list[ProcedureParameter] = []
        for group in groups:
            if not group:
                continue
            mode = "IN"
            pos = 0
            if group[0].upper in {"IN", "OUT", "INOUT"}:
                mode = group[0].upper
                pos = 1
            if pos >= len(group):
                continue
            name_token = group[pos]
            type_tokens = group[pos + 1 :]
            if not type_tokens:
                continue
            type_text = self._slice_text(source, type_tokens[0].offset, type_tokens[-1].offset + len(type_tokens[-1].value)).strip()
            params.append(
                ProcedureParameter(
                    name=name_token.value.strip('"').upper(),
                    mode=cast("Literal[\"IN\", \"OUT\", \"INOUT\"]", mode),
                    type_text=type_text,
                    source_range=self._range_from_tokens(source, group),
                )
            )
        return tuple(params)

    @staticmethod
    def _find_body_begin(tokens: list[Token]) -> int | None:
        # Choose the first BEGIN after the procedure parameter list.
        return next((i for i, token in enumerate(tokens) if token.upper == "BEGIN"), None)

    @staticmethod
    def _find_final_end(tokens: list[Token]) -> int | None:
        for i in range(len(tokens) - 1, -1, -1):
            if tokens[i].upper == "END":
                return i
        return None

    @staticmethod
    def _value_after_sequence(tokens: list[Token], sequence: tuple[str, ...]) -> str | None:
        if not sequence:
            return None
        for index in range(len(tokens) - len(sequence)):
            if tuple(token.upper for token in tokens[index : index + len(sequence)]) == sequence:
                value_index = index + len(sequence)
                if value_index < len(tokens):
                    return tokens[value_index].value.strip('"').upper()
        return None


    @staticmethod
    def _render_header_tokens(tokens: list[Token]) -> str:
        return " ".join(token.value for token in tokens)

    @staticmethod
    def _integer_after_sequence(
        tokens: list[Token],
        sequences: tuple[tuple[str, ...], ...],
    ) -> int | None:
        for sequence in sequences:
            for index in range(len(tokens) - len(sequence) + 1):
                if tuple(token.upper for token in tokens[index : index + len(sequence)]) != sequence:
                    continue
                value_index = index + len(sequence)
                if value_index >= len(tokens):
                    continue
                try:
                    return int(tokens[value_index].value)
                except ValueError:
                    continue
        return None
