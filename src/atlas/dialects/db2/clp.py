from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Literal

from pydantic import Field

from atlas.core.models import AtlasModel
from .clp_lexer import Db2LexicalScanner, Token, TokenKind


class ClpSourceRange(AtlasModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    start_offset: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    end_offset: int = Field(ge=0)


class Db2ClpSourceUnit(AtlasModel):
    unit_index: int = Field(ge=1)
    unit_kind: Literal["CREATE_PROCEDURE"] = "CREATE_PROCEDURE"
    source_range: ClpSourceRange
    source_text: str
    source_digest: str
    terminator: str
    declared_name: str | None = None


class Db2ClpScript(AtlasModel):
    schema_version: Literal["db2-clp-script-1.0"] = "db2-clp-script-1.0"
    source_name: str
    source_digest: str
    detected_terminator: str
    terminator_detection: Literal["DIRECTIVE", "INFERRED", "DEFAULT"]
    expected_source_unit_count: int = Field(ge=0)
    discovered_source_unit_count: int = Field(ge=0)
    source_units: tuple[Db2ClpSourceUnit, ...]
    unclassified_fragment_count: int = Field(ge=0)
    unclassified_fragments: tuple[str, ...] = ()


class Db2ClpScriptSegmenter:
    """Segments Db2 CLP scripts into CREATE PROCEDURE source units.

    The segmenter is comment/literal aware through the shared lexical scanner and
    matches each procedure's outer BEGIN/END rather than splitting on internal
    semicolons. Custom CLP terminators are retained as source evidence.
    """

    _directive = re.compile(r"(?im)^\s*--\s*#SET\s+TERMINATOR\s+([^\s]+)")
    _command_hint = re.compile(r"(?im)\bdb2\s+-td([^\s]+)")
    _create = ("CREATE", "PROCEDURE")
    _create_or_replace = ("CREATE", "OR", "REPLACE", "PROCEDURE")
    _block_kinds = {"BEGIN", "IF", "CASE", "LOOP", "WHILE", "REPEAT", "FOR"}

    def __init__(self) -> None:
        self._scanner = Db2LexicalScanner()

    def segment_file(self, path: Path) -> Db2ClpScript:
        data = path.read_bytes()
        return self.segment_text(data.decode("utf-8-sig"), source_name=path.name)

    def segment_text(self, source_text: str, *, source_name: str = "<memory>") -> Db2ClpScript:
        source_digest = "sha256:" + hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        terminator, detection = self._detect_terminator(source_text)
        tokens = list(self._scanner.scan(source_text).tokens)
        starts = self._procedure_starts(tokens)
        units: list[Db2ClpSourceUnit] = []
        covered: list[tuple[int, int]] = []

        for ordinal, start_index in enumerate(starts, start=1):
            end_index = self._procedure_end(tokens, start_index, terminator)
            if end_index is None:
                continue
            start_offset = tokens[start_index].offset
            end_offset = tokens[end_index].offset + len(tokens[end_index].value)
            end_offset = self._include_terminator(source_text, end_offset, terminator)
            text = source_text[start_offset:end_offset]
            source_range = self._range_from_offsets(source_text, start_offset, end_offset)
            declared_name = self._declared_name(tokens, start_index)
            units.append(
                Db2ClpSourceUnit(
                    unit_index=ordinal,
                    source_range=source_range,
                    source_text=text,
                    source_digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    terminator=terminator,
                    declared_name=declared_name,
                )
            )
            covered.append((start_offset, end_offset))

        fragments = self._unclassified_fragments(source_text, covered, terminator)
        return Db2ClpScript(
            source_name=source_name,
            source_digest=source_digest,
            detected_terminator=terminator,
            terminator_detection=detection,
            expected_source_unit_count=len(starts),
            discovered_source_unit_count=len(units),
            source_units=tuple(units),
            unclassified_fragment_count=len(fragments),
            unclassified_fragments=tuple(fragments),
        )

    def _detect_terminator(self, source: str) -> tuple[str, Literal["DIRECTIVE", "INFERRED", "DEFAULT"]]:
        directive = self._directive.search(source)
        if directive:
            return directive.group(1), "DIRECTIVE"
        hint = self._command_hint.search(source)
        if hint:
            value = hint.group(1).strip('"\'')
            if value:
                return value, "INFERRED"
        # Common CLP scripts end their outer compound statement with a custom
        # token on the same line. Infer only non-semicolon terminators.
        endings = re.findall(r"(?im)^\s*END(?:\s+[A-Za-z_#$@][A-Za-z0-9_#$@]*)?\s*([^\w\s;]|@)\s*(?:--.*)?$", source)
        if endings:
            return max(set(endings), key=endings.count), "INFERRED"
        return ";", "DEFAULT"

    def _procedure_starts(self, tokens: list[Token]) -> list[int]:
        result: list[int] = []
        for index in range(len(tokens)):
            seq4 = tuple(token.upper for token in tokens[index:index + 4])
            seq2 = tuple(token.upper for token in tokens[index:index + 2])
            if seq4 == self._create_or_replace or seq2 == self._create:
                result.append(index)
        return result

    def _procedure_end(self, tokens: list[Token], start_index: int, terminator: str = "") -> int | None:
        begin_index = next((i for i in range(start_index, len(tokens)) if tokens[i].upper == "BEGIN"), None)
        if begin_index is None:
            return None
        stack = ["BEGIN"]
        paren_depth = 0
        def block_keyword(token: Token) -> str:
            value = token.upper
            if terminator and value.endswith(terminator.upper()):
                candidate = value[:-len(terminator)]
                if candidate == "END" or candidate in self._block_kinds:
                    return candidate
            return value

        for index in range(begin_index + 1, len(tokens)):
            token = tokens[index]
            token_upper = block_keyword(token)
            previous = block_keyword(tokens[index - 1]) if index > begin_index else ""
            following = block_keyword(tokens[index + 1]) if index + 1 < len(tokens) else ""
            if token.value == "(":
                paren_depth += 1
                continue
            if token.value == ")":
                paren_depth = max(0, paren_depth - 1)
                continue
            if paren_depth:
                continue
            if token_upper == "END":
                # A bare END closes the nearest scalar CASE expression before it
                # can participate in procedural BEGIN/END matching.  Without this
                # marker, SET x = CASE ... END; can truncate the whole source unit.
                if following not in self._block_kinds - {"BEGIN"} and stack and stack[-1] == "EXPRESSION_CASE":
                    stack.pop()
                    continue
                expected = following if following in self._block_kinds - {"BEGIN"} else "BEGIN"
                if expected in stack:
                    reverse = len(stack) - 1 - stack[::-1].index(expected)
                    del stack[reverse:]
                if not stack:
                    # Include the closer keyword (END IF/CASE/...) or an optional
                    # compound-statement label (END label) before the CLP terminator.
                    if following in self._block_kinds - {"BEGIN"}:
                        return index + 1
                    if index + 1 < len(tokens) and tokens[index + 1].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
                        return index + 1
                    return index
                continue
            if token_upper in self._block_kinds and previous != "END":
                if token_upper == "CASE":
                    # A CASE nested inside an already open scalar CASE (including
                    # after ELSE) is still an expression, not a procedural CASE.
                    expression_case_open = "EXPRESSION_CASE" in stack
                    if expression_case_open or not self._is_case_statement_start(tokens, index):
                        stack.append("EXPRESSION_CASE")
                        continue
                if token_upper != "FOR" or self._is_for_loop_start(tokens, index):
                    stack.append(token_upper)
        return None

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
        lookahead = [token.upper for token in tokens[index + 1:index + 10]]
        return "AS" in lookahead and "CURSOR" in lookahead

    @staticmethod
    def _include_terminator(source: str, end_offset: int, terminator: str) -> int:
        cursor = end_offset
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if terminator and source.startswith(terminator, cursor):
            return cursor + len(terminator)
        if cursor < len(source) and source[cursor] == ";":
            return cursor + 1
        return end_offset

    @staticmethod
    def _declared_name(tokens: list[Token], start_index: int) -> str | None:
        proc_index = next((i for i in range(start_index, min(start_index + 5, len(tokens))) if tokens[i].upper == "PROCEDURE"), None)
        if proc_index is None:
            return None
        parts: list[str] = []
        for token in tokens[proc_index + 1:]:
            if token.value == "(":
                break
            if token.value == "." or token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
                parts.append(token.value.strip('"'))
        value = "".join(parts).strip()
        return value.upper() or None

    @staticmethod
    def _range_from_offsets(source: str, start: int, end: int) -> ClpSourceRange:
        prefix = source[:start]
        body = source[start:end]
        start_line = prefix.count("\n") + 1
        start_column = start - prefix.rfind("\n")
        end_line = start_line + body.count("\n")
        end_column = len(body) - body.rfind("\n") if "\n" in body else start_column + len(body)
        return ClpSourceRange(
            start_line=start_line,
            start_column=start_column,
            start_offset=start,
            end_line=end_line,
            end_column=end_column,
            end_offset=end,
        )

    @staticmethod
    def _unclassified_fragments(source: str, covered: list[tuple[int, int]], terminator: str) -> list[str]:
        if not covered:
            residuals = [source]
        else:
            residuals: list[str] = []
            cursor = 0
            for start, end in sorted(covered):
                residuals.append(source[cursor:start])
                cursor = end
            residuals.append(source[cursor:])
        fragments: list[str] = []
        for residual in residuals:
            stripped = re.sub(r"(?s)/\*.*?\*/", " ", residual)
            stripped = re.sub(r"(?m)--.*$", " ", stripped)
            if terminator:
                stripped = stripped.replace(terminator, " ")
            stripped = stripped.replace(";", " ").strip()
            if stripped:
                fragments.append(" ".join(stripped.split())[:500])
        return fragments
