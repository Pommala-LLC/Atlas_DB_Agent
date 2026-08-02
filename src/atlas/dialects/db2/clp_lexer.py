from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TokenKind(StrEnum):
    WORD = "WORD"
    STRING = "STRING"
    QUOTED_IDENTIFIER = "QUOTED_IDENTIFIER"
    NUMBER = "NUMBER"
    SYMBOL = "SYMBOL"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str
    upper: str
    line: int
    column: int
    offset: int


@dataclass(frozen=True, slots=True)
class LexResult:
    tokens: tuple[Token, ...]
    code_lines: frozenset[int]
    unterminated_string: bool = False
    unterminated_comment: bool = False


class Db2LexicalScanner:
    """A deterministic Gate 0 scanner, not the canonical DB2 SQL PL parser.

    It recognizes comments, literals, delimited identifiers, words, numbers and
    symbols so that inventory counts do not split on keywords inside comments or
    quoted values.
    """

    def scan(self, text: str) -> LexResult:
        tokens: list[Token] = []
        code_lines: set[int] = set()
        i = 0
        line = 1
        col = 1
        n = len(text)
        unterminated_string = False
        unterminated_comment = False

        def advance_char(ch: str) -> None:
            nonlocal line, col
            if ch == "\n":
                line += 1
                col = 1
            else:
                col += 1

        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""

            if ch.isspace():
                advance_char(ch)
                i += 1
                continue

            if ch == "-" and nxt == "-":
                while i < n and text[i] != "\n":
                    advance_char(text[i])
                    i += 1
                continue

            if ch == "/" and nxt == "*":
                start_line = line
                advance_char(ch)
                advance_char(nxt)
                i += 2
                depth = 1
                while i < n and depth:
                    cur = text[i]
                    look = text[i + 1] if i + 1 < n else ""
                    if cur == "/" and look == "*":
                        depth += 1
                        advance_char(cur)
                        advance_char(look)
                        i += 2
                    elif cur == "*" and look == "/":
                        depth -= 1
                        advance_char(cur)
                        advance_char(look)
                        i += 2
                    else:
                        advance_char(cur)
                        i += 1
                if depth:
                    unterminated_comment = True
                    code_lines.add(start_line)
                continue

            start_line, start_col, start_offset = line, col, i

            if ch == "'":
                value = [ch]
                advance_char(ch)
                i += 1
                closed = False
                while i < n:
                    cur = text[i]
                    value.append(cur)
                    advance_char(cur)
                    i += 1
                    if cur == "'":
                        if i < n and text[i] == "'":
                            value.append(text[i])
                            advance_char(text[i])
                            i += 1
                        else:
                            closed = True
                            break
                if not closed:
                    unterminated_string = True
                raw = "".join(value)
                tokens.append(Token(TokenKind.STRING, raw, raw, start_line, start_col, start_offset))
                code_lines.add(start_line)
                continue

            if ch == '"':
                value = [ch]
                advance_char(ch)
                i += 1
                closed = False
                while i < n:
                    cur = text[i]
                    value.append(cur)
                    advance_char(cur)
                    i += 1
                    if cur == '"':
                        if i < n and text[i] == '"':
                            value.append(text[i])
                            advance_char(text[i])
                            i += 1
                        else:
                            closed = True
                            break
                if not closed:
                    unterminated_string = True
                raw = "".join(value)
                tokens.append(
                    Token(TokenKind.QUOTED_IDENTIFIER, raw, raw.upper(), start_line, start_col, start_offset)
                )
                code_lines.add(start_line)
                continue

            if ch.isalpha() or ch in "_#$@":
                value = [ch]
                advance_char(ch)
                i += 1
                while i < n and (text[i].isalnum() or text[i] in "_#$@"):
                    value.append(text[i])
                    advance_char(text[i])
                    i += 1
                raw = "".join(value)
                tokens.append(Token(TokenKind.WORD, raw, raw.upper(), start_line, start_col, start_offset))
                code_lines.add(start_line)
                continue

            if ch.isdigit():
                value = [ch]
                advance_char(ch)
                i += 1
                while i < n and (text[i].isdigit() or text[i] in ".Ee+-"):
                    value.append(text[i])
                    advance_char(text[i])
                    i += 1
                raw = "".join(value)
                tokens.append(Token(TokenKind.NUMBER, raw, raw.upper(), start_line, start_col, start_offset))
                code_lines.add(start_line)
                continue

            two_char = ch + nxt
            if two_char in {"<=", ">=", "<>", "!=", "||", ":=", "=>"}:
                tokens.append(Token(TokenKind.SYMBOL, two_char, two_char, start_line, start_col, start_offset))
                advance_char(ch)
                advance_char(nxt)
                i += 2
            else:
                tokens.append(Token(TokenKind.SYMBOL, ch, ch, start_line, start_col, start_offset))
                advance_char(ch)
                i += 1
            code_lines.add(start_line)

        return LexResult(
            tokens=tuple(tokens),
            code_lines=frozenset(code_lines),
            unterminated_string=unterminated_string,
            unterminated_comment=unterminated_comment,
        )
