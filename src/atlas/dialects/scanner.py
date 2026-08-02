from __future__ import annotations

import re
from dataclasses import dataclass

from atlas.core.models import DialectId, SourceSpan

_STARTERS = re.compile(
    r"(?is)^(?:BEGIN(?:\s+(?:TRY|CATCH|TRAN|TRANSACTION))?|END(?:\s+(?:IF|LOOP|CASE|TRY|CATCH|WHILE|REPEAT))?|"
    r"IF\b|ELSIF\b|ELSEIF\b|ELSE\b|CASE\b|WHEN\b|EXCEPTION\b|WHILE\b|LOOP\b|FOR\b|FOREACH\b|REPEAT\b|UNTIL\b|"
    r"DECLARE\b|SET\b|SELECT\b|WITH\b|INSERT\b|UPDATE\b|DELETE\b|MERGE\b|CALL\b|EXEC\b|EXECUTE\b|PREPARE\b|"
    r"OPEN\b|FETCH\b|CLOSE\b|DEALLOCATE\b|RETURN\b|RAISE\b|SIGNAL\b|RESIGNAL\b|THROW\b|RAISERROR\b|"
    r"GET\b|COMMIT\b|ROLLBACK\b|SAVEPOINT\b|START\s+TRANSACTION\b|PERFORM\b|EXIT\b|CONTINUE\b|LEAVE\b|ITERATE\b|"
    r"CREATE\s+(?:TEMP|TEMPORARY|GLOBAL\s+TEMPORARY)\b|ALTER\s+SESSION\b|EXECUTE\s+AS\b|REVERT\b|"
    r"PRAGMA\b|ASSERT\b|FORALL\b|GOTO\b|LOCK\b|TRUNCATE\b|PRINT\b|DBMS_OUTPUT\b|DO\b|"
    r"SET\s+TRANSACTION\b|SET\s+XACT_ABORT\b|SET\s+TRANSACTION\s+ISOLATION\b|<<[^>]+>>|[A-Z_$#][A-Z0-9_$#]*:\s*$)"
)


@dataclass(frozen=True, slots=True)
class _Statement:
    text: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int

def _mask_comments(text: str) -> str:
    chars = list(text)
    i = 0
    quote: str | None = None
    dollar: str | None = None
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ''
        if dollar:
            if text.startswith(dollar, i):
                i += len(dollar)
                dollar = None
                continue
            i += 1
            continue
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if ch in {"'", '"', '`'}:
            quote = ch
            i += 1
            continue
        if ch == '$':
            match = re.match('\\$[A-Za-z0-9_]*\\$', text[i:])
            if match:
                dollar = match.group(0)
                i += len(dollar)
                continue
        if ch == '-' and nxt == '-':
            j = i
            while j < len(chars) and chars[j] != '\n':
                chars[j] = ' '
                j += 1
            i = j
            continue
        if ch == '/' and nxt == '*':
            j = i
            while j + 1 < len(chars) and (not (chars[j] == '*' and chars[j + 1] == '/')):
                if chars[j] != '\n':
                    chars[j] = ' '
                j += 1
            if j + 1 < len(chars):
                chars[j] = chars[j + 1] = ' '
                j += 2
            i = j
            continue
        i += 1
    return ''.join(chars)

def _split_semicolon_pieces(line: str) -> list[str]:
    pieces: list[str] = []
    start = 0
    quote: str | None = None
    bracket = False
    depth = 0
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ''
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif bracket:
            if ch == ']':
                bracket = False
        elif ch == '[':
            bracket = True
        elif ch in {"'", '"', '`'}:
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif ch == ';' and depth == 0:
            if line[start:i + 1].strip():
                pieces.append(line[start:i + 1])
            start = i + 1
        i += 1
    if line[start:].strip():
        pieces.append(line[start:])
    return pieces


def _has_unclosed_expression_case(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", text.strip().upper())
    # Statements beginning with CASE are procedural in this scanner lane.
    # Scalar CASE expressions are embedded in SET/SELECT/DML expressions.
    if normalized.startswith("CASE ") or normalized == "CASE":
        return False
    return len(re.findall(r"\bCASE\b", normalized)) > len(re.findall(r"\bEND\b", normalized))


def _expression_case_continuation(previous: str, current: str) -> bool:
    """Whether a control-looking line belongs to an open SQL CASE expression."""
    if not _has_unclosed_expression_case(previous):
        return False
    current_upper = re.sub(r"\s+", " ", current.strip().upper())
    return current_upper.startswith(("CASE", "WHEN ", "ELSE", "END"))

def _continues_statement(previous: str, current: str) -> bool:
    prev = re.sub(r"\s+", " ", previous.strip().upper())
    cur = re.sub(r"\s+", " ", current.strip().upper())
    if previous.rstrip().endswith((",", "(", "=", "+", "-", "*", "/", "||")):
        return True
    if prev.startswith("UPDATE ") and cur.startswith(("SET ", "OUTPUT ", "FROM ", "WHERE ", "OPTION ")):
        return True
    if prev.startswith("DELETE ") and cur.startswith(("OUTPUT ", "FROM ", "WHERE ", "OPTION ")):
        return True
    if prev.startswith("INSERT ") and cur.startswith(("VALUES ", "SELECT ", "OUTPUT ", "RETURNING ", "ON CONFLICT ", "ON DUPLICATE ")):
        return True
    if prev.startswith("MERGE ") and cur.startswith(("USING ", "ON ", "WHEN ", "OUTPUT ")):
        return True
    if prev.startswith("WITH ") and cur.startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "MERGE ")):
        return True
    if prev.startswith("SELECT ") and cur.startswith(("FROM ", "WHERE ", "GROUP ", "HAVING ", "ORDER ", "UNION ", "INTO ", "FOR ", "OPTION ")):
        return True
    if prev.startswith(("SIGNAL ", "RESIGNAL ")) and cur.startswith("SET "):
        return True
    if prev.startswith("EXEC ") or prev.startswith("EXECUTE "):
        return cur.startswith(("USING ", "INTO ", "OUTPUT "))
    return False

def _logical_statements(body: str, absolute_start: int, full_text: str) -> list[_Statement]:
    masked = _mask_comments(body)
    lines = body.splitlines(keepends=True)
    masked_lines = masked.splitlines(keepends=True)
    statements: list[_Statement] = []
    buffer: list[str] = []
    start_line = 1
    start_local_offset = 0
    local_offset = 0

    def flush(end_line: int, end_local_offset: int) -> None:
        nonlocal buffer, start_line, start_local_offset
        text = ''.join(buffer).strip()
        if text and text.strip(';').strip():
            abs_start = absolute_start + start_local_offset
            abs_end = absolute_start + end_local_offset
            statements.append(_Statement(text=text, start_line=start_line, end_line=end_line, start_offset=abs_start, end_offset=abs_end))
        buffer = []
    for index, (raw_line, masked_line) in enumerate(zip(lines, masked_lines), start=1):
        if re.match('(?i)^\\s*(?:DELIMITER\\s+\\S+|GO|/)\\s*$', masked_line):
            local_offset += len(raw_line)
            continue
        pieces = _split_semicolon_pieces(raw_line)
        piece_cursor = 0
        for piece in pieces:
            piece_mask = _split_semicolon_pieces(masked_line)[min(piece_cursor, len(_split_semicolon_pieces(masked_line)) - 1)] if _split_semicolon_pieces(masked_line) else masked_line
            piece_cursor += 1
            clean = piece_mask.strip()
            if not clean:
                local_offset += len(piece)
                continue
            is_starter = bool(_STARTERS.match(clean))
            if buffer and is_starter:
                previous = ''.join(buffer).rstrip()
                continuation = _continues_statement(previous, clean)
                control_boundary = bool(re.match('(?is)^(?:ELSE|ELSIF|ELSEIF|WHEN|EXCEPTION|END\\b|BEGIN\\s+CATCH|END\\s+TRY)', clean))
                expression_case = _expression_case_continuation(previous, clean)
                if not expression_case and (control_boundary or not continuation):
                    flush(index - 1 if index > start_line else index, local_offset)
            if not buffer:
                start_line = index
                start_local_offset = local_offset
            buffer.append(piece)
            immediate_boundary = bool(re.match(
                r'(?is)^\s*(?:BEGIN|ELSE|ELSIF\b.*THEN|ELSEIF\b.*THEN|EXCEPTION|END\s+(?:TRY|CATCH))\s*;?\s*$',
                clean,
            ))
            if piece.rstrip().endswith(';') or (
                immediate_boundary and not _has_unclosed_expression_case(''.join(buffer))
            ):
                flush(index, local_offset + len(piece))
            local_offset += len(piece)
        consumed = sum((len(piece) for piece in pieces))
        if consumed < len(raw_line):
            local_offset += len(raw_line) - consumed
    if buffer:
        flush(len(lines) or 1, len(body))
    return statements

def _expand_inline_control_statements(statements: list[_Statement], dialect: DialectId) -> list[_Statement]:
    current = list(statements)
    for _round in range(12):
        expanded: list[_Statement] = []
        changed = False
        for statement in current:
            text = statement.text.strip()
            patterns: list[tuple[re.Pattern[str], str]] = [
                (re.compile(r'(?is)^(BEGIN\s+(?:ATOMIC|NOT\s+ATOMIC))\s+(.+)$'), 'DB2_BLOCK'),
                (re.compile(r'(?is)^(UNTIL\s+.+?)(END\s+REPEAT\s*;?)$'), 'UNTIL'),
                (re.compile(r'(?is)^(IF\s+.+?\s+THEN)\s+(.+)$'), 'THEN'),
                (re.compile(r'(?is)^(WHILE\s+.+?\s+(?:DO|LOOP))\s+(.+)$'), 'WHILE'),
                (re.compile(r'(?is)^((?:FOR|FOREACH)\s+.+?\s+LOOP)\s+(.+)$'), 'FOR_LOOP'),
                (re.compile(r'(?is)^(LOOP)\s+(.+)$'), 'LOOP'),
                (re.compile(r'(?is)^((?:ELSIF|ELSEIF|ELSE\s+IF)\s+.+?\s+THEN)\s+(.+)$'), 'THEN'),
                (re.compile(r'(?is)^(WHEN\s+.+?\s+THEN)\s+(.+)$'), 'THEN'),
                (re.compile(r'(?is)^(ELSE)(?!\s+IF\b)\s+(.+)$'), 'ELSE'),
                (re.compile(r'(?is)^(<<[^>]+>>|[A-Z_$#][A-Z0-9_$#]*:)\s+(.+)$'), 'LABEL'),
                (re.compile(r'(?is)^(BEGIN)(?!\s+(?:TRY|CATCH|TRAN|TRANSACTION|ATOMIC|NOT\s+ATOMIC)\b)\s+(.+)$'), 'BEGIN'),
            ]
            if dialect is DialectId.SQLSERVER_TSQL:
                patterns.extend([
                    (re.compile(r'(?is)^(IF\s+.+?)\s+(BREAK|CONTINUE|RETURN|GOTO\s+[A-Z_$#][A-Z0-9_$#]*|THROW(?:\s+.+)?|RAISERROR\s*\(.+|ROLLBACK(?:\s+TRANSACTION)?|COMMIT(?:\s+TRANSACTION)?|SET\s+.+|EXEC(?:UTE)?\s+.+)$'), 'TSQL'),
                    (re.compile(r'(?is)^((?:ELSE\s+)?IF\s+.+?)\s+(BREAK|CONTINUE|RETURN|GOTO\s+[A-Z_$#][A-Z0-9_$#]*|THROW(?:\s+.+)?|RAISERROR\s*\(.+|ROLLBACK(?:\s+TRANSACTION)?|COMMIT(?:\s+TRANSACTION)?|SET\s+.+)$'), 'TSQL'),
                ])
            matched = False
            for pattern, _kind in patterns:
                match = pattern.match(text.rstrip(';'))
                if not match:
                    continue
                head, tail = (match.group(1).strip(), match.group(2).strip())
                if not tail:
                    continue
                split_at = statement.text.upper().find(tail.upper())
                if split_at < 0:
                    split_at = len(head)
                head_end = statement.start_offset + split_at
                expanded.append(_Statement(head, statement.start_line, statement.start_line, statement.start_offset, head_end))
                expanded.append(_Statement(tail + (';' if statement.text.rstrip().endswith(';') and not tail.endswith(';') else ''), statement.start_line, statement.end_line, head_end, statement.end_offset))
                matched = True
                changed = True
                break
            if not matched:
                expanded.append(statement)
        current = expanded
        if not changed:
            break
    return current

def _span(statement: _Statement, full_text: str) -> SourceSpan:
    start_line_offset = full_text.rfind('\n', 0, statement.start_offset) + 1
    end_line_offset = full_text.rfind('\n', 0, statement.end_offset) + 1
    return SourceSpan(start_line=full_text.count('\n', 0, statement.start_offset) + 1, start_column=statement.start_offset - start_line_offset + 1, end_line=full_text.count('\n', 0, statement.end_offset) + 1, end_column=max(1, statement.end_offset - end_line_offset + 1), start_offset=statement.start_offset, end_offset=statement.end_offset)
