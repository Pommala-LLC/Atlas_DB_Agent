from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from .base import ProceduralDialectProfile
from .scanner import _Statement
from .normalization import DialectNormalizer

_WORD = re.compile(r"[@:]?[A-Za-z_$#][A-Za-z0-9_$#]*")
_SQL_KEYWORDS = {
    "SELECT", "FROM", "WHERE", "JOIN", "LEFT", "RIGHT", "FULL", "INNER", "OUTER", "ON", "AND", "OR", "NOT",
    "NULL", "TRUE", "FALSE", "CASE", "WHEN", "THEN", "ELSE", "END", "IF", "BEGIN", "LOOP", "WHILE", "FOR",
    "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "MERGE", "USING", "MATCHED", "CALL", "EXEC", "EXECUTE",
    "RETURN", "RAISE", "SIGNAL", "THROW", "DECLARE", "CURSOR", "OPEN", "FETCH", "CLOSE", "COMMIT", "ROLLBACK",
    "SAVEPOINT", "AS", "IS", "LANGUAGE", "PROCEDURE", "FUNCTION", "CREATE", "ALTER", "REPLACE", "OUTPUT", "OUT", "IN",
    "INOUT", "DEFAULT", "CURRENT", "GET", "DIAGNOSTICS", "EXCEPTION", "OTHERS", "TRY", "CATCH", "PERFORM", "QUERY",
    "PRAGMA", "ASSERT", "FORALL", "BULK", "COLLECT", "GOTO", "LOCK", "TRUNCATE", "PRINT", "NOTICE", "WARNING",
    "INFO", "DEBUG", "LOG", "DO", "CONDITION", "ISOLATION", "LEVEL", "XACT_ABORT", "ROWCOUNT", "IDENTITY",
}


def _relations(text: str, normalizer: DialectNormalizer) -> tuple[str, ...]:
    found: list[str] = []
    patterns = ('(?is)\\bFROM\\s+([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bJOIN\\s+([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bUPDATE\\s+([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bINSERT\\s+INTO\\s+([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bDELETE\\s+FROM\\s+([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bMERGE\\s+(?:INTO\\s+)?([\\[\\]`\\"A-Z0-9_$#.]+)', '(?is)\\bTRUNCATE\\s+TABLE\\s+([\\[\\]`\\"A-Z0-9_$#.]+)')
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            raw = match.group(1)
            value = normalizer.normalize_identifier(raw)
            if value not in found and not raw.startswith(("@", ":")):
                found.append(value)
    return tuple(found)

def _variables(text: str, normalizer: DialectNormalizer) -> tuple[str, ...]:
    values: list[str] = []
    for match in _WORD.finditer(text):
        raw = match.group(0).lstrip("@:")
        if raw.upper() in _SQL_KEYWORDS or raw.isdigit():
            continue
        value = normalizer.normalize_variable(match.group(0))
        if value not in values:
            values.append(value)
    return tuple(values)

def _condition_text(text: str) -> str | None:
    patterns = ('(?is)^\\s*IF\\s+(.+?)(?:\\s+THEN)?\\s*;?$', '(?is)^\\s*(?:ELSIF|ELSEIF|ELSE\\s+IF)\\s+(.+?)(?:\\s+THEN)?\\s*;?$', '(?is)^\\s*WHILE\\s+(.+?)(?:\\s+LOOP|\\s+DO)?\\s*;?$', '(?is)^\\s*(?:EXIT|CONTINUE|LEAVE|ITERATE)\\b.*?\\bWHEN\\s+(.+?)\\s*;?$', '(?is)^\\s*UNTIL\\s+(.+?)\\s*;?$', '(?is)^\\s*WHEN\\s+(.+?)\\s+THEN\\s*;?$')
    for pattern in patterns:
        match = re.match(pattern, text)
        if match:
            return match.group(1).strip()
    return None

def _assignment(text: str, dialect: DialectId) -> tuple[str, str] | None:
    patterns = [
        r'(?is)^\s*SET\s+([@:]?[A-Z_$#][A-Z0-9_$#.]*)\s*(?::=|=|\+=|-=|\*=|/=)\s*(.+?)\s*;?$',
        r'(?is)^\s*([@:]?[A-Z_$#][A-Z0-9_$#.]*)\s*:=\s*(.+?)\s*;?$',
    ]
    if dialect is DialectId.SQLSERVER_TSQL:
        patterns.append(r'(?is)^\s*SELECT\s+(@[A-Z_$#][A-Z0-9_$#.]*)\s*=\s*(.+?)\s*;?$')
    for pattern in patterns:
        match = re.match(pattern, text)
        if match:
            return match.group(1).lstrip('@:'), match.group(2).strip().rstrip(';')
    return None

def _call_target(text: str, dialect: DialectId) -> str | None:
    patterns = [
        r'(?is)^\s*CALL\s+([\[\]`"A-Z0-9_$#.]+)',
        r'(?is)^\s*(?:EXEC|EXECUTE)\s+(?!IMMEDIATE\b)(?:@?\w+\s*=\s*)?([\[\]`"A-Z0-9_$#.]+)',
        r'(?is)^\s*PERFORM\s+([\[\]`"A-Z0-9_$#.]+)\s*\(',
    ]
    if dialect is DialectId.ORACLE_PLSQL:
        patterns.append(r'(?is)^\s*([A-Z_$#][A-Z0-9_$#.]*)\s*\(.*\)\s*;?$')
    for pattern in patterns:
        match = re.match(pattern, text)
        if match:
            value = match.group(1)
            keyword_probe = re.sub(r'[\[\]`"]', '', value).upper()
            if keyword_probe not in {'IF', 'WHILE', 'FOR', 'CASE', 'RAISE_APPLICATION_ERROR'}:
                return value
    return None

def _classify(statement: _Statement, profile: ProceduralDialectProfile, in_declare_section: bool) -> tuple[SemanticNodeKind, dict[str, object]]:
    text = statement.text.strip()
    upper = re.sub('\\s+', ' ', text.upper()).strip()
    attrs: dict[str, object] = {}
    condition = _condition_text(text)
    if condition is not None and upper.startswith(('IF ', 'ELSIF ', 'ELSEIF ', 'ELSE IF ')):
        return (SemanticNodeKind.CONDITION, {'condition_text': condition, 'branch_kind': 'ELSEIF' if upper.startswith('ELSE IF ') else upper.split()[0]})
    if upper == 'ELSE' or upper.startswith('ELSE '):
        return (SemanticNodeKind.CONDITION, {'condition_text': 'ELSE', 'branch_kind': 'ELSE'})
    if upper.startswith('CASE') and (not upper.startswith('CASE WHEN')):
        return (SemanticNodeKind.CASE, {'condition_text': text[4:].strip().rstrip(';') or None})
    if upper.startswith('WHEN ') and ' THEN' in upper:
        return (SemanticNodeKind.CONDITION, {'condition_text': condition or text, 'branch_kind': 'WHEN'})
    if upper.startswith(('WHILE ', 'LOOP', 'FOR ', 'FOREACH ', 'REPEAT')) or re.match('(?is)^[A-Z_$#][A-Z0-9_$#]*:\\s*(?:LOOP|WHILE|REPEAT)\\b', text):
        return (SemanticNodeKind.LOOP, {'condition_text': condition, 'loop_kind': upper.split()[0]})
    if upper.startswith(('EXIT', 'CONTINUE', 'LEAVE', 'ITERATE', 'BREAK', 'UNTIL ')):
        control = upper.split()[0].rstrip(';')
        label_match = re.match(r'(?is)^\s*(?:LEAVE|ITERATE)\s+([A-Z_$#][A-Z0-9_$#]*)', text)
        return (
            SemanticNodeKind.LOOP_CONTROL,
            {
                'condition_text': condition,
                'control_kind': control,
                'target_label': label_match.group(1).upper() if label_match else None,
            },
        )
    if upper.startswith(('BEGIN TRY', 'BEGIN CATCH', 'EXCEPTION', 'WHEN OTHERS', 'WHEN SQLWARNING', 'WHEN SQLEXCEPTION')):
        return (SemanticNodeKind.ERROR_HANDLER, {'handler_kind': upper.split()[1] if upper.startswith('BEGIN ') else upper.split()[0]})
    if re.match(r'(?is)^\s*DECLARE\s+.*\bHANDLER\b', text):
        return (SemanticNodeKind.ERROR_HANDLER, {'handler_kind': 'DECLARE_HANDLER'})
    if re.match(r'(?is)^\s*DECLARE\s+[A-Z_$#][A-Z0-9_$#]*\s+CONDITION\s+FOR\b', text):
        match = re.match(r'(?is)^\s*DECLARE\s+([A-Z_$#][A-Z0-9_$#]*)\s+CONDITION\s+FOR\s+(.+?);?$', text)
        return (SemanticNodeKind.CONDITION_DECLARE, {'condition_name': match.group(1).upper() if match else None, 'condition_definition': match.group(2).strip().rstrip(';') if match else None})
    if re.match(r'(?is)^\s*[A-Z_$#][A-Z0-9_$#]*\s+EXCEPTION\s*;?$', text):
        return (SemanticNodeKind.CONDITION_DECLARE, {'exception_declaration': True})
    if upper.startswith('PRAGMA '):
        return (SemanticNodeKind.PRAGMA, {'pragma_name': upper.split()[1].rstrip(';') if len(upper.split()) > 1 else None})
    if upper.startswith('ASSERT '):
        match = re.match(r'(?is)^\s*ASSERT\s+(.+?)(?:\s*,\s*(.+?))?;?$', text)
        return (SemanticNodeKind.ASSERT, {'condition_text': match.group(1).strip() if match else text, 'message_text': match.group(2).strip() if match and match.group(2) else None})
    if upper.startswith('FORALL ') or ' BULK COLLECT ' in f' {upper} ':
        return (SemanticNodeKind.BULK_OPERATION, {'bulk_kind': 'FORALL' if upper.startswith('FORALL ') else 'BULK_COLLECT'})
    if re.match(r'(?is)^\s*<<[^>]+>>\s*;?$', text) or re.match(r'(?is)^\s*[A-Z_$#][A-Z0-9_$#]*:\s*$', text):
        return (SemanticNodeKind.LABEL, {'label_name': re.sub(r'[<>:;\s]', '', text).upper()})
    if upper.startswith('GOTO '):
        return (SemanticNodeKind.GOTO, {'label_name': upper.split()[1].rstrip(';') if len(upper.split()) > 1 else None})
    if upper.startswith(('LOCK TABLE', 'LOCK TABLES', 'SELECT GET_LOCK', 'SELECT RELEASE_LOCK')):
        return (SemanticNodeKind.LOCK, {'lock_semantics': upper.split()[0]})
    if upper.startswith(('SET TRANSACTION', 'SET SESSION TRANSACTION', 'SET GLOBAL TRANSACTION', 'SET XACT_ABORT', 'SET TRANSACTION ISOLATION LEVEL')):
        return (SemanticNodeKind.TRANSACTION_SETTING, {'setting_text': text.rstrip(';')})
    if upper.startswith(('PRINT ', 'DBMS_OUTPUT.', 'RAISE NOTICE', 'RAISE WARNING', 'RAISE INFO', 'RAISE DEBUG', 'RAISE LOG')):
        return (SemanticNodeKind.MESSAGE, {'message_text': text.rstrip(';')})
    if upper.startswith('TRUNCATE '):
        return (SemanticNodeKind.TRUNCATE, {})
    if upper.startswith(('CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'CREATE INDEX', 'DROP INDEX', 'CREATE VIEW', 'DROP VIEW')):
        if re.search(r'(?is)\b(?:TEMP|TEMPORARY)\b|[#@][A-Z0-9_$#]+', text):
            return (SemanticNodeKind.TEMP_OBJECT, {})
        return (SemanticNodeKind.DDL, {})
    if (upper.startswith('BEGIN') and not upper.startswith(('BEGIN TRAN', 'BEGIN TRANSACTION'))) or upper.startswith('END'):
        return (SemanticNodeKind.BLOCK, {'boundary': upper.rstrip(';')})
    assignment = _assignment(text, profile.dialect)
    if assignment:
        return (SemanticNodeKind.ASSIGNMENT, {'target_name': assignment[0], 'expression_text': assignment[1]})
    if upper.startswith('DECLARE ') or (in_declare_section and re.match('(?is)^[A-Z_$#][A-Z0-9_$#]*\\s+[^;]+;?$', text)):
        if ' CURSOR ' in f' {upper} ' or re.search('(?is)\\bCURSOR\\s+(?:IS|FOR)\\b', text):
            match = re.search('(?is)(?:DECLARE\\s+)?([A-Z_$#][A-Z0-9_$#]*)\\s+CURSOR|CURSOR\\s+([A-Z_$#][A-Z0-9_$#]*)', text)
            return (SemanticNodeKind.CURSOR_DECLARE, {'cursor_name': next((g for g in match.groups() if g), None).upper() if match else None})
        return (SemanticNodeKind.DECLARE, {})
    if upper.startswith('OPEN '):
        match = re.match('(?is)^\\s*OPEN\\s+([A-Z_$#][A-Z0-9_$#]*)', text)
        if ' FOR ' in upper:
            return (SemanticNodeKind.RESULT_SET, {'cursor_name': match.group(1).upper() if match else None, 'dynamic': 'EXECUTE' in upper})
        return (SemanticNodeKind.CURSOR_OPEN, {'cursor_name': match.group(1).upper() if match else None})
    if upper.startswith('FETCH '):
        match = re.search('(?is)^\\s*FETCH(?:\\s+\\w+\\s+FROM)?\\s+([A-Z_$#][A-Z0-9_$#]*)', text)
        return (SemanticNodeKind.CURSOR_FETCH, {'cursor_name': match.group(1).upper() if match else None})
    if upper.startswith('CLOSE '):
        match = re.match('(?is)^\\s*CLOSE\\s+([A-Z_$#][A-Z0-9_$#]*)', text)
        return (SemanticNodeKind.CURSOR_CLOSE, {'cursor_name': match.group(1).upper() if match else None})
    if upper.startswith(('EXECUTE IMMEDIATE', 'PREPARE ', 'DEALLOCATE PREPARE', 'RETURN QUERY EXECUTE')) or 'SP_EXECUTESQL' in upper or re.match('(?is)^\\s*EXECUTE\\s+[\\\'\\"]', text):
        return (SemanticNodeKind.DYNAMIC_SQL, {})
    if upper.startswith('EXEC') and ('(' in text or '@' in text) and (_call_target(text, profile.dialect) is None):
        return (SemanticNodeKind.DYNAMIC_SQL, {})
    target = _call_target(text, profile.dialect)
    if target:
        return (SemanticNodeKind.CALL, {'call_target': target})
    if upper.startswith(('RAISE', 'SIGNAL', 'RESIGNAL', 'THROW', 'RAISERROR')):
        code_match = re.search('(?is)(?:SQLSTATE\\s+VALUE\\s+|SQLSTATE\\s+|RAISE_APPLICATION_ERROR\\s*\\(\\s*)([\'\\"]?-?\\d{4,5}[A-Z0-9]*[\'\\"]?)', text)
        return (SemanticNodeKind.ERROR_RAISE, {'error_code': code_match.group(1).strip('\'"') if code_match else None})
    if upper.startswith(('GET DIAGNOSTICS', 'GET STACKED DIAGNOSTICS')):
        return (SemanticNodeKind.DIAGNOSTICS, {})
    if upper.startswith(('BEGIN TRAN', 'BEGIN TRANSACTION', 'START TRANSACTION')):
        return (SemanticNodeKind.TRANSACTION_BEGIN, {})
    if upper.startswith('COMMIT'):
        return (SemanticNodeKind.COMMIT, {})
    if upper.startswith('ROLLBACK'):
        return (SemanticNodeKind.ROLLBACK, {})
    if upper.startswith('SAVEPOINT') or upper.startswith('SAVE TRAN'):
        return (SemanticNodeKind.SAVEPOINT, {})
    if upper.startswith(('RETURN QUERY', 'RETURN NEXT', 'PIPE ROW')):
        return (SemanticNodeKind.RESULT_SET, {})
    if upper.startswith('RETURN'):
        return (SemanticNodeKind.RETURN, {'expression_text': re.sub('(?is)^\\s*RETURN\\s*', '', text).rstrip(';').strip() or None})
    if re.search(r'(?is)\bON\s+CONFLICT\b|\bON\s+DUPLICATE\s+KEY\b', text):
        return (SemanticNodeKind.UPSERT, {})
    if upper.startswith('INSERT'):
        return (SemanticNodeKind.INSERT, {})
    if upper.startswith('UPDATE'):
        return (SemanticNodeKind.UPDATE, {})
    if upper.startswith('DELETE'):
        return (SemanticNodeKind.DELETE, {})
    if upper.startswith('MERGE'):
        return (SemanticNodeKind.MERGE, {})
    if upper.startswith(('SELECT', 'WITH')):
        if re.search('(?is)\\bINTO\\b', text) or re.search('(?is)SELECT\\s+@[A-Z0-9_$#]+\\s*=', text):
            return (SemanticNodeKind.SELECT_INTO, {})
        return (SemanticNodeKind.RESULT_SET if profile.dialect in {DialectId.SQLSERVER_TSQL, DialectId.MYSQL_STORED_PROGRAM} else SemanticNodeKind.QUERY, {})
    if upper.startswith('PERFORM'):
        return (SemanticNodeKind.QUERY, {})
    if upper.startswith(('CREATE TEMP', 'CREATE TEMPORARY', 'CREATE GLOBAL TEMPORARY', 'DECLARE GLOBAL TEMPORARY')):
        return (SemanticNodeKind.TEMP_OBJECT, {})
    if upper.startswith(('EXECUTE AS', 'REVERT', 'ALTER SESSION SET CURRENT_SCHEMA', 'SET ROLE', 'SET NOCOUNT')):
        return (SemanticNodeKind.SECURITY_CONTEXT, {})
    return (SemanticNodeKind.OPAQUE, {'opaque_reason': 'UNCLASSIFIED_DIALECT_STATEMENT'})


class CommonStatementClassifier:
    """Shared fallback classifier used after dialect-owned rules decline a statement."""

    def __init__(self, dialect: DialectId) -> None:
        self.dialect = dialect

    def classify(
        self,
        statement: _Statement,
        profile: ProceduralDialectProfile,
        in_declare_section: bool,
    ) -> tuple[SemanticNodeKind, dict[str, object]]:
        return _classify(statement, profile, in_declare_section)
