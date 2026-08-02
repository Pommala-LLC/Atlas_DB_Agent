from __future__ import annotations

import re
from dataclasses import dataclass
from typing import cast

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from .base import DialectAdapterError, ProceduralDialectProfile
from .normalization import DialectNormalizer


@dataclass(frozen=True, slots=True)
class _Header:
    match: re.Match[str]
    routine_kind: RoutineKind
    schema_name: str | None
    routine_name: str
    parameters: tuple[RoutineParameter, ...]
    return_type: str | None
    routine_attributes: dict[str, object]


def _strip_identifier(value: str) -> str:
    value = value.strip().strip('`"')
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    return value


def _qualified(value: str, normalizer: DialectNormalizer) -> tuple[str | None, str]:
    normalized = normalizer.normalize_identifier(value)
    parts = [part for part in normalizer._split_qualified(normalized) if part]
    if not parts:
        raise DialectAdapterError("UNSUPPORTED_SYNTAX: routine identifier was empty.")
    return (parts[-2] if len(parts) > 1 else None, parts[-1])


def _split_csv(raw: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    bracket = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        nxt = raw[i + 1] if i + 1 < len(raw) else ''
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
        elif ch == ',' and depth == 0:
            parts.append(raw[start:i].strip())
            start = i + 1
        i += 1
    tail = raw[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_parameters(raw: str, profile: ProceduralDialectProfile, return_type: str | None) -> tuple[RoutineParameter, ...]:
    if profile.parameter_parser is not None:
        return profile.parameter_parser(raw, return_type)
    dialect = profile.dialect
    values: list[RoutineParameter] = []
    for index, item in enumerate(_split_csv(raw), start=1):
        clean = re.sub(r'\s+', ' ', item.strip())
        if not clean:
            continue
        mode = 'IN'
        default_text: str | None = None
        default_match = re.search(r'(?is)\s+(?:DEFAULT|:=|=)\s+(.+)$', clean)
        if default_match:
            default_text = default_match.group(1).strip()
            clean = clean[:default_match.start()].strip()
        tokens = clean.split()
        if dialect is DialectId.SQLSERVER_TSQL:
            name = tokens[0].lstrip('@')
            if tokens[-1].upper() in {'OUT', 'OUTPUT'}:
                mode = 'OUT'
                tokens = tokens[:-1]
            type_text = ' '.join(tokens[1:]) or 'UNKNOWN'
        else:
            if tokens and tokens[0].upper() in {'IN', 'OUT', 'INOUT'}:
                mode = tokens.pop(0).upper()
            name = tokens.pop(0).lstrip(':') if tokens else f'ARG_{index}'
            if tokens and tokens[0].upper() in {'IN', 'OUT', 'INOUT'}:
                mode = tokens.pop(0).upper()
            type_text = ' '.join(tokens) or 'UNKNOWN'
        values.append(RoutineParameter(name=name, mode=mode, type_text=type_text, default_text=default_text))
    if return_type:
        values.append(RoutineParameter(name='RETURN_VALUE', mode='RETURN', type_text=return_type.strip()))
    return tuple(values)


def _normalize_parameters(
    parameters: tuple[RoutineParameter, ...],
    normalizer: DialectNormalizer,
) -> tuple[RoutineParameter, ...]:
    values: list[RoutineParameter] = []
    for parameter in parameters:
        name = (
            parameter.name
            if parameter.mode == "RETURN" or re.fullmatch(r"ARG_\d+", parameter.name)
            else normalizer.normalize_variable(parameter.name)
        )
        values.append(
            parameter.model_copy(
                update={
                    "name": name,
                    "type_text": normalizer.normalize_type(parameter.type_text),
                }
            )
        )
    return tuple(values)


def _routine_attributes(text: str, match: re.Match[str], profile: ProceduralDialectProfile, kind: RoutineKind) -> dict[str, object]:
    if profile.routine_attribute_extractor is not None:
        return profile.routine_attribute_extractor(text, match, kind)
    return {"routine_kind": kind.value}


def _matching_paren(text: str, open_at: int) -> int:
    depth = 0
    quote: str | None = None
    bracket = False
    i = open_at
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif bracket:
            if ch == "]":
                bracket = False
        elif ch == "[":
            bracket = True
        elif ch in {"'", '"', '`'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise DialectAdapterError("UNSUPPORTED_SYNTAX: unclosed routine parameter list.")


_PG_OPTION = re.compile(
    r"(?is)\s+(?=(?:LANGUAGE\b|TRANSFORM\b|WINDOW\b|IMMUTABLE\b|STABLE\b|VOLATILE\b|"
    r"LEAKPROOF\b|CALLED\s+ON\s+NULL\s+INPUT\b|RETURNS\s+NULL\s+ON\s+NULL\s+INPUT\b|STRICT\b|"
    r"SECURITY\s+(?:INVOKER|DEFINER)\b|PARALLEL\b|COST\b|ROWS\b|SUPPORT\b|SET\b|AS\s+(?:\$[A-Za-z0-9_]*\$|E?'|')))"
)


def _extract_postgresql_header(
    text: str,
    profile: ProceduralDialectProfile,
    normalizer: DialectNormalizer,
) -> _Header:
    create = re.search(
        r'(?is)CREATE\s+(?:OR\s+REPLACE\s+)?(?P<kind>FUNCTION|PROCEDURE)\s+'
        r'(?P<name>(?:"[^"]+"|[A-Z_][A-Z0-9_$]*)(?:\.(?:"[^"]+"|[A-Z_][A-Z0-9_$]*))?)\s*\(',
        text,
    )
    if not create:
        raise DialectAdapterError("UNSUPPORTED_SYNTAX: no POSTGRESQL_PLPGSQL routine header was recognized.")
    open_at = create.end() - 1
    close_at = _matching_paren(text, open_at)
    params_raw = text[open_at + 1 : close_at]
    tail = text[close_at + 1 :]
    declared_kind = create.group("kind").upper()
    return_type: str | None = None
    kind = RoutineKind.PROCEDURE if declared_kind == "PROCEDURE" else RoutineKind.FUNCTION
    if declared_kind == "FUNCTION":
        returns = re.match(r'(?is)\s*RETURNS\s+', tail)
        if not returns:
            raise DialectAdapterError("UNSUPPORTED_SYNTAX: PostgreSQL function has no RETURNS clause.")
        remainder = tail[returns.end() :]
        boundary = _PG_OPTION.search(remainder)
        return_type = (remainder[: boundary.start()] if boundary else remainder).strip()
        if not return_type:
            raise DialectAdapterError("UNSUPPORTED_SYNTAX: PostgreSQL function return type was empty.")
        normalized_return = normalizer.normalize_type(return_type)
        if normalized_return in {"TRIGGER", "EVENT_TRIGGER"}:
            kind = RoutineKind.TRIGGER
    if not re.search(r'(?is)\bLANGUAGE\s+PLPGSQL\b', text):
        raise DialectAdapterError("UNSUPPORTED_SYNTAX: PostgreSQL routine is not declared LANGUAGE plpgsql.")
    schema, name = _qualified(create.group('name'), normalizer)
    params = _normalize_parameters(_parse_parameters(params_raw, profile, return_type), normalizer)
    attributes = _routine_attributes(text, cast(re.Match[str], create), profile, kind)
    return _Header(
        match=cast(re.Match[str], create),
        routine_kind=kind,
        schema_name=schema,
        routine_name=name,
        parameters=params,
        return_type=normalizer.normalize_type(return_type) if return_type else None,
        routine_attributes=attributes,
    )


def _extract_header(
    text: str,
    profile: ProceduralDialectProfile,
    normalizer: DialectNormalizer,
) -> _Header:
    if profile.dialect is DialectId.POSTGRESQL_PLPGSQL:
        return _extract_postgresql_header(text, profile, normalizer)

    patterns: list[tuple[str, RoutineKind]] = []
    patterns.extend(((pattern, RoutineKind.PROCEDURE) for pattern in profile.header_patterns))
    patterns.extend(((pattern, RoutineKind.TRIGGER) for pattern in profile.trigger_patterns))
    patterns.extend(((pattern, RoutineKind.FUNCTION) for pattern in profile.function_patterns))
    patterns.extend(((pattern, RoutineKind.PACKAGE_ROUTINE) for pattern in profile.package_procedure_patterns))
    patterns.extend(((pattern, RoutineKind.PACKAGE_ROUTINE) for pattern in profile.package_function_patterns))
    for pattern, kind in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        schema, name = _qualified(match.group('name'), normalizer)
        params = match.groupdict().get('params') or ''
        return_type = match.groupdict().get('return_type')
        normalized_return = normalizer.normalize_type(return_type) if return_type else None
        parameters = _normalize_parameters(_parse_parameters(params, profile, normalized_return), normalizer)
        return _Header(
            match=match,
            routine_kind=kind,
            schema_name=schema,
            routine_name=name,
            parameters=parameters,
            return_type=normalized_return,
            routine_attributes=_routine_attributes(text, match, profile, kind),
        )
    raise DialectAdapterError(f'UNSUPPORTED_SYNTAX: no {profile.dialect.value} routine header was recognized.')


def _extract_body(text: str, header: _Header, profile: ProceduralDialectProfile) -> tuple[str, int]:
    if profile.body_style == 'POSTGRES_DOLLAR_BODY':
        search_from = header.match.start()
        opener = re.search(r'\$[A-Za-z0-9_]*\$', text[search_from:])
        if opener:
            token = opener.group(0)
            absolute = search_from + opener.start()
            close = text.find(token, absolute + len(token))
            if close >= 0:
                body_start = absolute + len(token)
                return (text[body_start:close], body_start)
        raise DialectAdapterError("UNSUPPORTED_SYNTAX: PostgreSQL plpgsql body requires a bounded dollar-quoted body.")
    body_start = header.match.end()
    body = text[body_start:]
    body = re.sub(r'(?im)^\s*(?:GO|/|DELIMITER\s+\S+)\s*$', '', body)
    body = re.sub(r'(?s)\s*/\s*$', '', body)
    return (body, body_start)
