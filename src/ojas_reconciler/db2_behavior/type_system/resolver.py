"""Deterministic declared-type parsing and source-priority reconciliation."""
from __future__ import annotations

import re
from collections.abc import Iterable

from .models import (
    CanonicalSqlType,
    ResolutionCompleteness,
    SqlTypeFamily,
    TypeResolution,
    TypeResolutionStatus,
)

_TYPE_RE = re.compile(
    r"^\s*(?P<name>[A-Z][A-Z0-9_ ]*)(?:\s*\(\s*(?P<a>\d+)\s*(?:,\s*(?P<b>\d+)\s*)?\))?",
    re.IGNORECASE,
)

_FAMILY_MAP: dict[str, SqlTypeFamily] = {
    "SMALLINT": SqlTypeFamily.SMALL_INTEGER,
    "INTEGER": SqlTypeFamily.INTEGER,
    "INT": SqlTypeFamily.INTEGER,
    "BIGINT": SqlTypeFamily.BIG_INTEGER,
    "DECIMAL": SqlTypeFamily.DECIMAL,
    "DEC": SqlTypeFamily.DECIMAL,
    "NUMERIC": SqlTypeFamily.DECIMAL,
    "REAL": SqlTypeFamily.FLOATING_POINT,
    "DOUBLE": SqlTypeFamily.FLOATING_POINT,
    "DOUBLE PRECISION": SqlTypeFamily.FLOATING_POINT,
    "FLOAT": SqlTypeFamily.FLOATING_POINT,
    "CHAR": SqlTypeFamily.CHARACTER,
    "CHARACTER": SqlTypeFamily.CHARACTER,
    "VARCHAR": SqlTypeFamily.CHARACTER,
    "CHARACTER VARYING": SqlTypeFamily.CHARACTER,
    "GRAPHIC": SqlTypeFamily.GRAPHIC,
    "VARGRAPHIC": SqlTypeFamily.GRAPHIC,
    "DATE": SqlTypeFamily.DATE,
    "TIME": SqlTypeFamily.TIME,
    "TIMESTAMP": SqlTypeFamily.TIMESTAMP,
    "BOOLEAN": SqlTypeFamily.BOOLEAN,
    "BINARY": SqlTypeFamily.BINARY,
    "VARBINARY": SqlTypeFamily.BINARY,
    "BLOB": SqlTypeFamily.LOB,
    "CLOB": SqlTypeFamily.LOB,
    "DBCLOB": SqlTypeFamily.LOB,
    "XML": SqlTypeFamily.XML,
}


def parse_declared_sql_type(type_text: str, *, source_ref: str) -> CanonicalSqlType:
    """Parse the declared DB2 type without consulting a catalog or guessing aliases."""
    normalized = " ".join(type_text.strip().upper().split())
    match = _TYPE_RE.match(normalized)
    if match is None:
        return CanonicalSqlType(
            family=SqlTypeFamily.UNKNOWN,
            database_type=normalized or "UNKNOWN",
            resolution_status=TypeResolutionStatus.UNKNOWN,
            completeness=ResolutionCompleteness.UNKNOWN,
            source_refs=(source_ref,),
        )
    database_type = " ".join(match.group("name").split())
    family = _FAMILY_MAP.get(database_type, SqlTypeFamily.DISTINCT)
    first = int(match.group("a")) if match.group("a") else None
    second = int(match.group("b")) if match.group("b") else None
    length = first if family in {SqlTypeFamily.CHARACTER, SqlTypeFamily.GRAPHIC, SqlTypeFamily.BINARY, SqlTypeFamily.LOB} else None
    precision = first if family is SqlTypeFamily.DECIMAL else None
    scale = second if family is SqlTypeFamily.DECIMAL else None
    return CanonicalSqlType(
        family=family,
        database_type=database_type,
        length=length,
        precision=precision,
        scale=scale,
        distinct_type_name=database_type if family is SqlTypeFamily.DISTINCT else None,
        resolution_status=TypeResolutionStatus.DECLARED,
        completeness=(
            ResolutionCompleteness.PARTIAL
            if family is SqlTypeFamily.DISTINCT
            else ResolutionCompleteness.COMPLETE
        ),
        source_refs=(source_ref,),
    )


class TypeResolutionEngine:
    """Select the first authoritative source and expose conflicts instead of coercing."""

    SOURCE_PRIORITY = (
        TypeResolutionStatus.DECLARED,
        TypeResolutionStatus.CATALOG_RESOLVED,
        TypeResolutionStatus.DDL_RESOLVED,
        TypeResolutionStatus.AUTHORITY_OVERRIDE,
        TypeResolutionStatus.DIALECT_INFERRED,
    )

    def resolve(self, *, subject_ref: str, candidates: Iterable[CanonicalSqlType]) -> TypeResolution:
        values = tuple(candidates)
        attempted = tuple(value.resolution_status.value for value in values)
        if not values:
            unknown = CanonicalSqlType(
                family=SqlTypeFamily.UNKNOWN,
                database_type="UNKNOWN",
                resolution_status=TypeResolutionStatus.UNKNOWN,
                completeness=ResolutionCompleteness.UNKNOWN,
                source_refs=(subject_ref,),
            )
            return TypeResolution(
                subject_ref=subject_ref,
                resolved_type=unknown,
                attempted_sources=attempted,
                selected_source=None,
                blockers=("COLUMN_TYPE_UNRESOLVED",),
            )
        ranked = sorted(values, key=lambda value: self.SOURCE_PRIORITY.index(value.resolution_status))
        selected = ranked[0]
        signatures = {(value.family, value.database_type, value.length, value.precision, value.scale) for value in values}
        if len(signatures) > 1:
            conflict = selected.model_copy(
                update={
                    "resolution_status": TypeResolutionStatus.CONFLICT,
                    "completeness": ResolutionCompleteness.PARTIAL,
                    "source_refs": tuple(dict.fromkeys(ref for value in values for ref in value.source_refs)),
                }
            )
            return TypeResolution(
                subject_ref=subject_ref,
                resolved_type=conflict,
                attempted_sources=attempted,
                selected_source=selected.resolution_status.value,
                conflicts=("PARAMETER_COLUMN_TYPE_MISMATCH",),
                blockers=("TYPE_RESOLUTION_CONFLICT",),
            )
        return TypeResolution(
            subject_ref=subject_ref,
            resolved_type=selected,
            attempted_sources=attempted,
            selected_source=selected.resolution_status.value,
        )
