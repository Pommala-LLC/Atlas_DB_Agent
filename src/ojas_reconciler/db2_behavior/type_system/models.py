"""Canonical, dialect-aware SQL type and relation metadata models."""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ..core.models import CanonicalModel


class SqlDialect(StrEnum):
    DB2_SQL_PL = "DB2_SQL_PL"
    POSTGRESQL_PLPGSQL = "POSTGRESQL_PLPGSQL"
    ORACLE_PLSQL = "ORACLE_PLSQL"
    SQLSERVER_TSQL = "SQLSERVER_TSQL"


class DatabasePlatform(StrEnum):
    DB2_LUW = "DB2_LUW"
    DB2_ZOS = "DB2_ZOS"
    POSTGRESQL = "POSTGRESQL"
    ORACLE = "ORACLE"
    SQLSERVER = "SQLSERVER"
    UNSPECIFIED = "UNSPECIFIED"


class SqlTypeFamily(StrEnum):
    SMALL_INTEGER = "SMALL_INTEGER"
    INTEGER = "INTEGER"
    BIG_INTEGER = "BIG_INTEGER"
    DECIMAL = "DECIMAL"
    FLOATING_POINT = "FLOATING_POINT"
    CHARACTER = "CHARACTER"
    GRAPHIC = "GRAPHIC"
    DATE = "DATE"
    TIME = "TIME"
    TIMESTAMP = "TIMESTAMP"
    BOOLEAN = "BOOLEAN"
    BINARY = "BINARY"
    LOB = "LOB"
    XML = "XML"
    DISTINCT = "DISTINCT"
    UNKNOWN = "UNKNOWN"


class TypeResolutionStatus(StrEnum):
    DECLARED = "DECLARED"
    CATALOG_RESOLVED = "CATALOG_RESOLVED"
    DDL_RESOLVED = "DDL_RESOLVED"
    AUTHORITY_OVERRIDE = "AUTHORITY_OVERRIDE"
    DIALECT_INFERRED = "DIALECT_INFERRED"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


class ResolutionCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class CanonicalSqlType(CanonicalModel):
    family: SqlTypeFamily
    database_type: str
    length: int | None = Field(default=None, ge=1)
    precision: int | None = Field(default=None, ge=1)
    scale: int | None = Field(default=None, ge=0)
    nullable: bool | None = None
    code_page: str | None = None
    for_bit_data: bool = False
    distinct_type_name: str | None = None
    resolution_status: TypeResolutionStatus
    completeness: ResolutionCompleteness
    source_refs: tuple[str, ...]

    @model_validator(mode="after")
    def validate_precision_scale(self) -> "CanonicalSqlType":
        if self.scale is not None and self.precision is not None and self.scale > self.precision:
            raise ValueError("SQL type scale cannot exceed precision.")
        if self.family is SqlTypeFamily.UNKNOWN and self.resolution_status is not TypeResolutionStatus.UNKNOWN:
            raise ValueError("UNKNOWN family is reserved for unresolved types.")
        return self


class DeclaredSymbolType(CanonicalModel):
    symbol_name: str
    symbol_kind: Literal["PROCEDURE_PARAMETER", "LOCAL_VARIABLE", "CONDITION", "CURSOR"]
    parameter_mode: Literal["IN", "OUT", "INOUT"] | None = None
    sql_type: CanonicalSqlType | None = None
    default_expression: str | None = None
    lexical_scope_ref: str | None = None
    source_ref: str

    @model_validator(mode="after")
    def validate_mode(self) -> "DeclaredSymbolType":
        if self.symbol_kind != "PROCEDURE_PARAMETER" and self.parameter_mode is not None:
            raise ValueError("parameter_mode is valid only for procedure parameters.")
        return self


class TemporalRole(StrEnum):
    NONE = "NONE"
    SYSTEM_TIME_START = "SYSTEM_TIME_START"
    SYSTEM_TIME_END = "SYSTEM_TIME_END"
    BUSINESS_TIME_START = "BUSINESS_TIME_START"
    BUSINESS_TIME_END = "BUSINESS_TIME_END"


class ColumnDefinition(CanonicalModel):
    relation_name: str
    column_name: str
    sql_type: CanonicalSqlType
    nullable: bool
    default_expression: str | None = None
    generated: bool = False
    generated_expression: str | None = None
    identity_column: bool = False
    tenant_isolation: bool = False
    temporal_role: TemporalRole = TemporalRole.NONE
    source_refs: tuple[str, ...]


class ForeignKeyDefinition(CanonicalModel):
    constraint_name: str | None = None
    local_columns: tuple[str, ...]
    referenced_schema: str | None = None
    referenced_relation: str
    referenced_columns: tuple[str, ...]
    source_refs: tuple[str, ...] = ()


class RelationDefinition(CanonicalModel):
    schema_name: str
    relation_name: str
    columns: tuple[ColumnDefinition, ...]
    primary_key: tuple[str, ...] = ()
    unique_constraints: tuple[tuple[str, ...], ...] = ()
    foreign_keys: tuple[ForeignKeyDefinition, ...] = ()
    check_constraints: tuple[str, ...] = ()
    temporal_kind: Literal[
        "NONE",
        "SYSTEM_PERIOD_TEMPORAL",
        "APPLICATION_PERIOD_TEMPORAL",
        "BITEMPORAL",
    ] = "NONE"
    provider_ref: str
    content_digest: str


class DatabaseProfile(CanonicalModel):
    dialect: SqlDialect
    platform: DatabasePlatform
    product_name: str
    major_version: int | None = Field(default=None, ge=1)
    minor_version: int | None = Field(default=None, ge=0)
    function_level: str | None = None


class TypeResolution(CanonicalModel):
    subject_ref: str
    resolved_type: CanonicalSqlType
    attempted_sources: tuple[str, ...]
    selected_source: str | None
    conflicts: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()


class ColumnPopulationDecision(CanonicalModel):
    column_ref: str
    action: Literal[
        "GENERATE_VALUE",
        "USE_SCENARIO_VALUE",
        "OMIT_USE_DEFAULT",
        "OMIT_GENERATED",
        "SET_NULL",
        "BLOCKED",
    ]
    reason: str
    evidence_refs: tuple[str, ...]


class TemporalPeriodConstraint(CanonicalModel):
    start_column: str
    end_column: str
    invariant: Literal["START_BEFORE_END", "CONTAINS_REFERENCE_TIME", "EXCLUDES_REFERENCE_TIME"]
    reference_time_ref: str | None = None


class TestDataGenerationStatus(StrEnum):
    GENERATED = "GENERATED"
    GENERATED_WITH_WARNINGS = "GENERATED_WITH_WARNINGS"
    BLOCKED = "BLOCKED"


class TestDataGenerationResult(CanonicalModel):
    status: TestDataGenerationStatus
    decisions: tuple[ColumnPopulationDecision, ...] = ()
    requirements: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
