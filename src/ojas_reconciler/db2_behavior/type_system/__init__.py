"""Canonical SQL type and metadata-resolution contracts."""

from .models import (
    CanonicalSqlType,
    ColumnDefinition,
    ColumnPopulationDecision,
    DatabasePlatform,
    DatabaseProfile,
    DeclaredSymbolType,
    ForeignKeyDefinition,
    RelationDefinition,
    ResolutionCompleteness,
    SqlDialect,
    SqlTypeFamily,
    TemporalPeriodConstraint,
    TemporalRole,
    TestDataGenerationResult,
    TestDataGenerationStatus,
    TypeResolution,
    TypeResolutionStatus,
)
from .ports import CatalogMetadataProvider, ExpressionTypeRuleProvider
from .resolver import TypeResolutionEngine, parse_declared_sql_type

__all__ = [
    "CanonicalSqlType",
    "CatalogMetadataProvider",
    "ColumnDefinition",
    "ColumnPopulationDecision",
    "DatabasePlatform",
    "DatabaseProfile",
    "DeclaredSymbolType",
    "ExpressionTypeRuleProvider",
    "ForeignKeyDefinition",
    "RelationDefinition",
    "ResolutionCompleteness",
    "SqlDialect",
    "SqlTypeFamily",
    "TemporalPeriodConstraint",
    "TemporalRole",
    "TestDataGenerationResult",
    "TestDataGenerationStatus",
    "TypeResolution",
    "TypeResolutionEngine",
    "TypeResolutionStatus",
    "parse_declared_sql_type",
]
