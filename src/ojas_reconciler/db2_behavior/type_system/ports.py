"""Ports isolating type resolution from DB2 catalog and DDL adapters."""
from __future__ import annotations

from typing import Protocol

from .models import CanonicalSqlType, DatabaseProfile, RelationDefinition, TypeResolution


class CatalogMetadataProvider(Protocol):
    def provider_ref(self) -> str: ...

    def database_profile(self) -> DatabaseProfile: ...

    def load_relations(
        self,
        *,
        schemas: tuple[str, ...],
        relation_names: tuple[str, ...],
    ) -> tuple[RelationDefinition, ...]: ...


class ExpressionTypeRuleProvider(Protocol):
    def infer(
        self,
        *,
        expression_text: str,
        operand_types: tuple[CanonicalSqlType, ...],
        database_profile: DatabaseProfile,
    ) -> TypeResolution: ...
