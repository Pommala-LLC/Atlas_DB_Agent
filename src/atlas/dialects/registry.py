from __future__ import annotations

from atlas.core.models import DialectId
from .base import DialectAdapter, DialectAdapterError
from .db2 import Db2SqlPlAdapter
from .mysql import MySqlStoredProgramAdapter
from .oracle import OraclePlSqlAdapter
from .postgresql import PostgreSqlPlPgSqlAdapter
from .sqlserver import SqlServerTSqlAdapter


class AtlasDialectRegistry:
    """Replaceable dialect adapter registry with no parser-specific application coupling."""

    def __init__(self, atlas_version: str) -> None:
        self.atlas_version = atlas_version
        self._adapters: dict[DialectId, DialectAdapter] = {}

    def register(self, adapter: DialectAdapter) -> None:
        if adapter.dialect in self._adapters:
            raise DialectAdapterError(f"Duplicate adapter for {adapter.dialect.value}")
        self._adapters[adapter.dialect] = adapter

    def adapter(self, dialect: DialectId) -> DialectAdapter:
        try:
            return self._adapters[dialect]
        except KeyError as exc:
            raise DialectAdapterError(f"No Atlas adapter for {dialect.value}") from exc

    def dialects(self) -> tuple[DialectId, ...]:
        return tuple(sorted(self._adapters, key=lambda value: value.value))

    @classmethod
    def default(cls, atlas_version: str) -> "AtlasDialectRegistry":
        registry = cls(atlas_version)
        for adapter in (
            Db2SqlPlAdapter(atlas_version),
            OraclePlSqlAdapter(atlas_version),
            SqlServerTSqlAdapter(atlas_version),
            PostgreSqlPlPgSqlAdapter(atlas_version),
            MySqlStoredProgramAdapter(atlas_version),
        ):
            registry.register(adapter)
        return registry
