from __future__ import annotations

from enum import StrEnum
from pydantic import model_validator

from ..core.models import CanonicalModel


class DialectId(StrEnum):
    DB2_SQL_PL = "DB2_SQL_PL"
    ORACLE_PLSQL = "ORACLE_PLSQL"
    SQLSERVER_TSQL = "SQLSERVER_TSQL"
    POSTGRESQL_PLPGSQL = "POSTGRESQL_PLPGSQL"
    MYSQL_STORED_PROGRAM = "MYSQL_STORED_PROGRAM"


class DialectCapability(StrEnum):
    FULL_SEMANTIC_PIPELINE = "FULL_SEMANTIC_PIPELINE"
    HEADER_AND_INVENTORY = "HEADER_AND_INVENTORY"
    NORMALIZED_IR_IMPORT = "NORMALIZED_IR_IMPORT"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class RoutineParameter(CanonicalModel):
    name: str
    mode: str
    type_text: str


class RoutineInventory(CanonicalModel):
    schema_version: str = "routine-inventory-1.0"
    dialect: DialectId
    schema_name: str | None = None
    routine_name: str
    routine_kind: str
    parameters: tuple[RoutineParameter, ...]
    source_digest: str
    body_status: str
    body_text: str | None = None
    blockers: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    content_digest: str


class DialectAdapterDescriptor(CanonicalModel):
    adapter_id: str
    dialect: DialectId
    version: str
    capability: DialectCapability
    supported_constructs: tuple[str, ...]
    limitations: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()


class DialectRegistrySnapshot(CanonicalModel):
    schema_version: str = "dialect-registry-snapshot-1.0"
    adapters: tuple[DialectAdapterDescriptor, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_unique_dialects(self) -> "DialectRegistrySnapshot":
        values = [item.dialect for item in self.adapters]
        if len(values) != len(set(values)):
            raise ValueError("Dialect registry requires one active adapter per dialect.")
        return self
