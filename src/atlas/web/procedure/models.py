from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from atlas.core.models import DialectId


class ProcedureAnalysisError(RuntimeError):
    """A user-correctable stored-procedure analysis intake error."""


class DatabaseType(StrEnum):
    DB2 = "DB2"
    ORACLE = "ORACLE"
    SQLSERVER = "SQLSERVER"
    POSTGRESQL = "POSTGRESQL"
    MYSQL = "MYSQL"


@dataclass(frozen=True)
class DatabaseDescriptor:
    database_type: DatabaseType
    display_name: str
    dialect: DialectId


@dataclass(frozen=True)
class SourceInput:
    name: str
    text: str
    intake_kind: str


DATABASES = (
    DatabaseDescriptor(DatabaseType.DB2, "IBM Db2", DialectId.DB2_SQL_PL),
    DatabaseDescriptor(DatabaseType.ORACLE, "Oracle Database", DialectId.ORACLE_PLSQL),
    DatabaseDescriptor(DatabaseType.SQLSERVER, "Microsoft SQL Server", DialectId.SQLSERVER_TSQL),
    DatabaseDescriptor(DatabaseType.POSTGRESQL, "PostgreSQL", DialectId.POSTGRESQL_PLPGSQL),
    DatabaseDescriptor(DatabaseType.MYSQL, "MySQL", DialectId.MYSQL_STORED_PROGRAM),
)
DATABASE_BY_TYPE = {item.database_type: item for item in DATABASES}
