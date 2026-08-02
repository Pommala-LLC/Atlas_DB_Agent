"""Compatibility semantic-policy index.

Canonical policy implementations live under atlas.dialects.<vendor>.semantics.
"""

from atlas.core.models import DialectId
from .base import DialectSemanticPolicy
from .db2 import Db2SemanticPolicy
from .mysql import MySqlSemanticPolicy
from .oracle import OracleSemanticPolicy
from .postgresql import PostgreSqlSemanticPolicy
from .sqlserver import SqlServerSemanticPolicy

POLICIES: dict[DialectId, DialectSemanticPolicy] = {
    DialectId.DB2_SQL_PL: Db2SemanticPolicy(),
    DialectId.ORACLE_PLSQL: OracleSemanticPolicy(),
    DialectId.SQLSERVER_TSQL: SqlServerSemanticPolicy(),
    DialectId.POSTGRESQL_PLPGSQL: PostgreSqlSemanticPolicy(),
    DialectId.MYSQL_STORED_PROGRAM: MySqlSemanticPolicy(),
}

__all__ = [
    "Db2SemanticPolicy", "OracleSemanticPolicy", "SqlServerSemanticPolicy",
    "PostgreSqlSemanticPolicy", "MySqlSemanticPolicy", "POLICIES",
]
