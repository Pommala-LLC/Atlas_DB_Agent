"""Compatibility profile index.

Canonical profile ownership lives under atlas.dialects.<vendor>.profile.
"""

from .db2 import DB2
from .mysql import MYSQL
from .oracle import ORACLE
from .postgresql import POSTGRESQL
from .sqlserver import SQLSERVER

ALL_PROFILES = (DB2, ORACLE, SQLSERVER, POSTGRESQL, MYSQL)

__all__ = ["DB2", "ORACLE", "SQLSERVER", "POSTGRESQL", "MYSQL", "ALL_PROFILES"]
