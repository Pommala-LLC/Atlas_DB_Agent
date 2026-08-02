from __future__ import annotations

import re
from pathlib import Path

from atlas.core.canonical import canonical_json_bytes
from atlas.core.models import DialectId

ALIASES = {
    "DB2": DialectId.DB2_SQL_PL, "ORACLE": DialectId.ORACLE_PLSQL,
    "PLSQL": DialectId.ORACLE_PLSQL, "SQLSERVER": DialectId.SQLSERVER_TSQL,
    "TSQL": DialectId.SQLSERVER_TSQL, "POSTGRES": DialectId.POSTGRESQL_PLPGSQL,
    "POSTGRESQL": DialectId.POSTGRESQL_PLPGSQL, "PLPGSQL": DialectId.POSTGRESQL_PLPGSQL,
    "MYSQL": DialectId.MYSQL_STORED_PROGRAM,
}


def dialect(value: str) -> DialectId:
    normalized = value.upper().replace("-", "_")
    return ALIASES[normalized] if normalized in ALIASES else DialectId(normalized)


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_bytes(canonical_json_bytes(value) + b"\n")


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "routine"
