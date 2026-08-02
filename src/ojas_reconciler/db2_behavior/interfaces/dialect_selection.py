from __future__ import annotations

import sys

DB2_VALUES = {"DB2", "DB2_SQL_PL", "DB2-SQL-PL"}


def extract_explicit_e2e_dialect(argv: list[str] | None) -> tuple[list[str] | None, str | None]:
    values = list(sys.argv[1:] if argv is None else argv)
    if "run-end-to-end" not in values:
        return argv, None
    if "--dialect" not in values:
        raise SystemExit("EXPLICIT_DIALECT_REQUIRED: run-end-to-end requires --dialect DB2_SQL_PL")
    index = values.index("--dialect")
    if index + 1 >= len(values):
        raise SystemExit("EXPLICIT_DIALECT_REQUIRED: --dialect requires DB2_SQL_PL")
    dialect = values[index + 1].upper()
    if dialect not in DB2_VALUES:
        raise SystemExit(f"DIALECT_PROVIDER_MISMATCH: run-end-to-end supports DB2_SQL_PL, not {dialect}")
    del values[index:index + 2]
    return values, "DB2_SQL_PL"
