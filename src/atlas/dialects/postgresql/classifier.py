from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from ..base import ProceduralDialectProfile
from ..classifier import _classify
from ..scanner import _Statement


class PostgreSqlStatementClassifier:
    dialect = DialectId.POSTGRESQL_PLPGSQL

    def classify(self, statement: _Statement, profile: ProceduralDialectProfile, in_declare_section: bool) -> tuple[SemanticNodeKind, dict[str, object]]:
        text = statement.text.strip()
        upper = re.sub(r"\s+", " ", text.upper()).strip().rstrip(";")
        if upper == "NULL":
            return SemanticNodeKind.BLOCK, {"boundary": "NULL_STATEMENT", "no_op": True}
        if upper.startswith("RETURN QUERY EXECUTE"):
            return SemanticNodeKind.DYNAMIC_SQL, {"returns_rows": True, "postgres_statement": "RETURN_QUERY_EXECUTE"}
        if upper.startswith("OPEN ") and " FOR EXECUTE " in f" {upper} ":
            match = re.match(r"(?is)^\s*OPEN\s+([A-Z_$][A-Z0-9_$]*)", text)
            return SemanticNodeKind.DYNAMIC_SQL, {"cursor_name": match.group(1).upper() if match else None, "opens_refcursor": True}
        kind, attrs = _classify(statement, profile, in_declare_section)
        if kind is SemanticNodeKind.QUERY and upper.startswith("PERFORM"):
            attrs = {**attrs, "discarded_result": True}
        return kind, attrs
