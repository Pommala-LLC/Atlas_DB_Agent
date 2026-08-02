from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from ..base import ProceduralDialectProfile
from ..classifier import _classify
from ..scanner import _Statement


class OracleStatementClassifier:
    dialect = DialectId.ORACLE_PLSQL

    def classify(
        self,
        statement: _Statement,
        profile: ProceduralDialectProfile,
        in_declare_section: bool,
    ) -> tuple[SemanticNodeKind, dict[str, object]]:
        text = statement.text.strip()
        upper = re.sub(r"\s+", " ", text.upper()).strip().rstrip(";")
        if upper == "NULL":
            return SemanticNodeKind.BLOCK, {"boundary": "NULL_STATEMENT", "no_op": True}
        if upper.startswith("OPEN ") and " FOR " in f" {upper} ":
            match = re.match(r"(?is)^\s*OPEN\s+([A-Z_$#][A-Z0-9_$#]*)", text)
            return SemanticNodeKind.RESULT_SET, {
                "cursor_name": match.group(1).upper() if match else None,
                "dynamic": "EXECUTE" in upper or "'" in text,
                "oracle_statement": "OPEN_FOR",
            }
        kind, attrs = _classify(statement, profile, in_declare_section)
        if kind is SemanticNodeKind.CALL and attrs.get("call_target"):
            attrs = {**attrs, "invocation_style": "PLSQL_OR_CALL_STATEMENT"}
        return kind, attrs
