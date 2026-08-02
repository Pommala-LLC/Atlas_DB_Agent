from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from ..base import ProceduralDialectProfile
from ..classifier import _classify
from ..scanner import _Statement


class Db2StatementClassifier:
    dialect = DialectId.DB2_SQL_PL

    def classify(
        self,
        statement: _Statement,
        profile: ProceduralDialectProfile,
        in_declare_section: bool,
    ) -> tuple[SemanticNodeKind, dict[str, object]]:
        text = statement.text.strip()
        upper = re.sub(r"\s+", " ", text.upper()).strip()
        if re.match(r"(?is)^\s*VALUES\s+.+?\s+INTO\s+", text):
            return SemanticNodeKind.SELECT_INTO, {"db2_statement": "VALUES_INTO"}
        if upper.startswith("ALLOCATE CURSOR"):
            match = re.match(r"(?is)^\s*ALLOCATE\s+CURSOR\s+([A-Z_$#][A-Z0-9_$#]*)", text)
            return SemanticNodeKind.CURSOR_DECLARE, {
                "cursor_name": match.group(1).upper() if match else None,
                "db2_statement": "ALLOCATE_CURSOR",
            }
        if upper.startswith("ASSOCIATE RESULT SET LOCATORS"):
            return SemanticNodeKind.RESULT_SET, {"db2_statement": "ASSOCIATE_RESULT_SET_LOCATORS"}
        if upper.startswith("SET CURRENT "):
            return SemanticNodeKind.SECURITY_CONTEXT, {"db2_statement": "SET_CURRENT_SPECIAL_REGISTER"}
        kind, attrs = _classify(statement, profile, in_declare_section)
        if kind is SemanticNodeKind.ERROR_HANDLER and " HANDLER " in f" {upper} ":
            action = next((value for value in ("CONTINUE", "EXIT", "UNDO") if f"DECLARE {value} HANDLER" in upper), None)
            attrs = {**attrs, "handler_action": action or "UNKNOWN"}
        return kind, attrs
