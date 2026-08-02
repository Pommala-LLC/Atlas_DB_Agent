from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from ..base import ProceduralDialectProfile
from ..classifier import _classify
from ..scanner import _Statement


class SqlServerStatementClassifier:
    dialect = DialectId.SQLSERVER_TSQL

    def classify(self, statement: _Statement, profile: ProceduralDialectProfile, in_declare_section: bool) -> tuple[SemanticNodeKind, dict[str, object]]:
        text = statement.text.strip()
        upper = re.sub(r"\s+", " ", text.upper()).strip().rstrip(";")
        if re.match(r"(?is)^\s*DECLARE\s+@[A-Z0-9_$#]+\s+TABLE\b", text):
            return SemanticNodeKind.TEMP_OBJECT, {"table_variable": True, "scope": "BATCH"}
        if upper.startswith(("CREATE TABLE #", "CREATE TABLE ##")):
            return SemanticNodeKind.TEMP_OBJECT, {"table_variable": False}
        if upper.startswith(("SET ANSI_", "SET ARITHABORT", "SET DEADLOCK_PRIORITY", "SET LOCK_TIMEOUT")):
            return SemanticNodeKind.TRANSACTION_SETTING, {"setting_text": text.rstrip(";")}
        if upper.startswith("USE "):
            return SemanticNodeKind.SECURITY_CONTEXT, {"context_change": "DATABASE"}
        kind, attrs = _classify(statement, profile, in_declare_section)
        if kind is SemanticNodeKind.DYNAMIC_SQL:
            attrs = {**attrs, "execution_api": "SP_EXECUTESQL" if "SP_EXECUTESQL" in upper else "EXECUTE"}
        return kind, attrs
