from __future__ import annotations

import re

from atlas.core.models import DialectId, SemanticNodeKind
from ..base import ProceduralDialectProfile
from ..classifier import _classify
from ..scanner import _Statement


class MySqlStatementClassifier:
    dialect = DialectId.MYSQL_STORED_PROGRAM

    def classify(self, statement: _Statement, profile: ProceduralDialectProfile, in_declare_section: bool) -> tuple[SemanticNodeKind, dict[str, object]]:
        text = statement.text.strip()
        upper = re.sub(r"\s+", " ", text.upper()).strip().rstrip(";")
        if upper.startswith("DO "):
            return SemanticNodeKind.QUERY, {"discarded_result": True, "mysql_statement": "DO"}
        if upper.startswith("GET CURRENT DIAGNOSTICS"):
            return SemanticNodeKind.DIAGNOSTICS, {"diagnostics_area": "CURRENT"}
        if upper.startswith("GET STACKED DIAGNOSTICS"):
            return SemanticNodeKind.DIAGNOSTICS, {"diagnostics_area": "STACKED"}
        kind, attrs = _classify(statement, profile, in_declare_section)
        if kind is SemanticNodeKind.UPSERT:
            attrs = {**attrs, "upsert_form": "ON_DUPLICATE_KEY_UPDATE"}
        return kind, attrs
