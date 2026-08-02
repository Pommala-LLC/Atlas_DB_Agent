from __future__ import annotations

from typing import Protocol

from ..analysis.models import Phase1SemanticResult
from ..parsing.models import ProcedureParseResult


class Phase1SemanticAnalyzerPort(Protocol):
    def analyze(self, parse_result: ProcedureParseResult) -> Phase1SemanticResult: ...
