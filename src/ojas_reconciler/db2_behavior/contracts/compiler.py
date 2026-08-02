"""Compiler ports consumed by application orchestration."""
from __future__ import annotations

from typing import Protocol

from ..analysis.models import Phase1SemanticResult
from ..bdd.models import BddCompilationBatch, ClassificationSnapshot, VocabularySnapshot
from ..bdd.scenario_models import ScenarioSpecBatchResult
from ..parsing.models import ProcedureParseResult


class ScenarioSpecCompilerPort(Protocol):
    def compile_all(
        self,
        parse_result: ProcedureParseResult,
        semantic_result: Phase1SemanticResult,
    ) -> ScenarioSpecBatchResult: ...


class BddCompilerPort(Protocol):
    def compile_all(
        self,
        scenario_batch: ScenarioSpecBatchResult,
        vocabulary: VocabularySnapshot,
        classification: ClassificationSnapshot,
    ) -> BddCompilationBatch: ...
