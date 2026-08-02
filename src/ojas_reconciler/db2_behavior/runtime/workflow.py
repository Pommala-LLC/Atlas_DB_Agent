from __future__ import annotations

from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.parsing.models import ProcedureParseResult
from ojas_reconciler.db2_behavior.runtime.plan import RuntimeVerificationPlanner
from ojas_reconciler.db2_behavior.runtime.safety import RuntimeSafetyAssessor
from ojas_reconciler.db2_behavior.runtime.models import RuntimeVerificationPlanBatch
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpecBatchResult
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.analysis.models import Phase1SemanticResult


class RuntimeWorkflowBuilder:
    def build(
        self,
        parse_result: ProcedureParseResult,
        semantic_analyzer: Phase1SemanticAnalyzer,
    ) -> tuple[Phase1SemanticResult, ScenarioSpecBatchResult, RuntimeVerificationPlanBatch]:
        semantic_result = semantic_analyzer.analyze(parse_result)
        scenario_batch = ScenarioSpecCompiler().compile_all(parse_result, semantic_result)
        procedure_identity_ref = scenario_batch.procedure_identity_ref
        safety = RuntimeSafetyAssessor().assess(parse_result, semantic_result, procedure_identity_ref)
        plan_batch = RuntimeVerificationPlanner().plan_all(
            parse_result=parse_result,
            semantic_result=semantic_result,
            scenario_batch=scenario_batch,
            safety=safety,
        )
        return semantic_result, scenario_batch, plan_batch
