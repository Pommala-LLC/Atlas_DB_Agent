from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.runtime_executor import ScriptedRuntimeExecutor
from ojas_reconciler.db2_behavior.runtime_models import (
    RuntimeExecutionStatus,
    RuntimeInvocation,
    RuntimeInvocationParameter,
    RuntimeObservedParameter,
    RuntimeObservationScript,
    RuntimeValue,
    RuntimeValueKind,
)
from ojas_reconciler.db2_behavior.runtime_plan import RuntimeVerificationPlanner
from ojas_reconciler.db2_behavior.runtime_safety import RuntimeSafetyAssessor
from ojas_reconciler.db2_behavior.runtime_verify import RuntimeVerifier
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "constraint_contradiction.sql"


def load_schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def runtime_artifacts():
    parse_result = LarkSqlPlSpikeParser().parse_file(FIXTURE)
    semantic = Phase1SemanticAnalyzer().analyze(parse_result)
    scenarios = ScenarioSpecCompiler().compile_all(parse_result, semantic)
    safety = RuntimeSafetyAssessor().assess(parse_result, semantic, scenarios.procedure_identity_ref)
    plans = RuntimeVerificationPlanner().plan_all(
        parse_result=parse_result,
        semantic_result=semantic,
        scenario_batch=scenarios,
        safety=safety,
    )
    plan = plans.plans[0]
    invocation_payload = {
        "invocation_id": "invocation-schema-001",
        "procedure_schema": "CLAIMS",
        "procedure_name": "CONSTRAINT_CONTRADICTION",
        "parameters": (
            RuntimeInvocationParameter(
                parameter_name="P_VALUE",
                parameter_mode="IN",
                type_text="DECIMAL(10,2)",
                value=RuntimeValue(value_kind=RuntimeValueKind.DECIMAL, canonical_value="1.00"),
            ),
            RuntimeInvocationParameter(
                parameter_name="P_RESULT",
                parameter_mode="OUT",
                type_text="VARCHAR(20)",
                value=RuntimeValue(value_kind=RuntimeValueKind.NULL),
            ),
        ),
    }
    invocation = RuntimeInvocation(
        **invocation_payload,
        content_digest=canonical_digest(invocation_payload),
    )
    script_payload = {
        "schema_version": "runtime-observation-script-1.0",
        "script_id": "runtime-script-schema-001",
        "plan_ref": plan.plan_id,
        "plan_digest": plan.content_digest,
        "invocation": invocation,
        "execution_status": RuntimeExecutionStatus.SUCCEEDED,
        "output_parameters": (
            RuntimeObservedParameter(
                parameter_name="P_RESULT",
                value=RuntimeValue(value_kind=RuntimeValueKind.STRING, canonical_value="POSSIBLE"),
            ),
        ),
        "sqlstate": None,
        "observed_effect_refs": tuple(value.scenario_effect_ref for value in plan.expected_observations),
        "row_changes": (),
        "called_routines": (),
        "transaction_events": (),
        "result_set_digests": (),
        "error_message": None,
        "started_at": "2026-07-28T22:00:00.000000Z",
        "ended_at": "2026-07-28T22:00:01.000000Z",
    }
    script = RuntimeObservationScript(**script_payload, content_digest=canonical_digest(script_payload))
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    verification = RuntimeVerifier().verify_batch(
        plan_batch_digest=plans.content_digest,
        pairs=((plan, execution),),
    )
    return plans, script, verification


def test_runtime_contract_schemas() -> None:
    plans, script, verification = runtime_artifacts()
    cases = (
        ("runtime-verification-plan-batch-1.0.schema.json", plans.model_dump(mode="json")),
        ("runtime-observation-script-1.0.schema.json", script.model_dump(mode="json")),
        ("runtime-verification-batch-1.0.schema.json", verification.model_dump(mode="json")),
    )
    for schema_name, payload in cases:
        validator = Draft202012Validator(load_schema(schema_name))
        assert not list(validator.iter_errors(payload)), schema_name
