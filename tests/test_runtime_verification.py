from __future__ import annotations

from pathlib import Path

import pytest

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.runtime_executor import (
    IbmDbSandboxExecutor,
    RuntimeExecutionError,
    ScriptedRuntimeExecutor,
)
from ojas_reconciler.db2_behavior.runtime_models import (
    Db2SandboxConfig,
    LiveVerificationEligibility,
    RuntimeExecutionStatus,
    RuntimeInvocation,
    RuntimeInvocationParameter,
    RuntimeObservedParameter,
    RuntimeObservationScript,
    RuntimePlanStatus,
    RuntimeValue,
    RuntimeValueKind,
    RuntimeVerificationFindingCode,
    RuntimeVerificationStatus,
)
from ojas_reconciler.db2_behavior.runtime_plan import RuntimeVerificationPlanner
from ojas_reconciler.db2_behavior.runtime_safety import RuntimeSafetyAssessor
from ojas_reconciler.db2_behavior.runtime_verify import RuntimeVerifier
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


def build_runtime(name: str):
    parse_result = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    semantic = Phase1SemanticAnalyzer().analyze(parse_result)
    scenarios = ScenarioSpecCompiler().compile_all(parse_result, semantic)
    safety = RuntimeSafetyAssessor().assess(parse_result, semantic, scenarios.procedure_identity_ref)
    plans = RuntimeVerificationPlanner().plan_all(
        parse_result=parse_result,
        semantic_result=semantic,
        scenario_batch=scenarios,
        safety=safety,
    )
    return parse_result, semantic, scenarios, safety, plans


def invocation() -> RuntimeInvocation:
    payload = {
        "invocation_id": "invocation-constraint-001",
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
    return RuntimeInvocation(**payload, content_digest=canonical_digest(payload))


def observation_script(plan, value: str = "POSSIBLE") -> RuntimeObservationScript:
    inv = invocation()
    payload = {
        "schema_version": "runtime-observation-script-1.0",
        "script_id": "script-constraint-001-" + value.lower(),
        "plan_ref": plan.plan_id,
        "plan_digest": plan.content_digest,
        "invocation": inv,
        "execution_status": RuntimeExecutionStatus.SUCCEEDED,
        "output_parameters": (
            RuntimeObservedParameter(
                parameter_name="P_RESULT",
                value=RuntimeValue(value_kind=RuntimeValueKind.STRING, canonical_value=value),
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
    return RuntimeObservationScript(**payload, content_digest=canonical_digest(payload))


def test_runtime_safety_blocks_internal_commit() -> None:
    _, _, _, safety, plans = build_runtime("settle_customer_claims.sql")
    assert safety.live_eligibility == LiveVerificationEligibility.PROHIBITED
    assert "INTERNAL_COMMIT_PRESENT" in safety.reason_codes
    assert all(plan.plan_status == RuntimePlanStatus.READY_SCRIPTED for plan in plans.plans)


def test_runtime_safety_requires_approval_for_unresolved_dynamic_boundaries() -> None:
    _, _, _, safety, plans = build_runtime("process_claim_batch.sql")
    assert safety.live_eligibility == LiveVerificationEligibility.MANUAL_APPROVAL_REQUIRED
    assert "UNRESOLVED_DYNAMIC_SQL_BOUNDARY" in safety.reason_codes
    assert all(plan.plan_status == RuntimePlanStatus.MANUAL_APPROVAL_REQUIRED for plan in plans.plans)


def test_scripted_runtime_match() -> None:
    _, _, _, safety, plans = build_runtime("constraint_contradiction.sql")
    assert safety.live_eligibility == LiveVerificationEligibility.DB2_SANDBOX_ALLOWED
    plan = plans.plans[0]
    script = observation_script(plan)
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    result = RuntimeVerifier().verify(plan=plan, execution=execution)
    assert result.verification_status == RuntimeVerificationStatus.MATCHED
    assert not result.static_runtime_conflict


def test_scripted_runtime_mismatch_is_static_runtime_conflict() -> None:
    _, _, _, _, plans = build_runtime("constraint_contradiction.sql")
    plan = plans.plans[0]
    script = observation_script(plan, value="WRONG")
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    result = RuntimeVerifier().verify(plan=plan, execution=execution)
    assert result.verification_status == RuntimeVerificationStatus.MISMATCH
    assert result.static_runtime_conflict
    codes = {finding.code for finding in result.findings}
    assert RuntimeVerificationFindingCode.OUT_PARAMETER_VALUE_MISMATCH in codes
    assert RuntimeVerificationFindingCode.STATIC_RUNTIME_EVIDENCE_CONFLICT in codes


def test_script_digest_tamper_is_rejected() -> None:
    _, _, _, _, plans = build_runtime("constraint_contradiction.sql")
    plan = plans.plans[0]
    script = observation_script(plan).model_copy(update={"content_digest": "sha256:bad"})
    with pytest.raises(RuntimeExecutionError, match="digest"):
        ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)


def test_live_db2_executor_refuses_without_execute_live() -> None:
    _, _, _, safety, plans = build_runtime("constraint_contradiction.sql")
    plan = plans.plans[0]
    config = Db2SandboxConfig(
        connection_ref="sandbox-connection",
        sandbox_attestation="attestation-001",
        execute_live=False,
    )
    with pytest.raises(RuntimeExecutionError, match="execute_live"):
        IbmDbSandboxExecutor().execute_db2(
            plan=plan,
            invocation=invocation(),
            config=config,
            live_eligibility=safety.live_eligibility,
        )


def test_live_db2_executor_refuses_prohibited_plan_before_import() -> None:
    _, _, _, safety, plans = build_runtime("settle_customer_claims.sql")
    plan = plans.plans[0]
    config = Db2SandboxConfig(
        connection_ref="sandbox-connection",
        sandbox_attestation="attestation-001",
        execute_live=True,
    )
    with pytest.raises(RuntimeExecutionError, match="prohibited"):
        IbmDbSandboxExecutor().execute_db2(
            plan=plan,
            invocation=invocation(),
            config=config,
            live_eligibility=safety.live_eligibility,
        )


def test_scripted_runtime_rejects_invalid_invocation_digest() -> None:
    _, _, _, _, plans = build_runtime("constraint_contradiction.sql")
    plan = plans.plans[0]
    script = observation_script(plan)
    bad_invocation = script.invocation.model_copy(update={"content_digest": "sha256:bad"})
    payload = script.model_dump(exclude={"content_digest"})
    payload["invocation"] = bad_invocation
    bad_script = RuntimeObservationScript(**payload, content_digest=canonical_digest(payload))
    with pytest.raises(RuntimeExecutionError, match="invocation digest"):
        ScriptedRuntimeExecutor().execute_script(plan=plan, script=bad_script)


def test_scripted_runtime_rejects_missing_required_input() -> None:
    _, _, _, _, plans = build_runtime("constraint_contradiction.sql")
    plan = plans.plans[0]
    original = observation_script(plan)
    missing_payload = {
        "invocation_id": "invocation-missing-input",
        "procedure_schema": "CLAIMS",
        "procedure_name": "CONSTRAINT_CONTRADICTION",
        "parameters": (
            RuntimeInvocationParameter(
                parameter_name="P_RESULT",
                parameter_mode="OUT",
                type_text="VARCHAR(20)",
                value=RuntimeValue(value_kind=RuntimeValueKind.NULL),
            ),
        ),
    }
    missing_invocation = RuntimeInvocation(
        **missing_payload,
        content_digest=canonical_digest(missing_payload),
    )
    script_payload = original.model_dump(exclude={"content_digest"})
    script_payload["invocation"] = missing_invocation
    script = RuntimeObservationScript(
        **script_payload,
        content_digest=canonical_digest(script_payload),
    )
    with pytest.raises(RuntimeExecutionError, match="Missing required runtime inputs"):
        ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)


def test_no_rollback_is_prohibited_without_safe_executor_owned_containment() -> None:
    _, _, _, safety, plans = build_runtime("process_claim_batch.sql")
    plan = plans.plans[0]
    config = Db2SandboxConfig(
        connection_ref="sandbox-connection",
        sandbox_attestation="attestation-001",
        manual_approval_ref="approval-001",
        rollback_after_call=False,
        execute_live=True,
    )
    with pytest.raises(RuntimeExecutionError, match="NO_ROLLBACK_PROHIBITED"):
        IbmDbSandboxExecutor().execute_db2(
            plan=plan,
            invocation=invocation(),
            config=config,
            safety_assessment=safety,
        )


def test_public_cli_does_not_expose_no_rollback() -> None:
    from ojas_reconciler.db2_behavior.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "verify-runtime-db2",
            str(FIXTURES / "constraint_contradiction.sql"),
            "--plan-id", "plan",
            "--invocation", "invocation.json",
            "--no-rollback",
        ])
