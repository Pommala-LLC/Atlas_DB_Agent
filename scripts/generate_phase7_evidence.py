from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.governance_models import CertificationEnvelope, PlatformDecisionEnvelope
from ojas_reconciler.db2_behavior.governance_store import GovernanceStore
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
from ojas_reconciler.db2_behavior.runtime_verify import RuntimeVerifier
from ojas_reconciler.db2_behavior.runtime_workflow import RuntimeWorkflowBuilder
from ojas_reconciler.db2_behavior.scenario_models import ScenarioEffect, ScenarioSpec
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

NOW = "2026-07-29T00:00:00.000000Z"
T1 = "2026-07-29T01:00:00.000000Z"
T2 = "2026-07-29T02:00:00.000000Z"


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def main() -> None:
    root = Path(__file__).parents[1]
    output = root / "reports/v0.15"
    output.mkdir(parents=True, exist_ok=True)
    for path in output.glob("*"):
        if path.is_file():
            path.unlink()

    source = root / "tests/fixtures/constraint_contradiction.sql"
    parsed = LarkSqlPlSpikeParser().parse_file(source)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    vocabulary, classification = FixtureAuthorityBuilder().build(scenarios)
    bdd = BddCompiler().compile_all(scenarios, vocabulary, classification)

    _, _, plan_batch = RuntimeWorkflowBuilder().build(parsed, Phase1SemanticAnalyzer())
    plan = plan_batch.plans[0]
    invocation_payload = {
        "invocation_id": "invocation-phase7-demo",
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
        "script_id": "script-phase7-demo",
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
        "observed_effect_refs": tuple(item.scenario_effect_ref for item in plan.expected_observations),
        "row_changes": (),
        "called_routines": (),
        "transaction_events": (),
        "result_set_digests": (),
        "error_message": None,
        "started_at": NOW,
        "ended_at": T1,
    }
    script = RuntimeObservationScript(
        **script_payload,
        content_digest=canonical_digest(script_payload),
    )
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    runtime_batch = RuntimeVerifier().verify_batch(
        plan_batch_digest=plan_batch.content_digest,
        pairs=((plan, execution),),
    )

    database = output / "phase7-governance-demo.sqlite3"
    store = GovernanceStore(database)
    store.initialize(applied_at=NOW)
    scenario_admission = store.admit_scenario_batch(
        scenarios,
        created_at=NOW,
        actor_ref="actor:scenario-compiler",
    )
    bdd_admission = store.admit_bdd_batch(
        bdd,
        created_at=NOW,
        actor_ref="actor:bdd-compiler",
    )
    runtime_admission = store.admit_runtime_batch(
        runtime_batch,
        created_at=T1,
        actor_ref="actor:runtime-verifier",
    )
    spec_record = next(
        item for item in scenario_admission.records if item.artifact_type.value == "SCENARIO_SPEC"
    )
    store.register_baseline(
        artifact_id=spec_record.artifact_id,
        authority_ref="test-authority:baseline-board",
        effective_from=NOW,
        actor_ref="test-authority:baseline-board",
    )
    match = store.compare_to_baseline(
        candidate_artifact_id=spec_record.artifact_id,
        compared_at=T1,
        actor_ref="actor:baseline-comparator",
    )

    original = scenarios.scenario_specs[0]
    changed_effect = ScenarioEffect(
        effect_ref="effect-phase7-conflict",
        modality=original.expected_effects[0].modality,
    )
    amended_payload = original.model_dump(
        mode="python",
        exclude={"scenario_spec_id", "expected_effects", "content_digest"},
    )
    amended_payload["scenario_spec_id"] = original.scenario_spec_id + "-human-amendment"
    amended_payload["expected_effects"] = (changed_effect, *original.expected_effects[1:])
    amended = ScenarioSpec(
        **amended_payload,
        content_digest=canonical_digest(amended_payload),
    )
    amended_record, amendment = store.amend_scenario_spec(
        original_artifact_id=spec_record.artifact_id,
        amended_spec=amended,
        editor_ref="test-reviewer:domain",
        reason="Fixture amendment to exercise baseline conflict governance.",
        amended_at=T1,
    )
    conflict = store.compare_to_baseline(
        candidate_artifact_id=amended_record.artifact_id,
        compared_at=T2,
        actor_ref="actor:baseline-comparator",
    )

    decision_payload = {
        "binding_id": "decision-binding-phase7-demo",
        "artifact_id": amended_record.artifact_id,
        "artifact_digest": amended_record.content_digest,
        "platform_decision_ref": "test-platform-decision:baseline-violation-001",
        "decision_type": "BASELINE_BEHAVIOR_VIOLATION",
        "authority_ref": "test-authority:governance-board",
        "effective_at": T2,
        "evidence_refs": (conflict.comparison_id,),
    }
    decision = PlatformDecisionEnvelope(
        **decision_payload,
        content_digest=canonical_digest(decision_payload),
    )
    store.bind_platform_decision(decision)

    certification_payload = {
        "certification_binding_id": "certification-binding-phase7-demo",
        "artifact_id": spec_record.artifact_id,
        "artifact_digest": spec_record.content_digest,
        "certification_ref": "test-certification:domain-reviewed-001",
        "certification_type": "DOMAIN_REVIEWED",
        "authority_ref": "test-authority:certification-board",
        "valid_from": T1,
        "valid_to": None,
        "evidence_refs": (runtime_batch.verification_results[0].verification_result_id,),
    }
    certification = CertificationEnvelope(
        **certification_payload,
        content_digest=canonical_digest(certification_payload),
    )
    store.bind_certification(certification)

    baseline_history = store.history(spec_record.artifact_id)
    amended_history = store.history(amended_record.artifact_id)
    outputs = {
        "constraint_contradiction.scenarios.json": scenarios,
        "constraint_contradiction.bdd.json": bdd,
        "constraint_contradiction.runtime.json": runtime_batch,
        "scenario-admission.json": {
            "records": scenario_admission.records,
            "idempotent_artifact_ids": scenario_admission.idempotent_artifact_ids,
        },
        "bdd-admission.json": {
            "records": bdd_admission.records,
            "idempotent_artifact_ids": bdd_admission.idempotent_artifact_ids,
        },
        "runtime-admission.json": {
            "records": runtime_admission.records,
            "idempotent_artifact_ids": runtime_admission.idempotent_artifact_ids,
        },
        "baseline-match.json": match,
        "amendment.json": {"artifact": amended_record, "amendment": amendment},
        "baseline-conflict.json": conflict,
        "platform-decision.json": decision,
        "certification.json": certification,
        "baseline-history.json": baseline_history,
        "amended-history.json": amended_history,
    }
    for filename, value in outputs.items():
        write_json(output / filename, value)

    with store.connect() as connection:
        counts = {
            table: connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
            for table in (
                "governance_artifacts",
                "governance_baselines",
                "governance_comparisons",
                "governance_amendments",
                "governance_platform_decisions",
                "governance_certifications",
                "governance_audit_events",
            )
        }
    summary = f"""# Measured Phase 7 Governance Results

## Stored records

```text
Governance artifacts: {counts['governance_artifacts']}
Baseline registrations: {counts['governance_baselines']}
Baseline comparisons: {counts['governance_comparisons']}
Amendments: {counts['governance_amendments']}
Platform decisions: {counts['governance_platform_decisions']}
Certifications: {counts['governance_certifications']}
Audit events: {counts['governance_audit_events']}
```

## Baseline results

```text
Original candidate vs baseline: {match.status.value}
Human-amended candidate vs baseline: {conflict.status.value}
Conflict classification candidate: {conflict.classification_candidate}
```

The conflict is not automatically promoted. A separate external decision envelope binds `BASELINE_BEHAVIOR_VIOLATION` to the amended artifact digest.

## Identity propagation

CandidateBDD and runtime verification artifacts inherit `behavior_id`, `source_symbol_id`, and `symbol_lineage_id` from their admitted ScenarioSpec references.

## Amendment law

The amended artifact preserves the identity spine, references the original artifact, and records `invalidates_machine_attestation = true`.

## Audit

```text
Baseline artifact audit chain valid: {baseline_history.audit_chain_valid}
Amended artifact audit chain valid: {amended_history.audit_chain_valid}
```

All authority references in this report are `test-*` fixture references. They are not platform approvals.
"""
    (output / "MEASURED_PHASE7_RESULTS.md").write_text(summary, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
