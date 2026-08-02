from __future__ import annotations

from pathlib import Path
import json

import pytest

from ojas_reconciler.db2_behavior.bdd_models import BddCompilationBatch
from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.governance_models import (
    BaselineComparisonStatus,
    CertificationEnvelope,
    PlatformDecisionEnvelope,
)
from ojas_reconciler.db2_behavior.governance_store import GovernanceStore, GovernanceStoreError
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

FIXTURES = Path(__file__).parent / "fixtures"
NOW = "2026-07-29T00:00:00.000000Z"
LATER = "2026-07-29T01:00:00.000000Z"


def build_scenarios(name: str = "constraint_contradiction.sql"):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    return parsed, semantic, scenarios


def build_store(tmp_path: Path) -> GovernanceStore:
    store = GovernanceStore(tmp_path / "governance.sqlite3")
    store.initialize(applied_at=NOW)
    return store


def first_spec_artifact(store: GovernanceStore, admission) -> str:
    for record in admission.records:
        if record.artifact_type.value == "SCENARIO_SPEC":
            return record.artifact_id
    raise AssertionError("No ScenarioSpec artifact admitted")


def test_schema_migration_and_identity_guard(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    store.assert_schema_guard()
    with store.session() as connection:
        rows = connection.execute("SELECT migration_id FROM governance_schema_migrations").fetchall()
    assert [row["migration_id"] for row in rows] == ["0001_initial", "0002_local_non_authoritative_scope"]


def test_scenario_admission_is_idempotent_and_digest_guarded(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    _, _, batch = build_scenarios()
    first = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    second = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    assert first.records
    assert set(second.idempotent_artifact_ids) == {record.artifact_id for record in second.records}
    tampered = batch.model_copy(update={"content_digest": "sha256:bad"})
    with pytest.raises(GovernanceStoreError, match="Invalid content digest"):
        store.admit_scenario_batch(tampered, created_at=NOW, actor_ref="actor:extractor")


def test_baseline_match_and_conflict_candidate(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    _, _, batch = build_scenarios()
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    artifact_id = first_spec_artifact(store, admission)
    store.register_baseline(
        artifact_id=artifact_id,
        authority_ref="authority:baseline-board",
        effective_from=NOW,
        actor_ref="authority:baseline-board",
    )
    match = store.compare_to_baseline(
        candidate_artifact_id=artifact_id,
        compared_at=LATER,
        actor_ref="actor:comparator",
    )
    assert match.status == BaselineComparisonStatus.MATCH

    _, payload = store.get_artifact(artifact_id)
    original = ScenarioSpec.model_validate_json(json.dumps(payload))
    changed_effect = ScenarioEffect(effect_ref="effect-conflict", modality=original.expected_effects[0].modality)
    amended_payload = original.model_dump(
        mode="python",
        exclude={"scenario_spec_id", "expected_effects", "content_digest"},
    )
    amended_payload["scenario_spec_id"] = original.scenario_spec_id + "-human-amendment"
    amended_payload["expected_effects"] = (changed_effect, *original.expected_effects[1:])
    amended = ScenarioSpec(**amended_payload, content_digest=canonical_digest(amended_payload))
    amended_record, amendment = store.amend_scenario_spec(
        original_artifact_id=artifact_id,
        amended_spec=amended,
        editor_ref="reviewer:domain",
        reason="Correct expected effect",
        amended_at=LATER,
    )
    assert amendment.invalidates_machine_attestation
    assert amended_record.invalidates_machine_attestation
    conflict = store.compare_to_baseline(
        candidate_artifact_id=amended_record.artifact_id,
        compared_at="2026-07-29T02:00:00.000000Z",
        actor_ref="actor:comparator",
    )
    assert conflict.status == BaselineComparisonStatus.CONFLICT
    assert conflict.classification_candidate == "BASELINE_BEHAVIOR_VIOLATION_CANDIDATE"


def test_amendment_cannot_change_identity_spine(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    _, _, batch = build_scenarios()
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    artifact_id = first_spec_artifact(store, admission)
    _, payload = store.get_artifact(artifact_id)
    original = ScenarioSpec.model_validate_json(json.dumps(payload))
    changed = original.model_copy(update={"behavior_id": "behavior-other", "content_digest": "sha256:bad"})
    with pytest.raises(GovernanceStoreError, match="behavior_id"):
        store.amend_scenario_spec(
            original_artifact_id=artifact_id,
            amended_spec=changed,
            editor_ref="reviewer:domain",
            reason="invalid identity change",
            amended_at=LATER,
        )


def test_platform_decision_certification_and_audit_chain(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    _, _, batch = build_scenarios()
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    artifact_id = first_spec_artifact(store, admission)
    record, _ = store.get_artifact(artifact_id)

    decision_payload = {
        "binding_id": "decision-binding-001",
        "artifact_id": artifact_id,
        "artifact_digest": record.content_digest,
        "platform_decision_ref": "platform-decision-001",
        "decision_type": "APPROVED_CANDIDATE",
        "authority_ref": "authority:governance-board",
        "effective_at": LATER,
        "evidence_refs": (),
    }
    decision = PlatformDecisionEnvelope(
        **decision_payload,
        content_digest=canonical_digest(decision_payload),
    )
    store.bind_platform_decision(decision)

    cert_payload = {
        "certification_binding_id": "cert-binding-001",
        "artifact_id": artifact_id,
        "artifact_digest": record.content_digest,
        "certification_ref": "certification-001",
        "certification_type": "DOMAIN_REVIEWED",
        "authority_ref": "authority:certifier",
        "valid_from": LATER,
        "valid_to": None,
        "evidence_refs": (),
    }
    certification = CertificationEnvelope(
        **cert_payload,
        content_digest=canonical_digest(cert_payload),
    )
    store.bind_certification(certification)
    history = store.history(artifact_id)
    assert history.platform_decisions == (decision,)
    assert history.certifications == (certification,)
    assert history.audit_chain_valid


def test_governance_rejects_decision_digest_mismatch(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    _, _, batch = build_scenarios()
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    artifact_id = first_spec_artifact(store, admission)
    payload = {
        "binding_id": "decision-binding-bad",
        "artifact_id": artifact_id,
        "artifact_digest": "sha256:bad",
        "platform_decision_ref": "platform-decision-bad",
        "decision_type": "APPROVED_CANDIDATE",
        "authority_ref": "authority:governance-board",
        "effective_at": LATER,
        "evidence_refs": (),
    }
    envelope = PlatformDecisionEnvelope(**payload, content_digest=canonical_digest(payload))
    with pytest.raises(GovernanceStoreError, match="artifact digest mismatch"):
        store.bind_platform_decision(envelope)


def test_bdd_and_runtime_batches_are_persisted(tmp_path: Path) -> None:
    store = build_store(tmp_path)
    parsed, semantic, scenarios = build_scenarios()
    store.admit_scenario_batch(scenarios, created_at=NOW, actor_ref="actor:scenario-compiler")
    vocabulary, classification = FixtureAuthorityBuilder().build(scenarios)
    bdd = BddCompiler().compile_all(scenarios, vocabulary, classification)
    assert isinstance(bdd, BddCompilationBatch)
    bdd_admission = store.admit_bdd_batch(bdd, created_at=NOW, actor_ref="actor:bdd-compiler")
    candidate_records = [record for record in bdd_admission.records if record.artifact_type.value == "CANDIDATE_BDD"]
    assert candidate_records
    assert all(record.behavior_id and record.source_symbol_id and record.symbol_lineage_id for record in candidate_records)

    _, scenario_batch, plan_batch = RuntimeWorkflowBuilder().build(parsed, Phase1SemanticAnalyzer())
    plan = plan_batch.plans[0]
    invocation_payload = {
        "invocation_id": "invocation-governance-001",
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
    invocation = RuntimeInvocation(**invocation_payload, content_digest=canonical_digest(invocation_payload))
    script_payload = {
        "schema_version": "runtime-observation-script-1.0",
        "script_id": "script-governance-001",
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
        "ended_at": LATER,
    }
    script = RuntimeObservationScript(**script_payload, content_digest=canonical_digest(script_payload))
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    runtime_batch = RuntimeVerifier().verify_batch(
        plan_batch_digest=plan_batch.content_digest,
        pairs=((plan, execution),),
    )
    runtime_admission = store.admit_runtime_batch(
        runtime_batch, created_at=LATER, actor_ref="actor:runtime-verifier"
    )
    runtime_records = [
        record for record in runtime_admission.records
        if record.artifact_type.value == "RUNTIME_VERIFICATION_RESULT"
    ]
    assert runtime_records
    assert all(record.behavior_id and record.source_symbol_id and record.symbol_lineage_id for record in runtime_records)


def test_governance_artifact_and_history_digests_are_reproducible(tmp_path: Path) -> None:
    _, _, batch = build_scenarios()
    histories = []
    artifact_ids = []
    for index in (1, 2):
        store = GovernanceStore(tmp_path / f"governance-{index}.sqlite3")
        store.initialize(applied_at=NOW)
        admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
        artifact_id = first_spec_artifact(store, admission)
        store.register_baseline(
            artifact_id=artifact_id,
            authority_ref="authority:baseline-board",
            effective_from=NOW,
            actor_ref="authority:baseline-board",
        )
        store.compare_to_baseline(
            candidate_artifact_id=artifact_id,
            compared_at=LATER,
            actor_ref="actor:comparator",
        )
        artifact_ids.append(artifact_id)
        histories.append(store.history(artifact_id).content_digest)
    assert artifact_ids[0] == artifact_ids[1]
    assert histories[0] == histories[1]


def test_local_store_is_explicitly_non_authoritative(tmp_path: Path) -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "constraint_contradiction.sql")
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    batch = ScenarioSpecCompiler().compile_all(parsed, semantic)
    store = build_store(tmp_path)
    result = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    assert result.records
    assert {record.authority_scope.value for record in result.records} == {
        "LOCAL_NON_AUTHORITATIVE_EVIDENCE"
    }


def test_migration_upgrades_existing_0001_database(tmp_path: Path) -> None:
    import sqlite3
    from hashlib import sha256

    root = Path(__file__).parents[1]
    migrations = root / "src/ojas_reconciler/db2_behavior/governance_migrations"
    db = tmp_path / "governance-v1.sqlite3"
    with sqlite3.connect(db) as connection:
        sql = (migrations / "0001_initial.sql").read_text(encoding="utf-8")
        connection.executescript(sql)
        digest = "sha256:" + sha256((migrations / "0001_initial.sql").read_bytes()).hexdigest()
        connection.execute(
            "INSERT INTO governance_schema_migrations "
            "(migration_id, migration_digest, previous_migration_digest, applied_at) "
            "VALUES (?, ?, ?, ?)",
            ("0001_initial", digest, None, NOW),
        )
    store = GovernanceStore(db)
    store.initialize(applied_at=LATER)
    with store.session() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(governance_artifacts)")}
        migrations_applied = [
            row["migration_id"]
            for row in connection.execute(
                "SELECT migration_id FROM governance_schema_migrations ORDER BY migration_id"
            )
        ]
    assert "authority_scope" in columns
    assert migrations_applied == ["0001_initial", "0002_local_non_authoritative_scope"]


def test_store_owned_session_closes_connection_after_initialize(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    store = GovernanceStore(tmp_path / "governance-close.sqlite3")
    connection = store.connect()
    monkeypatch.setattr(store, "connect", lambda: connection)

    store.initialize(applied_at=NOW)

    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_store_session_closes_connection_after_exception(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    store = GovernanceStore(tmp_path / "governance-exception-close.sqlite3")
    connection = store.connect()
    monkeypatch.setattr(store, "connect", lambda: connection)

    with pytest.raises(RuntimeError, match="forced"):
        with store.session() as active:
            active.execute("CREATE TABLE lifecycle_test(id INTEGER)")
            raise RuntimeError("forced")

    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_migration_initialization_is_idempotent(tmp_path: Path) -> None:
    store = GovernanceStore(tmp_path / "governance-repeat.sqlite3")
    store.initialize(applied_at=NOW)
    store.initialize(applied_at=LATER)

    with store.session() as connection:
        migrations = connection.execute(
            "SELECT migration_id, COUNT(*) AS count "
            "FROM governance_schema_migrations GROUP BY migration_id ORDER BY migration_id"
        ).fetchall()
        authority_columns = [
            row["name"]
            for row in connection.execute("PRAGMA table_info(governance_artifacts)")
            if row["name"] == "authority_scope"
        ]

    assert [(row["migration_id"], row["count"]) for row in migrations] == [
        ("0001_initial", 1),
        ("0002_local_non_authoritative_scope", 1),
    ]
    assert authority_columns == ["authority_scope"]
