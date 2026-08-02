from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.governance_store import GovernanceStore, GovernanceStoreError
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
NOW = "2026-07-29T00:00:00.000000Z"


def _validate(instance, schema_name: str) -> None:
    schema = json.loads((ROOT / "contracts" / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(instance)


def test_governance_migration_manifest_schema() -> None:
    manifest = json.loads(
        (ROOT / "src/ojas_reconciler/db2_behavior/governance_migrations/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    _validate(manifest, "governance-migration-manifest-1.0.schema.json")


def test_governance_record_and_history_schemas(tmp_path: Path) -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "constraint_contradiction.sql")
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    batch = ScenarioSpecCompiler().compile_all(parsed, semantic)
    store = GovernanceStore(tmp_path / "governance.sqlite3")
    store.initialize(applied_at=NOW)
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    spec_record = next(item for item in admission.records if item.artifact_type.value == "SCENARIO_SPEC")
    _validate(spec_record.model_dump(mode="json"), "governance-artifact-record-1.0.schema.json")
    history = store.history(spec_record.artifact_id)
    _validate(history.model_dump(mode="json"), "governance-history-1.0.schema.json")


def test_audit_chain_tamper_is_detected(tmp_path: Path) -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "constraint_contradiction.sql")
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    batch = ScenarioSpecCompiler().compile_all(parsed, semantic)
    store = GovernanceStore(tmp_path / "governance.sqlite3")
    store.initialize(applied_at=NOW)
    admission = store.admit_scenario_batch(batch, created_at=NOW, actor_ref="actor:extractor")
    spec_record = next(item for item in admission.records if item.artifact_type.value == "SCENARIO_SPEC")
    with store.session() as connection:
        connection.execute(
            "UPDATE governance_audit_events SET actor_ref = 'tampered' WHERE sequence = 1"
        )
    assert not store.history(spec_record.artifact_id).audit_chain_valid


def test_migration_digest_tamper_is_rejected(tmp_path: Path) -> None:
    source = ROOT / "src/ojas_reconciler/db2_behavior/governance_migrations"
    copied = tmp_path / "migrations"
    copied.mkdir()
    for path in source.iterdir():
        copied.joinpath(path.name).write_bytes(path.read_bytes())
    copied.joinpath("0001_initial.sql").write_text("-- tampered\n", encoding="utf-8")
    store = GovernanceStore(tmp_path / "governance.sqlite3", migrations_dir=copied)
    with pytest.raises(GovernanceStoreError, match="Migration digest mismatch"):
        store.initialize(applied_at=NOW)


def test_tenant_isolation_catalog_schema() -> None:
    payload = json.loads((FIXTURES / "tenant_catalog.json").read_text(encoding="utf-8"))
    _validate(payload, "tenant-isolation-catalog-1.0.schema.json")
