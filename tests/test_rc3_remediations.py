from __future__ import annotations

import json
from pathlib import Path

from ojas_reconciler.db2_behavior.bdd_models import AuthorityScope
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.pipeline import EndToEndPipeline
from ojas_reconciler.db2_behavior.release_models import AuthorityMode
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.semantic_models import (
    BehaviorActionScope,
    EffectModality,
    SemanticFindingCode,
    WindowModelStatus,
)
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.query_semantics import load_query_semantics_catalog
from ojas_reconciler.db2_behavior.caller_contract import load_caller_transaction_contract


FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(*, with_catalog: bool = True, with_contract: bool = True):
    parse = LarkSqlPlSpikeParser().parse_file(FIXTURES / "process_claim_batch.sql")
    semantic = Phase1SemanticAnalyzer(
        query_semantics_catalog=(
            load_query_semantics_catalog(FIXTURES / "query_semantics_catalog.json")
            if with_catalog else None
        ),
        caller_transaction_contract=(
            load_caller_transaction_contract(FIXTURES / "caller_transaction_contract.json")
            if with_contract else None
        ),
    ).analyze(parse)
    return parse, semantic


def test_window_model_blocks_false_completeness_without_catalog() -> None:
    _, semantic = _analyze(with_catalog=False, with_contract=False)
    summaries = [value for value in semantic.query_summaries if value.window_functions]
    assert len(summaries) == 1
    assert summaries[0].analysis_completeness == "PARTIAL"
    assert summaries[0].window_model_status == WindowModelStatus.WINDOW_INPUT_CARDINALITY_UNKNOWN
    codes = {value.code for value in semantic.findings}
    assert SemanticFindingCode.WINDOW_INPUT_CARDINALITY_UNKNOWN in codes
    assert SemanticFindingCode.QUERY_SUMMARY_COMPLETE_WITHOUT_WINDOW_MODEL not in codes


def test_single_row_lag_marks_amount_spike_unreachable() -> None:
    _, semantic = _analyze()
    summaries = [value for value in semantic.query_summaries if value.window_functions]
    assert summaries[0].window_model_status == WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION
    codes = [value.code for value in semantic.findings]
    assert SemanticFindingCode.WINDOW_OVER_SINGLE_ROW_PARTITION in codes
    assert codes.count(SemanticFindingCode.UNREACHABLE_BRANCH) == 1
    unreachable = next(value for value in semantic.findings if value.code == SemanticFindingCode.UNREACHABLE_BRANCH)
    assert "V_PREV_AMOUNT" in unreachable.message


def test_caller_contract_and_iteration_scope_admit_conditional_dml() -> None:
    parse, semantic = _analyze()
    iteration_bundles = [
        value for value in semantic.behavior_bundles
        if value.action_scope == BehaviorActionScope.CURSOR_ITERATION
    ]
    assert iteration_bundles
    assert any(value.bundle_completeness == "COMPLETE" for value in iteration_bundles)
    assert any(
        value.modality == EffectModality.MUST_IF_CALLER_CONTRACT_HOLDS
        for value in semantic.effect_obligations
    )
    batch = ScenarioSpecCompiler().compile_all(parse, semantic)
    assert len(batch.scenario_specs) >= 6
    assert any(value.action.action_kind == "CURSOR_ITERATION" for value in batch.scenario_specs)
    assert any(value.ordered_decision_reduction_refs for value in batch.scenario_specs)
    assert all(
        "caller-contract-process-claim-batch-v1" in value.caller_transaction_contract_refs
        for value in batch.scenario_specs
    )


def test_fixture_bdd_wording_identity_and_evidence_are_correct() -> None:
    parse, semantic = _analyze()
    scenarios = ScenarioSpecCompiler().compile_all(parse, semantic)
    vocabulary, classification = FixtureAuthorityBuilder().build(
        scenarios, authority_scope=AuthorityScope.TEST_FIXTURE_ONLY
    )
    bdd = BddCompiler().compile_all(scenarios, vocabulary, classification)
    assert bdd.candidate_bdds
    assert all(
        artifact.text.startswith("Feature: DB2 procedure technical behavior candidates\n")
        for artifact in bdd.gherkin_artifacts
    )
    specs = {value.scenario_spec_id: value for value in scenarios.scenario_specs}
    for artifact in bdd.gherkin_artifacts:
        assert artifact.behavior_id
        assert artifact.source_symbol_id
        assert artifact.symbol_lineage_id
        assert artifact.artifact_revision_id
    for manifest in bdd.traceability_manifests:
        spec = specs[manifest.scenario_spec_ref]
        assert manifest.behavior_id == spec.behavior_id
        action_refs = [
            value.evidence_refs for value in manifest.element_bindings
            if value.element_kind == "WHEN"
        ]
        effect_refs = [
            value.evidence_refs for value in manifest.element_bindings
            if value.element_kind in {"THEN", "AND"} and value.effect_or_precondition_refs
        ]
        assert action_refs == [spec.action.evidence_refs]
        assert effect_refs
        assert all(value != spec.action.evidence_refs for value in effect_refs)
    for candidate in bdd.candidate_bdds:
        spec = specs[candidate.scenario_spec_ref]
        assert candidate.behavior_id == spec.behavior_id
        assert candidate.source_symbol_id == spec.source_symbol_id
        assert candidate.symbol_lineage_id == spec.symbol_lineage_id


def test_pipeline_reports_primary_and_supporting_counts(tmp_path: Path) -> None:
    output = tmp_path / "run"
    db = output / "evidence.sqlite3"
    EndToEndPipeline().run(
        source=FIXTURES / "process_claim_batch.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
        query_semantics_catalog=FIXTURES / "query_semantics_catalog.json",
        caller_transaction_contract=FIXTURES / "caller_transaction_contract.json",
        governance_db=db,
    )
    payload = json.loads((output / "09-local-governance.json").read_text())
    assert payload["scenario_spec_count"] == 6
    assert payload["scenario_compilation_blocked_count"] == 3
    assert payload["candidate_bdd_count"] == 6
    assert payload["gherkin_artifact_count"] == 6
    assert payload["traceability_manifest_count"] == 6
    assert "scenario_records" not in payload
    assert "bdd_records" not in payload
