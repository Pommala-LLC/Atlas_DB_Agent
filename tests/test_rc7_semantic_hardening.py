from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.analysis.tenant_isolation import load_tenant_isolation_catalog
from ojas_reconciler.db2_behavior.compiler.scenario_spec import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.inventory import InventoryAnalyzer
from ojas_reconciler.db2_behavior.scenario_models import (
    ScenarioBlockerCode,
    ScenarioCompilationStatus,
)
from ojas_reconciler.db2_behavior.semantic_models import SemanticFindingCode
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str, *, tenant_catalog: str | None = None):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    catalog = load_tenant_isolation_catalog(FIXTURES / tenant_catalog) if tenant_catalog else None
    semantic = Phase1SemanticAnalyzer(tenant_isolation_catalog=catalog).analyze(parsed)
    return parsed, semantic


def _targets(parsed, findings, code: SemanticFindingCode) -> set[str]:
    assert parsed.ast is not None
    nodes = {node.node_id: node for node in parsed.ast.nodes}
    result: set[str] = set()
    for finding in findings:
        if finding.code != code or not finding.evidence_node_refs:
            continue
        node = nodes.get(finding.evidence_node_refs[0])
        if node is not None and node.assignment_binding is not None:
            result.add(node.assignment_binding.target_name.upper())
    return result


def test_join_breakdown_is_mutually_exclusive_and_reconciles() -> None:
    advanced = InventoryAnalyzer().analyze_path(FIXTURES / "advanced_claim_evaluation.sql")
    comprehensive = InventoryAnalyzer().analyze_path(FIXTURES / "comprehensive_claim_assess.sql")

    assert advanced.query_complexity.join_count == 5
    assert advanced.query_complexity.inner_join_count == 4
    assert advanced.query_complexity.cross_join_count == 1
    assert comprehensive.query_complexity.join_count == 4
    assert comprehensive.query_complexity.inner_join_count == 3
    assert comprehensive.query_complexity.cross_join_count == 1

    for report in (advanced, comprehensive):
        q = report.query_complexity
        assert (
            q.inner_join_count
            + q.left_join_count
            + q.right_join_count
            + q.full_join_count
            + q.cross_join_count
            == q.join_count
        )
        assert not any(finding.code == "COUNTER_INVARIANT_VIOLATION" for finding in report.findings)


def test_missing_not_found_handlers_and_coverage_facts_are_emitted() -> None:
    _, semantic = _analyze("advanced_claim_evaluation.sql")
    missing = [
        finding for finding in semantic.findings
        if finding.code == SemanticFindingCode.MISSING_NOT_FOUND_HANDLER
    ]
    assert len(missing) == 2
    assert len(semantic.handler_coverage) == 2
    assert all(fact.coverage_status == "MISSING" for fact in semantic.handler_coverage)

    _, covered = _analyze("process_claim_batch.sql")
    assert any(fact.coverage_status == "COVERED" for fact in covered.handler_coverage)
    assert all(
        fact.handler_region_ref and fact.handler_binding_ref
        for fact in covered.handler_coverage
        if fact.coverage_status == "COVERED"
    )


def test_dead_local_findings_distinguish_unassigned_and_unconsumed() -> None:
    _, semantic = _analyze("comprehensive_claim_assess.sql")
    never_assigned = {
        finding.message for finding in semantic.findings
        if finding.code == SemanticFindingCode.DECLARED_SYMBOL_NEVER_ASSIGNED
    }
    never_consumed = {
        finding.message for finding in semantic.findings
        if finding.code == SemanticFindingCode.ASSIGNED_SYMBOL_NEVER_CONSUMED
    }
    assert "Local symbol V_SIMILAR_CLAIMS is declared but never assigned." in never_assigned
    assert "Local symbol V_CURRENT_TS is assigned but never consumed." in never_consumed
    assert "Local symbol V_ESCALATION_NOTE is assigned but never consumed." in never_consumed


def test_declared_decimal_narrowing_is_reported_conservatively() -> None:
    parsed, semantic = _analyze("comprehensive_claim_assess.sql")
    targets = _targets(
        parsed,
        semantic.findings,
        SemanticFindingCode.NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW,
    )
    assert "P_CONFIDENCE_SCORE" in targets

    parsed, semantic = _analyze("advanced_claim_evaluation.sql")
    targets = _targets(
        parsed,
        semantic.findings,
        SemanticFindingCode.NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW,
    )
    assert "P_RISK_SCORE" in targets


def test_tenant_catalog_distinguishes_missing_from_not_evaluated() -> None:
    _, no_catalog = _analyze("advanced_claim_evaluation.sql")
    assert any(
        finding.code == SemanticFindingCode.TENANT_ISOLATION_NOT_EVALUATED
        for finding in no_catalog.findings
    )

    _, evaluated = _analyze(
        "advanced_claim_evaluation.sql",
        tenant_catalog="tenant_catalog_read_write.json",
    )
    missing_messages = [
        finding.message for finding in evaluated.findings
        if finding.code == SemanticFindingCode.TENANT_ISOLATION_MISSING
    ]
    assert any("READ access on CLAIM" in message for message in missing_messages)
    assert any("READ access on CUSTOMER" in message for message in missing_messages)


def test_ordered_decision_and_dominating_score_dependencies_block_admission() -> None:
    parsed, semantic = _analyze("comprehensive_claim_assess.sql")
    batch = ScenarioSpecCompiler().compile_all(parsed, semantic)

    # P_CONFIDENCE_SCORE is assigned before the ordered decision and reaches
    # normal exit on every branch. Its partial query slice is therefore a
    # required co-effect, including for the fraud branch.
    assert len(batch.scenario_specs) == 0
    blocked = [
        result for result in batch.compilation_results
        if result.compilation_status == ScenarioCompilationStatus.BLOCKED
    ]
    assert len(blocked) == 6
    assert all(ScenarioBlockerCode.BEHAVIOR_SLICE_PARTIAL in result.blockers for result in blocked)
    assert any(
        ScenarioBlockerCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL
        in result.blockers
        for result in blocked
    )
    assert any(
        any("Negated preceding arm" in detail for detail in result.blocker_details)
        for result in blocked
    )
    assert any(
        finding.code == SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL
        for finding in semantic.findings
    )

    effect_by_id = {effect.effect_id: effect for effect in semantic.effects}
    fraud_bundle = next(
        bundle
        for bundle in semantic.behavior_bundles
        if effect_by_id[bundle.primary_effect_ref].value_expression == "'REJECTED_FRAUD'"
    )
    fraud_targets = {
        effect_by_id[member.effect_ref].target for member in fraud_bundle.effect_members
    }
    assert {"P_FINAL_DECISION", "P_CONFIDENCE_SCORE", "P_EXCEPTION_FLAG"} <= fraud_targets


def test_global_aggregate_select_into_does_not_report_not_found() -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "comprehensive_claim_assess.sql")
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    missing = [fact for fact in semantic.handler_coverage if fact.coverage_status == "MISSING"]
    assert len(missing) == 2
    lines = sorted(
        next(node.source_range.start_line for node in parsed.ast.nodes if node.node_id == fact.source_node_ref)
        for fact in missing
    )
    assert lines == [25, 94]
