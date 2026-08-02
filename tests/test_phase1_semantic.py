from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.parser_models import NodeKind
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.semantic_models import (
    CfgEdgeKind,
    EffectKind,
    EffectObservability,
    SemanticFindingCode,
)
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    return parsed, Phase1SemanticAnalyzer().analyze(parsed)


def test_cfg_contains_loop_handler_and_jump_edges() -> None:
    parsed, semantic = _analyze("settle_customer_claims.sql")
    assert parsed.ast is not None
    edge_kinds = {edge.edge_kind for edge in semantic.cfg.edges}
    assert CfgEdgeKind.LOOP_BODY in edge_kinds
    assert CfgEdgeKind.LOOP_EXIT in edge_kinds
    assert CfgEdgeKind.LEAVE in edge_kinds
    assert CfgEdgeKind.ITERATE in edge_kinds
    assert CfgEdgeKind.HANDLER in edge_kinds
    assert len(semantic.cfg.handler_bindings) >= 4


def test_shared_not_found_handler_interference_is_reported() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    codes = {finding.code for finding in semantic.findings}
    assert SemanticFindingCode.SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE in codes
    assert SemanticFindingCode.STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE in codes


def test_process_batch_dynamic_and_call_boundaries_are_explicit() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    kinds = {effect.effect_kind for effect in semantic.effects}
    assert EffectKind.DYNAMIC_SQL in kinds
    assert EffectKind.CALL in kinds
    assert any(
        effect.effect_kind == EffectKind.DYNAMIC_SQL
        and effect.observability == EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED
        for effect in semantic.effects
    )
    assert semantic.dynamic_sql_sites
    assert all(site.analysis_completeness == "COMPLETE" for site in semantic.dynamic_sql_sites)


def test_out_assignments_are_classified_by_reaching_exit() -> None:
    parsed, semantic = _analyze("process_claim_batch.sql")
    assert parsed.ast is not None
    out_effects = [
        effect for effect in semantic.effects
        if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT
    ]
    assert out_effects
    assert any(effect.observability == EffectObservability.ESCAPING_EFFECT for effect in out_effects)
    assert any(
        effect.observability == EffectObservability.OVERWRITTEN_OUTPUT_ASSIGNMENT
        for effect in out_effects
    )


def test_cfg_excludes_declarations_from_normal_flow() -> None:
    parsed, semantic = _analyze("settle_customer_claims.sql")
    assert parsed.ast is not None
    declared = {
        node.node_id for node in parsed.ast.nodes
        if node.kind in {NodeKind.DECLARE_VARIABLE, NodeKind.DECLARE_CURSOR, NodeKind.HANDLER_REGION}
    }
    assert declared.issubset(set(semantic.cfg.excluded_declaration_refs))


def test_transaction_survival_is_conservative_and_explicit() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    assert semantic.transaction_regions
    assert semantic.transaction_analyses
    assert all(analysis.reachable_outcomes for analysis in semantic.transaction_analyses)
    classifications = {analysis.classification.value for analysis in semantic.transaction_analyses}
    assert "MAY_COMMIT_ROLLBACK_OR_CALLER_CONTROLLED" in classifications
    dml_effects = [effect for effect in semantic.effects if effect.effect_kind == EffectKind.DML]
    assert dml_effects
    assert all(effect.transaction_analysis_ref for effect in dml_effects)


def test_process_batch_dml_remains_caller_controlled_or_exceptional() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    classifications = {analysis.classification.value for analysis in semantic.transaction_analyses}
    assert "CALLER_CONTROLLED" in classifications or "CALLER_CONTROLLED_OR_EXCEPTIONAL" in classifications
    assert all(
        effect.observability == EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED
        for effect in semantic.effects
        if effect.effect_kind == EffectKind.DML
    )


def test_behavior_effect_bundles_preserve_loop_coeffects() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    loop_bundles = [
        bundle for bundle in semantic.behavior_bundles
        if bundle.controlling_region_ref.startswith("loop-region:")
    ]
    assert len(loop_bundles) == 1
    loop_bundle = loop_bundles[0]
    assert len(loop_bundle.effect_members) == 4
    relationships = {member.relationship.value for member in loop_bundle.effect_members}
    assert "PRIMARY" in relationships
    assert "AUDIT_EFFECT" in relationships
    assert loop_bundle.bundle_completeness == "PARTIAL"


def test_loop_summary_emits_proof_obligations_without_claiming_exactness() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    assert len(semantic.loop_summaries) == 1
    summary = semantic.loop_summaries[0]
    assert summary.soundness.value == "PARTIAL_SUMMARY"
    assert summary.analysis_completeness == "PARTIAL"
    assert summary.cursor_fetch_refs
    assert summary.accumulator_assignment_refs
    statuses = {obligation.obligation: obligation.status.value for obligation in summary.proof_obligations}
    assert statuses["FETCH_BINDING_IDENTIFIED"] == "SATISFIED"
    assert statuses["HANDLER_INTERFERENCE_RESOLVED"] == "PARTIAL"
    assert SemanticFindingCode.LOOP_SUMMARY_PARTIAL in {finding.code for finding in semantic.findings}


def test_query_source_summaries_capture_cursor_and_select_into_structure() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    cursor = next(summary for summary in semantic.query_summaries if summary.cursor_name == "C_SETTLE")
    assert cursor.projection_expressions == (
        "C.CLAIM_ID",
        "C.AMOUNT",
        "COALESCE (P.PAID_TOTAL, 0)",
    )
    assert {join.join_kind for join in cursor.joins} == {"LEFT"}
    assert {"CLAIM", "CLAIM_PAYMENT", "CLAIM_AUDIT"}.issubset(set(cursor.relation_refs))

    aggregate = next(
        summary
        for summary in semantic.query_summaries
        if summary.summary_kind.value == "SELECT_INTO_QUERY"
        and any(clause.clause_kind == "HAVING" for clause in summary.clauses)
    )
    assert len(aggregate.projection_expressions) == 3
    assert any(clause.clause_kind == "WHERE" for clause in aggregate.clauses)
    assert any(clause.clause_kind == "HAVING" for clause in aggregate.clauses)


def test_query_bindings_reconcile_select_and_fetch_positions() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    fetch_bindings = [binding for binding in semantic.query_bindings if binding.binding_kind.value == "FETCH"]
    assert len(fetch_bindings) == 4
    assert all(binding.analysis_completeness == "COMPLETE" for binding in fetch_bindings)
    assert [binding.target_symbol for binding in sorted(fetch_bindings, key=lambda item: item.projection_index)] == [
        "V_CLAIM_ID",
        "V_AMOUNT",
        "V_STATUS",
        "V_RISK_SCORE",
    ]

    history = next(summary for summary in semantic.query_summaries if "CLAIM_HISTORY" in summary.cte_names)
    assert history.window_functions == ("LAG",)
    history_bindings = [binding for binding in semantic.query_bindings if binding.query_summary_ref == history.query_summary_id]
    assert len(history_bindings) == 1
    assert history_bindings[0].target_symbol == "V_PREV_AMOUNT"
    assert history_bindings[0].projection_expression == "PREV_AMOUNT"


def test_backward_slice_connects_risk_decision_to_aggregate_query_binding() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    effects = {effect.effect_id: effect for effect in semantic.effects}
    risk_bundle = next(
        bundle
        for bundle in semantic.behavior_bundles
        if any(
            effects[member.effect_ref].value_expression == "'RISK_REVIEW'"
            for member in bundle.effect_members
        )
    )
    behavior_slice = next(item for item in semantic.behavior_slices if item.bundle_ref == risk_bundle.bundle_id)
    assert behavior_slice.analysis_completeness == "COMPLETE"
    assert behavior_slice.query_summary_refs
    bindings = {binding.binding_id: binding for binding in semantic.query_bindings}
    bound_targets = {bindings[ref].target_symbol for ref in behavior_slice.query_binding_refs}
    assert "V_MAX_RISK" in bound_targets
    assert "P_CUSTOMER_ID" in behavior_slice.parameter_source_names


def test_loop_effect_slice_includes_cursor_query_and_fetch_bindings() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    loop_bundle = next(
        bundle for bundle in semantic.behavior_bundles if bundle.controlling_region_ref.startswith("loop-region:")
    )
    behavior_slice = next(item for item in semantic.behavior_slices if item.bundle_ref == loop_bundle.bundle_id)
    summaries = {summary.query_summary_id: summary for summary in semantic.query_summaries}
    assert any(summaries[ref].cursor_name == "C_SETTLE" for ref in behavior_slice.query_summary_refs)
    bindings = {binding.binding_id: binding for binding in semantic.query_bindings}
    assert {bindings[ref].target_symbol for ref in behavior_slice.query_binding_refs}.issuperset(
        {"V_CLAIM_ID", "V_AMOUNT", "V_PAID"}
    )


def test_ordered_if_predicate_graph_preserves_precedence() -> None:
    _, semantic = _analyze("settle_customer_claims.sql")
    capacity = next(
        graph
        for graph in semantic.predicate_graphs
        if graph.controlling_region_ref.endswith(":1:ELSEIF")
        and any("V_OPEN_COUNT" in (expr.technical_expression or "") for expr in graph.expressions)
    )
    kinds = {expr.node_kind.value for expr in capacity.expressions}
    assert {"AND", "NOT", "OR", "ATOMIC"}.issubset(kinds)
    assessment = next(
        item for item in semantic.constraint_assessments
        if item.predicate_graph_ref == capacity.predicate_graph_id
    )
    assert assessment.status.value in {
        "SYNTACTICALLY_CONSISTENT",
        "DATA_STATE_ASSUMPTION_REQUIRED",
        "UNSUPPORTED_CONSTRAINT_THEORY",
    }


def test_local_constraint_evaluator_detects_obvious_contradiction() -> None:
    _, semantic = _analyze("constraint_contradiction.sql")
    contradiction = next(
        item for item in semantic.constraint_assessments
        if item.status.value == "OBVIOUS_CONTRADICTION"
    )
    assert "empty" in contradiction.reason.lower() or "contradict" in contradiction.reason.lower()
    assert SemanticFindingCode.OBVIOUS_PREDICATE_CONTRADICTION in {
        finding.code for finding in semantic.findings
    }
    affected = next(
        behavior_slice for behavior_slice in semantic.behavior_slices
        if contradiction.assessment_id in behavior_slice.constraint_assessment_refs
    )
    assert affected.analysis_completeness == "PARTIAL"


def test_effect_modality_never_strengthens_partial_loop_effects_to_must() -> None:
    parsed, semantic = _analyze("settle_customer_claims.sql")
    assert parsed.ast is not None
    loop_node_refs = {
        node.node_id for node in parsed.ast.nodes if node.kind == NodeKind.LOOP_REGION
    }
    child_to_loop: dict[str, str] = {}
    by_id = {node.node_id: node for node in parsed.ast.nodes}

    def mark(ref: str, loop_ref: str) -> None:
        child_to_loop[ref] = loop_ref
        node = by_id[ref]
        if node.if_region is not None:
            children = [child for arm in node.if_region.arms for child in arm.body_node_refs]
        elif node.loop_region is not None:
            children = list(node.loop_region.body_node_refs)
        else:
            children = list(node.child_refs)
        for child in children:
            mark(child, loop_ref)

    for loop_ref in loop_node_refs:
        loop = by_id[loop_ref]
        assert loop.loop_region is not None
        for child in loop.loop_region.body_node_refs:
            mark(child, loop_ref)

    effect_by_id = {effect.effect_id: effect for effect in semantic.effects}
    loop_obligations = [
        obligation
        for obligation in semantic.effect_obligations
        if effect_by_id[obligation.effect_ref].source_node_ref in child_to_loop
    ]
    assert loop_obligations
    assert all(obligation.modality.value != "MUST" for obligation in loop_obligations)
    assert any(obligation.modality.value == "UNKNOWN" for obligation in loop_obligations)


def test_behavior_slice_references_predicate_and_effect_obligations() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    effect_by_id = {effect.effect_id: effect for effect in semantic.effects}
    warning_bundle = next(
        bundle
        for bundle in semantic.behavior_bundles
        if any(effect_by_id[member.effect_ref].value_expression == "'WARN1'" for member in bundle.effect_members)
    )
    behavior_slice = next(item for item in semantic.behavior_slices if item.bundle_ref == warning_bundle.bundle_id)
    assert behavior_slice.predicate_graph_ref is not None
    assert behavior_slice.constraint_assessment_refs
    assert behavior_slice.effect_obligations
    assert all(obligation.bundle_ref == warning_bundle.bundle_id for obligation in behavior_slice.effect_obligations)


def test_semantic_output_is_stable_across_process_environment() -> None:
    import os
    import subprocess
    import sys

    root = Path(__file__).parents[1]
    fixture = root / "tests" / "fixtures" / "settle_customer_claims.sql"
    script = (
        "from pathlib import Path;"
        "from ojas_reconciler.db2_behavior.canonical_json import canonical_json_bytes;"
        "from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer;"
        "from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser;"
        f"p=LarkSqlPlSpikeParser().parse_file(Path({str(fixture)!r}));"
        "s=Phase1SemanticAnalyzer().analyze(p);"
        "import sys;sys.stdout.buffer.write(canonical_json_bytes(s))"
    )
    outputs = []
    for seed, timezone in (("17", "UTC"), ("913", "America/Chicago")):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["PYTHONHASHSEED"] = seed
        env["TZ"] = timezone
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            env=env,
            cwd=root,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]


def test_literal_true_if_marks_else_unreachable_and_only_always_reaches_exit() -> None:
    parsed, semantic = _analyze("test_unreachable.sql")
    assert parsed.ast is not None
    findings = [
        finding
        for finding in semantic.findings
        if finding.code == SemanticFindingCode.UNREACHABLE_BRANCH
    ]
    assert len(findings) == 1
    assert findings[0].source_ranges[0].start_line == 8

    out_effects = [
        effect
        for effect in semantic.effects
        if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT
    ]
    by_value = {effect.value_expression: effect.observability for effect in out_effects}
    assert by_value["'ALWAYS'"] == EffectObservability.ESCAPING_EFFECT
    assert by_value["'NEVER'"] == EffectObservability.OVERWRITTEN_OUTPUT_ASSIGNMENT


def test_named_not_found_handler_is_bound_only_inside_nested_compound() -> None:
    _, semantic = _analyze("nested_named_condition.sql")
    assert len(semantic.cfg.handler_bindings) == 1
    binding = semantic.cfg.handler_bindings[0]
    assert binding.handled_condition_text == "CUSTOMER_NOT_FOUND"


def test_tenant_catalog_flags_only_missing_tenant_predicate() -> None:
    from ojas_reconciler.db2_behavior.semantic_models import TenantIsolationCatalog

    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "test_tenant_missing.sql")
    assert parsed.ast is not None
    catalog = TenantIsolationCatalog.model_validate_json(
        (FIXTURES / "tenant_catalog.json").read_text(encoding="utf-8")
    )
    semantic = Phase1SemanticAnalyzer(tenant_isolation_catalog=catalog).analyze(parsed)
    findings = [
        finding
        for finding in semantic.findings
        if finding.code == SemanticFindingCode.TENANT_ISOLATION_MISSING
    ]
    assert len(findings) == 1
    assert findings[0].source_ranges[0].start_line == 12
    assert "CLAIM" in findings[0].message
    assert "TENANT_ID" in findings[0].message
    assert semantic.tenant_isolation_catalog_digest == catalog.content_digest
