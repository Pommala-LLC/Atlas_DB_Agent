from pathlib import Path

import pytest

from ojas_reconciler.db2_behavior.parser_models import NodeKind, StateAccessKind
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.dynamic_sql import validate_dynamic_resolution_catalog
from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.semantic_models import (
    DynamicIdentifierResolutionStatus,
    DynamicSqlResolutionStatus,
    DynamicSqlStatementKind,
    DynamicObjectVerificationStatus,
    DynamicResolutionCatalog,
    EffectKind,
    QueryBindingKind,
    QuerySummaryKind,
    SemanticFindingCode,
)
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser


FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    return parsed, Phase1SemanticAnalyzer().analyze(parsed)


def test_parser_emits_prepare_execute_bindings_and_state_facts() -> None:
    parsed, _ = _analyze("process_claim_batch.sql")
    assert parsed.ast is not None
    prepared = [node for node in parsed.ast.nodes if node.kind == NodeKind.PREPARE]
    executes = [node for node in parsed.ast.nodes if node.kind in {NodeKind.EXECUTE, NodeKind.EXECUTE_IMMEDIATE}]
    assert prepared and prepared[0].dynamic_prepare_binding is not None
    assert prepared[0].dynamic_prepare_binding.statement_name == "S1"
    assert len(executes) == 3
    prepared_execute = next(node for node in executes if node.kind == NodeKind.EXECUTE)
    assert prepared_execute.dynamic_execute_binding is not None
    assert prepared_execute.dynamic_execute_binding.into_target_names == ("V_PARALLEL_ENABLED",)
    facts = [
        fact for fact in parsed.ast.state_access_facts
        if fact.source_node_ref == prepared_execute.node_id
    ]
    assert any(fact.access_kind == StateAccessKind.DEF and fact.symbol_name == "V_PARALLEL_ENABLED" for fact in facts)


def test_process_batch_resolves_all_dynamic_sites_to_bounded_static_shapes() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    statuses = [site.resolution_status for site in semantic.dynamic_sql_sites]
    assert statuses.count(DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED) == 1
    assert statuses.count(DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED) == 2
    assert not any(status == DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL for status in statuses)
    targets = {
        resolution.relation_name
        for resolution in semantic.dynamic_relation_resolutions
        if resolution.status == DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
    }
    assert {"SYSTEM_CONFIG", "ERROR_LOG", "CLAIM"}.issubset(targets)


def test_prepared_select_creates_dynamic_query_summary_and_output_binding() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    summary = next(value for value in semantic.query_summaries if value.summary_kind == QuerySummaryKind.DYNAMIC_QUERY)
    assert summary.projection_expressions == ("VALUE",)
    assert summary.relation_refs == ("SYSTEM_CONFIG",)
    binding = next(value for value in semantic.query_bindings if value.binding_kind == QueryBindingKind.EXECUTE_INTO)
    assert binding.target_symbol == "V_PARALLEL_ENABLED"
    assert binding.projection_expression == "VALUE"
    assert binding.analysis_completeness == "COMPLETE"


def test_enumerated_variants_and_dynamic_identifiers_are_distinguished() -> None:
    _, semantic = _analyze("dynamic_resolution.sql")
    update_site = next(
        site for site in semantic.dynamic_sql_sites
        if DynamicSqlStatementKind.UPDATE in site.statement_kinds and len(site.variant_refs) == 2
    )
    assert update_site.resolution_status == DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED
    assert len(update_site.variant_refs) == 2
    assert update_site.relation_resolution_status == DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED

    delete_site = next(site for site in semantic.dynamic_sql_sites if DynamicSqlStatementKind.DELETE in site.statement_kinds)
    assert delete_site.resolution_status == DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED
    assert delete_site.relation_resolution_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER

    unresolved_call = next(
        site for site in semantic.dynamic_sql_sites
        if DynamicSqlStatementKind.CALL in site.statement_kinds
        and site.call_resolution_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
    )
    assert unresolved_call.resolution_status == DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED
    assert any(
        value.site_ref == unresolved_call.site_id
        and value.status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
        and "${P_PROC}" in value.call_target
        for value in semantic.dynamic_call_resolutions
    )
    resolved_call = next(
        site for site in semantic.dynamic_sql_sites
        if DynamicSqlStatementKind.CALL in site.statement_kinds
        and site.call_resolution_status == DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
    )
    assert resolved_call.resolution_status == DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED
    assert len(semantic.runtime_capture_contracts) >= 2


def test_dynamic_variant_budget_fails_closed() -> None:
    _, semantic = _analyze("dynamic_variant_budget.sql")
    assert len(semantic.dynamic_sql_sites) == 1
    site = semantic.dynamic_sql_sites[0]
    assert site.resolution_status == DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED
    assert len(site.variant_refs) == 10
    assert SemanticFindingCode.DYNAMIC_VARIANT_BUDGET_EXCEEDED in {finding.code for finding in semantic.findings}
    assert semantic.runtime_capture_contracts


def test_resolved_dynamic_dml_is_no_longer_an_unresolved_effect_boundary() -> None:
    _, semantic = _analyze("process_claim_batch.sql")
    dynamic_effects = [effect for effect in semantic.effects if effect.effect_kind == EffectKind.DYNAMIC_SQL]
    assert len(dynamic_effects) == 2
    assert {effect.target for effect in dynamic_effects} == {"ERROR_LOG", "CLAIM"}
    assert all(effect.transaction_analysis_ref is not None for effect in dynamic_effects)
    assert not any(
        finding.code == SemanticFindingCode.DYNAMIC_SQL_EFFECT_BOUNDARY
        for finding in semantic.findings
    )


def test_optional_catalog_verifies_literal_dynamic_objects() -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / "dynamic_resolution.sql")
    assert parsed.ast is not None
    payload = {
        "schema_version": "dynamic-resolution-catalog-1.0",
        "catalog_id": "fixture-catalog",
        "source_kind": "CATALOG",
        "relation_names": ("CLAIM_A", "CLAIM_B", "CLAIM"),
        "routine_names": ("CLAIMS.STATIC_NOTIFY",),
    }
    catalog = DynamicResolutionCatalog(**payload, content_digest=canonical_digest(payload))
    semantic = Phase1SemanticAnalyzer(catalog).analyze(parsed)
    assert any(
        resolution.relation_name == "CLAIM_A"
        and resolution.verification_status == DynamicObjectVerificationStatus.VERIFIED_CATALOG
        for resolution in semantic.dynamic_relation_resolutions
    )
    assert any(
        resolution.call_target == "CLAIMS.STATIC_NOTIFY"
        and resolution.verification_status == DynamicObjectVerificationStatus.VERIFIED_CATALOG
        for resolution in semantic.dynamic_call_resolutions
    )


def test_prepared_dml_using_parameters_is_statically_reconstructed() -> None:
    parsed, semantic = _analyze("dynamic_resolution.sql")
    assert parsed.ast is not None
    execute = next(
        node for node in parsed.ast.nodes
        if node.kind == NodeKind.EXECUTE
        and node.dynamic_execute_binding is not None
        and node.dynamic_execute_binding.statement_name == "S2"
    )
    assert execute.dynamic_execute_binding.using_expressions == ("'DONE'", "P_ID")
    site = next(value for value in semantic.dynamic_sql_sites if value.execute_node_ref == execute.node_id)
    assert site.resolution_status == DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED
    assert site.relation_resolution_status == DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
    assert site.using_expressions == ("'DONE'", "P_ID")
    assert any(
        effect.effect_kind == EffectKind.DYNAMIC_SQL
        and effect.source_node_ref == execute.node_id
        and effect.target == "CLAIM"
        for effect in semantic.effects
    )


def test_missing_prepare_definition_requires_runtime_capture() -> None:
    _, semantic = _analyze("dynamic_missing_prepare.sql")
    assert len(semantic.dynamic_sql_sites) == 1
    site = semantic.dynamic_sql_sites[0]
    assert site.resolution_status == DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL
    assert site.analysis_completeness == "PARTIAL"
    assert semantic.runtime_capture_contracts
    assert SemanticFindingCode.DYNAMIC_SQL_UNRESOLVED in {finding.code for finding in semantic.findings}


def test_dynamic_query_output_arity_mismatch_is_partial() -> None:
    _, semantic = _analyze("dynamic_query_arity.sql")
    assert len(semantic.dynamic_query_bindings) == 1
    binding = semantic.dynamic_query_bindings[0]
    assert binding.analysis_completeness == "PARTIAL"
    assert binding.projection_expression == "A"
    assert SemanticFindingCode.DYNAMIC_QUERY_BINDING_PARTIAL in {finding.code for finding in semantic.findings}


def test_dynamic_resolution_catalog_digest_is_verified() -> None:
    catalog = DynamicResolutionCatalog(
        catalog_id="bad-catalog",
        source_kind="SOURCE",
        relation_names=("CLAIM",),
        routine_names=(),
        content_digest="sha256:" + "0" * 64,
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_dynamic_resolution_catalog(catalog)
