from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.corpus import CorpusRunner
from ojas_reconciler.db2_behavior.explain import explain_parse_result
from ojas_reconciler.db2_behavior.parser_models import NodeKind, ParseOutcome
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parents[1]


def test_canonical_json_sorts_keys_and_preserves_decimal_scale() -> None:
    left = {"zeta": "z", "alpha": Decimal("1234.50"), "note": "café"}
    right = {"note": "cafe\u0301", "alpha": Decimal("1234.50"), "zeta": "z"}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_digest(left) == canonical_digest(right)
    assert b'"$decimal":"1234.50"' in canonical_json_bytes(left)


def test_parser_emits_structured_if_region() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "eligible_claim.sql")
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.procedure_name == "EVALUATE_CLAIM"
    assert any(node.kind == NodeKind.IF_REGION for node in result.ast.nodes)
    explain = explain_parse_result(result)
    assert explain.result == "SUCCEEDED"


def test_select_into_binding_is_removed_from_residual_query() -> None:
    source = """
CREATE PROCEDURE CLAIMS.P1(OUT V_A INTEGER, OUT V_B DECIMAL(10,2))
LANGUAGE SQL
BEGIN
  SELECT A, SUM(B) INTO V_A, V_B FROM T HAVING COUNT(*) > 0;
END
"""
    result = LarkSqlPlSpikeParser().parse_text(
        source_text=source,
        artifact_id="fixture",
        artifact_revision_id="rev-1",
    )
    assert result.ast is not None
    node = next(node for node in result.ast.nodes if node.kind == NodeKind.SELECT_INTO)
    binding = node.select_into_binding
    assert binding is not None
    assert binding.target_names == ("V_A", "V_B")
    assert binding.projection_count == 2
    assert binding.arity_status == "ARITY_MATCHED"
    assert " INTO " not in binding.residual_query_text.upper()
    assert "HAVING" in binding.residual_query_text.upper()


def test_corpus_runner_reports_by_construct() -> None:
    report = CorpusRunner().run(
        ROOT / "tests" / "corpus" / "manifest.json",
        ROOT / "contracts" / "corpus-manifest-1.0.schema.json",
    )
    assert report["passed"] is True
    assert report["by_construct"]["CREATE_PROCEDURE"]["total"] == 12


def test_process_claim_batch_measured_constructs() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "process_claim_batch.sql")
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.schema_name == "CLAIMS"
    assert result.ast.procedure_name == "PROCESS_CLAIM_BATCH"
    kinds = [node.kind for node in result.ast.nodes]
    assert NodeKind.PREPARE in kinds
    assert NodeKind.EXECUTE in kinds
    assert NodeKind.OPEN_CURSOR in kinds
    assert NodeKind.CLOSE_CURSOR in kinds
    loop = next(node for node in result.ast.nodes if node.kind == NodeKind.LOOP_REGION)
    assert loop.loop_region is not None
    assert loop.loop_region.label == "PROCESS_LOOP"
    assert loop.loop_region.loop_kind == "LOOP"
    assert any(node.kind == NodeKind.FETCH_CURSOR for node in result.ast.nodes)
    assert any(node.kind == NodeKind.HANDLER_REGION for node in result.ast.nodes)
    binding = next(
        node.select_into_binding
        for node in result.ast.nodes
        if node.kind == NodeKind.SELECT_INTO
        and node.select_into_binding is not None
        and node.select_into_binding.target_names == ("V_ITEM_COUNT", "V_TOTAL_AMOUNT")
    )
    assert binding.target_names == ("V_ITEM_COUNT", "V_TOTAL_AMOUNT")
    assert binding.projection_count == 2
    assert binding.arity_status == "ARITY_MATCHED"


def test_process_claim_batch_nested_cte_and_merge_are_structured() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "process_claim_batch.sql")
    assert result.ast is not None
    nested_binding = next(
        node.select_into_binding
        for node in result.ast.nodes
        if node.kind == NodeKind.SELECT_INTO
        and node.source_range.start_line == 91
    )
    assert nested_binding is not None
    assert nested_binding.target_names == ("V_PREV_AMOUNT",)
    assert nested_binding.projection_count == 1
    assert "LAG(AMOUNT)" in nested_binding.residual_query_text

    merge = next(node for node in result.ast.nodes if node.merge_structure is not None)
    assert merge.merge_structure is not None
    assert merge.merge_structure.target_text == "CUSTOMER_CLAIM_SUMMARY AS T"
    assert [action.action_kind for action in merge.merge_structure.actions] == ["UPDATE", "INSERT"]


def test_handler_and_fetch_state_facts_are_emitted() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "settle_customer_claims.sql")
    assert result.ast is not None
    handler = next(
        node for node in result.ast.nodes
        if node.kind == NodeKind.HANDLER_REGION
        and node.handler_region is not None
        and node.handler_region.handled_condition_text.upper() == "NOT FOUND"
    )
    assert handler.handler_region is not None
    assert handler.handler_region.handler_kind == "CONTINUE"
    assert handler.handler_region.continuation_semantics == "AFTER_RAISING_STATEMENT"

    fetch = next(node for node in result.ast.nodes if node.kind == NodeKind.FETCH_CURSOR)
    assert fetch.fetch_binding is not None
    assert fetch.fetch_binding.cursor_name == "C_SETTLE"
    assert fetch.fetch_binding.target_names == ("V_CLAIM_ID", "V_AMOUNT", "V_PAID")

    handler_defs = {
        fact.symbol_name
        for fact in result.ast.state_access_facts
        if fact.context_kind == "HANDLER_ASSIGNMENT" and fact.access_kind == "DEF"
    }
    assert "V_NOT_FOUND" in handler_defs


def test_settle_customer_claims_header_and_bindings() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "settle_customer_claims.sql")
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.specific_name == "SETTLE_CUSTOMER_CLAIMS_V2"
    assert result.ast.routine_version_id == "V2"
    assert result.ast.commit_on_return == "NO"
    bindings = [
        node.select_into_binding
        for node in result.ast.nodes
        if node.kind == NodeKind.SELECT_INTO and node.select_into_binding is not None
    ]
    assert [binding.target_names for binding in bindings] == [
        ("V_OPEN_COUNT", "V_OPEN_TOTAL", "V_MAX_RISK"),
        ("V_LAST_PAYMENT",),
    ]
    assert all(binding.arity_status == "ARITY_MATCHED" for binding in bindings)


def test_if_region_has_explicit_arm_nodes() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "process_claim_batch.sql")
    assert result.ast is not None
    by_id = {node.node_id: node for node in result.ast.nodes}
    regions = [node for node in result.ast.nodes if node.kind == NodeKind.IF_REGION]
    assert regions
    for region in regions:
        assert region.if_region is not None
        assert region.child_refs == tuple(arm.arm_id for arm in region.if_region.arms)
        for expected_index, arm in enumerate(region.if_region.arms):
            assert arm.ordered_precedence == expected_index
            arm_node = by_id[arm.arm_id]
            assert arm_node.kind == NodeKind.IF_ARM
            assert arm_node.if_arm == arm
            assert arm_node.child_refs == arm.body_node_refs
            assert arm.source_range == arm_node.source_range


def test_nested_compound_and_named_condition_are_fully_structured() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "nested_named_condition.sql")
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert not any(node.kind == NodeKind.OPAQUE for node in result.ast.nodes)

    compound = next(node for node in result.ast.nodes if node.kind == NodeKind.COMPOUND)
    assert compound.compound_region is not None
    assert compound.compound_region.label == "INNER_BLOCK"

    condition = next(node for node in result.ast.nodes if node.kind == NodeKind.DECLARE_CONDITION)
    assert condition.condition_declaration is not None
    assert condition.condition_declaration.condition_name == "CUSTOMER_NOT_FOUND"
    assert condition.condition_declaration.sqlstate == "02000"
    assert condition.lexical_scope_ref == compound.node_id

    handler = next(node for node in result.ast.nodes if node.kind == NodeKind.HANDLER_REGION)
    assert handler.handler_region is not None
    assert handler.handler_region.condition_resolution_status == "NAMED_CONDITION_RESOLVED"
    assert handler.handler_region.named_condition_ref == condition.node_id
    assert handler.handler_region.resolved_sqlstate == "02000"
    assert handler.handler_region.lexical_scope_ref == compound.node_id


def test_create_or_replace_procedure_header_is_supported() -> None:
    result = LarkSqlPlSpikeParser().parse_file(
        FIXTURES / "advanced_claim_orchestrate_db2.sql"
    )
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.schema_name == "CLAIMS"
    assert result.ast.procedure_name == "ADVANCED_CLAIM_ORCHESTRATE"
    assert len(result.ast.nodes) >= 100
