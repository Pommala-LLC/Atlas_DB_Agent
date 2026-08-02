from pathlib import Path

from ojas_reconciler.db2_behavior.inventory import InventoryAnalyzer
from ojas_reconciler.db2_behavior.models import Eligibility

FIXTURES = Path(__file__).parent / "fixtures"


def test_eligible_fixture() -> None:
    report = InventoryAnalyzer().analyze_path(FIXTURES / "eligible_claim.sql")
    assert report.procedure.schema_name == "CLAIMS"
    assert report.procedure.name == "EVALUATE_CLAIM"
    assert report.procedure.out_parameter_names == ("P_DECISION",)
    assert report.effects.out_assignment_count == 2
    assert report.effects.computed_out_assignment_count == 0
    assert report.eligibility == Eligibility.POC_FULLY_ELIGIBLE


def test_partial_fixture() -> None:
    report = InventoryAnalyzer().analyze_path(FIXTURES / "partial_complex.sql")
    assert report.query_complexity.left_join_count == 1
    assert report.control_complexity.handler_count == 1
    assert report.control_complexity.loop_count >= 1
    assert report.effects.computed_out_assignment_count == 1
    assert report.eligibility == Eligibility.POC_PARTIAL_SLICE_EXPECTED


def test_comments_and_literals_do_not_create_false_keywords() -> None:
    report = InventoryAnalyzer().analyze_path(FIXTURES / "dynamic_and_comments.sql")
    assert report.control_complexity.if_count == 0
    assert report.query_complexity.join_count == 0
    assert report.effects.prepare_count == 1
    assert report.dynamic_sql_present is True
    assert report.eligibility == Eligibility.POC_PARSE_ONLY


def test_tool_inspection_reports_required_tools() -> None:
    from ojas_reconciler.db2_behavior.tooling import inspect_tools

    statuses = {status.package: status for status in inspect_tools()}
    assert statuses["pydantic"].installed is True
    assert statuses["lark"].installed is True
    assert statuses["networkx"].installed is True


def test_window_function_count_counts_window_specs_once() -> None:
    report = InventoryAnalyzer().analyze_path(FIXTURES / "process_claim_batch.sql")
    assert report.query_complexity.window_function_count == 1


def test_mega_inventory_detects_structural_recursion_and_not_sequence_for_loop() -> None:
    result = InventoryAnalyzer().analyze_path(FIXTURES / "mega_claim_processing.sql")
    assert result.query_complexity.recursive_cte_count == 1
    assert result.control_complexity.for_count == 0
    assert result.control_complexity.generic_loop_count == 1
    assert result.control_complexity.loop_count == 1
    # Bare JOIN is semantically an inner join and remains in the inner count.
    assert result.query_complexity.join_count == 4
    assert result.query_complexity.inner_join_count == 4
