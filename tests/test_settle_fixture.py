from __future__ import annotations

from collections import Counter
from pathlib import Path

from ojas_reconciler.db2_behavior.inventory import InventoryAnalyzer
from ojas_reconciler.db2_behavior.parser_models import NodeKind, ParseOutcome
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser


FIXTURE = Path('tests/fixtures/settle_customer_claims.sql')


def test_gate0_counts_db2_constructs_without_clause_false_positives() -> None:
    report = InventoryAnalyzer().analyze_path(FIXTURE)

    assert report.procedure.routine_version_id == 'V2'
    assert report.procedure.commit_on_return == 'NO'
    assert report.control_complexity.loop_count == 1
    assert report.control_complexity.for_count == 0
    assert report.control_complexity.while_count == 1
    assert report.control_complexity.case_when_arm_count == 0
    assert report.control_complexity.merge_when_arm_count == 3
    assert report.effects.commit_count == 1
    assert report.effects.rollback_count == 1
    assert report.effects.dml_effect_count == 3
    assert report.effects.first_effect_line == 58
    assert report.effects.computed_output_derivations == {
        'P_SETTLED_COUNT': ('P_SETTLED_COUNT + 1',),
        'P_SETTLED_TOTAL': ('P_SETTLED_TOTAL + V_NET',),
    }


def test_parser_groups_compound_regions_and_preserves_select_into_bindings() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURE)

    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.specific_name == 'SETTLE_CUSTOMER_CLAIMS_V2'
    assert result.ast.routine_version_id == 'V2'
    assert result.ast.commit_on_return == 'NO'

    counts = Counter(node.kind for node in result.ast.nodes)
    assert counts[NodeKind.OPAQUE] == 0
    assert counts[NodeKind.DECLARE_VARIABLE] == 11
    assert counts[NodeKind.DECLARE_CURSOR] == 1
    assert counts[NodeKind.SELECT_INTO] == 2
    assert counts[NodeKind.HANDLER_REGION] == 2
    assert counts[NodeKind.LOOP_REGION] == 1
    assert counts[NodeKind.IF_REGION] == 6
    assert counts[NodeKind.GET_DIAGNOSTICS] == 1
    assert counts[NodeKind.FETCH_CURSOR] == 1

    bindings = [
        node.select_into_binding
        for node in result.ast.nodes
        if node.kind == NodeKind.SELECT_INTO
    ]
    assert all(binding is not None for binding in bindings)
    assert [binding.arity_status for binding in bindings if binding] == [
        'ARITY_MATCHED',
        'ARITY_MATCHED',
    ]
    assert 'HAVING COUNT(*) >= 3' in bindings[0].residual_query_text  # type: ignore[union-attr]

    loop = next(node for node in result.ast.nodes if node.kind == NodeKind.LOOP_REGION)
    assert loop.loop_region is not None
    assert loop.loop_region.loop_kind == "WHILE"
    assert loop.loop_region.label == "SETTLE_LOOP"
    assert loop.loop_region.condition_text == "V_LOOP_DONE = 0"
