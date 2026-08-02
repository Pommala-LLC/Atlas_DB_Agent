from __future__ import annotations

from pathlib import Path

from atlas import AtlasSemanticService, __version__
from atlas.application import AtlasSourceUnitService
from atlas.core.models import DialectId, SemanticNodeKind
from atlas.dialects.db2.clp import Db2ClpScriptSegmenter


FIXTURE = Path(__file__).parent / "fixtures" / "reconcile_settlement_batch_nested_case.sql"


def test_db2_clp_segmenter_does_not_truncate_on_nested_scalar_case() -> None:
    script = Db2ClpScriptSegmenter().segment_file(FIXTURE)
    assert script.expected_source_unit_count == 1
    assert script.discovered_source_unit_count == 1
    assert script.unclassified_fragment_count == 0
    assert script.source_units[0].source_range.end_line == len(FIXTURE.read_text(encoding="utf-8").splitlines())
    assert script.source_units[0].source_text.rstrip().endswith("END P_RECONCILE")


def test_nested_scalar_case_remains_one_assignment_without_opaque_fragments() -> None:
    analysis = AtlasSourceUnitService(__version__).analyze(FIXTURE, DialectId.DB2_SQL_PL)
    assert analysis.discovery_findings == ()
    assert len(analysis.routines) == 1
    bundle = analysis.routines[0]
    assert bundle.routine_ref == "CLAIMS.RECONCILE_SETTLEMENT_BATCH"
    assert bundle.semantic_report.parse_status == "COMPLETE"
    assert bundle.semantic_report.opaque_node_refs == ()
    assert bundle.routine_ir.findings == ()

    fee_assignment = next(
        node
        for node in bundle.routine_ir.nodes
        if node.kind is SemanticNodeKind.ASSIGNMENT and node.target_name == "V_FEE_RATE"
    )
    assert "WHEN V_TIER = 'PLATINUM' THEN 0.0050" in fee_assignment.text
    assert "WHEN P_AS_OF_DATE < CURRENT DATE - 30 DAYS THEN 0.0125" in fee_assignment.text
    assert "ELSE 0.0100" in fee_assignment.text
    assert fee_assignment.source_span.start_line == 103
    assert fee_assignment.source_span.end_line == 112


def test_empty_statement_is_not_an_opaque_node() -> None:
    ir, report, _ = AtlasSemanticService(__version__).analyze(FIXTURE, DialectId.DB2_SQL_PL)
    assert report.parse_status == "COMPLETE"
    assert report.opaque_node_refs == ()
    assert all(node.text.strip() != ";" for node in ir.nodes)


def test_scalar_case_fragments_are_not_misreported_as_top_level_decisions() -> None:
    _, report, _ = AtlasSemanticService(__version__).analyze(FIXTURE, DialectId.DB2_SQL_PL)
    conditions = [arm.condition_text for arm in report.decision_arms]
    assert "P_AS_OF_DATE < CURRENT DATE - 30 DAYS" not in conditions
    assert conditions == [
        "V_ROWS > 0",
        "V_DONE = 1",
        "V_HOLD_TOTAL IS NOT NULL AND V_HOLD_TOTAL > 0",
        "V_NET <= 0",
        "P_SETTLED_COUNT = 0",
        "V_ROWS > 0",
        "V_SKIPPED > 0",
        "ELSE",
    ]
