from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.analysis.models import SemanticFindingCode
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.bdd.scenario_models import (
    ScenarioBlockerCode,
    ScenarioCompilationStatus,
)
from ojas_reconciler.db2_behavior.compiler.scenario_spec import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.parsing.models import ParseOutcome

FIXTURE = Path(__file__).parent / "fixtures" / "undeclared_symbols.sql"


def _run():
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURE)
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    batch = ScenarioSpecCompiler().compile_all(parsed, semantic)
    return parsed, semantic, batch


def test_undeclared_and_out_of_scope_symbols_are_source_bound_findings() -> None:
    parsed, semantic, _ = _run()
    assert parsed.outcome == ParseOutcome.PARSES_COMPLETE
    assert parsed.ast is not None
    assert not parsed.findings

    findings = [
        finding
        for finding in semantic.findings
        if finding.code == SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE
    ]
    assert len(findings) == 2
    messages = {finding.message for finding in findings}
    assert any("V_MISSING_COUNT" in message and "no parameter or local declaration" in message for message in messages)
    assert any("V_INNER_ONLY" in message and "not visible" in message for message in messages)
    assert all(finding.evidence_node_refs for finding in findings)
    assert all(finding.source_ranges for finding in findings)


def test_undeclared_symbol_blocks_only_dependent_scenarios() -> None:
    _, semantic, batch = _run()
    dependent = [
        result
        for result in batch.compilation_results
        if ScenarioBlockerCode.UNDECLARED_SYMBOL_REFERENCE in result.blockers
    ]
    assert dependent
    assert all(result.compilation_status == ScenarioCompilationStatus.BLOCKED for result in dependent)
    assert any(
        any("V_MISSING_COUNT" in detail for detail in result.blocker_details)
        for result in dependent
    )

    # The independent first arm remains admissible. The final sequence assignment is
    # now blocked separately because NEXT VALUE FOR advances dialect-defined external state.
    assert len(batch.scenario_specs) >= 1
    assert any(
        ScenarioBlockerCode.UNRESOLVED_EFFECT_OBSERVABILITY in result.blockers
        for result in batch.compilation_results
    )


def test_validator_never_creates_an_implicit_or_typo_binding() -> None:
    parsed, semantic, _ = _run()
    assert parsed.ast is not None
    declared = {value.symbol_name for value in parsed.ast.declared_symbol_types}
    assert "V_MISSING_COUNT" not in declared
    assert "V_INNER_ONLY" in declared
    assert any(
        finding.code == SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE
        and "no automatic binding was applied" not in finding.message
        for finding in semantic.findings
    )


def test_all_source_finding_node_references_resolve_for_fixture() -> None:
    parsed, semantic, _ = _run()
    assert parsed.ast is not None
    node_ids = {node.node_id for node in parsed.ast.nodes}
    for finding in semantic.findings:
        assert set(finding.evidence_node_refs) <= node_ids
        assert len(finding.source_ranges) == len(finding.evidence_node_refs)


def test_doctor_supports_installed_distribution_mode(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.application.doctor import build_doctor_report

    report = build_doctor_report(tmp_path / "no-source-checkout")
    status = {check.check_id: check.status.value for check in report.checks}
    assert status["JSON_CONTRACTS"] == "PASS"
    assert status["PROJECT_METADATA"] == "PASS"
