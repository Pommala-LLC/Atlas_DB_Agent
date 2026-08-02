from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.analysis.models import (
    EffectKind,
    EffectObservability,
    SemanticFindingCode,
)
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.parsing.models import ParseOutcome

FIXTURE = Path(__file__).parent / "fixtures" / "mega_claim_processing.sql"


def _analyze():
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURE)
    assert parsed.outcome == ParseOutcome.PARSES_COMPLETE
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    return parsed, semantic


def test_sequence_value_acquisition_is_an_external_state_effect() -> None:
    _, semantic = _analyze()
    sequence_effects = [
        effect
        for effect in semantic.effects
        if effect.effect_kind == EffectKind.SEQUENCE_VALUE_ACQUISITION
    ]
    assert len(sequence_effects) == 1
    effect = sequence_effects[0]
    assert effect.target == "AUDIT_SEQ"
    assert effect.value_expression == "NEXT VALUE FOR AUDIT_SEQ"
    assert effect.observability == EffectObservability.UNRESOLVED_EFFECT_BOUNDARY

    finding = next(
        finding
        for finding in semantic.findings
        if finding.code
        == SemanticFindingCode.SEQUENCE_ADVANCE_ROLLBACK_SEMANTICS_DIALECT_DEFINED
    )
    assert "nondeterministic" in finding.consequence
    assert "configured Db2 dialect profile" in finding.consequence


def test_exit_handler_scope_propagation_and_logging_are_explicit() -> None:
    _, semantic = _analyze()
    swallowed = [
        fact
        for fact in semantic.handler_semantics
        if fact.exited_compound_statement_ref is not None
    ]
    assert len(swallowed) == 1
    fact = swallowed[0]
    assert fact.handler_scope_ref == "procedure-body"
    assert fact.exited_compound_statement_ref == "procedure-body"
    assert fact.procedure_continues_after_scope is False
    assert fact.resignal_present is False
    assert fact.original_condition_propagated is False
    assert fact.logging_transaction_scope == "CALLER_UNIT_OF_WORK"
    assert fact.rollback_visibility == "ROLLS_BACK_WITH_CALLER"

    codes = {finding.code for finding in semantic.findings}
    assert SemanticFindingCode.HANDLER_SWALLOWS_ORIGINAL_CONDITION in codes
    assert SemanticFindingCode.HANDLER_LOGGING_ROLLBACK_COUPLED in codes


def test_sqlerrm_is_qualified_by_dialect_instead_of_declared_invalid() -> None:
    _, semantic = _analyze()
    findings = [
        finding
        for finding in semantic.findings
        if finding.code == SemanticFindingCode.DIALECT_SYMBOL_COMPATIBILITY_UNRESOLVED
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert "configured DB2_SQL_PL dialect profile" in finding.message
    assert "platform and compatibility mode" in finding.message
    assert "GET DIAGNOSTICS" in finding.message
    combined = f"{finding.message} {finding.consequence}".lower()
    assert "will not compile" not in combined
    assert "no compile failure" in combined
