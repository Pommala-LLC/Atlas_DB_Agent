from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.analysis.models import (
    EffectKind,
    NullabilityStatus,
    SemanticFindingCode,
)
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.application.deliverables import DeliverablesGenerator
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.parsing.models import ParseOutcome


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _scenario_block(text: str, scenario_name: str) -> str:
    marker = f"Scenario: {scenario_name}"
    start = text.index(marker)
    remainder = text[start:]
    next_scenario = remainder.find("\n    Scenario:", len(marker))
    next_rule = remainder.find("\n  Rule:", len(marker))
    ends = [value for value in (next_scenario, next_rule) if value >= 0]
    end = min(ends) if ends else len(remainder)
    return remainder[:end]


def test_advanced_claim_paths_use_real_reaching_definitions_and_context(tmp_path: Path) -> None:
    output = tmp_path / "advanced"
    result = DeliverablesGenerator().generate(
        source=FIXTURES / "advanced_claim_orchestrate_db2.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    assert result.generated_bdd_files == 8
    readable = (output / "bdd" / "READABLE_CANDIDATES.feature").read_text()

    assert "Missing required HISTORY_SUMMARY row" not in readable
    assert 'Then P_FINAL_DECISION is set to "CLAIM_NOT_FOUND"' in readable

    approved = _scenario_block(readable, "Approve when no earlier decision condition applies")
    assert "P_APPROVER_ID is set to NULL" not in approved
    assert "P_AUDIT_ID is set to NULL" not in approved
    assert "APPROVER_ID is set to P_APPROVER_ID" in approved

    error = _scenario_block(readable, "Convert an unexpected SQL exception into error outputs")
    assert "Given an SQL exception occurs during procedure processing" in error
    assert "prerequisite statements complete successfully" not in error
    assert "the original SQL condition is not propagated to the caller" in error

    escalated = _scenario_block(readable, "Set P_FINAL_DECISION to manual review escalated")
    assert "P_FINAL_DECISION IN" in escalated
    assert "When one C_RELATED cursor row is evaluated" in escalated
    assert "V_ESCALATION_COUNT is set to V_ESCALATION_COUNT + 1" in escalated
    assert "125 percent" in escalated

    assert "Readable technical behavior" not in readable
    rules = [line.strip() for line in readable.splitlines() if line.startswith("  Rule:")]
    assert len(rules) == len(set(rules))


def test_settle_semantics_distinguish_conditional_impossible_and_observable_paths(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "settle_and_disburse.sql"
    parsed = LarkSqlPlSpikeParser().parse_file(source)
    assert parsed.outcome == ParseOutcome.PARSES_COMPLETE
    semantic = Phase1SemanticAnalyzer().analyze(parsed)

    findings = {finding.code for finding in semantic.findings}
    assert SemanticFindingCode.CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION in findings
    assert SemanticFindingCode.HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT in findings
    assert SemanticFindingCode.SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE in findings
    assert SemanticFindingCode.FINAL_TABLE_DATA_CHANGE_EFFECT in findings
    assert SemanticFindingCode.RETURNED_RESULT_SET in findings

    nullability = {fact.symbol_name: fact.status for fact in semantic.symbol_nullability}
    assert nullability["V_REJECTED"] == NullabilityStatus.DEFINITELY_NON_NULL
    assert nullability["V_STALE_TOTAL"] == NullabilityStatus.POSSIBLY_NULL

    kinds = {effect.effect_kind for effect in semantic.effects}
    assert EffectKind.RESULT_SET_RETURN in kinds
    assert any(
        effect.effect_kind == EffectKind.DML
        and effect.target == "DISBURSEMENT"
        and effect.value_expression == "FINAL_TABLE_INSERT_WITH_RETURNED_ROW"
        for effect in semantic.effects
    )

    atomic = next(
        bundle
        for bundle in semantic.behavior_bundles
        if any(
            effect.target == "CLAIM_AUDIT"
            and effect.effect_id in {member.effect_ref for member in bundle.effect_members}
            for effect in semantic.effects
        )
    )
    assert any(edge.atomicity == "ATOMIC_COMPOUND" for edge in atomic.ordering_edges)

    output = tmp_path / "settle-output"
    DeliverablesGenerator().generate(
        source=source,
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    readable = (output / "bdd" / "READABLE_CANDIDATES.feature").read_text()

    assert "V_REJECTED is null" not in readable
    assert "V_REJECTED is at most 0.00" not in readable
    assert readable.count("V_REJECTED is at most 0") == 1
    assert "a CLAIM_AUDIT row is inserted" in readable
    assert "a SETTLEMENT_LEDGER row is inserted" in readable
    assert "all mutations in the atomic compound succeed together" in readable
    assert "a DISBURSEMENT row is inserted and its generated row is returned by FINAL TABLE" in readable
    assert "the C_REPORT result set is returned to the client" in readable
    assert "Cursor eligibility conflicts with a prior state transition" in readable
    assert "Shared handler state can affect later cursor behavior" in readable
    assert "Exception handling may reference an unavailable savepoint" in readable
    assert "@analysis_warning" in readable

    settled = _scenario_block(readable, "Set P_STATUS to settled")
    assert "P_SETTLED_COUNT contains the accumulated value" in settled
    assert "P_DISBURSED_TOTAL contains the accumulated value" in settled
    assert "P_SETTLED_COUNT is set to 0" not in settled

    manifest = json.loads((output / "bdd" / "proposal-manifest.json").read_text())
    schema = json.loads(
        (ROOT / "contracts" / "readable-bdd-proposal-batch-1.5.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(manifest)
    assert manifest["accounting"]["readable_analysis_warning_candidates"] >= 3
    assert {
        item["analysis_status"] for item in manifest["artifacts"]
    } >= {"CONDITIONAL_TECHNICAL_CANDIDATE", "ANALYSIS_WARNING"}
