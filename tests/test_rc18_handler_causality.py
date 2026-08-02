from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.analysis.models import SemanticFindingCode
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.application.deliverables import DeliverablesGenerator
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "advanced_claim_orchestrate_db2.sql"


def _rule_block(text: str, name: str) -> str:
    marker = f"  Rule: {name}"
    start = text.index(marker)
    end = text.find("\n  Rule:", start + len(marker))
    return text[start : end if end >= 0 else len(text)]


def test_validation_signal_precedes_handler_and_is_collapsed_to_outline(tmp_path: Path) -> None:
    output = tmp_path / "advanced"
    DeliverablesGenerator().generate(
        source=FIXTURE,
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    readable = (output / "bdd" / "READABLE_CANDIDATES.feature").read_text()
    validation = _rule_block(readable, "Required input validation")

    assert "Scenario Outline: Convert an invalid required input into error outputs" in validation
    assert "Given <invalid_input>" in validation
    assert "Then SQLSTATE <sqlstate> is raised internally" in validation
    assert "And the enclosing SQLEXCEPTION handler is activated" in validation
    assert validation.index("SQLSTATE <sqlstate> is raised internally") < validation.index(
        "the enclosing SQLEXCEPTION handler is activated"
    )
    assert "the original SQL condition is not propagated to the caller" in validation
    assert '| P_CLAIM_ID is null | "75001" |' in validation
    assert '| P_TENANT_ID is null or blank | "75002" |' in validation
    assert '| P_REQUESTED_BY is null or blank | "75003" |' in validation
    assert "Given the SQLEXCEPTION handler is activated" not in validation
    assert "Scenario: SQLSTATE 75001 is raised internally" not in readable

    manifest = json.loads((output / "bdd" / "proposal-manifest.json").read_text())
    schema = json.loads(
        (ROOT / "contracts" / "readable-bdd-proposal-batch-1.5.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(manifest)
    outline = next(
        item
        for item in manifest["artifacts"]
        if item["variant_key"] == "required-input-validation-outline"
    )
    assert len(outline["source_behavior_refs"]) == 3
    assert len(outline["source_bundle_refs"]) == 3


def test_handler_failure_diagnostics_and_duplicate_suppression(tmp_path: Path) -> None:
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURE)
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    codes = {finding.code for finding in semantic.findings}
    assert SemanticFindingCode.HANDLER_BODY_FAILURE_PROPAGATES in codes
    assert SemanticFindingCode.DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM in codes

    output = tmp_path / "advanced"
    DeliverablesGenerator().generate(
        source=FIXTURE,
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    readable = (output / "bdd" / "READABLE_CANDIDATES.feature").read_text()

    assert "Scenario: Error logging can fail inside the exception handler" in readable
    assert "the current handler does not catch the logging failure" in readable
    assert "successful delivery of the assigned output parameters is not established" in readable
    assert "Scenario: Verify the diagnostic item against the target Db2 profile" in readable
    assert "the EXCEPTION selector is not rejected solely as non-Db2 syntax" in readable

    assert "Rule: Claim persistence" not in readable
    assert "Rule: Claim Rejection Audit persistence" not in readable
    assert "Rule: Claim Processing Audit persistence" not in readable

    approval = _rule_block(readable, "Approval lookup")
    assert "P_APPROVER_ID is set to null" in approval
    assert "V_APPROVAL_DEPTH is set to null" in approval
    assert "V_APPROVAL_PATH is set to null" in approval
    assert " is set to NULL" not in readable
