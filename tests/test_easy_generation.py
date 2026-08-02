from __future__ import annotations

import json

import pytest
from pathlib import Path

from ojas_reconciler.db2_behavior.application.deliverables import (
    DeliverablesGenerationBlocked,
    DeliverablesGenerator,
)
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode
from ojas_reconciler.db2_behavior.testkit.models import BddTestCaseBatch, BddTestPackageManifest, ExecutionMode


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def test_easy_generator_creates_one_folder_with_bdd_and_external_test_assets(tmp_path: Path) -> None:
    output = tmp_path / "generated"
    result = DeliverablesGenerator().generate(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )

    assert result.output_dir == output.resolve()
    assert result.generated_bdd_files >= 1
    assert result.generated_test_cases == result.generated_bdd_files
    assert result.test_execution_status == "BLOCKED_PENDING_DB2_AND_RELATIONAL_DATA"
    assert (output / "OPEN_ME_FIRST.txt").exists()
    assert (output / "bdd" / "READABLE_CANDIDATES.feature").exists()
    assert list((output / "bdd" / "technical").glob("*.feature"))
    assert (output / "extraction" / "03-semantic-phase2-4.json").exists()
    assert (output / "test-package" / "specs" / "test-cases.json").exists()
    assert (output / "test-package" / "data" / "test-data-requirements.json").exists()
    assert (output / "test-package" / "results" / "execution.json").exists()
    assert (output / "test-package" / "results" / "junit.xml").exists()

    manifest = BddTestPackageManifest.model_validate_json(
        (output / "test-package" / "test-package.json").read_text(encoding="utf-8")
    )
    assert manifest.execution_mode is ExecutionMode.GENERATE_ONLY
    cases = BddTestCaseBatch.model_validate_json(
        (output / "test-package" / "specs" / "test-cases.json").read_text(encoding="utf-8")
    )
    assert len(cases.test_cases) == result.generated_test_cases
    assert all(case.expected_status.value == "BLOCKED" for case in cases.test_cases)

    execution = json.loads((output / "test-package" / "results" / "execution.json").read_text())
    assert execution["actual_blocked"] == result.generated_test_cases
    assert execution["live_database_executed"] is False


def test_easy_generator_default_output_is_beside_sql_file(tmp_path: Path) -> None:
    source = tmp_path / "sample.sql"
    source.write_text((FIXTURES / "eligible_claim.sql").read_text(encoding="utf-8"), encoding="utf-8")
    result = DeliverablesGenerator().generate(source=source)
    assert result.output_dir == (tmp_path / "sample-agent-output").resolve()


def test_windows_entry_points_are_consolidated_and_explicit() -> None:
    analyze = (ROOT / "ATLAS_ANALYZE.bat").read_text(encoding="utf-8")
    console = (ROOT / "ATLAS_CONSOLE.bat").read_text(encoding="utf-8")
    e2e = (ROOT / "RUN_UI_E2E.bat").read_text(encoding="utf-8")

    assert 'call "%APP_ROOT%build.bat"' in analyze
    assert "-m atlas analyze" in analyze
    assert "DIALECT_REQUIRED" in analyze
    assert '--dialect "%DIALECT%"' in analyze
    assert "-m atlas serve" in console
    assert "ATLAS_UI_WORKSPACE" in console
    assert "tests\\test_procedure_analysis_ui_e2e.py" in e2e

    top_level_batch_files = {path.name for path in ROOT.glob("*.bat")}
    assert top_level_batch_files == {
        "ATLAS_ANALYZE.bat",
        "ATLAS_CONSOLE.bat",
        "RUN_UI_E2E.bat",
        "build.bat",
    }
    assert (ROOT / "scripts" / "resolve_python.bat").exists()
    assert not (ROOT / "RUN_AGENT.bat").exists()
    assert not (ROOT / "RUN_COMMERCIAL_UI.bat").exists()

def test_python_resolver_accepts_313_and_314_without_hidden_default() -> None:
    resolver = (ROOT / "scripts" / "resolve_python.bat").read_text(encoding="utf-8")
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "py -3 -c" in resolver
    assert "Python 3.13 and Python 3.14" in resolver
    assert "py -3.13 -c" not in resolver
    assert 'requires-python = ">=3.13,<3.15"' in metadata


def test_easy_generator_can_reuse_existing_output_database(tmp_path: Path) -> None:
    output = tmp_path / "generated-repeat"
    generator = DeliverablesGenerator()

    first = generator.generate(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    second = generator.generate(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )

    assert first.generated_bdd_files == second.generated_bdd_files
    assert (output / "extraction" / "evidence-cache.sqlite3").exists()
    assert (output / "OPEN_ME_FIRST.txt").exists()


def test_easy_generator_separates_readable_and_technical_bdd(tmp_path: Path) -> None:
    output = tmp_path / "readable"
    result = DeliverablesGenerator().generate(
        source=FIXTURES / "comprehensive_claim_assess.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )

    # The previously admitted fraud branch now carries the dominating score
    # co-effect. Its partial score slice therefore blocks authority-bound BDD,
    # while the readable layer still exposes every technical candidate.
    assert result.generated_bdd_files == 0
    assert result.readable_candidate_files == 11
    readable = (output / "bdd" / "READABLE_CANDIDATES.feature").read_text(encoding="utf-8")
    assert readable.count("@technical_candidate") == 1
    assert readable.count("@non_authoritative") == 1
    assert readable.count("@requires_vocabulary_approval") == 1
    assert "# behavior_id:" not in readable
    assert "# scenario_spec_ref:" not in readable
    assert "# technical_gherkin_artifact_ref:" not in readable
    assert "These scenarios are deterministic technical proposals" not in readable
    assert "V_FRAUD_FLAG equals" not in readable
    assert 'the FRAUD_WATCHLIST lookup finds a row where ACTIVE_IND equals "Y"' in readable
    assert 'Then P_FINAL_DECISION is set to "REJECTED_FRAUD"' in readable
    assert 'And P_CONFIDENCE_SCORE is set to the rounded computed confidence score' in readable
    assert 'And P_EXCEPTION_FLAG is set to "Y"' in readable
    assert "Reject when the high-risk condition applies" in readable
    assert "Send the case to manual review with the preceding exception condition" in readable
    assert "Approve an eligible case with monitoring when confidence score is null" in readable
    assert "Missing required RISK_FACTOR_WEIGHTS row terminates the procedure" in readable
    assert "the qualifying CLAIM row count is at least 10" in readable
    assert "the CLAIM_DOCUMENT query row count" in readable

    # No blocked readable proposal may masquerade as authority-bound output.
    assert list((output / "bdd" / "technical").glob("*.feature")) == []

    manifest = json.loads((output / "bdd" / "proposal-manifest.json").read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "contracts" / "readable-bdd-proposal-batch-1.5.schema.json").read_text())
    Draft202012Validator(schema).validate(manifest)
    assert manifest["authority_scope"] == "NON_AUTHORITATIVE_PROPOSAL"
    assert manifest["review_required"] is True
    assert manifest["accounting"] == {
        "semantic_behavior_bundles": 6,
        "scenario_admitted": 0,
        "scenario_blocked": 6,
        "readable_behavior_candidates": 9,
        "readable_unhandled_condition_candidates": 2,
        "readable_analysis_warning_candidates": 0,
            "readable_suppressed_composed_candidates": 0,
        "readable_total": 11,
        "omitted_semantic_behavior_bundles": 0,
    }
    admitted = [
        item for item in manifest["artifacts"]
        if item["analysis_status"] == "ADMITTED_TECHNICAL_SCENARIO"
    ]
    conditional = [
        item for item in manifest["artifacts"]
        if item["analysis_status"] == "CONDITIONAL_TECHNICAL_CANDIDATE"
    ]
    assert admitted == []
    assert len(conditional) == 9
    assert all(item["technical_gherkin_artifact_ref"] is None for item in conditional)
    assert all(item["blocker_codes"] for item in conditional)


def test_readable_candidate_does_not_exist_without_compiler_emission(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.compiler.readable_candidate import ReadableCandidateRenderer

    parse_payload = {
        "ast": {"procedure_name": "P", "schema_name": "S"},
    }
    batch = ReadableCandidateRenderer().render(
        parse_payload=parse_payload,
        semantic_payload={"effects": [], "predicate_graphs": []},
        scenario_payload={"scenario_specs": [{"behavior_id": "behavior-1"}]},
        bdd_payload={"gherkin_artifacts": []},
    )
    assert batch["artifacts"] == ()
    assert batch["combined_text"].startswith(
        "@technical_candidate @non_authoritative @requires_vocabulary_approval"
    )
    assert "#" not in batch["combined_text"]


def test_easy_generator_supports_create_or_replace_procedure(tmp_path: Path) -> None:
    output = tmp_path / "advanced"
    result = DeliverablesGenerator().generate(
        source=FIXTURES / "advanced_claim_orchestrate_db2.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    assert result.generated_bdd_files == 8
    assert result.readable_candidate_files == 18
    parse_payload = json.loads((output / "extraction" / "02-parse.json").read_text())
    assert parse_payload["outcome"] == "PARSES_COMPLETE"
    assert (output / "extraction" / "03-semantic-phase2-4.json").exists()


def test_easy_generator_reports_upstream_blocker_instead_of_missing_artifact(
    tmp_path: Path,
) -> None:
    source = tmp_path / "broken.sql"
    source.write_text(
        "CREATE PROCEDURE CLAIMS.BROKEN(IN P_ID BIGINT) LANGUAGE SQL BEGIN",
        encoding="utf-8",
    )
    output = tmp_path / "broken-output"

    with pytest.raises(DeliverablesGenerationBlocked) as captured:
        DeliverablesGenerator().generate(
            source=source,
            output_dir=output,
            authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
        )

    message = str(captured.value)
    assert "PHASE_1_PARSE_EVIDENCE" in message
    assert "UNBALANCED_COMPOUND_STATEMENT" in message
    assert "03-semantic-phase2-4.json" in message
    assert "FileNotFoundError" not in message
    assert (output / "extraction" / "run-manifest.json").exists()
