from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from atlas import POLICY, AtlasSemanticService, DialectId, __version__
from atlas.core.models import RoutineKind, SemanticNodeKind
from atlas.renderers import render_gherkin, render_graph


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "polyglot"
DIALECT_CASES = {
    DialectId.ORACLE_PLSQL: "oracle_claim_process.sql",
    DialectId.SQLSERVER_TSQL: "sqlserver_claim_process.sql",
    DialectId.POSTGRESQL_PLPGSQL: "postgresql_claim_process.sql",
    DialectId.MYSQL_STORED_PROGRAM: "mysql_claim_process.sql",
}


@pytest.fixture(scope="module")
def service() -> AtlasSemanticService:
    return AtlasSemanticService(__version__)


@pytest.mark.parametrize(("dialect", "filename"), DIALECT_CASES.items())
def test_every_database_has_full_body_semantic_pipeline(service: AtlasSemanticService, dialect: DialectId, filename: str) -> None:
    ir, report, scenarios = service.analyze(FIXTURES / filename, dialect)
    assert ir.dialect is dialect
    assert report.parse_status == "COMPLETE"
    assert report.opaque_node_refs == ()
    assert not any(finding.severity == "ERROR" for finding in ir.findings)
    assert report.decision_arms
    assert report.effects
    assert scenarios.scenarios
    assert any(node.kind is SemanticNodeKind.ASSIGNMENT for node in ir.nodes)
    assert any(node.kind in {SemanticNodeKind.INSERT, SemanticNodeKind.UPDATE, SemanticNodeKind.MERGE} for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.ERROR_HANDLER for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.ERROR_RAISE for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.DYNAMIC_SQL for node in ir.nodes)
    assert any(node.kind in {SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK} for node in ir.nodes)
    assert ir.content_digest.startswith("sha256:")
    assert report.content_digest.startswith("sha256:")


def test_oracle_semantics_are_dialect_specific(service: AtlasSemanticService) -> None:
    ir, report, _ = service.analyze(FIXTURES / DIALECT_CASES[DialectId.ORACLE_PLSQL], DialectId.ORACLE_PLSQL)
    select_into = next(node for node in ir.nodes if node.kind is SemanticNodeKind.SELECT_INTO)
    handler = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER)
    dynamic = next(node for node in ir.nodes if node.kind is SemanticNodeKind.DYNAMIC_SQL)
    assert select_into.attributes["cardinality_semantics"] == "EXACTLY_ONE_OR_NO_DATA_FOUND_OR_TOO_MANY_ROWS"
    assert handler.attributes["handler_semantics"] == "EXIT_DECLARING_BLOCK"
    assert dynamic.attributes["dynamic_semantics"] == "EXECUTE_IMMEDIATE"
    assert report.handler_node_refs


def test_sqlserver_semantics_are_dialect_specific(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / DIALECT_CASES[DialectId.SQLSERVER_TSQL], DialectId.SQLSERVER_TSQL)
    handlers = [node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER]
    transaction = next(node for node in ir.nodes if node.kind is SemanticNodeKind.TRANSACTION_BEGIN)
    assert handlers and all(node.attributes["handler_semantics"] == "TRY_CATCH" for node in handlers)
    assert transaction.attributes["transaction_registers"] == ("@@TRANCOUNT", "XACT_STATE()")
    assert any(node.kind is SemanticNodeKind.RESULT_SET for node in ir.nodes)


def test_postgresql_semantics_are_dialect_specific(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / DIALECT_CASES[DialectId.POSTGRESQL_PLPGSQL], DialectId.POSTGRESQL_PLPGSQL)
    handler = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER)
    select_into = next(node for node in ir.nodes if node.kind is SemanticNodeKind.SELECT_INTO)
    dynamic = next(node for node in ir.nodes if node.kind is SemanticNodeKind.DYNAMIC_SQL)
    assert handler.attributes["block_changes_rolled_back_before_handler"] is True
    assert select_into.attributes["cardinality_semantics"] == "STRICT_EXACTLY_ONE"
    assert dynamic.attributes["dynamic_semantics"] == "PLPGSQL_EXECUTE"
    assert dynamic.attributes["updates_found_register"] is False


def test_mysql_semantics_are_dialect_specific(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / DIALECT_CASES[DialectId.MYSQL_STORED_PROGRAM], DialectId.MYSQL_STORED_PROGRAM)
    handlers = [node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER]
    cursor = next(node for node in ir.nodes if node.kind is SemanticNodeKind.CURSOR_DECLARE)
    assert {node.attributes.get("handler_action") for node in handlers} >= {"CONTINUE", "EXIT"}
    assert cursor.attributes["cursor_updatability"] == "READ_ONLY"
    assert cursor.attributes["cursor_scrollability"] == "NONSCROLLABLE"


def test_outputs_are_database_neutral_and_deterministic(service: AtlasSemanticService) -> None:
    source = FIXTURES / "oracle_claim_process.sql"
    first = service.analyze(source, DialectId.ORACLE_PLSQL)
    second = service.analyze(source, DialectId.ORACLE_PLSQL)
    assert first[0].content_digest == second[0].content_digest
    assert first[1].content_digest == second[1].content_digest
    assert first[2].content_digest == second[2].content_digest
    feature = render_gherkin(first[2])
    assert "@non_authoritative" in feature
    assert "ORACLE_PLSQL behavior candidates" in feature
    graph = render_graph(first[0])
    assert graph["schema_version"] == "atlas-routine-graph-1.0"
    assert graph["dialect"] == "ORACLE_PLSQL"


def test_atlas_cli_generates_all_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "atlas-output"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "atlas",
            "analyze",
            str(FIXTURES / "postgresql_claim_process.sql"),
            "--dialect",
            "postgresql",
            "--output",
            str(output),
            "--emit-gherkin",
            "--emit-graph",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["product"] == "Atlas"
    assert summary["parse_status"] == "COMPLETE"
    for relative in (
        "routine-ir.json",
        "semantic-report.json",
        "scenario-candidates.json",
        "behavior-candidates.feature",
        "routine-graph.json",
    ):
        assert (output / relative).exists()


def test_atlas_schema_contracts_validate(service: AtlasSemanticService) -> None:
    ir, report, scenarios = service.analyze(FIXTURES / "mysql_claim_process.sql", DialectId.MYSQL_STORED_PROGRAM)
    mapping = {
        "atlas-routine-ir-1.0.schema.json": ir.model_dump(mode="json"),
        "atlas-routine-semantic-report-1.0.schema.json": report.model_dump(mode="json"),
        "atlas-scenario-candidate-batch-1.0.schema.json": scenarios.model_dump(mode="json"),
        "atlas-routine-graph-1.0.schema.json": render_graph(ir),
    }
    for name, payload in mapping.items():
        schema = json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_atlas_naming_is_frozen_without_rewriting_legacy_evidence() -> None:
    policy = json.loads((ROOT / "ATLAS_NAMING_MIGRATION.json").read_text(encoding="utf-8"))
    assert POLICY.product_name == "Atlas"
    assert POLICY.distribution_name == "atlas-procedure-intelligence"
    assert policy["status"] == "FROZEN"
    assert policy["canonical"]["python_namespace"] == "atlas"
    assert policy["artifact_policy"]["existing_content_digests"] == "NEVER_REWRITTEN"
    assert policy["legacy_compatibility"]["python_namespace"] == "ojas_reconciler.db2_behavior"


def test_atlas_core_is_decoupled_from_legacy_namespace() -> None:
    for relative in ("core", "dialects", "application", "renderers"):
        for path in (ROOT / "src" / "atlas" / relative).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "ojas_reconciler" not in text, f"Legacy coupling in {path.relative_to(ROOT)}"


def test_function_and_trigger_headers_are_supported(tmp_path: Path, service: AtlasSemanticService) -> None:
    cases = [
        (DialectId.ORACLE_PLSQL, "CREATE OR REPLACE FUNCTION calc(p_x NUMBER) RETURN NUMBER AS BEGIN RETURN p_x + 1; END; /", RoutineKind.FUNCTION),
        (DialectId.SQLSERVER_TSQL, "CREATE OR ALTER FUNCTION dbo.calc(@x int) RETURNS int AS BEGIN RETURN @x + 1; END;", RoutineKind.FUNCTION),
        (DialectId.POSTGRESQL_PLPGSQL, "CREATE OR REPLACE FUNCTION calc(p_x int) RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN p_x + 1; END; $$;", RoutineKind.FUNCTION),
        (DialectId.MYSQL_STORED_PROGRAM, "CREATE TRIGGER trg BEFORE INSERT ON claim FOR EACH ROW BEGIN SET NEW.updated_at = CURRENT_TIMESTAMP; END;", RoutineKind.TRIGGER),
    ]
    for index, (dialect, text, expected_kind) in enumerate(cases):
        source = tmp_path / f"case-{index}.sql"
        source.write_text(text, encoding="utf-8")
        ir, report, _ = service.analyze(source, dialect)
        assert ir.routine_kind is expected_kind
        assert report.parse_status == "COMPLETE"
        assert report.opaque_node_refs == ()

EXTENDED_CASES = {
    DialectId.ORACLE_PLSQL: "oracle_extended_semantics.sql",
    DialectId.SQLSERVER_TSQL: "sqlserver_extended_semantics.sql",
    DialectId.POSTGRESQL_PLPGSQL: "postgresql_extended_semantics.sql",
    DialectId.MYSQL_STORED_PROGRAM: "mysql_extended_semantics.sql",
}


@pytest.mark.parametrize(("dialect", "filename"), EXTENDED_CASES.items())
def test_extended_vendor_constructs_have_no_opaque_nodes(service: AtlasSemanticService, dialect: DialectId, filename: str) -> None:
    ir, report, _ = service.analyze(FIXTURES / filename, dialect)
    assert report.parse_status == "COMPLETE"
    assert report.opaque_node_refs == ()
    assert not [finding for finding in ir.findings if finding.severity == "ERROR"]
    assert ir.routine_attributes


def test_structured_branch_parentage_is_preserved(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "sqlserver_claim_process.sql", DialectId.SQLSERVER_TSQL)
    conditions = [node for node in ir.nodes if node.kind is SemanticNodeKind.CONDITION]
    root = next(node for node in conditions if node.condition_text == "@ClaimId IS NULL")
    elseif = next(node for node in conditions if node.condition_text == "@Amount > 100000")
    else_node = next(node for node in conditions if node.condition_text == "ELSE")
    review = next(node for node in ir.nodes if node.target_name == "DECISION" and "REVIEW" in (node.expression_text or ""))
    assert elseif.parent_ref == root.node_id
    assert else_node.parent_ref == root.node_id
    by_id = {node.node_id: node for node in ir.nodes}
    ancestor = review.parent_ref
    lineage: set[str] = set()
    while ancestor:
        lineage.add(ancestor)
        ancestor = by_id[ancestor].parent_ref
    assert elseif.node_id in lineage


def test_mysql_inline_handler_does_not_leak_scope(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "mysql_claim_process.sql", DialectId.MYSQL_STORED_PROGRAM)
    inline = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER and "CONTINUE HANDLER" in node.text.upper())
    later = next(node for node in ir.nodes if node.target_name == "SQL_TEXT")
    assert inline.parent_ref is not None
    assert later.parent_ref == inline.parent_ref


def test_oracle_extended_semantics(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "oracle_extended_semantics.sql", DialectId.ORACLE_PLSQL)
    assert ir.routine_attributes["security_mode"] == "CURRENT_USER"
    assert ir.routine_attributes["autonomous_transaction_declared"] is True
    pragma = [node for node in ir.nodes if node.kind is SemanticNodeKind.PRAGMA]
    bulk = [node for node in ir.nodes if node.kind is SemanticNodeKind.BULK_OPERATION]
    assert any(node.attributes.get("autonomous_transaction") for node in pragma)
    assert {node.attributes.get("bulk_semantics") for node in bulk} == {"BULK_COLLECT", "FORALL"}
    assert any(node.kind is SemanticNodeKind.GOTO for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.LOCK for node in ir.nodes)


def test_sqlserver_extended_semantics(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "sqlserver_extended_semantics.sql", DialectId.SQLSERVER_TSQL)
    assert ir.routine_attributes["security_mode"] == "OWNER"
    assert ir.routine_attributes["recompile"] is True
    settings = [node for node in ir.nodes if node.kind is SemanticNodeKind.TRANSACTION_SETTING]
    assert any(node.attributes.get("xact_abort") for node in settings)
    assert any(node.attributes.get("isolation_level") == "SERIALIZABLE" for node in settings)
    update = next(node for node in ir.nodes if node.kind is SemanticNodeKind.UPDATE)
    assert update.attributes["output_clause"] is True
    assert any(node.kind is SemanticNodeKind.TEMP_OBJECT for node in ir.nodes)


def test_postgresql_extended_semantics(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "postgresql_extended_semantics.sql", DialectId.POSTGRESQL_PLPGSQL)
    assert ir.routine_attributes["security_mode"] == "DEFINER"
    assert ir.routine_attributes["volatility"] == "VOLATILE"
    assertion = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ASSERT)
    assert assertion.attributes["assertion_failure_sqlstate"] == "P0004"
    assert any(node.kind is SemanticNodeKind.UPSERT for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.LOCK for node in ir.nodes)


def test_mysql_extended_semantics(service: AtlasSemanticService) -> None:
    ir, _, _ = service.analyze(FIXTURES / "mysql_extended_semantics.sql", DialectId.MYSQL_STORED_PROGRAM)
    assert ir.routine_attributes["security_mode"] == "INVOKER"
    assert ir.routine_attributes["sql_data_access"] == "MODIFIES SQL DATA"
    condition = next(node for node in ir.nodes if node.kind is SemanticNodeKind.CONDITION_DECLARE)
    assert condition.attributes["declaration_semantics"] == "NAMED_CONDITION"
    assert any(node.kind is SemanticNodeKind.UPSERT for node in ir.nodes)
    assert any(node.kind is SemanticNodeKind.DIAGNOSTICS for node in ir.nodes)


def test_postgresql_function_transaction_control_is_rejected(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = tmp_path / "invalid-pg-function.sql"
    source.write_text(
        "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN COMMIT; RETURN 1; END; $$;",
        encoding="utf-8",
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "PARTIAL"
    assert "POSTGRES_TRANSACTION_CONTROL_OUTSIDE_PROCEDURE" in {finding.code for finding in ir.findings}


def test_mysql_function_restrictions_are_findings(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = tmp_path / "invalid-mysql-function.sql"
    source.write_text(
        "CREATE FUNCTION f(p_id int) RETURNS int DETERMINISTIC BEGIN START TRANSACTION; PREPARE s FROM 'SELECT 1'; SELECT p_id; RETURN p_id; END;",
        encoding="utf-8",
    )
    ir, report, _ = service.analyze(source, DialectId.MYSQL_STORED_PROGRAM)
    codes = {finding.code for finding in ir.findings}
    assert report.parse_status == "PARTIAL"
    assert "MYSQL_TRANSACTION_CONTROL_NOT_ALLOWED_IN_FUNCTION_OR_TRIGGER" in codes
    assert "MYSQL_DYNAMIC_SQL_NOT_ALLOWED_IN_FUNCTION_OR_TRIGGER" in codes
    assert "MYSQL_RESULT_SET_NOT_ALLOWED_IN_FUNCTION" in codes


def test_source_unit_discovers_multiple_routines(tmp_path: Path) -> None:
    from atlas.application import AtlasSourceUnitService
    result = AtlasSourceUnitService(__version__).analyze(
        FIXTURES / "oracle_source_unit.sql",
        DialectId.ORACLE_PLSQL,
    )
    assert [item.routine_ref for item in result.routines] == [
        "CLAIMS.VALIDATE_CLAIM(IN:NUMBER,OUT:NUMBER)",
        "CLAIMS.CLAIM_SCORE(IN:NUMBER)",
    ]
    assert not result.discovery_findings
    schema = json.loads((ROOT / "contracts" / "atlas-source-unit-analysis-1.0.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result.model_dump(mode="json"))
    output = tmp_path / "unit.json"
    completed = subprocess.run([
        sys.executable, "-m", "atlas", "analyze-unit",
        str(FIXTURES / "oracle_source_unit.sql"),
        "--dialect", "oracle", "--output", str(output),
    ], cwd=ROOT, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["routines_analyzed"] == 2


def test_atlas_semantic_coverage_manifest_is_digest_bound_and_complete() -> None:
    from atlas.core.canonical import canonical_digest
    from atlas.core.models import DialectId
    from atlas.product import load_semantic_coverage_manifest

    manifest = load_semantic_coverage_manifest()
    assert manifest.product_name == "Atlas"
    assert {entry.dialect for entry in manifest.dialects} == set(DialectId)
    assert all(entry.status == "DIALECT_BOUNDED_SEMANTICS" for entry in manifest.dialects)
    payload = manifest.model_dump(mode="json", exclude={"content_digest"})
    assert manifest.content_digest == canonical_digest(payload)
    assert all("unclassified_vendor_extensions_are_retained_as_opaque_nodes_with_source_spans" in entry.explicit_boundaries for entry in manifest.dialects)


def test_atlas_naming_and_coverage_contracts_are_packaged() -> None:
    from importlib.resources import files

    root = files("atlas")
    assert root.joinpath("ATLAS_NAMING_MIGRATION.json").is_file()
    assert root.joinpath("ATLAS_NAMING_COMPATIBILITY_POLICY.json").is_file()
    assert root.joinpath("ATLAS_CAPABILITY_MANIFEST.json").is_file()
    assert root.joinpath("ATLAS_DIALECT_COVERAGE.json").is_file()


def test_atlas_cli_exposes_frozen_coverage_and_naming(capsys) -> None:
    from atlas.cli import main

    assert main(["coverage"]) == 0
    coverage = json.loads(capsys.readouterr().out)
    assert coverage["product_name"] == "Atlas"
    assert len(coverage["dialects"]) == 5

    assert main(["naming"]) == 0
    naming = json.loads(capsys.readouterr().out)
    assert naming["canonical"]["product_name"] == "Atlas"
    assert naming["status"] == "FROZEN_WITH_COMPATIBILITY_POLICY"


def test_db2_multiline_case_expression_remains_one_assignment(service: AtlasSemanticService) -> None:
    source = ROOT / "tests" / "fixtures" / "advanced_claim_orchestrate_db2.sql"
    ir, report, _ = service.analyze(source, DialectId.DB2_SQL_PL)
    score = next(node for node in ir.nodes if node.target_name == "V_SCORE" and "V_LIFETIME_COUNT" in (node.expression_text or ""))
    assert "WHEN V_MAX_SELF_AMOUNT > 0" in score.text
    assert "CASE WHEN V_DOC_COUNT < 2" in score.text
    assert report.opaque_node_refs == ()
