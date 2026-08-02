from __future__ import annotations

from pathlib import Path

import pytest

from atlas import AtlasSemanticService, DialectId, __version__
from atlas.core.models import RoutineKind, SemanticNodeKind
from atlas.dialects.db2 import CAPABILITIES as DB2_CAPABILITIES
from atlas.dialects.db2 import NORMALIZER as DB2_NORMALIZER
from atlas.dialects.db2 import Db2SemanticPolicy, Db2SqlPlAdapter, Db2StatementClassifier
from atlas.dialects.mysql import CAPABILITIES as MYSQL_CAPABILITIES
from atlas.dialects.mysql import NORMALIZER as MYSQL_NORMALIZER
from atlas.dialects.mysql import MySqlSemanticPolicy, MySqlStoredProgramAdapter, MySqlStatementClassifier
from atlas.dialects.oracle import CAPABILITIES as ORACLE_CAPABILITIES
from atlas.dialects.oracle import NORMALIZER as ORACLE_NORMALIZER
from atlas.dialects.oracle import OraclePlSqlAdapter, OracleSemanticPolicy, OracleStatementClassifier
from atlas.dialects.postgresql import CAPABILITIES as POSTGRES_CAPABILITIES
from atlas.dialects.postgresql import NORMALIZER as POSTGRES_NORMALIZER
from atlas.dialects.postgresql import PostgreSqlPlPgSqlAdapter, PostgreSqlSemanticPolicy, PostgreSqlStatementClassifier
from atlas.dialects.sqlserver import CAPABILITIES as SQLSERVER_CAPABILITIES
from atlas.dialects.sqlserver import NORMALIZER as SQLSERVER_NORMALIZER
from atlas.dialects.sqlserver import SqlServerSemanticPolicy, SqlServerStatementClassifier, SqlServerTSqlAdapter


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("adapter_type", "classifier_type", "policy_type"),
    (
        (Db2SqlPlAdapter, Db2StatementClassifier, Db2SemanticPolicy),
        (OraclePlSqlAdapter, OracleStatementClassifier, OracleSemanticPolicy),
        (SqlServerTSqlAdapter, SqlServerStatementClassifier, SqlServerSemanticPolicy),
        (PostgreSqlPlPgSqlAdapter, PostgreSqlStatementClassifier, PostgreSqlSemanticPolicy),
        (MySqlStoredProgramAdapter, MySqlStatementClassifier, MySqlSemanticPolicy),
    ),
)
def test_each_dialect_package_owns_classifier_and_policy(adapter_type: type, classifier_type: type, policy_type: type) -> None:
    adapter = adapter_type(__version__)
    assert isinstance(adapter.classifier, classifier_type)
    assert isinstance(adapter.semantic_policy, policy_type)
    assert adapter.classifier.dialect is adapter.dialect
    assert adapter.semantic_policy.dialect is adapter.dialect


def test_every_dialect_exports_executable_capabilities() -> None:
    capabilities = (
        DB2_CAPABILITIES,
        ORACLE_CAPABILITIES,
        SQLSERVER_CAPABILITIES,
        POSTGRES_CAPABILITIES,
        MYSQL_CAPABILITIES,
    )
    assert {item.dialect for item in capabilities} == set(DialectId)
    assert all(item.routine_kinds for item in capabilities)
    assert all(item.statement_families for item in capabilities)
    assert all(item.vendor_constructs for item in capabilities)
    assert all("unclassified_extensions_are_opaque" in item.explicit_boundaries for item in capabilities)



def test_dialect_normalizers_expose_server_folding_and_type_aliases() -> None:
    assert DB2_NORMALIZER.normalize_identifier('\"Claims\".\"CaseId\"') == '\"Claims\".\"CaseId\"'
    assert ORACLE_NORMALIZER.normalize_type("varchar(40)") == "VARCHAR2(40)"
    assert SQLSERVER_NORMALIZER.normalize_identifier("[claims].[Claim]") == "[claims].[Claim]"
    assert POSTGRES_NORMALIZER.unquoted_server_case == "LOWER"
    assert POSTGRES_NORMALIZER.normalize_type("int8") == "BIGINT"
    assert MYSQL_NORMALIZER.unquoted_server_case == "FILESYSTEM_AND_SERVER_SETTING_DEPENDENT"

def test_db2_policy_enriches_handlers_and_sequence_references() -> None:
    service = AtlasSemanticService(__version__)
    source = ROOT / "tests" / "fixtures" / "advanced_claim_orchestrate_db2.sql"
    ir, report, _ = service.analyze(source, DialectId.DB2_SQL_PL)
    handlers = [node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER]
    sequence = next(node for node in ir.nodes if "NEXT VALUE FOR CLAIM_PROCESSING_AUDIT_SEQ" in node.text.upper())
    assert handlers
    assert all(node.attributes.get("handler_semantics") == "COMPOUND_STATEMENT_CONDITION_HANDLER" for node in handlers)
    assert sequence.attributes["sequence_reference"] == "NEXT"
    assert sequence.attributes["non_transactional_sequence_effect"] is True
    assert report.parse_status == "COMPLETE"


def test_sqlserver_function_restrictions_are_explicit_findings(tmp_path: Path) -> None:
    source = tmp_path / "invalid_tsql_function.sql"
    source.write_text(
        """
        CREATE FUNCTION dbo.bad_fn(@id int) RETURNS int AS
        BEGIN
            CREATE TABLE #t(id int);
            BEGIN TRY
                EXEC('SELECT 1');
            END TRY
            BEGIN CATCH
                THROW;
            END CATCH;
            RETURN @id;
        END;
        """,
        encoding="utf-8",
    )
    ir, report, _ = AtlasSemanticService(__version__).analyze(source, DialectId.SQLSERVER_TSQL)
    codes = {item.code for item in ir.findings}
    assert {
        "SQLSERVER_FUNCTION_TEMP_TABLE_NOT_ALLOWED",
        "SQLSERVER_FUNCTION_TRY_CATCH_NOT_ALLOWED",
        "SQLSERVER_FUNCTION_DYNAMIC_SQL_NOT_ALLOWED",
        "SQLSERVER_FUNCTION_ERROR_RAISE_NOT_ALLOWED",
    } <= codes
    assert report.parse_status == "PARTIAL"


def test_postgresql_return_query_keeps_found_and_result_semantics(tmp_path: Path) -> None:
    source = tmp_path / "pg_result.sql"
    source.write_text(
        """
        CREATE FUNCTION claims.f() RETURNS SETOF int LANGUAGE plpgsql AS $$
        BEGIN
            RETURN QUERY SELECT 1;
            RETURN;
        END;
        $$;
        """,
        encoding="utf-8",
    )
    ir, _, _ = AtlasSemanticService(__version__).analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    result = next(node for node in ir.nodes if node.kind is SemanticNodeKind.RESULT_SET)
    assert result.attributes["updates_found_register"] is True
    assert result.attributes["result_semantics"] == "RETURN_QUERY"


def test_mysql_cursor_contract_is_complete() -> None:
    source = ROOT / "tests" / "fixtures" / "polyglot" / "mysql_extended_semantics.sql"
    ir, _, _ = AtlasSemanticService(__version__).analyze(source, DialectId.MYSQL_STORED_PROGRAM)
    cursor = next(node for node in ir.nodes if node.kind is SemanticNodeKind.CURSOR_DECLARE)
    assert cursor.attributes["cursor_sensitivity"] == "ASENSITIVE"
    assert cursor.attributes["cursor_updatability"] == "READ_ONLY"
    assert cursor.attributes["cursor_scrollability"] == "NONSCROLLABLE"
    assert cursor.attributes["cursor_holdability"] == "NONHOLDABLE"


def test_profiles_capture_vendor_routine_attributes() -> None:
    service = AtlasSemanticService(__version__)
    sqlserver, _, _ = service.analyze(ROOT / "tests" / "fixtures" / "polyglot" / "sqlserver_extended_semantics.sql", DialectId.SQLSERVER_TSQL)
    mysql, _, _ = service.analyze(ROOT / "tests" / "fixtures" / "polyglot" / "mysql_extended_semantics.sql", DialectId.MYSQL_STORED_PROGRAM)
    assert sqlserver.routine_kind is RoutineKind.PROCEDURE
    assert sqlserver.routine_attributes["execute_as"] == "OWNER"
    assert sqlserver.routine_attributes["security_mode"] == "OWNER"
    assert mysql.routine_attributes["sql_data_access"] == "MODIFIES SQL DATA"


def test_postgresql_trigger_function_is_classified_as_trigger(tmp_path: Path) -> None:
    source = tmp_path / "pg_trigger.sql"
    source.write_text(
        """
        CREATE FUNCTION claims.audit_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RETURN NEW;
        END;
        $$;
        """,
        encoding="utf-8",
    )
    ir, _, _ = AtlasSemanticService(__version__).analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert ir.routine_kind is RoutineKind.TRIGGER


def test_db2_undo_handler_requires_its_own_atomic_scope(tmp_path: Path) -> None:
    source = tmp_path / "db2_undo.sql"
    source.write_text(
        """
        CREATE PROCEDURE claims.bad_undo()
        LANGUAGE SQL
        BEGIN
            DECLARE UNDO HANDLER FOR SQLEXCEPTION SET V_FAILED = 1;
            SET V_FAILED = 0;
        END
        """,
        encoding="utf-8",
    )
    ir, report, _ = AtlasSemanticService(__version__).analyze(source, DialectId.DB2_SQL_PL)
    assert "DB2_UNDO_HANDLER_REQUIRES_ATOMIC" in {item.code for item in ir.findings}
    assert report.parse_status == "PARTIAL"
