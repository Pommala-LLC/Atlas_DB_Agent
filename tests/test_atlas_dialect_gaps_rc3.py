from __future__ import annotations

from pathlib import Path

import pytest

from atlas import AtlasSemanticService, DialectId, __version__
from atlas.application import AtlasSourceUnitService
from atlas.core.models import EdgeKind, RoutineKind, SemanticNodeKind


@pytest.fixture
def service() -> AtlasSemanticService:
    return AtlasSemanticService(__version__)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    source = tmp_path / name
    source.write_text(text, encoding="utf-8")
    return source


def test_db2_atomic_body_and_undo_handler_keep_the_same_scope(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "db2_atomic.sql",
        """
        CREATE PROCEDURE claims.atomic_p()
        LANGUAGE SQL
        P1: BEGIN ATOMIC
            DECLARE v_state INTEGER DEFAULT 0;
            DECLARE UNDO HANDLER FOR SQLEXCEPTION
                SET v_state = -1;
            SET v_state = 1;
        END P1
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.DB2_SQL_PL)
    assert report.parse_status == "COMPLETE"
    assert not [finding for finding in ir.findings if finding.code == "DB2_UNDO_HANDLER_REQUIRES_ATOMIC"]
    atomic = next(node for node in ir.nodes if node.kind is SemanticNodeKind.BLOCK and "BEGIN ATOMIC" in node.text.upper())
    handler = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ERROR_HANDLER)
    assert atomic.node_id in _ancestors(ir, handler.node_id)
    assert report.opaque_node_refs == ()


def test_postgresql_signature_supports_unnamed_variadic_and_flexible_options(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "pg_signature.sql",
        '''
        CREATE OR REPLACE FUNCTION "Claims"."F"(integer, "pText" text, VARIADIC nums int[])
        RETURNS double precision
        AS $$
        BEGIN
            RETURN 1;
        END;
        $$
        LANGUAGE plpgsql IMMUTABLE;
        ''',
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "COMPLETE"
    assert ir.schema_name == '"Claims"'
    assert ir.routine_name == '"F"'
    assert [(p.name, p.mode, p.type_text) for p in ir.parameters] == [
        ("ARG_1", "IN", "INTEGER"),
        ('"pText"', "IN", "TEXT"),
        ("nums", "VARIADIC", "INTEGER[]"),
        ("RETURN_VALUE", "RETURN", "DOUBLE PRECISION"),
    ]
    assert ir.routine_attributes["volatility"] == "IMMUTABLE"


def test_postgresql_returns_trigger_is_a_trigger(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "pg_trigger_function.sql",
        """
        CREATE FUNCTION claims.audit_trigger() RETURNS trigger AS $$
        BEGIN
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "COMPLETE"
    assert ir.routine_kind is RoutineKind.TRIGGER


@pytest.mark.parametrize(
    ("name", "text", "expected_kind"),
    [
        (
            "simple_trigger.sql",
            "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.x = 1;",
            RoutineKind.TRIGGER,
        ),
        (
            "simple_function.sql",
            "CREATE FUNCTION f(p_id int) RETURNS int DETERMINISTIC RETURN p_id + 1;",
            RoutineKind.FUNCTION,
        ),
    ],
)
def test_mysql_simple_single_statement_bodies_are_supported(
    tmp_path: Path,
    service: AtlasSemanticService,
    name: str,
    text: str,
    expected_kind: RoutineKind,
) -> None:
    ir, report, _ = service.analyze(_write(tmp_path, name, text), DialectId.MYSQL_STORED_PROGRAM)
    assert report.parse_status == "COMPLETE"
    assert ir.routine_kind is expected_kind
    assert report.opaque_node_refs == ()


def test_mysql_declarations_are_validated_per_nested_block(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "mysql_bad_declare.sql",
        """
        CREATE PROCEDURE p()
        BEGIN
            DECLARE outer_v INT;
            BEGIN
                SET outer_v = 1;
                DECLARE inner_v INT;
            END;
        END;
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.MYSQL_STORED_PROGRAM)
    assert report.parse_status == "PARTIAL"
    assert "MYSQL_DECLARE_AFTER_EXECUTABLE_STATEMENT" in {finding.code for finding in ir.findings}


def test_quoted_and_unquoted_postgresql_relations_never_alias(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "pg_quoted_relations.sql",
        '''
        CREATE FUNCTION f() RETURNS void AS $$
        BEGIN
            PERFORM 1 FROM "CamelTable";
            PERFORM 1 FROM cameltable;
            RETURN;
        END;
        $$ LANGUAGE plpgsql;
        ''',
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "COMPLETE"
    relations = {relation for node in ir.nodes for relation in node.relation_refs}
    assert '"CamelTable"' in relations
    assert "cameltable" in relations
    assert len({'"CamelTable"', "cameltable"} & relations) == 2


def test_tsql_cfg_resolves_goto_break_false_paths_and_joins(service: AtlasSemanticService) -> None:
    root = Path(__file__).resolve().parents[1]
    primary, report, _ = service.analyze(
        root / "tests" / "fixtures" / "polyglot" / "sqlserver_claim_process.sql",
        DialectId.SQLSERVER_TSQL,
    )
    assert report.parse_status == "COMPLETE"
    by_id = {node.node_id: node for node in primary.nodes}
    break_node = next(node for node in primary.nodes if node.kind is SemanticNodeKind.LOOP_CONTROL and "BREAK" in node.text.upper())
    break_edges = [edge for edge in primary.edges if edge.source_ref == break_node.node_id and edge.kind is EdgeKind.BRANCH]
    assert break_edges
    assert all(by_id[edge.target_ref].kind is not SemanticNodeKind.EXIT for edge in break_edges)
    return_node = next(node for node in primary.nodes if node.kind is SemanticNodeKind.ERROR_RAISE and "THROW 50001" in node.text.upper())
    assert not [edge for edge in primary.edges if edge.source_ref == return_node.node_id and edge.kind is EdgeKind.NEXT]

    extended, report, _ = service.analyze(
        root / "tests" / "fixtures" / "polyglot" / "sqlserver_extended_semantics.sql",
        DialectId.SQLSERVER_TSQL,
    )
    assert report.parse_status == "COMPLETE"
    goto = next(node for node in extended.nodes if node.kind is SemanticNodeKind.GOTO and "NO_ROWS" in node.text.upper())
    label = next(node for node in extended.nodes if node.kind is SemanticNodeKind.LABEL and node.attributes.get("label_name") == "NO_ROWS")
    assert any(
        edge.source_ref == goto.node_id and edge.target_ref == label.node_id and edge.kind is EdgeKind.BRANCH
        for edge in extended.edges
    )


def test_inline_for_loop_body_is_not_swallowed(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "pg_inline_for.sql",
        """
        CREATE FUNCTION f() RETURNS int AS $$
        DECLARE total int := 0;
        BEGIN
            FOR i IN 1..3 LOOP total := total + i;
            END LOOP;
            RETURN total;
        END;
        $$ LANGUAGE plpgsql;
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "COMPLETE"
    loop = next(node for node in ir.nodes if node.kind is SemanticNodeKind.LOOP)
    assignment = next(node for node in ir.nodes if node.kind is SemanticNodeKind.ASSIGNMENT and node.target_name == "total")
    assert loop.node_id in _ancestors(ir, assignment.node_id)
    assert any(edge.kind is EdgeKind.LOOP_BACK for edge in ir.edges)


def test_calls_and_data_dependencies_are_materialized(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "oracle_call.sql",
        """
        CREATE OR REPLACE PROCEDURE p AS
          v_id NUMBER := 1;
          v_next NUMBER;
        BEGIN
          v_next := v_id + 1;
          claims.audit_claim(v_next);
        END;
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.ORACLE_PLSQL)
    assert report.parse_status == "COMPLETE"
    assert any(node.kind is SemanticNodeKind.CALL_TARGET for node in ir.nodes)
    assert any(edge.kind is EdgeKind.CALLS for edge in ir.edges)
    assert any(edge.kind is EdgeKind.DATA_DEPENDENCY for edge in ir.edges)


def test_oracle_standalone_routine_is_not_rediscovered_as_package_member(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "oracle_standalone.sql",
        """
        CREATE OR REPLACE PROCEDURE p(p_id IN NUMBER) AS
        BEGIN
          NULL;
        END;
        /
        """,
    )
    result = AtlasSourceUnitService(__version__).analyze(source, DialectId.ORACLE_PLSQL)
    assert len(result.routines) == 1
    assert result.routines[0].routine_ref == "P(IN:NUMBER)"


def test_overloaded_routine_references_include_signature(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "pg_overloads.sql",
        """
        CREATE FUNCTION f(p_id integer) RETURNS integer AS $$ BEGIN RETURN p_id; END; $$ LANGUAGE plpgsql;
        CREATE FUNCTION f(p_id text) RETURNS text AS $$ BEGIN RETURN p_id; END; $$ LANGUAGE plpgsql;
        """,
    )
    result = AtlasSourceUnitService(__version__).analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    refs = [routine.routine_ref for routine in result.routines]
    assert refs == ["f(INTEGER)", "f(TEXT)"]
    assert len(set(refs)) == 2


def test_complete_status_requires_no_opaque_or_warning_findings(tmp_path: Path, service: AtlasSemanticService) -> None:
    source = _write(
        tmp_path,
        "pg_opaque.sql",
        """
        CREATE FUNCTION f() RETURNS void AS $$
        BEGIN
          VACUUM strange_extension;
          RETURN;
        END;
        $$ LANGUAGE plpgsql;
        """,
    )
    ir, report, _ = service.analyze(source, DialectId.POSTGRESQL_PLPGSQL)
    assert report.parse_status == "PARTIAL"
    assert report.opaque_node_refs
    assert "DIALECT_STATEMENT_OPAQUE" in {finding.code for finding in ir.findings}


def _ancestors(ir, node_id: str) -> set[str]:
    by_id = {node.node_id: node for node in ir.nodes}
    result: set[str] = set()
    current = by_id[node_id].parent_ref
    while current and current not in result:
        result.add(current)
        current = by_id[current].parent_ref
    return result
