from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.type_system import (
    CanonicalSqlType,
    ResolutionCompleteness,
    SqlTypeFamily,
    TypeResolutionEngine,
    TypeResolutionStatus,
    parse_declared_sql_type,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_declared_db2_type_mapping_is_exact() -> None:
    integer = parse_declared_sql_type("INTEGER", source_ref="n1")
    small = parse_declared_sql_type("SMALLINT", source_ref="n2")
    big = parse_declared_sql_type("BIGINT", source_ref="n3")
    amount = parse_declared_sql_type("DECIMAL(15,2)", source_ref="n4")
    text = parse_declared_sql_type("VARCHAR(200)", source_ref="n5")

    assert integer.family is SqlTypeFamily.INTEGER
    assert small.family is SqlTypeFamily.SMALL_INTEGER
    assert big.family is SqlTypeFamily.BIG_INTEGER
    assert amount.precision == 15 and amount.scale == 2
    assert text.family is SqlTypeFamily.CHARACTER and text.length == 200


def test_phase1_ast_captures_parameter_and_local_declared_types() -> None:
    result = LarkSqlPlSpikeParser().parse_file(FIXTURES / "process_claim_batch.sql")
    assert result.ast is not None
    symbols = {symbol.symbol_name: symbol for symbol in result.ast.declared_symbol_types}
    assert symbols["P_BATCH_ID"].symbol_kind == "PROCEDURE_PARAMETER"
    assert symbols["P_BATCH_ID"].sql_type is not None
    assert symbols["P_BATCH_ID"].sql_type.family is SqlTypeFamily.BIG_INTEGER
    assert symbols["V_PREV_AMOUNT"].symbol_kind == "LOCAL_VARIABLE"
    assert symbols["V_PREV_AMOUNT"].sql_type is not None
    assert symbols["V_PREV_AMOUNT"].sql_type.family is SqlTypeFamily.DECIMAL


def test_resolution_conflict_is_blocking_not_coerced() -> None:
    declared = parse_declared_sql_type("INTEGER", source_ref="parameter")
    catalog = CanonicalSqlType(
        family=SqlTypeFamily.BIG_INTEGER,
        database_type="BIGINT",
        resolution_status=TypeResolutionStatus.CATALOG_RESOLVED,
        completeness=ResolutionCompleteness.COMPLETE,
        source_refs=("catalog",),
    )
    result = TypeResolutionEngine().resolve(subject_ref="CLAIM.CLAIM_ID", candidates=(declared, catalog))
    assert result.resolved_type.resolution_status is TypeResolutionStatus.CONFLICT
    assert result.blockers == ("TYPE_RESOLUTION_CONFLICT",)


def test_unresolved_type_blocks_concrete_generation() -> None:
    result = TypeResolutionEngine().resolve(subject_ref="CLAIM.UNKNOWN_COL", candidates=())
    assert result.resolved_type.family is SqlTypeFamily.UNKNOWN
    assert result.blockers == ("COLUMN_TYPE_UNRESOLVED",)


def test_type_system_contract_schemas_validate_examples() -> None:
    import json

    from jsonschema import Draft202012Validator

    root = Path(__file__).parent.parent
    result = TypeResolutionEngine().resolve(subject_ref="X", candidates=())
    payloads = {
        "canonical-sql-type-1.0.schema.json": result.resolved_type.model_dump(mode="json"),
        "type-resolution-1.0.schema.json": result.model_dump(mode="json"),
    }
    for filename, payload in payloads.items():
        schema = json.loads((root / "contracts" / filename).read_text(encoding="utf-8"))
        assert not list(Draft202012Validator(schema).iter_errors(payload)), filename
