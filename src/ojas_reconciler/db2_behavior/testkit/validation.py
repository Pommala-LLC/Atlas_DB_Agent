"""Fail-closed validation of external test data against resolved SQL metadata."""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from ..type_system.models import CanonicalSqlType, SqlTypeFamily
from .models import BddTestCatalog, BddTestCase, BddTestDataset, ProcedureTestContract, TypedValue


class TestDataValidationError(ValueError):
    pass


def type_signature(sql_type: CanonicalSqlType) -> str:
    base = sql_type.database_type.upper()
    if sql_type.precision is not None:
        if sql_type.scale is not None:
            return f"{base}({sql_type.precision},{sql_type.scale})"
        return f"{base}({sql_type.precision})"
    if sql_type.length is not None:
        return f"{base}({sql_type.length})"
    return base


def validate_typed_value(value: object, sql_type: CanonicalSqlType, *, subject: str) -> None:
    if value is None:
        if sql_type.nullable is False:
            raise TestDataValidationError(f"{subject}: NULL is not allowed")
        return
    family = sql_type.family
    try:
        if family in {SqlTypeFamily.SMALL_INTEGER, SqlTypeFamily.INTEGER, SqlTypeFamily.BIG_INTEGER}:
            if isinstance(value, bool):
                raise ValueError
            int(str(value))
            return
        if family is SqlTypeFamily.DECIMAL:
            number = Decimal(str(value))
            if sql_type.scale is not None:
                fractional = max(0, -number.as_tuple().exponent)
                if fractional > sql_type.scale:
                    raise TestDataValidationError(
                        f"{subject}: scale {fractional} exceeds {sql_type.scale}"
                    )
            return
        if family in {SqlTypeFamily.CHARACTER, SqlTypeFamily.GRAPHIC}:
            if not isinstance(value, str):
                raise ValueError
            if sql_type.length is not None and len(value) > sql_type.length:
                raise TestDataValidationError(
                    f"{subject}: length {len(value)} exceeds {sql_type.length}"
                )
            return
        if family is SqlTypeFamily.DATE:
            date.fromisoformat(str(value))
            return
        if family is SqlTypeFamily.TIMESTAMP:
            datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return
        if family is SqlTypeFamily.BOOLEAN:
            if not isinstance(value, bool):
                raise ValueError
            return
        if family is SqlTypeFamily.UNKNOWN:
            raise TestDataValidationError(f"{subject}: SQL type is unresolved")
    except (ValueError, InvalidOperation) as exc:
        raise TestDataValidationError(
            f"{subject}: value {value!r} is incompatible with {type_signature(sql_type)}"
        ) from exc


def validate_invocation(test_case: BddTestCase, contract: ProcedureTestContract) -> None:
    invocation = test_case.invocation
    if invocation.procedure_schema != contract.procedure_schema or invocation.procedure_name != contract.procedure_name:
        raise TestDataValidationError(f"{test_case.test_case_id}: procedure identity does not match contract")
    if set(invocation.parameters) != set(contract.parameter_types):
        missing = sorted(set(contract.parameter_types) - set(invocation.parameters))
        extra = sorted(set(invocation.parameters) - set(contract.parameter_types))
        raise TestDataValidationError(
            f"{test_case.test_case_id}: parameter mismatch missing={missing} extra={extra}"
        )
    for name, sql_type in contract.parameter_types.items():
        supplied: TypedValue = invocation.parameters[name]
        expected_signature = type_signature(sql_type)
        if supplied.database_type.upper() != expected_signature:
            raise TestDataValidationError(
                f"{test_case.test_case_id}.{name}: declared {supplied.database_type}, expected {expected_signature}"
            )
        mode = contract.parameter_modes[name]
        admitted_type = sql_type.model_copy(update={"nullable": True}) if mode in {"OUT", "INOUT"} else sql_type
        validate_typed_value(
            supplied.canonical_value,
            admitted_type,
            subject=f"{test_case.test_case_id}.{name}",
        )


def validate_dataset(dataset: BddTestDataset, catalog: BddTestCatalog) -> None:
    relations = {value.relation_name.upper(): value for value in catalog.relations}
    for relation_name, rows in dataset.relations.items():
        relation = relations.get(relation_name.upper())
        if relation is None:
            raise TestDataValidationError(
                f"{dataset.dataset_id}: relation {relation_name} has no resolved catalog metadata"
            )
        columns = {value.column_name.upper(): value for value in relation.columns}
        for index, row in enumerate(rows):
            for column_name, raw in row.items():
                column = columns.get(column_name.upper())
                if column is None:
                    raise TestDataValidationError(
                        f"{dataset.dataset_id}.{relation_name}[{index}].{column_name}: column type unresolved"
                    )
                validate_typed_value(
                    raw,
                    column.sql_type.model_copy(update={"nullable": column.nullable}),
                    subject=f"{dataset.dataset_id}.{relation_name}[{index}].{column_name}",
                )
            for column in relation.columns:
                if (
                    not column.nullable
                    and not column.generated
                    and column.default_expression is None
                    and column.column_name not in row
                ):
                    raise TestDataValidationError(
                        f"{dataset.dataset_id}.{relation_name}[{index}]: required column {column.column_name} missing"
                    )
