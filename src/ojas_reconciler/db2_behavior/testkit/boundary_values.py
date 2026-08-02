"""Deterministic boundary values for typed test-data generation."""
from __future__ import annotations

from decimal import Decimal

from ..type_system.models import CanonicalSqlType, SqlTypeFamily


class BoundaryValueGenerator:
    """Generate below/at/above values without randomized business expectations."""

    def around(self, *, sql_type: CanonicalSqlType, operator: str, threshold: str) -> tuple[str, ...]:
        family = sql_type.family
        if family in {SqlTypeFamily.SMALL_INTEGER, SqlTypeFamily.INTEGER, SqlTypeFamily.BIG_INTEGER}:
            value = int(threshold)
            step = 1
            candidates = (value - step, value, value + step)
            return tuple(str(item) for item in self._select(operator, candidates))
        if family is SqlTypeFamily.DECIMAL:
            scale = sql_type.scale if sql_type.scale is not None else 0
            quantum = Decimal(1).scaleb(-scale)
            value = Decimal(threshold)
            candidates = (value - quantum, value, value + quantum)
            return tuple(format(item, f".{scale}f") for item in self._select(operator, candidates))
        raise ValueError(f"Boundary generation is unsupported for {family}")

    @staticmethod
    def _select(operator: str, values: tuple[object, object, object]) -> tuple[object, ...]:
        below, at, above = values
        if operator in {">=", "<=", ">", "<", "=", "<>", "!="}:
            return below, at, above
        raise ValueError(f"Unsupported comparison operator: {operator}")
