from __future__ import annotations

from dataclasses import dataclass

from ojas_reconciler.db2_behavior.parsing.models import ProcedureParameter


@dataclass(frozen=True, slots=True)
class _Header:
    schema: str | None
    name: str
    parameters: tuple[ProcedureParameter, ...]
    specific_name: str | None
    routine_version_id: str | None
    commit_on_return: str | None
    declared_result_set_capacity: int | None
