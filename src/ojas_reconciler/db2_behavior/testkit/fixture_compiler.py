from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable

from pydantic import Field, model_validator

from ..catalog.models import CatalogSnapshot, RelationKind
from ..core.canonical_json import canonical_digest
from ..core.models import CanonicalModel
from ..type_system.models import ColumnDefinition, RelationDefinition, SqlTypeFamily


class FixtureCompilationError(RuntimeError):
    pass


class FixtureBundleStatus(StrEnum):
    EXECUTABLE = "EXECUTABLE"
    BLOCKED = "BLOCKED"


class ApprovedFixtureValue(CanonicalModel):
    relation_ref: str
    column_name: str
    canonical_value: object
    authority_ref: str
    evidence_refs: tuple[str, ...]


class FixtureRow(CanonicalModel):
    relation_ref: str
    values: dict[str, object]
    source: str


class ExecutableFixtureBundle(CanonicalModel):
    schema_version: str = "executable-fixture-bundle-1.0"
    bundle_id: str
    procedure_ref: str
    status: FixtureBundleStatus
    catalog_digest: str
    input_authority_refs: tuple[str, ...]
    rows: tuple[FixtureRow, ...]
    setup_sql: tuple[str, ...]
    teardown_sql: tuple[str, ...]
    blockers: tuple[str, ...]
    limitations: tuple[str, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_executable(self) -> "ExecutableFixtureBundle":
        if self.status is FixtureBundleStatus.EXECUTABLE:
            if self.blockers:
                raise ValueError("Executable fixture bundle cannot contain blockers.")
            if not self.setup_sql or not self.teardown_sql:
                raise ValueError("Executable fixture bundle requires setup and teardown SQL.")
        return self


def _quote_identifier(value: str) -> str:
    text = value.strip()
    if not text or any(ch in text for ch in "\x00\r\n;"):
        raise FixtureCompilationError(f"Unsafe SQL identifier: {value!r}")
    return '"' + text.replace('"', '""') + '"'


def _qualified(ref: str) -> str:
    parts = [part for part in ref.split(".") if part]
    if len(parts) != 2:
        raise FixtureCompilationError(f"Relation ref must be schema-qualified: {ref}")
    return ".".join(_quote_identifier(part) for part in parts)


def _literal(value: object) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float, Decimal)):
        return str(value)
    if isinstance(value, datetime):
        return "TIMESTAMP '" + value.isoformat(sep=" ") + "'"
    if isinstance(value, date):
        return "DATE '" + value.isoformat() + "'"
    text = str(value).replace("'", "''")
    return "'" + text + "'"


def _default_value(column: ColumnDefinition, seed: int) -> object:
    family = column.sql_type.family
    if family in {SqlTypeFamily.SMALL_INTEGER, SqlTypeFamily.INTEGER, SqlTypeFamily.BIG_INTEGER}:
        return seed
    if family in {SqlTypeFamily.DECIMAL, SqlTypeFamily.FLOATING_POINT}:
        return Decimal(seed)
    if family in {SqlTypeFamily.CHARACTER, SqlTypeFamily.GRAPHIC}:
        limit = column.sql_type.length or 64
        return (f"ATLAS_{column.column_name}_{seed}")[:limit]
    if family is SqlTypeFamily.BOOLEAN:
        return False
    if family is SqlTypeFamily.DATE:
        return date(2000, 1, min(seed, 28))
    if family is SqlTypeFamily.TIME:
        return f"00:00:{seed % 60:02d}"
    if family is SqlTypeFamily.TIMESTAMP:
        return datetime(2000, 1, 1, 0, 0, seed % 60)
    if family is SqlTypeFamily.BINARY:
        return f"{seed:02x}"
    raise FixtureCompilationError(
        f"No deterministic value generator for {column.sql_type.family.value} column {column.column_name}."
    )


class ExecutableRelationalFixtureCompiler:
    """Compile executable Db2 fixture SQL for an admitted metadata subset.

    The compiler is fail-closed for unresolved relations, incomplete types,
    check constraints without explicit acknowledgements, generated cleanup keys,
    unsupported types, and foreign-key cycles.
    """

    def compile(
        self,
        *,
        procedure_ref: str,
        catalog: CatalogSnapshot,
        relation_refs: Iterable[str],
        approved_values: Iterable[ApprovedFixtureValue] = (),
        acknowledged_check_constraints: Iterable[str] = (),
    ) -> ExecutableFixtureBundle:
        relation_map = {item.relation_ref.upper(): item for item in catalog.relations}
        requested = tuple(dict.fromkeys(value.upper() for value in relation_refs if value.strip()))
        values = {(item.relation_ref.upper(), item.column_name.upper()): item for item in approved_values}
        authority_refs = tuple(sorted({item.authority_ref for item in values.values()}))
        acknowledgements = {item.strip() for item in acknowledged_check_constraints if item.strip()}
        blockers: set[str] = set()
        selected: dict[str, RelationDefinition] = {}
        for ref in requested:
            relation = relation_map.get(ref)
            if relation is None:
                blockers.add(f"RELATION_UNRESOLVED:{ref}")
                continue
            if relation.relation_kind is not RelationKind.TABLE:
                blockers.add(f"FIXTURE_TARGET_NOT_BASE_TABLE:{ref}:{relation.relation_kind.value}")
                continue
            selected[ref] = relation.definition

        dependencies: dict[str, set[str]] = {ref: set() for ref in selected}
        fk_mappings: dict[tuple[str, str], tuple[str, str]] = {}
        for ref, relation in selected.items():
            for fk in relation.foreign_keys:
                parent = f"{(fk.referenced_schema or relation.schema_name).upper()}.{fk.referenced_relation.upper()}"
                if parent in selected:
                    dependencies[ref].add(parent)
                    for local, remote in zip(fk.local_columns, fk.referenced_columns, strict=False):
                        fk_mappings[(ref, local.upper())] = (parent, remote.upper())
        ordered: list[str] = []
        remaining = {key: set(value) for key, value in dependencies.items()}
        while remaining:
            ready = sorted(key for key, deps in remaining.items() if not deps)
            if not ready:
                blockers.add("FOREIGN_KEY_CYCLE_REQUIRES_CUSTOM_FIXTURE")
                break
            for key in ready:
                ordered.append(key)
                remaining.pop(key)
                for deps in remaining.values():
                    deps.discard(key)

        row_values: dict[str, dict[str, object]] = {}
        for index, ref in enumerate(ordered, start=1):
            relation = selected[ref]
            row: dict[str, object] = {}
            for constraint in relation.check_constraints:
                if constraint not in acknowledgements:
                    blockers.add(f"CHECK_CONSTRAINT_REQUIRES_ACKNOWLEDGEMENT:{ref}:{constraint}")
            for column in relation.columns:
                name = column.column_name.upper()
                if column.generated or column.identity_column:
                    continue
                approved = values.get((ref, name))
                if approved is not None:
                    row[name] = approved.canonical_value
                    continue
                parent_mapping = fk_mappings.get((ref, name))
                if parent_mapping:
                    parent_ref, parent_column = parent_mapping
                    parent_values = row_values.get(parent_ref, {})
                    if parent_column not in parent_values:
                        blockers.add(f"PARENT_KEY_VALUE_UNAVAILABLE:{ref}.{name}:{parent_ref}.{parent_column}")
                    else:
                        row[name] = parent_values[parent_column]
                    continue
                if column.default_expression is not None:
                    continue
                if column.nullable:
                    row[name] = None
                    continue
                try:
                    row[name] = _default_value(column, index)
                except FixtureCompilationError as exc:
                    blockers.add(str(exc))
            row_values[ref] = row
            cleanup_key = relation.primary_key or (relation.unique_constraints[0] if relation.unique_constraints else ())
            if not cleanup_key:
                blockers.add(f"CLEANUP_KEY_UNAVAILABLE:{ref}")
            elif any(column.upper() not in row for column in cleanup_key):
                blockers.add(f"CLEANUP_KEY_VALUE_UNAVAILABLE:{ref}")

        setup: list[str] = []
        teardown: list[str] = []
        rows: list[FixtureRow] = []
        if not blockers:
            for ref in ordered:
                row = row_values[ref]
                columns = tuple(row)
                setup.append(
                    f"INSERT INTO {_qualified(ref)} ({', '.join(_quote_identifier(c) for c in columns)}) "
                    f"VALUES ({', '.join(_literal(row[c]) for c in columns)});"
                )
                rows.append(FixtureRow(relation_ref=ref, values=row, source="APPROVED_OR_DETERMINISTIC_SYNTHETIC"))
            for ref in reversed(ordered):
                relation = selected[ref]
                row = row_values[ref]
                cleanup_key = relation.primary_key or relation.unique_constraints[0]
                predicate = " AND ".join(f"{_quote_identifier(c)} = {_literal(row[c.upper()])}" for c in cleanup_key)
                teardown.append(f"DELETE FROM {_qualified(ref)} WHERE {predicate};")
        status = FixtureBundleStatus.BLOCKED if blockers else FixtureBundleStatus.EXECUTABLE
        payload = {
            "schema_version": "executable-fixture-bundle-1.0",
            "bundle_id": "fixture-bundle-" + hashlib.sha256(
                (procedure_ref + "|" + catalog.content_digest + "|" + "|".join(requested)).encode()
            ).hexdigest()[:20],
            "procedure_ref": procedure_ref,
            "status": status,
            "catalog_digest": catalog.content_digest,
            "input_authority_refs": authority_refs,
            "rows": tuple(rows),
            "setup_sql": tuple(setup),
            "teardown_sql": tuple(teardown),
            "blockers": tuple(sorted(blockers)),
            "limitations": (
                "Generated values are synthetic and deterministic, not customer production data.",
                "Triggers, security policies, temporal history, and external side effects require separate verification.",
                "Execution remains restricted to an authorized disposable test environment.",
            ),
        }
        return ExecutableFixtureBundle(**payload, content_digest=canonical_digest(payload))

    @staticmethod
    def load_approved_values(path: Path) -> tuple[ApprovedFixtureValue, ...]:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
        values = payload.get("values", payload) if isinstance(payload, dict) else payload
        return tuple(ApprovedFixtureValue.model_validate(item) for item in values)
