from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import RLock
from time import monotonic, sleep
from typing import Any

from pydantic import BaseModel

from ojas_reconciler.db2_behavior.bdd.models import BddCompilationBatch, CandidateBdd, GherkinArtifact, TraceabilityManifest
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.bdd.gherkin import gherkin_digest
from ojas_reconciler.db2_behavior.governance.models import (
    AmendmentRecord,
    BaselineComparisonResult,
    BaselineComparisonStatus,
    BaselineRegistration,
    CertificationEnvelope,
    GovernanceArtifactType,
    GovernanceAuditEvent,
    GovernanceEventType,
    GovernanceHistory,
    LocalEvidenceAuthorityScope,
    PlatformDecisionEnvelope,
    StoredArtifactRecord,
)
from ojas_reconciler.db2_behavior.runtime.models import RuntimeVerificationBatch, RuntimeVerificationResult
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpec, ScenarioSpecBatchResult


class GovernanceStoreError(ValueError):
    """Raised when an artifact cannot be safely admitted or governed."""


@dataclass(frozen=True)
class AdmissionResult:
    records: tuple[StoredArtifactRecord, ...]
    idempotent_artifact_ids: tuple[str, ...] = ()


def _digest_without_content_digest(model: BaseModel) -> str:
    return canonical_digest(model.model_dump(mode="python", exclude={"content_digest"}))


def validate_content_digest(model: BaseModel) -> str:
    content_digest = getattr(model, "content_digest", None)
    if not isinstance(content_digest, str):
        # Some embedded technical facts do not carry their own digest in the upstream
        # schema. The governance store assigns a canonical artifact digest without
        # mutating the source object.
        return canonical_digest(model)
    if isinstance(model, GherkinArtifact):
        expected = gherkin_digest(model.text)
    else:
        expected = _digest_without_content_digest(model)
    if expected != content_digest:
        raise GovernanceStoreError(
            f"Invalid content digest for {type(model).__name__}: expected {expected}, got {content_digest}"
        )
    return content_digest


def _artifact_id(artifact_type: GovernanceArtifactType, artifact_ref: str, content_digest: str) -> str:
    material = f"{artifact_type.value}\0{artifact_ref}\0{content_digest}".encode("utf-8")
    return "gov-artifact-" + sha256(material).hexdigest()[:24]


def _model_json(model: BaseModel) -> str:
    return canonical_json_bytes(model).decode("utf-8")


class GovernanceStore:
    """Append-only, non-authoritative SQLite evidence cache for Phase 7 staging."""

    _initialization_lock = RLock()

    def __init__(self, database: Path, migrations_dir: Path | None = None) -> None:
        self.database = database
        self.migrations_dir = migrations_dir or Path(__file__).parents[2] / "governance_migrations"

    def connect(self) -> sqlite3.Connection:
        """Open a connection without performing file-mutating PRAGMAs.

        ``PRAGMA journal_mode = WAL`` is a database write.  Running it from
        every connection races before ``BEGIN IMMEDIATE`` can serialize
        concurrent initializers, and Windows commonly reports
        ``sqlite3.OperationalError: database is locked`` at that point.
        WAL negotiation therefore belongs to ``initialize()`` after the
        migration transaction has committed.
        """
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @classmethod
    def _ensure_wal_mode(
        cls,
        connection: sqlite3.Connection,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        """Enable persistent WAL mode after migration serialization.

        The process lock removes the same-process race exercised by the
        thread-pool regression.  A bounded retry remains necessary because a
        different process can still hold a short SQLite lock between our
        migration commit and journal-mode negotiation.
        """
        deadline = monotonic() + timeout_seconds
        with cls._initialization_lock:
            while True:
                try:
                    row = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                    if row is None or str(row[0]).lower() != "wal":
                        raise GovernanceStoreError("SQLite did not enter WAL journal mode")
                    return
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or monotonic() >= deadline:
                        raise
                    sleep(0.05)

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """Open a transactional SQLite session and always release the file handle.

        ``sqlite3.Connection`` as a context manager commits or rolls back, but it
        does not close the connection.  That distinction is observable on Windows,
        where an open connection prevents temporary database files from being
        deleted.  All store-owned database work must use this context manager.
        """
        connection = self.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _column_exists(connection: sqlite3.Connection, table_name: str, column_name: str) -> bool:
        if not GovernanceStore._table_exists(connection, table_name):
            return False
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        return any(row["name"] == column_name for row in rows)

    def _migration_is_structurally_satisfied(
        self, connection: sqlite3.Connection, migration_id: str
    ) -> bool:
        """Recognise a migration whose schema effect is already present.

        RC8-RC11 shipped an initial schema that already contained
        ``governance_artifacts.authority_scope`` while also retaining migration
        0002, which adds the same column.  Fresh databases and partially-created
        databases therefore failed with ``duplicate column name``.  The runner
        records 0002 as applied only when its exact required schema effect is
        already present; no arbitrary migration is skipped.
        """
        if migration_id == "0002_local_non_authoritative_scope":
            return self._column_exists(connection, "governance_artifacts", "authority_scope")
        return False

    @staticmethod
    def _migration_statements(sql: str, migration_id: str) -> tuple[str, ...]:
        """Split a SQLite migration without surrendering transaction control.

        ``sqlite3.executescript`` commits any pending transaction before running a
        script.  Migrations are instead executed one complete statement at a time
        so schema mutation and ledger admission remain in one ``BEGIN IMMEDIATE``
        transaction.  Migration files may not manage transactions themselves.
        """
        statements: list[str] = []
        buffer: list[str] = []
        for line in sql.splitlines(keepends=True):
            buffer.append(line)
            candidate = "".join(buffer).strip()
            if not candidate or not sqlite3.complete_statement(candidate):
                continue
            normalized = re.sub(r"(?m)^\s*--.*$", "", candidate).strip()
            first = re.match(r"([A-Za-z]+)", normalized)
            if first and first.group(1).upper() in {
                "BEGIN",
                "COMMIT",
                "END",
                "ROLLBACK",
                "SAVEPOINT",
                "RELEASE",
            }:
                raise GovernanceStoreError(
                    f"Migration contains transaction control: {migration_id}"
                )
            if normalized:
                statements.append(candidate)
            buffer = []
        if "".join(buffer).strip():
            raise GovernanceStoreError(f"Migration contains incomplete SQL: {migration_id}")
        return tuple(statements)

    @staticmethod
    def _validate_applied_migration_prefix(
        connection: sqlite3.Connection,
        validated: list[tuple[dict[str, Any], Path, str]],
    ) -> dict[str, sqlite3.Row]:
        if not GovernanceStore._table_exists(connection, "governance_schema_migrations"):
            return {}
        rows = connection.execute(
            "SELECT migration_id, migration_digest, previous_migration_digest, applied_at "
            "FROM governance_schema_migrations ORDER BY rowid"
        ).fetchall()
        manifest_by_id = {item[0]["migration_id"]: item for item in validated}
        applied: dict[str, sqlite3.Row] = {}
        for index, row in enumerate(rows):
            migration_id = row["migration_id"]
            expected = manifest_by_id.get(migration_id)
            if expected is None:
                raise GovernanceStoreError(
                    f"Unknown applied migration is not present in manifest: {migration_id}"
                )
            manifest_item, _path, actual = expected
            expected_id = validated[index][0]["migration_id"] if index < len(validated) else None
            if migration_id != expected_id:
                raise GovernanceStoreError(
                    "Applied migrations are not a contiguous manifest prefix: "
                    f"expected {expected_id}, found {migration_id}"
                )
            if (
                row["migration_digest"] != actual
                or row["previous_migration_digest"]
                != manifest_item["previous_migration_digest"]
            ):
                raise GovernanceStoreError(
                    f"Applied migration differs from manifest: {migration_id}"
                )
            applied[migration_id] = row
        return applied

    def initialize(self, *, applied_at: str) -> None:
        manifest_path = self.migrations_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        validated: list[tuple[dict[str, Any], Path, str]] = []
        expected_previous: str | None = None
        for item in manifest["migrations"]:
            if item["previous_migration_digest"] != expected_previous:
                raise GovernanceStoreError("Migration manifest digest chain is invalid")
            sql_path = self.migrations_dir / item["filename"]
            actual = "sha256:" + sha256(sql_path.read_bytes()).hexdigest()
            if actual != item["digest"]:
                raise GovernanceStoreError(f"Migration digest mismatch: {item['migration_id']}")
            # Validate SQL structure before acquiring a write lock.
            self._migration_statements(
                sql_path.read_text(encoding="utf-8"), item["migration_id"]
            )
            validated.append((item, sql_path, actual))
            expected_previous = actual

        with self._initialization_lock:
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                applied = self._validate_applied_migration_prefix(connection, validated)
                for item, sql_path, actual in validated:
                    migration_id = item["migration_id"]
                    if migration_id in applied:
                        continue

                    if not self._migration_is_structurally_satisfied(connection, migration_id):
                        sql = sql_path.read_text(encoding="utf-8")
                        for statement in self._migration_statements(sql, migration_id):
                            connection.execute(statement)

                    if not self._table_exists(connection, "governance_schema_migrations"):
                        raise GovernanceStoreError(
                            f"Migration did not create tracking table: {migration_id}"
                        )

                    connection.execute(
                        "INSERT INTO governance_schema_migrations "
                        "(migration_id, migration_digest, previous_migration_digest, applied_at) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            migration_id,
                            actual,
                            item["previous_migration_digest"],
                            applied_at,
                        ),
                    )
                    applied[migration_id] = connection.execute(
                        "SELECT migration_id, migration_digest, previous_migration_digest, applied_at "
                        "FROM governance_schema_migrations WHERE migration_id = ?",
                        (migration_id,),
                    ).fetchone()

                self.assert_schema_guard(connection)
                connection.commit()
                self._ensure_wal_mode(connection)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def assert_schema_guard(self, connection: sqlite3.Connection | None = None) -> None:
        own = connection is None
        conn = connection or self.connect()
        try:
            required = {
                "artifact_id",
                "artifact_type",
                "artifact_ref",
                "content_digest",
                "payload_digest",
                "payload_json",
                "behavior_id",
                "source_symbol_id",
                "symbol_lineage_id",
                "artifact_revision_id",
                "parent_artifact_id",
                "invalidates_machine_attestation",
                "platform_governance_ref",
                "authority_scope",
                "created_at",
            }
            rows = conn.execute("PRAGMA table_info(governance_artifacts)").fetchall()
            actual = {row["name"] for row in rows}
            missing = sorted(required - actual)
            if missing:
                raise GovernanceStoreError(f"Governance schema missing mandatory columns: {missing}")
        finally:
            if own:
                conn.close()

    def _admit_model(
        self,
        model: BaseModel,
        *,
        artifact_type: GovernanceArtifactType,
        artifact_ref: str,
        created_at: str,
        actor_ref: str,
        behavior_id: str | None = None,
        source_symbol_id: str | None = None,
        symbol_lineage_id: str | None = None,
        artifact_revision_id: str | None = None,
        parent_artifact_id: str | None = None,
        invalidates_machine_attestation: bool = False,
        platform_governance_ref: str | None = None,
    ) -> tuple[StoredArtifactRecord, bool]:
        content_digest = validate_content_digest(model)
        payload_json = _model_json(model)
        payload_digest = canonical_digest(model)
        artifact_id = _artifact_id(artifact_type, artifact_ref, content_digest)
        record_payload = {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "artifact_ref": artifact_ref,
            "content_digest": content_digest,
            "payload_digest": payload_digest,
            "behavior_id": behavior_id,
            "source_symbol_id": source_symbol_id,
            "symbol_lineage_id": symbol_lineage_id,
            "artifact_revision_id": artifact_revision_id,
            "parent_artifact_id": parent_artifact_id,
            "invalidates_machine_attestation": invalidates_machine_attestation,
            "platform_governance_ref": platform_governance_ref,
            "authority_scope": LocalEvidenceAuthorityScope.LOCAL_NON_AUTHORITATIVE_EVIDENCE,
            "created_at": created_at,
        }
        record = StoredArtifactRecord(**record_payload)
        with self.session() as connection:
            existing = connection.execute(
                "SELECT content_digest, payload_digest FROM governance_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_digest"] != content_digest or existing["payload_digest"] != payload_digest:
                    raise GovernanceStoreError(f"Artifact identity collision: {artifact_id}")
                return record, True
            connection.execute(
                "INSERT INTO governance_artifacts ("
                "artifact_id, artifact_type, artifact_ref, content_digest, payload_digest, payload_json, "
                "behavior_id, source_symbol_id, symbol_lineage_id, artifact_revision_id, parent_artifact_id, "
                "invalidates_machine_attestation, platform_governance_ref, authority_scope, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    artifact_id,
                    artifact_type.value,
                    artifact_ref,
                    content_digest,
                    payload_digest,
                    payload_json,
                    behavior_id,
                    source_symbol_id,
                    symbol_lineage_id,
                    artifact_revision_id,
                    parent_artifact_id,
                    1 if invalidates_machine_attestation else 0,
                    platform_governance_ref,
                    LocalEvidenceAuthorityScope.LOCAL_NON_AUTHORITATIVE_EVIDENCE.value,
                    created_at,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.ARTIFACT_CACHED,
                artifact_id=artifact_id,
                actor_ref=actor_ref,
                event_at=created_at,
                payload_digest=payload_digest,
            )
        return record, False

    def admit_scenario_batch(
        self, batch: ScenarioSpecBatchResult, *, created_at: str, actor_ref: str
    ) -> AdmissionResult:
        records: list[StoredArtifactRecord] = []
        idempotent: list[str] = []
        batch_record, was_idempotent = self._admit_model(
            batch,
            artifact_type=GovernanceArtifactType.SCENARIO_SPEC_BATCH,
            artifact_ref=batch.procedure_identity_ref,
            created_at=created_at,
            actor_ref=actor_ref,
            source_symbol_id=batch.source_symbol_id,
            symbol_lineage_id=batch.symbol_lineage_id,
        )
        records.append(batch_record)
        if was_idempotent:
            idempotent.append(batch_record.artifact_id)
        for observation in batch.classification_observations:
            record, idem = self._admit_model(
                observation,
                artifact_type=GovernanceArtifactType.CLASSIFICATION_OBSERVATION,
                artifact_ref=observation.classification_observation_id,
                created_at=created_at,
                actor_ref=actor_ref,
                parent_artifact_id=batch_record.artifact_id,
            )
            records.append(record)
            if idem:
                idempotent.append(record.artifact_id)
        for closure in batch.effect_closures:
            record, idem = self._admit_model(
                closure,
                artifact_type=GovernanceArtifactType.EFFECT_CLOSURE,
                artifact_ref=closure.effect_closure_id,
                created_at=created_at,
                actor_ref=actor_ref,
                parent_artifact_id=batch_record.artifact_id,
            )
            records.append(record)
            if idem:
                idempotent.append(record.artifact_id)
        for resolution in batch.resolution_vectors:
            record, idem = self._admit_model(
                resolution,
                artifact_type=GovernanceArtifactType.RESOLUTION_VECTOR,
                artifact_ref=resolution.resolution_vector_id,
                created_at=created_at,
                actor_ref=actor_ref,
                parent_artifact_id=batch_record.artifact_id,
            )
            records.append(record)
            if idem:
                idempotent.append(record.artifact_id)
        for budget in batch.budget_reports:
            record, idem = self._admit_model(
                budget,
                artifact_type=GovernanceArtifactType.ANALYSIS_BUDGET_REPORT,
                artifact_ref=budget.budget_report_id,
                created_at=created_at,
                actor_ref=actor_ref,
                parent_artifact_id=batch_record.artifact_id,
            )
            records.append(record)
            if idem:
                idempotent.append(record.artifact_id)
        for spec in batch.scenario_specs:
            record, idem = self._admit_model(
                spec,
                artifact_type=GovernanceArtifactType.SCENARIO_SPEC,
                artifact_ref=spec.scenario_spec_id,
                created_at=created_at,
                actor_ref=actor_ref,
                behavior_id=spec.behavior_id,
                source_symbol_id=spec.source_symbol_id,
                symbol_lineage_id=spec.symbol_lineage_id,
                artifact_revision_id=spec.artifact_revision_id,
                parent_artifact_id=batch_record.artifact_id,
                platform_governance_ref=spec.platform_governance_ref,
            )
            records.append(record)
            if idem:
                idempotent.append(record.artifact_id)
        return AdmissionResult(tuple(records), tuple(idempotent))

    def _scenario_identity(self, scenario_spec_ref: str) -> StoredArtifactRecord:
        with self.session() as connection:
            row = connection.execute(
                "SELECT artifact_id FROM governance_artifacts "
                "WHERE artifact_type = ? AND artifact_ref = ? ORDER BY created_at DESC LIMIT 1",
                (GovernanceArtifactType.SCENARIO_SPEC.value, scenario_spec_ref),
            ).fetchone()
        if row is None:
            raise GovernanceStoreError(
                f"Referenced ScenarioSpec must be admitted before dependent artifacts: {scenario_spec_ref}"
            )
        record, _ = self.get_artifact(str(row["artifact_id"]))
        return record

    def admit_bdd_batch(
        self, batch: BddCompilationBatch, *, created_at: str, actor_ref: str
    ) -> AdmissionResult:
        records: list[StoredArtifactRecord] = []
        idempotent: list[str] = []
        parent, idem = self._admit_model(
            batch,
            artifact_type=GovernanceArtifactType.BDD_COMPILATION_BATCH,
            artifact_ref=batch.scenario_spec_batch_digest,
            created_at=created_at,
            actor_ref=actor_ref,
        )
        records.append(parent)
        if idem:
            idempotent.append(parent.artifact_id)
        for artifact in batch.gherkin_artifacts:
            record, flag = self._admit_model(
                artifact,
                artifact_type=GovernanceArtifactType.GHERKIN_ARTIFACT,
                artifact_ref=artifact.artifact_id,
                created_at=created_at,
                actor_ref=actor_ref,
                behavior_id=artifact.behavior_id,
                source_symbol_id=artifact.source_symbol_id,
                symbol_lineage_id=artifact.symbol_lineage_id,
                artifact_revision_id=artifact.artifact_revision_id,
                parent_artifact_id=parent.artifact_id,
            )
            records.append(record)
            if flag:
                idempotent.append(record.artifact_id)
        for manifest in batch.traceability_manifests:
            record, flag = self._admit_model(
                manifest,
                artifact_type=GovernanceArtifactType.TRACEABILITY_MANIFEST,
                artifact_ref=manifest.manifest_id,
                created_at=created_at,
                actor_ref=actor_ref,
                behavior_id=manifest.behavior_id,
                source_symbol_id=manifest.source_symbol_id,
                symbol_lineage_id=manifest.symbol_lineage_id,
                artifact_revision_id=manifest.artifact_revision_id,
                parent_artifact_id=parent.artifact_id,
            )
            records.append(record)
            if flag:
                idempotent.append(record.artifact_id)
        for candidate in batch.candidate_bdds:
            identity = self._scenario_identity(candidate.scenario_spec_ref)
            record, flag = self._admit_model(
                candidate,
                artifact_type=GovernanceArtifactType.CANDIDATE_BDD,
                artifact_ref=candidate.candidate_bdd_id,
                created_at=created_at,
                actor_ref=actor_ref,
                behavior_id=identity.behavior_id,
                source_symbol_id=identity.source_symbol_id,
                symbol_lineage_id=identity.symbol_lineage_id,
                artifact_revision_id=identity.artifact_revision_id,
                parent_artifact_id=parent.artifact_id,
                platform_governance_ref=candidate.platform_governance_ref,
            )
            records.append(record)
            if flag:
                idempotent.append(record.artifact_id)
        return AdmissionResult(tuple(records), tuple(idempotent))

    def admit_runtime_batch(
        self, batch: RuntimeVerificationBatch, *, created_at: str, actor_ref: str
    ) -> AdmissionResult:
        records: list[StoredArtifactRecord] = []
        idempotent: list[str] = []
        parent, idem = self._admit_model(
            batch,
            artifact_type=GovernanceArtifactType.RUNTIME_VERIFICATION_BATCH,
            artifact_ref=batch.plan_batch_digest,
            created_at=created_at,
            actor_ref=actor_ref,
        )
        records.append(parent)
        if idem:
            idempotent.append(parent.artifact_id)
        for execution in batch.execution_records:
            record, flag = self._admit_model(
                execution,
                artifact_type=GovernanceArtifactType.RUNTIME_EXECUTION_RECORD,
                artifact_ref=execution.execution_id,
                created_at=created_at,
                actor_ref=actor_ref,
                parent_artifact_id=parent.artifact_id,
            )
            records.append(record)
            if flag:
                idempotent.append(record.artifact_id)
        for result in batch.verification_results:
            identity = self._scenario_identity(result.scenario_spec_ref)
            record, flag = self._admit_model(
                result,
                artifact_type=GovernanceArtifactType.RUNTIME_VERIFICATION_RESULT,
                artifact_ref=result.verification_result_id,
                created_at=created_at,
                actor_ref=actor_ref,
                behavior_id=identity.behavior_id,
                source_symbol_id=identity.source_symbol_id,
                symbol_lineage_id=identity.symbol_lineage_id,
                artifact_revision_id=identity.artifact_revision_id,
                parent_artifact_id=parent.artifact_id,
                platform_governance_ref=result.platform_governance_ref,
            )
            records.append(record)
            if flag:
                idempotent.append(record.artifact_id)
        return AdmissionResult(tuple(records), tuple(idempotent))

    def get_artifact(self, artifact_id: str) -> tuple[StoredArtifactRecord, dict[str, Any]]:
        with self.session() as connection:
            row = connection.execute(
                "SELECT * FROM governance_artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            raise GovernanceStoreError(f"Unknown artifact: {artifact_id}")
        record = StoredArtifactRecord(
            artifact_id=row["artifact_id"],
            artifact_type=GovernanceArtifactType(row["artifact_type"]),
            artifact_ref=row["artifact_ref"],
            content_digest=row["content_digest"],
            payload_digest=row["payload_digest"],
            behavior_id=row["behavior_id"],
            source_symbol_id=row["source_symbol_id"],
            symbol_lineage_id=row["symbol_lineage_id"],
            artifact_revision_id=row["artifact_revision_id"],
            parent_artifact_id=row["parent_artifact_id"],
            invalidates_machine_attestation=bool(row["invalidates_machine_attestation"]),
            platform_governance_ref=row["platform_governance_ref"],
            authority_scope=LocalEvidenceAuthorityScope(row["authority_scope"]),
            created_at=row["created_at"],
        )
        payload = json.loads(row["payload_json"])
        if canonical_digest(payload) != row["payload_digest"]:
            raise GovernanceStoreError(f"Stored payload digest mismatch: {artifact_id}")
        return record, payload

    @staticmethod
    def _ensure_idempotent_binding(
        connection: sqlite3.Connection, *, table: str, key_column: str, key_value: str, content_digest: str
    ) -> bool:
        row = connection.execute(
            f"SELECT content_digest FROM {table} WHERE {key_column} = ?", (key_value,)
        ).fetchone()
        if row is None:
            return False
        if row["content_digest"] != content_digest:
            raise GovernanceStoreError(f"Governance binding identity conflict: {key_value}")
        return True

    def register_baseline(
        self,
        *,
        artifact_id: str,
        authority_ref: str,
        effective_from: str,
        actor_ref: str,
    ) -> BaselineRegistration:
        record, _ = self.get_artifact(artifact_id)
        if record.artifact_type != GovernanceArtifactType.SCENARIO_SPEC or not record.behavior_id:
            raise GovernanceStoreError("Only identity-bound ScenarioSpec artifacts can be baselines")
        payload = {
            "registration_id": "baseline-" + sha256(
                f"{artifact_id}\0{authority_ref}\0{effective_from}".encode("utf-8")
            ).hexdigest()[:24],
            "artifact_id": artifact_id,
            "behavior_id": record.behavior_id,
            "authority_ref": authority_ref,
            "effective_from": effective_from,
            "effective_to": None,
        }
        registration = BaselineRegistration(**payload, content_digest=canonical_digest(payload))
        with self.session() as connection:
            if self._ensure_idempotent_binding(
                connection, table="governance_baselines", key_column="registration_id",
                key_value=registration.registration_id, content_digest=registration.content_digest
            ):
                return registration
            connection.execute(
                "INSERT INTO governance_baselines "
                "(registration_id, artifact_id, behavior_id, authority_ref, effective_from, effective_to, content_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    registration.registration_id,
                    artifact_id,
                    record.behavior_id,
                    authority_ref,
                    registration.effective_from,
                    None,
                    registration.content_digest,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.REFERENCE_BASELINE_CACHED,
                artifact_id=artifact_id,
                actor_ref=actor_ref,
                event_at=registration.effective_from,
                payload_digest=registration.content_digest,
            )
        return registration

    @staticmethod
    def _scenario_signature(payload: dict[str, Any]) -> str:
        signature = {
            "behavior_id": payload.get("behavior_id"),
            "procedure_identity_ref": payload.get("procedure_identity_ref"),
            "action": payload.get("action"),
            "preconditions": sorted(
                (
                    {
                        "technical_fact_ref": item.get("technical_fact_ref"),
                        "modality": item.get("modality"),
                        "constraint_assessment_ref": item.get("constraint_assessment_ref"),
                    }
                    for item in payload.get("preconditions", [])
                ),
                key=lambda item: canonical_json_bytes(item),
            ),
            "expected_effects": sorted(
                payload.get("expected_effects", []), key=lambda item: canonical_json_bytes(item)
            ),
            "alternative_or_conditional_effects": sorted(
                payload.get("alternative_or_conditional_effects", []),
                key=lambda item: canonical_json_bytes(item),
            ),
        }
        return canonical_digest(signature)

    def compare_to_baseline(
        self, *, candidate_artifact_id: str, compared_at: str, actor_ref: str
    ) -> BaselineComparisonResult:
        candidate_record, candidate_payload = self.get_artifact(candidate_artifact_id)
        if candidate_record.artifact_type != GovernanceArtifactType.SCENARIO_SPEC or not candidate_record.behavior_id:
            raise GovernanceStoreError("Baseline comparison requires a ScenarioSpec candidate")
        with self.session() as connection:
            rows = connection.execute(
                "SELECT b.artifact_id FROM governance_baselines b "
                "WHERE b.behavior_id = ? AND b.effective_from <= ? "
                "AND (b.effective_to IS NULL OR b.effective_to > ?) "
                "ORDER BY b.effective_from DESC",
                (candidate_record.behavior_id, compared_at, compared_at),
            ).fetchall()
        candidate_signature = self._scenario_signature(candidate_payload)
        baseline_artifact_id: str | None = None
        baseline_signature: str | None = None
        classification: str | None = None
        if not rows:
            status = BaselineComparisonStatus.NO_BASELINE
        else:
            # Baseline registrations are append-only. The latest effective registration wins.
            baseline_artifact_id = rows[0]["artifact_id"]
            _, baseline_payload = self.get_artifact(baseline_artifact_id)
            baseline_signature = self._scenario_signature(baseline_payload)
            if baseline_signature == candidate_signature:
                status = BaselineComparisonStatus.MATCH
            else:
                status = BaselineComparisonStatus.CONFLICT
                classification = "BASELINE_BEHAVIOR_VIOLATION_CANDIDATE"
        payload = {
            "comparison_id": "comparison-" + sha256(
                f"{candidate_artifact_id}\0{baseline_artifact_id}\0{compared_at}".encode("utf-8")
            ).hexdigest()[:24],
            "candidate_artifact_id": candidate_artifact_id,
            "baseline_artifact_id": baseline_artifact_id,
            "behavior_id": candidate_record.behavior_id,
            "source_symbol_id": candidate_record.source_symbol_id,
            "symbol_lineage_id": candidate_record.symbol_lineage_id,
            "artifact_revision_id": candidate_record.artifact_revision_id,
            "status": status,
            "candidate_signature_digest": candidate_signature,
            "baseline_signature_digest": baseline_signature,
            "classification_candidate": classification,
            "evidence_refs": tuple(candidate_payload.get("evidence_refs", [])),
            "compared_at": compared_at,
        }
        result = BaselineComparisonResult(**payload, content_digest=canonical_digest(payload))
        with self.session() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO governance_comparisons "
                "(comparison_id, candidate_artifact_id, baseline_artifact_id, behavior_id, status, "
                "candidate_signature_digest, baseline_signature_digest, classification_candidate, "
                "evidence_refs_json, compared_at, content_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.comparison_id,
                    result.candidate_artifact_id,
                    result.baseline_artifact_id,
                    result.behavior_id,
                    result.status.value,
                    result.candidate_signature_digest,
                    result.baseline_signature_digest,
                    result.classification_candidate,
                    json.dumps(result.evidence_refs),
                    result.compared_at,
                    result.content_digest,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.BASELINE_COMPARED,
                artifact_id=candidate_artifact_id,
                actor_ref=actor_ref,
                event_at=result.compared_at,
                payload_digest=result.content_digest,
            )
        return result

    def amend_scenario_spec(
        self,
        *,
        original_artifact_id: str,
        amended_spec: ScenarioSpec,
        editor_ref: str,
        reason: str,
        amended_at: str,
    ) -> tuple[StoredArtifactRecord, AmendmentRecord]:
        original, original_payload = self.get_artifact(original_artifact_id)
        if original.artifact_type != GovernanceArtifactType.SCENARIO_SPEC:
            raise GovernanceStoreError("Only ScenarioSpec amendment is admitted by this adapter")
        if amended_spec.behavior_id != original.behavior_id:
            raise GovernanceStoreError("Amendment cannot change behavior_id")
        if amended_spec.source_symbol_id != original.source_symbol_id:
            raise GovernanceStoreError("Amendment cannot change source_symbol_id")
        if amended_spec.symbol_lineage_id != original.symbol_lineage_id:
            raise GovernanceStoreError("Amendment cannot change symbol_lineage_id")
        record, _ = self._admit_model(
            amended_spec,
            artifact_type=GovernanceArtifactType.SCENARIO_SPEC,
            artifact_ref=amended_spec.scenario_spec_id,
            created_at=amended_at,
            actor_ref=editor_ref,
            behavior_id=amended_spec.behavior_id,
            source_symbol_id=amended_spec.source_symbol_id,
            symbol_lineage_id=amended_spec.symbol_lineage_id,
            artifact_revision_id=amended_spec.artifact_revision_id,
            parent_artifact_id=original_artifact_id,
            invalidates_machine_attestation=True,
            platform_governance_ref=amended_spec.platform_governance_ref,
        )
        payload = {
            "amendment_id": "amendment-" + sha256(
                f"{original_artifact_id}\0{record.artifact_id}\0{editor_ref}\0{amended_at}".encode("utf-8")
            ).hexdigest()[:24],
            "original_artifact_id": original_artifact_id,
            "amended_artifact_id": record.artifact_id,
            "behavior_id": amended_spec.behavior_id,
            "source_symbol_id": amended_spec.source_symbol_id,
            "symbol_lineage_id": amended_spec.symbol_lineage_id,
            "artifact_revision_id": amended_spec.artifact_revision_id,
            "editor_ref": editor_ref,
            "reason": reason,
            "invalidates_machine_attestation": True,
            "amended_at": amended_at,
        }
        amendment = AmendmentRecord(**payload, content_digest=canonical_digest(payload))
        with self.session() as connection:
            connection.execute(
                "INSERT INTO governance_amendments "
                "(amendment_id, original_artifact_id, amended_artifact_id, editor_ref, reason, "
                "invalidates_machine_attestation, amended_at, content_digest) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    amendment.amendment_id,
                    original_artifact_id,
                    record.artifact_id,
                    editor_ref,
                    reason,
                    amendment.amended_at,
                    amendment.content_digest,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.REVIEW_AMENDMENT_CACHED,
                artifact_id=record.artifact_id,
                actor_ref=editor_ref,
                event_at=amendment.amended_at,
                payload_digest=amendment.content_digest,
            )
        return record, amendment

    def bind_platform_decision(self, envelope: PlatformDecisionEnvelope) -> None:
        validate_content_digest(envelope)
        record, _ = self.get_artifact(envelope.artifact_id)
        if record.content_digest != envelope.artifact_digest:
            raise GovernanceStoreError("Platform decision artifact digest mismatch")
        with self.session() as connection:
            if self._ensure_idempotent_binding(
                connection, table="governance_platform_decisions", key_column="binding_id",
                key_value=envelope.binding_id, content_digest=envelope.content_digest
            ):
                return
            connection.execute(
                "INSERT INTO governance_platform_decisions "
                "(binding_id, artifact_id, artifact_digest, platform_decision_ref, decision_type, "
                "authority_ref, effective_at, evidence_refs_json, content_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    envelope.binding_id,
                    envelope.artifact_id,
                    envelope.artifact_digest,
                    envelope.platform_decision_ref,
                    envelope.decision_type,
                    envelope.authority_ref,
                    envelope.effective_at,
                    json.dumps(envelope.evidence_refs),
                    envelope.content_digest,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.EXTERNAL_PLATFORM_DECISION_CACHED,
                artifact_id=envelope.artifact_id,
                actor_ref=envelope.authority_ref,
                event_at=envelope.effective_at,
                payload_digest=envelope.content_digest,
            )

    def bind_certification(self, envelope: CertificationEnvelope) -> None:
        validate_content_digest(envelope)
        record, _ = self.get_artifact(envelope.artifact_id)
        if record.content_digest != envelope.artifact_digest:
            raise GovernanceStoreError("Certification artifact digest mismatch")
        with self.session() as connection:
            if self._ensure_idempotent_binding(
                connection, table="governance_certifications", key_column="certification_binding_id",
                key_value=envelope.certification_binding_id, content_digest=envelope.content_digest
            ):
                return
            connection.execute(
                "INSERT INTO governance_certifications "
                "(certification_binding_id, artifact_id, artifact_digest, certification_ref, "
                "certification_type, authority_ref, valid_from, valid_to, evidence_refs_json, content_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    envelope.certification_binding_id,
                    envelope.artifact_id,
                    envelope.artifact_digest,
                    envelope.certification_ref,
                    envelope.certification_type,
                    envelope.authority_ref,
                    envelope.valid_from,
                    envelope.valid_to,
                    json.dumps(envelope.evidence_refs),
                    envelope.content_digest,
                ),
            )
            self._append_event(
                connection,
                event_type=GovernanceEventType.EXTERNAL_CERTIFICATION_CACHED,
                artifact_id=envelope.artifact_id,
                actor_ref=envelope.authority_ref,
                event_at=envelope.valid_from,
                payload_digest=envelope.content_digest,
            )

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: GovernanceEventType,
        artifact_id: str,
        actor_ref: str,
        event_at: str,
        payload_digest: str,
    ) -> GovernanceAuditEvent:
        previous = connection.execute(
            "SELECT sequence, content_digest FROM governance_audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_digest = None if previous is None else str(previous["content_digest"])
        payload = {
            "event_id": f"audit-{sequence:012d}",
            "sequence": sequence,
            "event_type": event_type,
            "artifact_id": artifact_id,
            "actor_ref": actor_ref,
            "event_at": event_at,
            "payload_digest": payload_digest,
            "previous_event_digest": previous_digest,
        }
        event = GovernanceAuditEvent(**payload, content_digest=canonical_digest(payload))
        connection.execute(
            "INSERT INTO governance_audit_events "
            "(event_id, sequence, event_type, artifact_id, actor_ref, event_at, payload_digest, "
            "previous_event_digest, content_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.sequence,
                event.event_type.value,
                event.artifact_id,
                event.actor_ref,
                event.event_at,
                event.payload_digest,
                event.previous_event_digest,
                event.content_digest,
            ),
        )
        return event

    def history(self, artifact_id: str) -> GovernanceHistory:
        artifact, _ = self.get_artifact(artifact_id)
        with self.session() as connection:
            baseline_rows = connection.execute(
                "SELECT * FROM governance_baselines WHERE artifact_id = ? ORDER BY effective_from",
                (artifact_id,),
            ).fetchall()
            comparison_rows = connection.execute(
                "SELECT * FROM governance_comparisons WHERE candidate_artifact_id = ? OR baseline_artifact_id = ? "
                "ORDER BY compared_at",
                (artifact_id, artifact_id),
            ).fetchall()
            amendment_rows = connection.execute(
                "SELECT * FROM governance_amendments WHERE original_artifact_id = ? OR amended_artifact_id = ? "
                "ORDER BY amended_at",
                (artifact_id, artifact_id),
            ).fetchall()
            decision_rows = connection.execute(
                "SELECT * FROM governance_platform_decisions WHERE artifact_id = ? ORDER BY effective_at",
                (artifact_id,),
            ).fetchall()
            certification_rows = connection.execute(
                "SELECT * FROM governance_certifications WHERE artifact_id = ? ORDER BY valid_from",
                (artifact_id,),
            ).fetchall()
            event_rows = connection.execute(
                "SELECT * FROM governance_audit_events WHERE artifact_id = ? ORDER BY sequence",
                (artifact_id,),
            ).fetchall()
            all_events = connection.execute(
                "SELECT * FROM governance_audit_events ORDER BY sequence"
            ).fetchall()
        baselines = tuple(
            BaselineRegistration(
                registration_id=row["registration_id"],
                artifact_id=row["artifact_id"],
                behavior_id=row["behavior_id"],
                authority_ref=row["authority_ref"],
                effective_from=row["effective_from"],
                effective_to=row["effective_to"],
                content_digest=row["content_digest"],
            )
            for row in baseline_rows
        )
        comparison_values: list[BaselineComparisonResult] = []
        for row in comparison_rows:
            identity, _ = self.get_artifact(row["candidate_artifact_id"])
            comparison_values.append(BaselineComparisonResult(
                comparison_id=row["comparison_id"],
                candidate_artifact_id=row["candidate_artifact_id"],
                baseline_artifact_id=row["baseline_artifact_id"],
                behavior_id=row["behavior_id"],
                source_symbol_id=identity.source_symbol_id or "",
                symbol_lineage_id=identity.symbol_lineage_id or "",
                artifact_revision_id=identity.artifact_revision_id or "",
                status=BaselineComparisonStatus(row["status"]),
                candidate_signature_digest=row["candidate_signature_digest"],
                baseline_signature_digest=row["baseline_signature_digest"],
                classification_candidate=row["classification_candidate"],
                evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
                compared_at=row["compared_at"],
                content_digest=row["content_digest"],
            ))
        comparisons = tuple(comparison_values)
        amendment_values: list[AmendmentRecord] = []
        for row in amendment_rows:
            identity, _ = self.get_artifact(row["amended_artifact_id"])
            amendment_values.append(AmendmentRecord(
                amendment_id=row["amendment_id"],
                original_artifact_id=row["original_artifact_id"],
                amended_artifact_id=row["amended_artifact_id"],
                behavior_id=identity.behavior_id or "",
                source_symbol_id=identity.source_symbol_id or "",
                symbol_lineage_id=identity.symbol_lineage_id or "",
                artifact_revision_id=identity.artifact_revision_id or "",
                editor_ref=row["editor_ref"],
                reason=row["reason"],
                invalidates_machine_attestation=True,
                amended_at=row["amended_at"],
                content_digest=row["content_digest"],
            ))
        amendments = tuple(amendment_values)
        decisions = tuple(
            PlatformDecisionEnvelope(
                binding_id=row["binding_id"],
                artifact_id=row["artifact_id"],
                artifact_digest=row["artifact_digest"],
                platform_decision_ref=row["platform_decision_ref"],
                decision_type=row["decision_type"],
                authority_ref=row["authority_ref"],
                effective_at=row["effective_at"],
                evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
                content_digest=row["content_digest"],
            )
            for row in decision_rows
        )
        certifications = tuple(
            CertificationEnvelope(
                certification_binding_id=row["certification_binding_id"],
                artifact_id=row["artifact_id"],
                artifact_digest=row["artifact_digest"],
                certification_ref=row["certification_ref"],
                certification_type=row["certification_type"],
                authority_ref=row["authority_ref"],
                valid_from=row["valid_from"],
                valid_to=row["valid_to"],
                evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
                content_digest=row["content_digest"],
            )
            for row in certification_rows
        )
        events = tuple(
            GovernanceAuditEvent(
                event_id=row["event_id"],
                sequence=row["sequence"],
                event_type=GovernanceEventType(row["event_type"]),
                artifact_id=row["artifact_id"],
                actor_ref=row["actor_ref"],
                event_at=row["event_at"],
                payload_digest=row["payload_digest"],
                previous_event_digest=row["previous_event_digest"],
                content_digest=row["content_digest"],
            )
            for row in event_rows
        )
        previous: str | None = None
        chain_valid = True
        for row in all_events:
            event_payload = {
                "event_id": row["event_id"],
                "sequence": row["sequence"],
                "event_type": GovernanceEventType(row["event_type"]),
                "artifact_id": row["artifact_id"],
                "actor_ref": row["actor_ref"],
                "event_at": row["event_at"],
                "payload_digest": row["payload_digest"],
                "previous_event_digest": row["previous_event_digest"],
            }
            if row["previous_event_digest"] != previous or row["content_digest"] != canonical_digest(event_payload):
                chain_valid = False
                break
            previous = row["content_digest"]
        payload = {
            "artifact": artifact,
            "baseline_registrations": baselines,
            "comparisons": comparisons,
            "amendments": amendments,
            "platform_decisions": decisions,
            "certifications": certifications,
            "audit_events": events,
            "audit_chain_valid": chain_valid,
        }
        return GovernanceHistory(**payload, content_digest=canonical_digest(payload))


# Preferred name: this store caches and stages evidence; it has no admission authority.
LocalEvidenceStore = GovernanceStore
