from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class PipelineStageStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class AuthorityMode(str, Enum):
    NONE = "NONE"
    TEST_FIXTURE_ONLY = "TEST_FIXTURE_ONLY"
    EXTERNAL_SNAPSHOT = "EXTERNAL_SNAPSHOT"


class PipelineStageRecord(FrozenModel):
    stage: str
    status: PipelineStageStatus
    artifact_path: str | None = None
    artifact_digest: str | None = None
    blocker_codes: tuple[str, ...] = ()
    details: tuple[str, ...] = ()


class EndToEndRunManifest(FrozenModel):
    schema_version: str = "db2-e2e-run-1.0"
    run_id: str
    source_path: str
    source_digest: str
    authority_mode: AuthorityMode
    governance_mode: str
    stage_records: tuple[PipelineStageRecord, ...]
    emitted_artifact_paths: tuple[str, ...]
    input_dependent_checks: tuple[str, ...]
    content_digest: str


class DoctorCheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class DoctorCheck(FrozenModel):
    check_id: str
    status: DoctorCheckStatus
    message: str


class DoctorReport(FrozenModel):
    schema_version: str = "db2-doctor-1.0"
    checks: tuple[DoctorCheck, ...]
    overall_status: DoctorCheckStatus
    content_digest: str
