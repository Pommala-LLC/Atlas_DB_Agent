from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import field_validator, model_validator

from ojas_reconciler.db2_behavior.bdd.models import canonical_timestamp
from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


class RuntimeExecutionMode(StrEnum):
    SCRIPTED_FIXTURE = "SCRIPTED_FIXTURE"
    DB2_SANDBOX = "DB2_SANDBOX"


class LiveVerificationEligibility(StrEnum):
    DB2_SANDBOX_ALLOWED = "DB2_SANDBOX_ALLOWED"
    MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"
    PROHIBITED = "PROHIBITED"


class TransactionOwnership(StrEnum):
    EXECUTOR_OWNED = "EXECUTOR_OWNED"
    CALLER_CONTROLLED = "CALLER_CONTROLLED"
    PROCEDURE_CONTROLLED = "PROCEDURE_CONTROLLED"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


class RollbackContainment(StrEnum):
    ROLLBACK_SAFE = "ROLLBACK_SAFE"
    CALLER_ROLLBACK_POSSIBLE = "CALLER_ROLLBACK_POSSIBLE"
    NOT_GUARANTEED = "NOT_GUARANTEED"
    UNKNOWN = "UNKNOWN"


class RuntimePlanStatus(StrEnum):
    READY_SCRIPTED = "READY_SCRIPTED"
    READY_DB2_SANDBOX = "READY_DB2_SANDBOX"
    MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


class RuntimeValueKind(StrEnum):
    NULL = "NULL"
    STRING = "STRING"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    BOOLEAN = "BOOLEAN"
    DATE = "DATE"
    TIMESTAMP = "TIMESTAMP"
    RAW = "RAW"


class RuntimeValue(CanonicalModel):
    value_kind: RuntimeValueKind
    canonical_value: str | None = None

    @model_validator(mode="after")
    def validate_value(self) -> RuntimeValue:
        if self.value_kind == RuntimeValueKind.NULL and self.canonical_value is not None:
            raise ValueError("NULL runtime values cannot carry canonical_value.")
        if self.value_kind != RuntimeValueKind.NULL and self.canonical_value is None:
            raise ValueError("Non-NULL runtime values require canonical_value.")
        return self


class RuntimeInputRequirement(CanonicalModel):
    parameter_name: str
    parameter_mode: Literal["IN", "INOUT"]
    type_text: str


class RuntimeInvocationParameter(CanonicalModel):
    parameter_name: str
    parameter_mode: Literal["IN", "OUT", "INOUT"]
    type_text: str
    value: RuntimeValue


class RuntimeInvocation(CanonicalModel):
    invocation_id: str
    procedure_schema: str | None = None
    procedure_name: str
    parameters: tuple[RuntimeInvocationParameter, ...]
    content_digest: str


class RuntimeSafetyAssessment(CanonicalModel):
    assessment_id: str
    procedure_identity_ref: str
    internal_commit_present: bool
    explicit_rollback_present: bool
    commit_on_return: Literal["YES", "NO", "UNKNOWN"]
    unresolved_call_boundaries: tuple[str, ...]
    unresolved_dynamic_boundaries: tuple[str, ...]
    external_side_effects_status: Literal["ABSENT", "POSSIBLE", "UNKNOWN"]
    transaction_ownership: TransactionOwnership
    rollback_containment: RollbackContainment
    live_eligibility: LiveVerificationEligibility
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    content_digest: str


class RuntimeObservationKind(StrEnum):
    OUT_PARAMETER = "OUT_PARAMETER"
    DML_EFFECT = "DML_EFFECT"
    CALL_EFFECT = "CALL_EFFECT"
    SQLSTATE = "SQLSTATE"
    RESULT_SET = "RESULT_SET"
    EFFECT_REFERENCE = "EFFECT_REFERENCE"


class RuntimeExpectedObservation(CanonicalModel):
    expectation_id: str
    scenario_effect_ref: str
    modality: EffectModality
    observation_kind: RuntimeObservationKind
    target: str | None = None
    expected_value: RuntimeValue | None = None
    evidence_refs: tuple[str, ...] = ()


class RuntimeVerificationPlan(CanonicalModel):
    plan_id: str
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    schema_version: Literal["runtime-verification-plan-1.0"] = "runtime-verification-plan-1.0"
    scenario_spec_ref: str
    scenario_spec_digest: str
    procedure_identity_ref: str
    procedure_schema: str | None = None
    procedure_name: str
    input_requirements: tuple[RuntimeInputRequirement, ...]
    expected_observations: tuple[RuntimeExpectedObservation, ...]
    safety_assessment_ref: str
    plan_status: RuntimePlanStatus
    blockers: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    content_digest: str


class RuntimeVerificationPlanBatch(CanonicalModel):
    schema_version: Literal["runtime-verification-plan-batch-1.0"] = "runtime-verification-plan-batch-1.0"
    scenario_spec_batch_digest: str
    semantic_result_digest: str
    safety_assessment: RuntimeSafetyAssessment
    plans: tuple[RuntimeVerificationPlan, ...]
    content_digest: str


class RuntimeObservedParameter(CanonicalModel):
    parameter_name: str
    value: RuntimeValue


class RuntimeRowChange(CanonicalModel):
    relation_name: str
    operation: Literal["INSERT", "UPDATE", "DELETE", "MERGE", "UNKNOWN"]
    before_digest: str | None = None
    after_digest: str | None = None
    row_count: int | None = None
    effect_ref: str | None = None


class RuntimeTransactionEvent(CanonicalModel):
    event_kind: Literal["BEGIN", "COMMIT", "ROLLBACK", "CALLER_ROLLBACK", "UNKNOWN"]
    sequence: int


class RuntimeExecutionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class RuntimeObservationScript(CanonicalModel):
    schema_version: Literal["runtime-observation-script-1.0"] = "runtime-observation-script-1.0"
    script_id: str
    plan_ref: str
    plan_digest: str
    invocation: RuntimeInvocation
    execution_status: RuntimeExecutionStatus
    output_parameters: tuple[RuntimeObservedParameter, ...] = ()
    sqlstate: str | None = None
    observed_effect_refs: tuple[str, ...] = ()
    row_changes: tuple[RuntimeRowChange, ...] = ()
    called_routines: tuple[str, ...] = ()
    transaction_events: tuple[RuntimeTransactionEvent, ...] = ()
    result_set_digests: tuple[str, ...] = ()
    error_message: str | None = None
    started_at: str
    ended_at: str
    content_digest: str

    @field_validator("started_at", "ended_at")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        return canonical_timestamp(value)


class RuntimeExecutionRecord(CanonicalModel):
    execution_id: str
    schema_version: Literal["runtime-execution-record-1.0"] = "runtime-execution-record-1.0"
    plan_ref: str
    plan_digest: str
    invocation_ref: str
    execution_mode: RuntimeExecutionMode
    executor_name: str
    executor_version: str
    execution_status: RuntimeExecutionStatus
    output_parameters: tuple[RuntimeObservedParameter, ...]
    sqlstate: str | None = None
    observed_effect_refs: tuple[str, ...]
    row_changes: tuple[RuntimeRowChange, ...]
    called_routines: tuple[str, ...]
    transaction_events: tuple[RuntimeTransactionEvent, ...]
    result_set_digests: tuple[str, ...]
    error_message: str | None = None
    started_at: str
    ended_at: str
    evidence_refs: tuple[str, ...]
    content_digest: str

    @field_validator("started_at", "ended_at")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        return canonical_timestamp(value)


class RuntimeVerificationStatus(StrEnum):
    MATCHED = "MATCHED"
    MISMATCH = "MISMATCH"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class RuntimeVerificationFindingCode(StrEnum):
    RUNTIME_PLAN_DIGEST_INVALID = "RUNTIME_PLAN_DIGEST_INVALID"
    SCENARIO_SPEC_DIGEST_INVALID = "SCENARIO_SPEC_DIGEST_INVALID"
    EXECUTION_RECORD_DIGEST_INVALID = "EXECUTION_RECORD_DIGEST_INVALID"
    OBSERVATION_SCRIPT_DIGEST_INVALID = "OBSERVATION_SCRIPT_DIGEST_INVALID"
    PLAN_SCRIPT_MISMATCH = "PLAN_SCRIPT_MISMATCH"
    LIVE_VERIFICATION_PROHIBITED = "LIVE_VERIFICATION_PROHIBITED"
    MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"
    MISSING_REQUIRED_INPUT = "MISSING_REQUIRED_INPUT"
    MUST_EFFECT_NOT_OBSERVED = "MUST_EFFECT_NOT_OBSERVED"
    MUST_NOT_EFFECT_OBSERVED = "MUST_NOT_EFFECT_OBSERVED"
    OUT_PARAMETER_VALUE_MISMATCH = "OUT_PARAMETER_VALUE_MISMATCH"
    STATIC_RUNTIME_EVIDENCE_CONFLICT = "STATIC_RUNTIME_EVIDENCE_CONFLICT"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_EVIDENCE_INCOMPLETE = "EXECUTION_EVIDENCE_INCOMPLETE"
    LIVE_ADAPTER_UNAVAILABLE = "LIVE_ADAPTER_UNAVAILABLE"
    SANDBOX_ATTESTATION_REQUIRED = "SANDBOX_ATTESTATION_REQUIRED"
    RUNTIME_RESULT_INCONCLUSIVE = "RUNTIME_RESULT_INCONCLUSIVE"


class RuntimeVerificationFinding(CanonicalModel):
    finding_id: str
    code: RuntimeVerificationFindingCode
    message: str
    evidence_refs: tuple[str, ...]
    consequence: str


class RuntimeExpectationResult(CanonicalModel):
    expectation_ref: str
    scenario_effect_ref: str
    modality: EffectModality
    matched: bool | None
    observed_refs: tuple[str, ...]
    finding_refs: tuple[str, ...]


class RuntimeVerificationResult(CanonicalModel):
    verification_result_id: str
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    schema_version: Literal["runtime-verification-result-1.0"] = "runtime-verification-result-1.0"
    scenario_spec_ref: str
    plan_ref: str
    execution_record_ref: str | None = None
    verification_status: RuntimeVerificationStatus
    expectation_results: tuple[RuntimeExpectationResult, ...]
    findings: tuple[RuntimeVerificationFinding, ...]
    static_runtime_conflict: bool
    platform_governance_ref: str | None = None
    input_digest_set: tuple[str, ...]
    content_digest: str


class RuntimeVerificationBatch(CanonicalModel):
    schema_version: Literal["runtime-verification-batch-1.0"] = "runtime-verification-batch-1.0"
    plan_batch_digest: str
    execution_records: tuple[RuntimeExecutionRecord, ...]
    verification_results: tuple[RuntimeVerificationResult, ...]
    content_digest: str


class Db2ObservationProbe(CanonicalModel):
    probe_id: str
    effect_ref: str
    relation_name: str
    operation: Literal["INSERT", "UPDATE", "DELETE", "MERGE", "UNKNOWN"]
    snapshot_query: str

    @field_validator("snapshot_query")
    @classmethod
    def validate_snapshot_query(cls, value: str) -> str:
        text = value.strip()
        upper = text.upper()
        if not (upper.startswith("SELECT ") or upper.startswith("WITH ")):
            raise ValueError("Runtime observation probes must be read-only SELECT or WITH queries.")
        if ";" in text:
            raise ValueError("Runtime observation probes must contain exactly one statement without semicolons.")
        return text


class Db2SandboxConfig(CanonicalModel):
    connection_ref: str
    environment_variable: str = "ATLAS_DB2_CONNECTION_STRING"
    sandbox_attestation: str
    manual_approval_ref: str | None = None
    rollback_after_call: bool = True
    execute_live: bool = False
    observation_probes: tuple[Db2ObservationProbe, ...] = ()
