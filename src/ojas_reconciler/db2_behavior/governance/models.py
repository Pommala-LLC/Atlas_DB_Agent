from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import field_validator, model_validator

from ojas_reconciler.db2_behavior.bdd.models import canonical_timestamp
from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel


class GovernanceArtifactType(StrEnum):
    SCENARIO_SPEC_BATCH = "SCENARIO_SPEC_BATCH"
    SCENARIO_SPEC = "SCENARIO_SPEC"
    CLASSIFICATION_OBSERVATION = "CLASSIFICATION_OBSERVATION"
    EFFECT_CLOSURE = "EFFECT_CLOSURE"
    RESOLUTION_VECTOR = "RESOLUTION_VECTOR"
    ANALYSIS_BUDGET_REPORT = "ANALYSIS_BUDGET_REPORT"
    BDD_COMPILATION_BATCH = "BDD_COMPILATION_BATCH"
    CANDIDATE_BDD = "CANDIDATE_BDD"
    TRACEABILITY_MANIFEST = "TRACEABILITY_MANIFEST"
    GHERKIN_ARTIFACT = "GHERKIN_ARTIFACT"
    RUNTIME_VERIFICATION_BATCH = "RUNTIME_VERIFICATION_BATCH"
    RUNTIME_EXECUTION_RECORD = "RUNTIME_EXECUTION_RECORD"
    RUNTIME_VERIFICATION_RESULT = "RUNTIME_VERIFICATION_RESULT"
    PLATFORM_DECISION = "PLATFORM_DECISION"
    CERTIFICATION_BINDING = "CERTIFICATION_BINDING"




class LocalEvidenceAuthorityScope(StrEnum):
    LOCAL_NON_AUTHORITATIVE_EVIDENCE = "LOCAL_NON_AUTHORITATIVE_EVIDENCE"

class BaselineComparisonStatus(StrEnum):
    MATCH = "MATCH"
    CONFLICT = "CONFLICT"
    NO_BASELINE = "NO_BASELINE"
    INCONCLUSIVE = "INCONCLUSIVE"


class GovernanceEventType(StrEnum):
    ARTIFACT_CACHED = "ARTIFACT_CACHED"
    REFERENCE_BASELINE_CACHED = "REFERENCE_BASELINE_CACHED"
    BASELINE_RETIRED = "BASELINE_RETIRED"
    BASELINE_COMPARED = "BASELINE_COMPARED"
    REVIEW_AMENDMENT_CACHED = "REVIEW_AMENDMENT_CACHED"
    EXTERNAL_PLATFORM_DECISION_CACHED = "EXTERNAL_PLATFORM_DECISION_CACHED"
    EXTERNAL_CERTIFICATION_CACHED = "EXTERNAL_CERTIFICATION_CACHED"
    # Legacy values remain readable for existing local cache files.
    ARTIFACT_ADMITTED = "ARTIFACT_ADMITTED"
    BASELINE_REGISTERED = "BASELINE_REGISTERED"
    ARTIFACT_AMENDED = "ARTIFACT_AMENDED"
    PLATFORM_DECISION_BOUND = "PLATFORM_DECISION_BOUND"
    CERTIFICATION_BOUND = "CERTIFICATION_BOUND"


class StoredArtifactRecord(CanonicalModel):
    artifact_id: str
    artifact_type: GovernanceArtifactType
    artifact_ref: str
    content_digest: str
    payload_digest: str
    behavior_id: str | None = None
    source_symbol_id: str | None = None
    symbol_lineage_id: str | None = None
    artifact_revision_id: str | None = None
    parent_artifact_id: str | None = None
    invalidates_machine_attestation: bool = False
    platform_governance_ref: str | None = None
    authority_scope: LocalEvidenceAuthorityScope = LocalEvidenceAuthorityScope.LOCAL_NON_AUTHORITATIVE_EVIDENCE
    created_at: str

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: str) -> str:
        return canonical_timestamp(value)


class BaselineRegistration(CanonicalModel):
    registration_id: str
    artifact_id: str
    behavior_id: str
    authority_ref: str
    effective_from: str
    effective_to: str | None = None
    content_digest: str

    @field_validator("effective_from", "effective_to")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        return canonical_timestamp(value) if value is not None else None

    @model_validator(mode="after")
    def validate_range(self) -> BaselineRegistration:
        if self.effective_to is not None and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be later than effective_from")
        return self


class BaselineComparisonResult(CanonicalModel):
    comparison_id: str
    candidate_artifact_id: str
    baseline_artifact_id: str | None
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    status: BaselineComparisonStatus
    candidate_signature_digest: str
    baseline_signature_digest: str | None
    classification_candidate: Literal["BASELINE_BEHAVIOR_VIOLATION_CANDIDATE"] | None = None
    evidence_refs: tuple[str, ...] = ()
    compared_at: str
    content_digest: str

    @field_validator("compared_at")
    @classmethod
    def validate_compared_at(cls, value: str) -> str:
        return canonical_timestamp(value)


class AmendmentRecord(CanonicalModel):
    amendment_id: str
    original_artifact_id: str
    amended_artifact_id: str
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    editor_ref: str
    reason: str
    invalidates_machine_attestation: Literal[True] = True
    amended_at: str
    content_digest: str

    @field_validator("amended_at")
    @classmethod
    def validate_amended_at(cls, value: str) -> str:
        return canonical_timestamp(value)


class PlatformDecisionEnvelope(CanonicalModel):
    binding_id: str
    artifact_id: str
    artifact_digest: str
    platform_decision_ref: str
    decision_type: str
    authority_ref: str
    effective_at: str
    evidence_refs: tuple[str, ...] = ()
    content_digest: str

    @field_validator("effective_at")
    @classmethod
    def validate_effective_at(cls, value: str) -> str:
        return canonical_timestamp(value)


class CertificationEnvelope(CanonicalModel):
    certification_binding_id: str
    artifact_id: str
    artifact_digest: str
    certification_ref: str
    certification_type: str
    authority_ref: str
    valid_from: str
    valid_to: str | None = None
    evidence_refs: tuple[str, ...] = ()
    content_digest: str

    @field_validator("valid_from", "valid_to")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        return canonical_timestamp(value) if value is not None else None


class GovernanceAuditEvent(CanonicalModel):
    event_id: str
    sequence: int
    event_type: GovernanceEventType
    artifact_id: str
    actor_ref: str
    event_at: str
    payload_digest: str
    previous_event_digest: str | None = None
    content_digest: str

    @field_validator("event_at")
    @classmethod
    def validate_event_at(cls, value: str) -> str:
        return canonical_timestamp(value)


class GovernanceHistory(CanonicalModel):
    artifact: StoredArtifactRecord
    baseline_registrations: tuple[BaselineRegistration, ...]
    comparisons: tuple[BaselineComparisonResult, ...]
    amendments: tuple[AmendmentRecord, ...]
    platform_decisions: tuple[PlatformDecisionEnvelope, ...]
    certifications: tuple[CertificationEnvelope, ...]
    audit_events: tuple[GovernanceAuditEvent, ...]
    audit_chain_valid: bool
    content_digest: str
