from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import field_validator, model_validator

from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


def canonical_timestamp(value: str) -> str:
    text = value.strip()
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Canonical timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp_active(*, at: str, valid_from: str, valid_to: str | None) -> bool:
    instant = datetime.fromisoformat(canonical_timestamp(at).replace("Z", "+00:00"))
    start = datetime.fromisoformat(canonical_timestamp(valid_from).replace("Z", "+00:00"))
    end = (
        datetime.fromisoformat(canonical_timestamp(valid_to).replace("Z", "+00:00"))
        if valid_to is not None
        else None
    )
    return instant >= start and (end is None or instant < end)


class AuthorityScope(StrEnum):
    TEST_FIXTURE_ONLY = "TEST_FIXTURE_ONLY"
    PLATFORM = "PLATFORM"


class MappingKind(StrEnum):
    EXACT_APPROVED_MAPPING = "EXACT_APPROVED_MAPPING"
    STRUCTURAL_APPROVED_MAPPING = "STRUCTURAL_APPROVED_MAPPING"
    SYMBOL_BOUND_APPROVED_MAPPING = "SYMBOL_BOUND_APPROVED_MAPPING"
    MANUALLY_APPROVED_MAPPING = "MANUALLY_APPROVED_MAPPING"
    MAPPING_CANDIDATE_ONLY = "MAPPING_CANDIDATE_ONLY"


class PlaceholderContract(CanonicalModel):
    placeholder: str
    required: bool = True

    @field_validator("placeholder")
    @classmethod
    def validate_placeholder(cls, value: str) -> str:
        text = value.strip()
        if not text or not text.replace("_", "").isalnum() or text[0].isdigit():
            raise ValueError("Placeholder must be a non-empty identifier.")
        return text


class VocabularyMapping(CanonicalModel):
    mapping_id: str
    mapping_version: str
    mapping_kind: MappingKind
    normalized_technical_pattern_ref: str
    structural_context_digest: str | None = None
    symbol_binding_refs: tuple[str, ...] = ()
    manual_requirement_ref: str | None = None
    phrase_template: str
    placeholder_contract: tuple[PlaceholderContract, ...] = ()
    supported_modalities: tuple[EffectModality, ...] = ()
    approval_ref: str
    authority_scope: AuthorityScope
    valid_from: str
    valid_to: str | None = None
    evidence_refs: tuple[str, ...] = ()
    content_digest: str

    @field_validator("phrase_template")
    @classmethod
    def validate_phrase(cls, value: str) -> str:
        phrase = value.strip()
        if not phrase:
            raise ValueError("Approved phrase cannot be empty.")
        if "\n" in phrase or "\r" in phrase:
            raise ValueError("Approved phrase must be a single canonical line.")
        return phrase

    @field_validator("valid_from", "valid_to")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        return canonical_timestamp(value) if value is not None else None

    @model_validator(mode="after")
    def validate_mapping_semantics(self) -> VocabularyMapping:
        if self.mapping_kind == MappingKind.STRUCTURAL_APPROVED_MAPPING and not self.structural_context_digest:
            raise ValueError("Structural mappings require structural_context_digest.")
        if self.mapping_kind == MappingKind.SYMBOL_BOUND_APPROVED_MAPPING and not self.symbol_binding_refs:
            raise ValueError("Symbol-bound mappings require symbol_binding_refs.")
        if self.mapping_kind == MappingKind.MANUALLY_APPROVED_MAPPING and not self.manual_requirement_ref:
            raise ValueError("Manual mappings require manual_requirement_ref.")
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be later than valid_from.")
        names = [item.placeholder for item in self.placeholder_contract]
        if len(names) != len(set(names)):
            raise ValueError("Placeholder contract contains duplicate names.")
        return self


class VocabularySnapshot(CanonicalModel):
    schema_version: Literal["vocabulary-snapshot-1.1"] = "vocabulary-snapshot-1.1"
    snapshot_id: str
    registry_version: str
    effective_timestamp: str
    authority_scope: AuthorityScope
    mappings: tuple[VocabularyMapping, ...]
    content_digest: str

    @field_validator("effective_timestamp")
    @classmethod
    def validate_effective_timestamp(cls, value: str) -> str:
        return canonical_timestamp(value)


class ClassificationApproval(CanonicalModel):
    approval_id: str
    classification_observation_ref: str
    classification_observation_digest: str
    approved_candidate: str
    approval_ref: str
    authority_scope: AuthorityScope
    valid_from: str
    valid_to: str | None = None
    evidence_refs: tuple[str, ...] = ()
    content_digest: str

    @field_validator("valid_from", "valid_to")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        return canonical_timestamp(value) if value is not None else None

    @model_validator(mode="after")
    def validate_interval(self) -> ClassificationApproval:
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be later than valid_from.")
        return self


class ClassificationSnapshot(CanonicalModel):
    schema_version: Literal["classification-snapshot-1.1"] = "classification-snapshot-1.1"
    snapshot_id: str
    registry_version: str
    effective_timestamp: str
    authority_scope: AuthorityScope
    approvals: tuple[ClassificationApproval, ...]
    content_digest: str

    @field_validator("effective_timestamp")
    @classmethod
    def validate_effective_timestamp(cls, value: str) -> str:
        return canonical_timestamp(value)


class BddCompilationStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class BddBlockerCode(StrEnum):
    SCENARIO_SPEC_BATCH_DIGEST_INVALID = "SCENARIO_SPEC_BATCH_DIGEST_INVALID"
    SCENARIO_SPEC_DIGEST_INVALID = "SCENARIO_SPEC_DIGEST_INVALID"
    SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID = "SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID"
    VOCABULARY_SNAPSHOT_DIGEST_INVALID = "VOCABULARY_SNAPSHOT_DIGEST_INVALID"
    CLASSIFICATION_SNAPSHOT_DIGEST_INVALID = "CLASSIFICATION_SNAPSHOT_DIGEST_INVALID"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    MISSING_CLASSIFICATION_APPROVAL = "MISSING_CLASSIFICATION_APPROVAL"
    AMBIGUOUS_CLASSIFICATION_APPROVAL = "AMBIGUOUS_CLASSIFICATION_APPROVAL"
    CLASSIFICATION_CANDIDATE_MISMATCH = "CLASSIFICATION_CANDIDATE_MISMATCH"
    CLASSIFICATION_OBSERVATION_DIGEST_MISMATCH = "CLASSIFICATION_OBSERVATION_DIGEST_MISMATCH"
    CLASSIFICATION_APPROVAL_NOT_EFFECTIVE = "CLASSIFICATION_APPROVAL_NOT_EFFECTIVE"
    NO_APPROVED_BUSINESS_TERM = "NO_APPROVED_BUSINESS_TERM"
    AMBIGUOUS_APPROVED_BUSINESS_TERM = "AMBIGUOUS_APPROVED_BUSINESS_TERM"
    MAPPING_NOT_EFFECTIVE = "MAPPING_NOT_EFFECTIVE"
    MAPPING_REQUIREMENT_MISMATCH = "MAPPING_REQUIREMENT_MISMATCH"
    MAPPING_KIND_SEMANTICS_INVALID = "MAPPING_KIND_SEMANTICS_INVALID"
    NON_PROMOTABLE_MAPPING_KIND = "NON_PROMOTABLE_MAPPING_KIND"
    PLACEHOLDER_BINDING_INVALID = "PLACEHOLDER_BINDING_INVALID"
    MODALITY_NOT_APPROVED_BY_MAPPING = "MODALITY_NOT_APPROVED_BY_MAPPING"
    NON_DEFINITIVE_EFFECT = "NON_DEFINITIVE_EFFECT"
    EFFECT_CLOSURE_INSUFFICIENT = "EFFECT_CLOSURE_INSUFFICIENT"
    DEPENDENCY_RESOLUTION_INCOMPLETE = "DEPENDENCY_RESOLUTION_INCOMPLETE"
    TRACEABILITY_MANIFEST_FAILED = "TRACEABILITY_MANIFEST_FAILED"
    GHERKIN_STRUCTURE_INVALID = "GHERKIN_STRUCTURE_INVALID"
    COMPILATION_INTERNAL_ERROR = "COMPILATION_INTERNAL_ERROR"


class GherkinArtifact(CanonicalModel):
    artifact_id: str
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    dialect: Literal["en"] = "en"
    text: str
    content_digest: str


class GherkinElementBinding(CanonicalModel):
    element_id: str
    element_kind: Literal["FEATURE", "SCENARIO_NAME", "GIVEN", "WHEN", "THEN", "AND"]
    scenario_spec_element_refs: tuple[str, ...]
    authority_requirement_ref: str
    mapping_ref: str
    effect_or_precondition_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


class TraceabilityManifest(CanonicalModel):
    manifest_id: str
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    scenario_spec_ref: str
    gherkin_artifact_ref: str
    element_bindings: tuple[GherkinElementBinding, ...]
    input_digest_set: tuple[str, ...]
    content_digest: str


class CandidateBdd(CanonicalModel):
    candidate_bdd_id: str
    schema_version: Literal["candidate-bdd-1.2"] = "candidate-bdd-1.2"
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    artifact_revision_id: str
    scenario_spec_ref: str
    gherkin_artifact_ref: str
    traceability_manifest_ref: str
    authority_requirements_digest: str
    vocabulary_snapshot_digest: str
    classification_snapshot_digest: str
    compiler_version: Literal["bdd-compiler-1.4"] = "bdd-compiler-1.4"
    authority_scope: AuthorityScope
    platform_governance_ref: str | None = None
    content_digest: str


class BddCompilationResult(CanonicalModel):
    compilation_status: BddCompilationStatus
    scenario_spec_ref: str
    candidate_bdd_ref: str | None = None
    blockers: tuple[BddBlockerCode, ...] = ()
    mapping_refs: tuple[str, ...] = ()
    classification_approval_refs: tuple[str, ...] = ()
    finding_refs: tuple[str, ...] = ()
    input_scenario_spec_digest: str
    authority_requirements_digest: str
    vocabulary_snapshot_digest: str
    classification_snapshot_digest: str
    compiler_version: Literal["bdd-compiler-1.4"] = "bdd-compiler-1.4"
    compiler_configuration_digest: str
    effective_timestamp: str
    output_digest: str | None = None

    @field_validator("effective_timestamp")
    @classmethod
    def validate_effective_timestamp(cls, value: str) -> str:
        return canonical_timestamp(value)


class BddCompilationBatch(CanonicalModel):
    schema_version: Literal["bdd-compilation-batch-1.1"] = "bdd-compilation-batch-1.1"
    scenario_spec_batch_digest: str
    authority_requirements_ref: str
    authority_requirements_digest: str
    vocabulary_snapshot_ref: str
    vocabulary_snapshot_digest: str
    classification_snapshot_ref: str
    classification_snapshot_digest: str
    authority_scope: AuthorityScope
    gherkin_artifacts: tuple[GherkinArtifact, ...]
    traceability_manifests: tuple[TraceabilityManifest, ...]
    candidate_bdds: tuple[CandidateBdd, ...]
    compilation_results: tuple[BddCompilationResult, ...]
    content_digest: str
