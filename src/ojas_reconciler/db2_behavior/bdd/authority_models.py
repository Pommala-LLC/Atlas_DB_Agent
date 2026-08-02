from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from ojas_reconciler.db2_behavior.bdd.models import AuthorityScope, BddBlockerCode
from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.bdd.scenario_models import EffectClosureCompleteness, ResolutionStatus
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


class VocabularySlotKind(StrEnum):
    FEATURE_TITLE = "FEATURE_TITLE"
    SCENARIO_NAME = "SCENARIO_NAME"
    ACTION = "ACTION"
    PRECONDITION = "PRECONDITION"
    EFFECT = "EFFECT"


class PlaceholderValue(CanonicalModel):
    placeholder: str
    value: str


class VocabularyRequirement(CanonicalModel):
    requirement_id: str
    scenario_spec_ref: str
    slot_id: str
    slot_kind: VocabularySlotKind
    source_ref: str
    normalized_technical_pattern_ref: str
    structural_context_digest: str
    symbol_binding_refs: tuple[str, ...] = ()
    placeholder_values: tuple[PlaceholderValue, ...] = ()
    required_modality: EffectModality | None = None
    evidence_refs: tuple[str, ...] = ()


class ClassificationRequirement(CanonicalModel):
    requirement_id: str
    scenario_spec_refs: tuple[str, ...]
    classification_observation_ref: str
    classification_observation_digest: str
    candidate: str
    method: str
    method_version: str
    classification_evidence_refs: tuple[str, ...] = ()


class AuthorityRequirementsManifest(CanonicalModel):
    schema_version: Literal["authority-requirements-1.1"] = "authority-requirements-1.1"
    manifest_id: str
    scenario_spec_batch_digest: str
    procedure_identity_ref: str
    required_authority_scope: Literal["PLATFORM"] = "PLATFORM"
    vocabulary_requirements: tuple[VocabularyRequirement, ...]
    classification_requirements: tuple[ClassificationRequirement, ...]
    content_digest: str


class AuthorityValidationIssueCode(StrEnum):
    VOCABULARY_SNAPSHOT_DIGEST_INVALID = "VOCABULARY_SNAPSHOT_DIGEST_INVALID"
    CLASSIFICATION_SNAPSHOT_DIGEST_INVALID = "CLASSIFICATION_SNAPSHOT_DIGEST_INVALID"
    MAPPING_DIGEST_INVALID = "MAPPING_DIGEST_INVALID"
    CLASSIFICATION_APPROVAL_DIGEST_INVALID = "CLASSIFICATION_APPROVAL_DIGEST_INVALID"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    DUPLICATE_MAPPING_ID = "DUPLICATE_MAPPING_ID"
    DUPLICATE_APPROVAL_ID = "DUPLICATE_APPROVAL_ID"
    DUPLICATE_ACTIVE_MAPPING_BINDING = "DUPLICATE_ACTIVE_MAPPING_BINDING"
    DUPLICATE_CLASSIFICATION_APPROVAL = "DUPLICATE_CLASSIFICATION_APPROVAL"
    NON_PROMOTABLE_PLATFORM_MAPPING = "NON_PROMOTABLE_PLATFORM_MAPPING"
    MAPPING_KIND_SEMANTICS_INVALID = "MAPPING_KIND_SEMANTICS_INVALID"
    INVALID_VALIDITY_INTERVAL = "INVALID_VALIDITY_INTERVAL"
    MAPPING_NOT_EFFECTIVE_AT_SNAPSHOT = "MAPPING_NOT_EFFECTIVE_AT_SNAPSHOT"
    APPROVAL_NOT_EFFECTIVE_AT_SNAPSHOT = "APPROVAL_NOT_EFFECTIVE_AT_SNAPSHOT"
    EMPTY_APPROVAL_REFERENCE = "EMPTY_APPROVAL_REFERENCE"
    EMPTY_MAPPING_EVIDENCE = "EMPTY_MAPPING_EVIDENCE"
    EMPTY_CLASSIFICATION_EVIDENCE = "EMPTY_CLASSIFICATION_EVIDENCE"


class AuthorityValidationIssue(CanonicalModel):
    code: AuthorityValidationIssueCode
    artifact_ref: str
    message: str


class AuthorityValidationStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"


class AuthoritySnapshotValidationResult(CanonicalModel):
    schema_version: Literal["authority-validation-1.1"] = "authority-validation-1.1"
    validation_status: AuthorityValidationStatus
    vocabulary_snapshot_ref: str
    vocabulary_snapshot_digest: str
    classification_snapshot_ref: str
    classification_snapshot_digest: str
    authority_scope: AuthorityScope | None
    issues: tuple[AuthorityValidationIssue, ...]
    content_digest: str


class BddGateExplanation(CanonicalModel):
    explanation_id: str
    scenario_spec_ref: str
    result: Literal["SUCCEEDED", "BLOCKED", "FAILED"]
    blocker_codes: tuple[BddBlockerCode, ...]
    missing_vocabulary_slots: tuple[str, ...] = ()
    ambiguous_vocabulary_slots: tuple[str, ...] = ()
    missing_classification_observation_refs: tuple[str, ...] = ()
    ambiguous_classification_observation_refs: tuple[str, ...] = ()
    effect_closure_completeness: EffectClosureCompleteness | None = None
    dependency_resolution: dict[str, ResolutionStatus] = Field(default_factory=dict)
    affected_outputs: tuple[str, ...] = ()
    withheld_outputs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    consequence: str
    recommended_actions: tuple[str, ...]
    content_digest: str


class BddExplanationBatch(CanonicalModel):
    schema_version: Literal["bdd-explanation-batch-1.1"] = "bdd-explanation-batch-1.1"
    bdd_compilation_batch_digest: str
    scenario_spec_batch_digest: str
    vocabulary_snapshot_digest: str
    classification_snapshot_digest: str
    explanations: tuple[BddGateExplanation, ...]
    content_digest: str
