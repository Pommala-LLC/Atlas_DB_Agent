from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.analysis.models import ConstraintAssessmentStatus, EffectModality


class ScenarioCompilationStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ScenarioBlockerCode(StrEnum):
    PARSER_RESULT_INCOMPLETE = "PARSER_RESULT_INCOMPLETE"
    BEHAVIOR_BUNDLE_PARTIAL = "BEHAVIOR_BUNDLE_PARTIAL"
    BEHAVIOR_SLICE_PARTIAL = "BEHAVIOR_SLICE_PARTIAL"
    ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL = "ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL"
    UNDECLARED_SYMBOL_REFERENCE = "UNDECLARED_SYMBOL_REFERENCE"
    PREDICATE_NORMALIZATION_PARTIAL = "PREDICATE_NORMALIZATION_PARTIAL"
    OBVIOUS_PREDICATE_CONTRADICTION = "OBVIOUS_PREDICATE_CONTRADICTION"
    UNKNOWN_EFFECT_MODALITY = "UNKNOWN_EFFECT_MODALITY"
    UNRESOLVED_EFFECT_OBSERVABILITY = "UNRESOLVED_EFFECT_OBSERVABILITY"
    TRANSACTION_SURVIVAL_UNRESOLVED = "TRANSACTION_SURVIVAL_UNRESOLVED"
    MISSING_PRIMARY_EFFECT_OBLIGATION = "MISSING_PRIMARY_EFFECT_OBLIGATION"
    COMPILATION_BUDGET_EXCEEDED = "COMPILATION_BUDGET_EXCEEDED"
    EVIDENCE_BINDING_INCOMPLETE = "EVIDENCE_BINDING_INCOMPLETE"
    SEMANTIC_RESULT_DIGEST_INVALID = "SEMANTIC_RESULT_DIGEST_INVALID"


class ClassificationAuthorityStatus(StrEnum):
    APPROVED = "APPROVED"
    UNAPPROVED = "UNAPPROVED"


class ClassificationObservation(CanonicalModel):
    classification_observation_id: str
    candidate: str
    method: str
    method_version: str
    ranking_score: float | None = None
    score_semantics: Literal["RANKING_ONLY"] | None = None
    classification_evidence_refs: tuple[str, ...] = ()
    authority_ref: str | None = None
    authority_status: ClassificationAuthorityStatus


class ScenarioAction(CanonicalModel):
    action_kind: Literal[
        "PROCEDURE_INVOCATION",
        "CURSOR_ITERATION",
        "HANDLER_ACTIVATION",
        "POST_LOOP_AGGREGATION",
        "TRANSACTION_COMPLETION",
    ] = "PROCEDURE_INVOCATION"
    procedure_identity_ref: str
    invocation_contract_ref: str
    action_scope_ref: str | None = None
    evidence_refs: tuple[str, ...] = ()


class ScenarioPrecondition(CanonicalModel):
    precondition_id: str
    technical_fact_ref: str
    modality: Literal["MUST"] = "MUST"
    constraint_assessment_ref: str | None = None
    classification_observation_ref: str | None = None
    evidence_refs: tuple[str, ...] = ()


class ScenarioEffect(CanonicalModel):
    effect_ref: str
    modality: EffectModality
    evidence_refs: tuple[str, ...] = ()
    caller_transaction_contract_ref: str | None = None


class EffectClosureCompleteness(StrEnum):
    DIRECT_EFFECT_ONLY = "DIRECT_EFFECT_ONLY"
    PARTIAL_TRANSITIVE_CLOSURE = "PARTIAL_TRANSITIVE_CLOSURE"
    CLOSED_WITHIN_SCOPE = "CLOSED_WITHIN_SCOPE"
    UNKNOWN = "UNKNOWN"


class EffectClosureArtifact(CanonicalModel):
    effect_closure_id: str
    scope: Literal["ANALYZED_DEPENDENCIES"] = "ANALYZED_DEPENDENCIES"
    completeness: EffectClosureCompleteness
    included_effect_refs: tuple[str, ...]
    unresolved_effect_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    content_digest: str


class ResolutionStatus(StrEnum):
    RESOLVED = "RESOLVED"
    RESOLVED_SOURCE_ONLY = "RESOLVED_SOURCE_ONLY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    UNRESOLVED = "UNRESOLVED"


class ResolutionVectorArtifact(CanonicalModel):
    resolution_vector_id: str
    routine_resolution: ResolutionStatus
    view_resolution: ResolutionStatus
    udf_resolution: ResolutionStatus
    trigger_resolution: ResolutionStatus
    constraint_resolution: ResolutionStatus
    dynamic_relation_resolution: ResolutionStatus
    evidence_refs: tuple[str, ...]
    content_digest: str


class ScenarioCompilerBudgetReport(CanonicalModel):
    budget_report_id: str
    configured_limits: dict[str, int]
    consumed: dict[str, int]
    exceeded_limits: tuple[str, ...]
    reporting_integrity: Literal["COMPLETE"] = "COMPLETE"
    analysis_result: Literal["COMPLETE", "PARTIAL"]
    content_digest: str


class ScenarioSpec(CanonicalModel):
    scenario_spec_id: str
    schema_version: Literal["1.1"] = "1.1"
    behavior_id: str
    source_symbol_id: str
    symbol_lineage_id: str
    procedure_identity_ref: str
    artifact_revision_id: str
    behavior_effect_bundle_ref: str
    behavior_slice_ref: str
    predicate_graph_ref: str | None = None
    action: ScenarioAction
    preconditions: tuple[ScenarioPrecondition, ...]
    expected_effects: tuple[ScenarioEffect, ...]
    alternative_or_conditional_effects: tuple[ScenarioEffect, ...]
    effect_closure_ref: str
    resolution_vector_ref: str
    summary_refs: tuple[str, ...]
    ordered_decision_reduction_refs: tuple[str, ...] = ()
    caller_transaction_contract_refs: tuple[str, ...] = ()
    analysis_budget_report_ref: str
    finding_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    required_classification_slots: tuple[str, ...]
    required_vocabulary_slots: tuple[str, ...]
    platform_governance_ref: str | None = None
    created_by_compiler_version: Literal["scenario-compiler-1.5"] = "scenario-compiler-1.5"
    content_digest: str


class ScenarioSpecCompilationResult(CanonicalModel):
    compilation_status: ScenarioCompilationStatus
    behavior_effect_bundle_ref: str
    behavior_slice_ref: str | None
    scenario_spec_ref: str | None = None
    blockers: tuple[ScenarioBlockerCode, ...] = ()
    finding_refs: tuple[str, ...] = ()
    blocker_details: tuple[str, ...] = ()
    input_digest_set: tuple[str, ...]
    compiler_version: Literal["scenario-compiler-1.5"] = "scenario-compiler-1.5"
    compiler_configuration_digest: str
    output_digest: str | None = None


class ScenarioSpecBatchResult(CanonicalModel):
    schema_version: Literal["scenario-spec-batch-0.1"] = "scenario-spec-batch-0.1"
    parser_result_digest: str
    semantic_result_digest: str
    procedure_identity_ref: str
    source_symbol_id: str
    symbol_lineage_id: str
    classification_observations: tuple[ClassificationObservation, ...]
    effect_closures: tuple[EffectClosureArtifact, ...]
    resolution_vectors: tuple[ResolutionVectorArtifact, ...]
    budget_reports: tuple[ScenarioCompilerBudgetReport, ...]
    scenario_specs: tuple[ScenarioSpec, ...]
    compilation_results: tuple[ScenarioSpecCompilationResult, ...]
    content_digest: str
