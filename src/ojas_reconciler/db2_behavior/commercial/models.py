from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from ..core.models import CanonicalModel


class CapabilityState(StrEnum):
    GENERALLY_AVAILABLE = "GENERALLY_AVAILABLE"
    COMMERCIAL_PREVIEW = "COMMERCIAL_PREVIEW"
    EXPERIMENTAL_DISABLED_BY_DEFAULT = "EXPERIMENTAL_DISABLED_BY_DEFAULT"
    DESIGNED_NOT_IMPLEMENTED = "DESIGNED_NOT_IMPLEMENTED"
    CUSTOMER_INPUT_REQUIRED = "CUSTOMER_INPUT_REQUIRED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class CommercialMaturity(StrEnum):
    COMMERCIALIZATION_CANDIDATE = "COMMERCIALIZATION_CANDIDATE"
    ORGANIC_VALIDATION_REQUIRED = "ORGANIC_VALIDATION_REQUIRED"
    COMMERCIAL_FOUNDATION_READY = "COMMERCIAL_FOUNDATION_READY"
    GENERALLY_AVAILABLE = "GENERALLY_AVAILABLE"


class NamingStatus(StrEnum):
    PROVISIONAL_PENDING_NAMING_BASELINE = "PROVISIONAL_PENDING_NAMING_BASELINE"
    FROZEN_WITH_COMPATIBILITY_POLICY = "FROZEN_WITH_COMPATIBILITY_POLICY"


class CapabilityEntry(CanonicalModel):
    capability_id: str
    display_name: str
    state: CapabilityState
    claim_text: str
    datasheet_eligible: bool = False
    customer_input_requirements: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_claim_boundary(self) -> "CapabilityEntry":
        unavailable = {
            CapabilityState.EXPERIMENTAL_DISABLED_BY_DEFAULT,
            CapabilityState.DESIGNED_NOT_IMPLEMENTED,
            CapabilityState.NOT_SUPPORTED,
        }
        if self.datasheet_eligible and self.state in unavailable:
            raise ValueError(
                f"{self.state.value} capability {self.capability_id!r} cannot be "
                "represented as available on a datasheet."
            )
        if self.state is CapabilityState.CUSTOMER_INPUT_REQUIRED and not self.customer_input_requirements:
            raise ValueError(
                f"CUSTOMER_INPUT_REQUIRED capability {self.capability_id!r} must name required customer inputs."
            )
        if (
            self.state
            in {CapabilityState.GENERALLY_AVAILABLE, CapabilityState.COMMERCIAL_PREVIEW}
            and not self.evidence_refs
        ):
            raise ValueError(
                f"{self.state.value} capability {self.capability_id!r} must carry measured evidence references."
            )
        return self


class NamingSurface(CanonicalModel):
    surface_kind: str
    current_value: str
    status: NamingStatus
    compatibility_notes: tuple[str, ...] = ()


class CustomerInputResponsibility(CanonicalModel):
    input_type: str
    prepared_by: str
    validated_by: str
    maintained_by: str
    delivery_model: str


class CommercialCapabilityManifest(CanonicalModel):
    schema_version: str = "commercial-capability-manifest-1.0"
    distribution_name: str
    distribution_version: str
    commercial_maturity: CommercialMaturity = CommercialMaturity.ORGANIC_VALIDATION_REQUIRED
    naming_surfaces: tuple[NamingSurface, ...]
    capabilities: tuple[CapabilityEntry, ...]
    prohibited_datasheet_claims: tuple[str, ...]
    customer_input_responsibilities: tuple[CustomerInputResponsibility, ...] = ()
    edition_model_status: str = "DEFERRED_UNTIL_TWO_SUPPORTED_BUNDLES_EXIST"
    content_digest: str

    @model_validator(mode="after")
    def validate_manifest(self) -> "CommercialCapabilityManifest":
        ids = [item.capability_id for item in self.capabilities]
        if len(ids) != len(set(ids)):
            raise ValueError("Capability IDs must be unique.")
        if self.commercial_maturity is CommercialMaturity.GENERALLY_AVAILABLE:
            raise ValueError(
                "This manifest cannot self-promote to GENERALLY_AVAILABLE; "
                "organic and deployment gates require external evidence."
            )
        if not self.prohibited_datasheet_claims:
            raise ValueError("The commercial capability manifest must include explicit prohibited datasheet claims.")
        if (
            any(
                item.state is CapabilityState.CUSTOMER_INPUT_REQUIRED
                for item in self.capabilities
            )
            and not self.customer_input_responsibilities
        ):
            raise ValueError("Customer-input capabilities require an ownership and delivery responsibility matrix.")
        return self


class CustodyAgreementStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ProcessingLocation(StrEnum):
    CUSTOMER_ENVIRONMENT = "CUSTOMER_ENVIRONMENT"
    VENDOR_ISOLATED_WORKSPACE = "VENDOR_ISOLATED_WORKSPACE"
    CUSTOMER_APPROVED_CLOUD_WORKSPACE = "CUSTOMER_APPROVED_CLOUD_WORKSPACE"


class CustodyApprovalEvidenceMode(StrEnum):
    CUSTOMER_ENVIRONMENT_SELF_ASSERTED = "CUSTOMER_ENVIRONMENT_SELF_ASSERTED"
    VERIFIED_EXTERNAL_ENVELOPE = "VERIFIED_EXTERNAL_ENVELOPE"


class RegressionFixturePermission(StrEnum):
    NO_RETENTION = "NO_RETENTION"
    RETAIN_DERIVED_NON_REVERSIBLE_PATTERN = "RETAIN_DERIVED_NON_REVERSIBLE_PATTERN"
    RETAIN_CUSTOMER_PRIVATE_REGRESSION_FIXTURE = "RETAIN_CUSTOMER_PRIVATE_REGRESSION_FIXTURE"
    LICENSE_ANONYMIZED_REDUCED_FIXTURE = "LICENSE_ANONYMIZED_REDUCED_FIXTURE"


class OrganicSourceCustodyAgreement(CanonicalModel):
    schema_version: str = "organic-source-custody-agreement-1.0"
    agreement_id: str
    customer_ref: str
    status: CustodyAgreementStatus
    asserted_approver_ref: str | None = None
    approval_evidence_mode: CustodyApprovalEvidenceMode
    approval_evidence_refs: tuple[str, ...] = ()
    approval_envelope_digest: str | None = None
    effective_from: str
    expires_at: str | None = None
    processing_location: ProcessingLocation
    authorized_role_refs: tuple[str, ...]
    encryption_in_transit_required: bool = True
    encryption_at_rest_required: bool = True
    access_logging_required: bool = True
    source_retention_days: int = Field(ge=0)
    derived_artifact_retention_days: int = Field(ge=0)
    deletion_request_sla_days: int = Field(ge=0)
    deletion_attestation_required: bool = True
    backup_policy: str
    regression_fixture_permission: RegressionFixturePermission
    model_training_use: str = "PROHIBITED"
    cross_border_processing: str
    incident_notification_hours: int = Field(gt=0)
    subprocessor_policy: str
    allowed_source_roots: tuple[str, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_custody(self) -> "OrganicSourceCustodyAgreement":
        if self.status is CustodyAgreementStatus.APPROVED and not self.asserted_approver_ref:
            raise ValueError("An APPROVED custody agreement requires asserted_approver_ref.")
        if self.approval_evidence_mode is CustodyApprovalEvidenceMode.VERIFIED_EXTERNAL_ENVELOPE:
            if not self.approval_evidence_refs or not self.approval_envelope_digest:
                raise ValueError("VERIFIED_EXTERNAL_ENVELOPE requires evidence refs and an envelope digest.")
        elif self.processing_location is not ProcessingLocation.CUSTOMER_ENVIRONMENT:
            raise ValueError(
                "Vendor or cloud processing requires VERIFIED_EXTERNAL_ENVELOPE custody approval evidence."
            )
        if self.model_training_use != "PROHIBITED":
            raise ValueError("Organic customer source model-training use must be PROHIBITED by default.")
        if not self.authorized_role_refs:
            raise ValueError("At least one authorized role is required.")
        if not self.allowed_source_roots:
            raise ValueError("At least one allowed source root is required.")
        return self


class OrganicValidationLevel(StrEnum):
    ORGANIC_SMOKE = "ORGANIC_SMOKE"
    DISCOVERY_SAMPLE = "DISCOVERY_SAMPLE"
    ESTATE_PILOT = "ESTATE_PILOT"


class OrganicProcedureCase(CanonicalModel):
    case_id: str
    source_path: str
    source_origin: str = "ORGANIC_CUSTOMER_SOURCE"
    customer_authorization_ref: str
    authored_for_tool: bool = False
    expected_platform: str = "DB2"
    procedure_role_hint: str | None = None
    source_must_remain_unmodified: bool = True

    @model_validator(mode="after")
    def validate_organic_attestation(self) -> "OrganicProcedureCase":
        if self.source_origin != "ORGANIC_CUSTOMER_SOURCE":
            raise ValueError("Organic validation accepts only ORGANIC_CUSTOMER_SOURCE cases.")
        if self.authored_for_tool:
            raise ValueError("A source authored for this tool is not organic validation evidence.")
        if not self.source_must_remain_unmodified:
            raise ValueError("Organic source must remain unmodified during validation.")
        return self


class OrganicValidationManifest(CanonicalModel):
    schema_version: str = "organic-validation-manifest-1.0"
    validation_id: str
    validation_level: OrganicValidationLevel
    customer_ref: str
    estate_ref: str
    custody_agreement_id: str
    custody_agreement_digest: str
    cases: tuple[OrganicProcedureCase, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_case_count(self) -> "OrganicValidationManifest":
        count = len(self.cases)
        if self.validation_level is OrganicValidationLevel.ORGANIC_SMOKE and count < 1:
            raise ValueError("ORGANIC_SMOKE requires at least one procedure.")
        if self.validation_level is OrganicValidationLevel.DISCOVERY_SAMPLE and count < 5:
            raise ValueError("DISCOVERY_SAMPLE requires at least five varied procedures.")
        if self.validation_level is OrganicValidationLevel.ESTATE_PILOT and not 20 <= count <= 50:
            raise ValueError("ESTATE_PILOT requires 20 to 50 unmodified procedures.")
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("Organic validation case IDs must be unique.")
        source_paths = [case.source_path for case in self.cases]
        if len(source_paths) != len(set(source_paths)):
            raise ValueError("Organic validation source paths must be unique within a corpus.")
        return self


class ReviewClassification(StrEnum):
    CORRECT = "CORRECT"
    CORRECT_BUT_TECHNICAL = "CORRECT_BUT_TECHNICAL"
    INCOMPLETE = "INCOMPLETE"
    MISLEADING = "MISLEADING"
    FALSE = "FALSE"
    UNREVIEWABLE_WITHOUT_MORE_EVIDENCE = "UNREVIEWABLE_WITHOUT_MORE_EVIDENCE"


class AssertionModality(StrEnum):
    MUST = "MUST"
    MUST_IF_CONTRACT_HOLDS = "MUST_IF_CONTRACT_HOLDS"
    MAY = "MAY"
    UNKNOWN = "UNKNOWN"


class ReviewConfirmation(StrEnum):
    CONFIRMED = "CONFIRMED"
    DISAGREED = "DISAGREED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_REVIEWED = "NOT_REVIEWED"


class AssertionReview(CanonicalModel):
    assertion_ref: str
    observable_kind: str
    modality: AssertionModality
    classification: ReviewClassification
    source_contradiction_ref: str | None = None
    comments: str | None = None

    @property
    def materially_false_confident_behavior(self) -> bool:
        return (
            self.modality is AssertionModality.MUST
            and self.classification is ReviewClassification.FALSE
            and self.source_contradiction_ref is not None
        )


class OrganicProcedureReview(CanonicalModel):
    case_id: str
    reviewer_ref: str
    decision_arms_confirmed: ReviewConfirmation = ReviewConfirmation.NOT_REVIEWED
    precedence_confirmed: ReviewConfirmation = ReviewConfirmation.NOT_REVIEWED
    terminal_outcomes_confirmed: ReviewConfirmation = ReviewConfirmation.NOT_REVIEWED
    handler_effects_confirmed: ReviewConfirmation = ReviewConfirmation.NOT_REVIEWED
    major_mutations_confirmed: ReviewConfirmation = ReviewConfirmation.NOT_REVIEWED
    assertion_reviews: tuple[AssertionReview, ...] = ()
    review_effort_minutes: int = Field(default=0, ge=0)
    review_notes: str | None = None


class OrganicReviewBatch(CanonicalModel):
    schema_version: str = "organic-review-batch-1.0"
    validation_id: str
    reviews: tuple[OrganicProcedureReview, ...]
    content_digest: str


class OrganicCaseOutcome(CanonicalModel):
    case_id: str
    source_path: str
    source_digest_before: str
    source_digest_after: str
    source_unmodified: bool
    parse_outcome: str
    parse_findings: tuple[str, ...]
    semantic_status: str
    admitted_scenarios: int = Field(ge=0)
    blocked_scenarios: int = Field(ge=0)
    blocker_codes: tuple[str, ...]
    internal_failure: str | None = None
    review_classifications: tuple[ReviewClassification, ...] = ()
    materially_false_confident_behaviors: int = Field(ge=0)
    owner_rule_confirmation_complete: bool = False


class OrganicValidationStatus(StrEnum):
    BLOCKED_CUSTODY = "BLOCKED_CUSTODY"
    ORGANIC_SMOKE_COMPLETED = "ORGANIC_SMOKE_COMPLETED"
    ORGANIC_SMOKE_FAILED = "ORGANIC_SMOKE_FAILED"
    DISCOVERY_COMPLETED = "DISCOVERY_COMPLETED"
    ESTATE_PILOT_MEASURED = "ESTATE_PILOT_MEASURED"
    PILOT_PAUSED_PRODUCT_GAP = "PILOT_PAUSED_PRODUCT_GAP"
    FAILED_INTERNAL = "FAILED_INTERNAL"


class OrganicValidationReport(CanonicalModel):
    schema_version: str = "organic-validation-report-1.0"
    validation_id: str
    validation_level: OrganicValidationLevel
    status: OrganicValidationStatus
    customer_ref: str
    estate_ref: str
    custody_agreement_id: str
    source_count: int = Field(ge=0)
    unique_source_digests: int = Field(ge=0)
    parsed_complete: int = Field(ge=0)
    parsed_partial: int = Field(ge=0)
    refused_expected: int = Field(ge=0)
    refused_unexpected: int = Field(ge=0)
    semantic_completed: int = Field(ge=0)
    semantic_blocked: int = Field(ge=0)
    admitted_scenarios: int = Field(ge=0)
    blocked_scenarios: int = Field(ge=0)
    source_modification_count: int = Field(ge=0)
    materially_false_confident_behaviors: int = Field(ge=0)
    owner_rule_confirmations_complete: int = Field(ge=0)
    reviewed_procedure_count: int = Field(ge=0)
    total_review_effort_minutes: int = Field(ge=0)
    procedures_with_admitted_scenarios: int = Field(ge=0)
    procedures_with_blocked_scenarios: int = Field(ge=0)
    parsed_complete_rate: float = Field(ge=0.0, le=1.0)
    semantic_completion_rate: float = Field(ge=0.0, le=1.0)
    classification_counts: dict[str, int]
    recurring_blocker_codes: tuple[str, ...]
    pause_reasons: tuple[str, ...]
    case_outcomes: tuple[OrganicCaseOutcome, ...]
    commercial_claim_eligible: bool
    content_digest: str


class CommercialGateStatus(StrEnum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CommercialGateRecord(CanonicalModel):
    gate_id: str
    status: CommercialGateStatus
    evidence_refs: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence(self) -> "CommercialGateRecord":
        if self.status is CommercialGateStatus.VERIFIED and not self.evidence_refs:
            raise ValueError(f"Verified gate {self.gate_id!r} requires evidence refs.")
        return self


class CommercialGateEvidence(CanonicalModel):
    schema_version: str = "commercial-gate-evidence-1.0"
    distribution_name: str
    distribution_version: str
    gates: tuple[CommercialGateRecord, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_unique_gates(self) -> "CommercialGateEvidence":
        ids = [gate.gate_id for gate in self.gates]
        if len(ids) != len(set(ids)):
            raise ValueError("Commercial gate IDs must be unique.")
        return self


class CommercialReadinessReport(CanonicalModel):
    schema_version: str = "commercial-readiness-report-1.0"
    distribution_name: str
    distribution_version: str
    commercial_maturity: CommercialMaturity
    capability_manifest_valid: bool
    custody_ready: bool
    organic_validation_status: OrganicValidationStatus | None = None
    organic_estate_pilot_measured: bool = False
    deployment_gates: tuple[str, ...]
    verified_gate_ids: tuple[str, ...] = ()
    customer_boundary_gates: tuple[str, ...]
    blockers: tuple[str, ...]
    naming_status: NamingStatus
    editions_status: str = "DEFERRED"
    content_digest: str


class CheckState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    CONDITIONAL = "CONDITIONAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ProcedureCheck(CanonicalModel):
    check_id: str
    display_name: str
    state: CheckState
    summary: str
    evidence_refs: tuple[str, ...] = ()
    condition_refs: tuple[str, ...] = ()
    blocker_codes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence_boundary(self) -> "ProcedureCheck":
        if self.state in {CheckState.PASS, CheckState.FAIL} and not self.evidence_refs:
            raise ValueError(f"{self.state.value} check {self.check_id!r} requires evidence references.")
        if self.state is CheckState.CONDITIONAL and not self.condition_refs:
            raise ValueError(f"CONDITIONAL check {self.check_id!r} requires named condition references.")
        if self.state is CheckState.NOT_EVALUATED and not self.blocker_codes:
            raise ValueError(f"NOT_EVALUATED check {self.check_id!r} requires blocker codes.")
        return self


class ProcedureCheckReport(CanonicalModel):
    schema_version: str = "procedure-check-report-1.0"
    report_id: str
    procedure_ref: str
    source_digest: str | None = None
    analysis_run_ref: str
    checks: tuple[ProcedureCheck, ...]
    counts_by_state: dict[str, int]
    content_digest: str

    @model_validator(mode="after")
    def validate_counts(self) -> "ProcedureCheckReport":
        actual = {state.value: 0 for state in CheckState}
        for item in self.checks:
            actual[item.state.value] += 1
        if dict(sorted(actual.items())) != dict(sorted(self.counts_by_state.items())):
            raise ValueError("Procedure check counts_by_state does not match checks.")
        return self


class PauseResponsibility(StrEnum):
    PRODUCT = "PRODUCT"
    CUSTOMER = "CUSTOMER"
    JOINT = "JOINT"


class PauseCause(StrEnum):
    PRODUCT_DEFECT = "PRODUCT_DEFECT"
    DIALECT_GAP = "DIALECT_GAP"
    CATALOG_INPUT_GAP = "CATALOG_INPUT_GAP"
    CUSTOMER_CONTRACT_GAP = "CUSTOMER_CONTRACT_GAP"
    PROCEDURE_CLASS_NOT_SUPPORTED = "PROCEDURE_CLASS_NOT_SUPPORTED"
    ESTATE_CONFIGURATION_GAP = "ESTATE_CONFIGURATION_GAP"
    SOURCE_CUSTODY_VIOLATION = "SOURCE_CUSTODY_VIOLATION"
    EPISTEMIC_FAILURE = "EPISTEMIC_FAILURE"


class PauseDispositionDecision(StrEnum):
    CONTINUE_PILOT = "CONTINUE_PILOT"
    PAUSE_FOR_PRODUCT_FIX = "PAUSE_FOR_PRODUCT_FIX"
    PAUSE_FOR_CUSTOMER_INPUT = "PAUSE_FOR_CUSTOMER_INPUT"
    STRATIFY_CORPUS = "STRATIFY_CORPUS"
    DECLARE_PROCEDURE_CLASS_NOT_SUPPORTED = "DECLARE_PROCEDURE_CLASS_NOT_SUPPORTED"
    TERMINATE_PILOT = "TERMINATE_PILOT"


class OrganicPauseDisposition(CanonicalModel):
    schema_version: str = "organic-pause-disposition-1.0"
    disposition_id: str
    validation_report_ref: str
    validation_report_digest: str
    validation_id: str
    source_digests: tuple[str, ...]
    pause_reasons: tuple[str, ...]
    dominant_cause: PauseCause
    responsibility: PauseResponsibility
    decision: PauseDispositionDecision
    blocker_codes: tuple[str, ...] = ()
    rationale: str
    remediation_actions: tuple[str, ...]
    owner_ref: str
    approved_by_ref: str | None = None
    decided_at: str
    target_reassessment_at: str | None = None
    content_digest: str

    @model_validator(mode="after")
    def validate_disposition(self) -> "OrganicPauseDisposition":
        if not self.pause_reasons:
            raise ValueError("A pause disposition requires at least one pause reason.")
        if not self.source_digests:
            raise ValueError("A pause disposition must bind the frozen organic source digests.")
        if not self.remediation_actions and self.decision not in {
            PauseDispositionDecision.TERMINATE_PILOT,
            PauseDispositionDecision.DECLARE_PROCEDURE_CLASS_NOT_SUPPORTED,
        }:
            raise ValueError("A non-terminal disposition requires remediation actions.")
        if self.decision is PauseDispositionDecision.CONTINUE_PILOT and not self.approved_by_ref:
            raise ValueError("CONTINUE_PILOT requires an explicit approving authority reference.")
        return self


class CompositionKind(StrEnum):
    DIRECT_CALL = "DIRECT_CALL"
    EXTERNAL_SEQUENCE = "EXTERNAL_SEQUENCE"
    EVENT_DRIVEN = "EVENT_DRIVEN"
    BATCH_ORCHESTRATION = "BATCH_ORCHESTRATION"
    APPLICATION_TRANSACTION = "APPLICATION_TRANSACTION"


class CompositionTransactionRelationship(StrEnum):
    SAME_UOW = "SAME_UOW"
    SEPARATE_COMMITTED_UOW = "SEPARATE_COMMITTED_UOW"
    CALLER_CONTROLLED = "CALLER_CONTROLLED"
    UNKNOWN = "UNKNOWN"


class CompositionResolution(StrEnum):
    PROVEN_BY_SOURCE_CALL = "PROVEN_BY_SOURCE_CALL"
    PROVEN_BY_COMPOSITION_CONTRACT = "PROVEN_BY_COMPOSITION_CONTRACT"
    CONDITIONAL_ON_COMPOSITION_CONTRACT = "CONDITIONAL_ON_COMPOSITION_CONTRACT"
    CONFLICTING_COMPOSITION_EVIDENCE = "CONFLICTING_COMPOSITION_EVIDENCE"
    UNRESOLVED_COMPOSITION_BOUNDARY = "UNRESOLVED_COMPOSITION_BOUNDARY"
    STALE_CONTRACT_DIGEST = "STALE_CONTRACT_DIGEST"


class ParameterMapping(CanonicalModel):
    upstream_ref: str
    downstream_ref: str
    mapping_expression: str | None = None
    evidence_refs: tuple[str, ...] = ()


class ConditionMapping(CanonicalModel):
    exported_postcondition_ref: str
    imported_precondition_ref: str
    entailment_status: str
    evidence_refs: tuple[str, ...] = ()


class ProcedureCompositionContract(CanonicalModel):
    schema_version: str = "procedure-composition-contract-1.0"
    contract_id: str
    composition_kind: CompositionKind
    upstream_procedure_ref: str
    downstream_procedure_ref: str
    upstream_semantic_digest: str
    downstream_semantic_digest: str
    orchestration_definition_digest: str | None = None
    transaction_contract_digest: str | None = None
    invocation_site_ref: str | None = None
    parameter_mappings: tuple[ParameterMapping, ...]
    condition_mappings: tuple[ConditionMapping, ...]
    sqlstate_mappings: dict[str, str] = {}
    output_status_mappings: dict[str, str] = {}
    transaction_relationship: CompositionTransactionRelationship
    failure_disposition: str
    authority_ref: str
    evidence_refs: tuple[str, ...]
    effective_from: str
    expires_at: str | None = None
    content_digest: str

    @model_validator(mode="after")
    def validate_contract(self) -> "ProcedureCompositionContract":
        if not self.parameter_mappings:
            raise ValueError("A composition contract requires at least one parameter mapping.")
        if not self.condition_mappings:
            raise ValueError("A composition contract requires at least one postcondition/precondition mapping.")
        if not self.evidence_refs:
            raise ValueError("A composition contract requires evidence references.")
        return self


class CompositionAssessment(CanonicalModel):
    schema_version: str = "composition-assessment-1.0"
    contract_id: str
    resolution: CompositionResolution
    upstream_digest_matches: bool
    downstream_digest_matches: bool
    transaction_contract_digest_matches: bool | None = None
    orchestration_digest_matches: bool | None = None
    proof_obligations: dict[str, CheckState]
    blockers: tuple[str, ...]
    content_digest: str


class NamingCompatibilityPolicy(CanonicalModel):
    schema_version: str = "naming-compatibility-policy-1.0"
    policy_id: str
    commercial_name: str
    distribution_name: str
    python_namespace: str
    cli_primary: str
    cli_aliases: tuple[str, ...]
    artifact_schema_compatibility: str
    governance_record_migration: str
    alias_support_until: str | None = None
    authority_ref: str
    evidence_refs: tuple[str, ...]
    content_digest: str


class SupportSeverity(StrEnum):
    SEVERITY_1 = "SEVERITY_1"
    SEVERITY_2 = "SEVERITY_2"
    SEVERITY_3 = "SEVERITY_3"
    SEVERITY_4 = "SEVERITY_4"


class SupportCaseClassification(CanonicalModel):
    case_id: str
    severity: SupportSeverity
    category: str
    source_digest: str | None = None
    dialect: str | None = None
    product_version: str
    stable_finding_code: str
    customer_impact: str
    reproduction_ref: str | None = None
    materially_false_confident_behavior: bool = False
    status: str


class MeteringSnapshot(CanonicalModel):
    schema_version: str = "metering-snapshot-1.0"
    tenant_ref: str
    estate_refs: tuple[str, ...]
    environment_refs: tuple[str, ...]
    unique_procedure_digests: int = Field(ge=0)
    analysis_runs: int = Field(ge=0)
    source_lines_processed: int = Field(ge=0)
    generated_artifacts: int = Field(ge=0)
    runtime_observations: int = Field(ge=0)
    period_start: str
    period_end: str
    content_digest: str


class GraphNode(CanonicalModel):
    node_id: str
    node_type: str
    label: str
    authority: str = "TECHNICAL_EVIDENCE"
    status: str = "OBSERVED_OR_EXTRACTED"
    attributes: dict[str, object] = {}


class GraphEdge(CanonicalModel):
    edge_id: str
    source: str
    target: str
    edge_type: str
    attributes: dict[str, object] = {}


class ProcedureKnowledgeGraph(CanonicalModel):
    schema_version: str = "procedure-knowledge-graph-1.0"
    graph_id: str
    procedure_ref: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    unresolved_boundaries: tuple[str, ...] = ()
    content_digest: str


class FixturePlanStatus(StrEnum):
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    BLOCKED = "BLOCKED"


class RelationFixtureRequirement(CanonicalModel):
    relation_ref: str
    insertion_order: int = Field(ge=1)
    required_input_columns: tuple[str, ...]
    omitted_generated_columns: tuple[str, ...]
    parent_relation_refs: tuple[str, ...] = ()
    check_constraints: tuple[str, ...] = ()
    blocker_codes: tuple[str, ...] = ()


class RelationalFixturePlan(CanonicalModel):
    schema_version: str = "relational-fixture-plan-1.0"
    plan_id: str
    procedure_ref: str
    status: FixturePlanStatus
    catalog_provider_refs: tuple[str, ...]
    relation_requirements: tuple[RelationFixtureRequirement, ...]
    unresolved_relation_refs: tuple[str, ...]
    generated_sql: tuple[str, ...] = ()
    limitations: tuple[str, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_no_unproven_sql(self) -> "RelationalFixturePlan":
        if self.generated_sql:
            raise ValueError("RC25 fixture planning must not emit executable SQL without approved value constraints.")
        if self.status is FixturePlanStatus.READY_FOR_REVIEW and self.unresolved_relation_refs:
            raise ValueError("A fixture plan with unresolved relations cannot be READY_FOR_REVIEW.")
        return self


class DeletionScope(StrEnum):
    DERIVED_ARTIFACTS = "DERIVED_ARTIFACTS"
    TENANT_WORKSPACE = "TENANT_WORKSPACE"


class CommercialDeletionRequest(CanonicalModel):
    schema_version: str = "commercial-deletion-request-1.0"
    request_id: str
    tenant_ref: str
    scope: DeletionScope
    target_artifact_refs: tuple[str, ...]
    custody_agreement_ref: str | None = None
    requested_by_ref: str
    approved_by_ref: str
    requested_at: str
    execute_after: str
    reason: str
    content_digest: str

    @model_validator(mode="after")
    def validate_request(self) -> "CommercialDeletionRequest":
        if not self.target_artifact_refs and self.scope is DeletionScope.DERIVED_ARTIFACTS:
            raise ValueError("DERIVED_ARTIFACTS deletion requires explicit target artifact refs.")
        if self.requested_by_ref == self.approved_by_ref:
            raise ValueError("Deletion requires separation between requester and approver.")
        return self


class DeletedArtifactRecord(CanonicalModel):
    artifact_ref: str
    artifact_digest_before_deletion: str
    size_bytes: int = Field(ge=0)


class CommercialDeletionAttestation(CanonicalModel):
    schema_version: str = "commercial-deletion-attestation-1.0"
    attestation_id: str
    request_id: str
    tenant_ref: str
    deleted_artifacts: tuple[DeletedArtifactRecord, ...]
    retained_audit_ref: str
    completed_at: str
    executed_by_ref: str
    content_digest: str
