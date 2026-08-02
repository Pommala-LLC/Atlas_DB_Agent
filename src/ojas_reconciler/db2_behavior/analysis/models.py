from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel, ParseFinding, SourceRange


class CfgNodeKind(StrEnum):
    ENTRY = "ENTRY"
    NORMAL_EXIT = "NORMAL_EXIT"
    EXCEPTIONAL_EXIT = "EXCEPTIONAL_EXIT"
    AST = "AST"
    HANDLER_EXIT = "HANDLER_EXIT"


class CfgEdgeKind(StrEnum):
    ENTRY = "ENTRY"
    SEQUENTIAL = "SEQUENTIAL"
    IF_ARM = "IF_ARM"
    IF_NO_MATCH = "IF_NO_MATCH"
    LOOP_BODY = "LOOP_BODY"
    LOOP_EXIT = "LOOP_EXIT"
    LOOP_BACK = "LOOP_BACK"
    LEAVE = "LEAVE"
    ITERATE = "ITERATE"
    RETURN = "RETURN"
    SIGNAL = "SIGNAL"
    RESIGNAL = "RESIGNAL"
    HANDLER = "HANDLER"
    HANDLER_BODY = "HANDLER_BODY"
    HANDLER_FALLTHROUGH = "HANDLER_FALLTHROUGH"


class CfgNode(CanonicalModel):
    cfg_node_id: str
    node_kind: CfgNodeKind
    ast_node_ref: str | None = None
    label: str
    source_range: SourceRange | None = None


class CfgEdge(CanonicalModel):
    edge_id: str
    source_ref: str
    target_ref: str
    edge_kind: CfgEdgeKind
    condition_text: str | None = None
    branch_index: int | None = Field(default=None, ge=0)
    handler_region_ref: str | None = None
    continuation_target_ref: str | None = None


class HandlerFlowBinding(CanonicalModel):
    binding_id: str
    source_ast_node_ref: str
    handler_region_ref: str
    handled_condition_text: str
    continuation_semantics: Literal[
        "AFTER_RAISING_STATEMENT",
        "EXIT_DECLARING_COMPOUND",
        "UNDO_AND_EXIT_DECLARING_COMPOUND",
    ]
    continuation_target_ref: str


class ControlFlowGraph(CanonicalModel):
    schema_version: Literal["db2-cfg-0.1"] = "db2-cfg-0.1"
    procedure_ast_ref: str
    entry_ref: str
    normal_exit_ref: str
    exceptional_exit_ref: str
    nodes: tuple[CfgNode, ...]
    edges: tuple[CfgEdge, ...]
    handler_bindings: tuple[HandlerFlowBinding, ...]
    excluded_declaration_refs: tuple[str, ...] = ()
    content_digest: str


class SemanticFindingCode(StrEnum):
    SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE = "SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE"
    STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE = "STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE"
    OUT_ASSIGNMENT_OVERWRITTEN = "OUT_ASSIGNMENT_OVERWRITTEN"
    OUT_ASSIGNMENT_REACHES_NORMAL_EXIT = "OUT_ASSIGNMENT_REACHES_NORMAL_EXIT"
    DML_TRANSACTION_SURVIVAL_UNRESOLVED = "DML_TRANSACTION_SURVIVAL_UNRESOLVED"
    DML_MAY_COMMIT_OR_ROLLBACK = "DML_MAY_COMMIT_OR_ROLLBACK"
    DML_CALLER_CONTROLLED = "DML_CALLER_CONTROLLED"
    UNRESOLVED_CALL_EFFECT_BOUNDARY = "UNRESOLVED_CALL_EFFECT_BOUNDARY"
    DYNAMIC_SQL_EFFECT_BOUNDARY = "DYNAMIC_SQL_EFFECT_BOUNDARY"
    HANDLER_FLOW_PARTIAL = "HANDLER_FLOW_PARTIAL"
    LOOP_SUMMARY_PARTIAL = "LOOP_SUMMARY_PARTIAL"
    LOOP_EFFECT_UNRESOLVED = "LOOP_EFFECT_UNRESOLVED"
    POSSIBLY_NON_TERMINATING_LOOP = "POSSIBLY_NON_TERMINATING_LOOP"
    BEHAVIOR_BUNDLE_PARTIAL = "BEHAVIOR_BUNDLE_PARTIAL"
    QUERY_SUMMARY_PARTIAL = "QUERY_SUMMARY_PARTIAL"
    QUERY_BINDING_ARITY_UNRESOLVED = "QUERY_BINDING_ARITY_UNRESOLVED"
    CURSOR_QUERY_BINDING_UNRESOLVED = "CURSOR_QUERY_BINDING_UNRESOLVED"
    BEHAVIOR_SLICE_PARTIAL = "BEHAVIOR_SLICE_PARTIAL"
    PREDICATE_NORMALIZATION_PARTIAL = "PREDICATE_NORMALIZATION_PARTIAL"
    UNSUPPORTED_CONSTRAINT_THEORY = "UNSUPPORTED_CONSTRAINT_THEORY"
    OBVIOUS_PREDICATE_CONTRADICTION = "OBVIOUS_PREDICATE_CONTRADICTION"
    DYNAMIC_SQL_STATICALLY_RECONSTRUCTED = "DYNAMIC_SQL_STATICALLY_RECONSTRUCTED"
    DYNAMIC_SQL_ENUMERABLE_VARIANTS = "DYNAMIC_SQL_ENUMERABLE_VARIANTS"
    DYNAMIC_SQL_PARTIALLY_RECONSTRUCTED = "DYNAMIC_SQL_PARTIALLY_RECONSTRUCTED"
    DYNAMIC_SQL_RUNTIME_CAPTURE_REQUIRED = "DYNAMIC_SQL_RUNTIME_CAPTURE_REQUIRED"
    DYNAMIC_SQL_UNRESOLVED = "DYNAMIC_SQL_UNRESOLVED"
    DYNAMIC_VARIANT_BUDGET_EXCEEDED = "DYNAMIC_VARIANT_BUDGET_EXCEEDED"
    DYNAMIC_RELATION_UNRESOLVED = "DYNAMIC_RELATION_UNRESOLVED"
    DYNAMIC_CALL_UNRESOLVED = "DYNAMIC_CALL_UNRESOLVED"
    DYNAMIC_QUERY_BINDING_PARTIAL = "DYNAMIC_QUERY_BINDING_PARTIAL"
    UNREACHABLE_BRANCH = "UNREACHABLE_BRANCH"
    TENANT_ISOLATION_MISSING = "TENANT_ISOLATION_MISSING"
    WINDOW_MODEL_PARTIAL = "WINDOW_MODEL_PARTIAL"
    WINDOW_INPUT_CARDINALITY_UNKNOWN = "WINDOW_INPUT_CARDINALITY_UNKNOWN"
    WINDOW_OVER_SINGLE_ROW_PARTITION = "WINDOW_OVER_SINGLE_ROW_PARTITION"
    WINDOW_ORDER_NONDETERMINISTIC = "WINDOW_ORDER_NONDETERMINISTIC"
    QUERY_SUMMARY_COMPLETE_WITHOUT_WINDOW_MODEL = "QUERY_SUMMARY_COMPLETE_WITHOUT_WINDOW_MODEL"
    MISSING_NOT_FOUND_HANDLER = "MISSING_NOT_FOUND_HANDLER"
    DECLARED_SYMBOL_NEVER_ASSIGNED = "DECLARED_SYMBOL_NEVER_ASSIGNED"
    ASSIGNED_SYMBOL_NEVER_CONSUMED = "ASSIGNED_SYMBOL_NEVER_CONSUMED"
    NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW = "NARROWING_ASSIGNMENT_POSSIBLE_OVERFLOW"
    TENANT_ISOLATION_NOT_EVALUATED = "TENANT_ISOLATION_NOT_EVALUATED"
    ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL = "ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL"
    UNDECLARED_SYMBOL_REFERENCE = "UNDECLARED_SYMBOL_REFERENCE"
    SEQUENCE_ADVANCE_ROLLBACK_SEMANTICS_DIALECT_DEFINED = "SEQUENCE_ADVANCE_ROLLBACK_SEMANTICS_DIALECT_DEFINED"
    HANDLER_SWALLOWS_ORIGINAL_CONDITION = "HANDLER_SWALLOWS_ORIGINAL_CONDITION"
    HANDLER_LOGGING_ROLLBACK_COUPLED = "HANDLER_LOGGING_ROLLBACK_COUPLED"
    HANDLER_BODY_FAILURE_PROPAGATES = "HANDLER_BODY_FAILURE_PROPAGATES"
    DIALECT_SYMBOL_COMPATIBILITY_UNRESOLVED = "DIALECT_SYMBOL_COMPATIBILITY_UNRESOLVED"
    DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM = "DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM"
    CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION = "CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION"
    HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT = "HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT"
    IMPOSSIBLE_NULL_PREDICATE = "IMPOSSIBLE_NULL_PREDICATE"
    FINAL_TABLE_DATA_CHANGE_EFFECT = "FINAL_TABLE_DATA_CHANGE_EFFECT"
    RETURNED_RESULT_SET = "RETURNED_RESULT_SET"
    ATOMIC_EFFECT_GROUP = "ATOMIC_EFFECT_GROUP"


class SemanticFinding(CanonicalModel):
    finding_id: str
    code: SemanticFindingCode
    message: str
    evidence_node_refs: tuple[str, ...]
    source_ranges: tuple[SourceRange, ...]
    consequence: str



class HandlerCoverageFact(CanonicalModel):
    coverage_id: str
    source_node_ref: str
    raised_condition: Literal["NOT_FOUND"] = "NOT_FOUND"
    coverage_status: Literal["COVERED", "MISSING"]
    handler_region_ref: str | None = None
    handler_binding_ref: str | None = None
    continuation_semantics: str | None = None
    evidence_refs: tuple[str, ...] = ()


class HandlerSemanticsFact(CanonicalModel):
    semantics_id: str
    handler_region_ref: str
    handler_scope_ref: str
    exited_compound_statement_ref: str | None = None
    procedure_continues_after_scope: bool | None = None
    resignal_present: bool
    original_condition_propagated: bool
    logging_transaction_scope: Literal[
        "CALLER_UNIT_OF_WORK", "HANDLER_MANAGED_TRANSACTION", "NOT_APPLICABLE", "UNKNOWN"
    ]
    rollback_visibility: Literal[
        "ROLLS_BACK_WITH_CALLER", "SURVIVES_CALLER_ROLLBACK", "NOT_APPLICABLE", "UNKNOWN"
    ]
    evidence_refs: tuple[str, ...] = ()


class UnresolvedInfluence(CanonicalModel):
    influence_id: str
    code: str
    detail: str
    source_node_refs: tuple[str, ...] = ()
    related_artifact_refs: tuple[str, ...] = ()


class EffectKind(StrEnum):
    OUT_PARAMETER_ASSIGNMENT = "OUT_PARAMETER_ASSIGNMENT"
    DML = "DML"
    CALL = "CALL"
    DYNAMIC_SQL = "DYNAMIC_SQL"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"
    SIGNAL = "SIGNAL"
    RESIGNAL = "RESIGNAL"
    SEQUENCE_VALUE_ACQUISITION = "SEQUENCE_VALUE_ACQUISITION"
    RESULT_SET_RETURN = "RESULT_SET_RETURN"
    STATE_ASSIGNMENT = "STATE_ASSIGNMENT"


class EffectObservability(StrEnum):
    INTERMEDIATE_EFFECT = "INTERMEDIATE_EFFECT"
    ESCAPING_EFFECT = "ESCAPING_EFFECT"
    COMMITTED_EFFECT = "COMMITTED_EFFECT"
    ROLLED_BACK_EFFECT = "ROLLED_BACK_EFFECT"
    OVERWRITTEN_OUTPUT_ASSIGNMENT = "OVERWRITTEN_OUTPUT_ASSIGNMENT"
    HANDLED_CONDITION = "HANDLED_CONDITION"
    UNHANDLED_ESCAPING_CONDITION = "UNHANDLED_ESCAPING_CONDITION"
    UNRESOLVED_EFFECT_BOUNDARY = "UNRESOLVED_EFFECT_BOUNDARY"
    TRANSACTION_SURVIVAL_UNRESOLVED = "TRANSACTION_SURVIVAL_UNRESOLVED"
    CONDITIONALLY_COMMITTED_EFFECT = "CONDITIONALLY_COMMITTED_EFFECT"


class EffectCandidate(CanonicalModel):
    effect_id: str
    effect_kind: EffectKind
    source_node_ref: str
    target: str | None = None
    value_expression: str | None = None
    observability: EffectObservability
    reaches_exit_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    transaction_analysis_ref: str | None = None


class TransactionPathOutcome(StrEnum):
    EXPLICIT_COMMIT = "EXPLICIT_COMMIT"
    EXPLICIT_ROLLBACK = "EXPLICIT_ROLLBACK"
    NORMAL_EXIT_CALLER_CONTROLLED = "NORMAL_EXIT_CALLER_CONTROLLED"
    CALLER_CONTRACT_COMMIT = "CALLER_CONTRACT_COMMIT"
    CALLER_CONTRACT_ROLLBACK = "CALLER_CONTRACT_ROLLBACK"
    COMMIT_ON_RETURN = "COMMIT_ON_RETURN"
    EXCEPTIONAL_ESCAPE = "EXCEPTIONAL_ESCAPE"
    NO_TERMINAL_PATH = "NO_TERMINAL_PATH"


class TransactionSurvivalClassification(StrEnum):
    MUST_COMMIT = "MUST_COMMIT"
    MUST_ROLLBACK = "MUST_ROLLBACK"
    CALLER_CONTROLLED = "CALLER_CONTROLLED"
    CALLER_CONTRACT_COMMIT = "CALLER_CONTRACT_COMMIT"
    MAY_COMMIT_OR_ROLLBACK = "MAY_COMMIT_OR_ROLLBACK"
    MAY_COMMIT_OR_CALLER_CONTROLLED = "MAY_COMMIT_OR_CALLER_CONTROLLED"
    CALLER_CONTROLLED_OR_EXCEPTIONAL = "CALLER_CONTROLLED_OR_EXCEPTIONAL"
    MAY_COMMIT_ROLLBACK_OR_CALLER_CONTROLLED = "MAY_COMMIT_ROLLBACK_OR_CALLER_CONTROLLED"
    UNRESOLVED = "UNRESOLVED"


class CallerTransactionContract(CanonicalModel):
    schema_version: Literal["caller-transaction-contract-1.0"] = "caller-transaction-contract-1.0"
    contract_id: str
    schema_name: str | None = None
    procedure_name: str
    success_disposition: Literal["CALLER_COMMITS"]
    failure_disposition: Literal["CALLER_ROLLS_BACK"]
    authority_ref: str
    evidence_refs: tuple[str, ...] = ()
    content_digest: str


class EffectTransactionAnalysis(CanonicalModel):
    analysis_id: str
    effect_ref: str
    transaction_region_ref: str
    reachable_outcomes: tuple[TransactionPathOutcome, ...]
    classification: TransactionSurvivalClassification
    boundary_node_refs: tuple[str, ...]
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    evidence_refs: tuple[str, ...]
    caller_transaction_contract_ref: str | None = None
    caller_transaction_contract_digest: str | None = None


class TransactionRegion(CanonicalModel):
    transaction_region_id: str
    procedure_ast_ref: str
    commit_on_return: Literal["YES", "NO", "UNKNOWN"]
    effect_refs: tuple[str, ...]
    explicit_commit_refs: tuple[str, ...]
    explicit_rollback_refs: tuple[str, ...]
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]


class EffectRelationship(StrEnum):
    PRIMARY = "PRIMARY"
    REQUIRED_CO_EFFECT = "REQUIRED_CO_EFFECT"
    CONDITIONAL_CO_EFFECT = "CONDITIONAL_CO_EFFECT"
    ALTERNATIVE_EFFECT = "ALTERNATIVE_EFFECT"
    COMPENSATING_EFFECT = "COMPENSATING_EFFECT"
    AUDIT_EFFECT = "AUDIT_EFFECT"
    ROLLED_BACK_EFFECT = "ROLLED_BACK_EFFECT"


class BundleEffectMember(CanonicalModel):
    effect_ref: str
    relationship: EffectRelationship
    condition_ref: str | None = None


class EffectOrderingEdge(CanonicalModel):
    before_effect_ref: str
    after_effect_ref: str
    condition_ref: str | None = None
    atomicity: Literal["ATOMIC_COMPOUND", "SAME_TRANSACTION_REGION", "UNKNOWN"]


class BehaviorActionScope(StrEnum):
    PROCEDURE_INVOCATION = "PROCEDURE_INVOCATION"
    CURSOR_ITERATION = "CURSOR_ITERATION"
    HANDLER_ACTIVATION = "HANDLER_ACTIVATION"
    POST_LOOP_AGGREGATION = "POST_LOOP_AGGREGATION"
    TRANSACTION_COMPLETION = "TRANSACTION_COMPLETION"


class BehaviorEffectBundle(CanonicalModel):
    bundle_id: str
    primary_effect_ref: str
    effect_members: tuple[BundleEffectMember, ...]
    transaction_region_ref: str
    controlling_region_ref: str
    action_scope: BehaviorActionScope = BehaviorActionScope.PROCEDURE_INVOCATION
    action_scope_ref: str | None = None
    ordering_edges: tuple[EffectOrderingEdge, ...]
    bundle_completeness: Literal["COMPLETE", "PARTIAL"]
    evidence_refs: tuple[str, ...]


class LoopTerminationStatus(StrEnum):
    PROVEN_TERMINATING = "PROVEN_TERMINATING"
    TERMINATION_CANDIDATE = "TERMINATION_CANDIDATE"
    POSSIBLY_NON_TERMINATING = "POSSIBLY_NON_TERMINATING"
    UNKNOWN = "UNKNOWN"


class LoopSummarySoundness(StrEnum):
    EXACT_SUMMARY = "EXACT_SUMMARY"
    CONSERVATIVE_MAY_SUMMARY = "CONSERVATIVE_MAY_SUMMARY"
    CONSERVATIVE_MUST_SUMMARY = "CONSERVATIVE_MUST_SUMMARY"
    PARTIAL_SUMMARY = "PARTIAL_SUMMARY"
    OPAQUE_BOUNDARY = "OPAQUE_BOUNDARY"


class LoopProofObligationStatus(StrEnum):
    SATISFIED = "SATISFIED"
    PARTIAL = "PARTIAL"
    UNSATISFIED = "UNSATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class LoopProofObligation(CanonicalModel):
    obligation: Literal[
        "CURSOR_POPULATION_IDENTIFIED",
        "FETCH_BINDING_IDENTIFIED",
        "ACCUMULATOR_INITIALIZATION_IDENTIFIED",
        "ACCUMULATOR_UPDATE_IDENTIFIED",
        "EARLY_EXIT_RESOLVED",
        "HANDLER_INTERFERENCE_RESOLVED",
        "SOURCE_MUTATION_RESOLVED",
        "NULL_SEMANTICS_RESOLVED",
        "TERMINATION_RESOLVED",
    ]
    status: LoopProofObligationStatus
    evidence_refs: tuple[str, ...] = ()
    note: str | None = None


class LoopSummaryCandidate(CanonicalModel):
    loop_summary_id: str
    loop_region_ref: str
    loop_kind: str
    label: str | None
    condition_text: str | None
    cursor_fetch_refs: tuple[str, ...]
    accumulator_assignment_refs: tuple[str, ...]
    early_exit_refs: tuple[str, ...]
    iterate_refs: tuple[str, ...]
    handler_binding_refs: tuple[str, ...]
    proof_obligations: tuple[LoopProofObligation, ...]
    termination_status: LoopTerminationStatus
    cardinality_status: Literal["DATA_DEPENDENT", "STATICALLY_BOUNDED", "UNKNOWN"]
    soundness: LoopSummarySoundness
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    evidence_refs: tuple[str, ...]


class QuerySummaryKind(StrEnum):
    CURSOR_QUERY = "CURSOR_QUERY"
    SELECT_INTO_QUERY = "SELECT_INTO_QUERY"
    DYNAMIC_QUERY = "DYNAMIC_QUERY"


class QueryBindingKind(StrEnum):
    SELECT_INTO = "SELECT_INTO"
    FETCH = "FETCH"
    EXECUTE_INTO = "EXECUTE_INTO"


class QueryJoinSummary(CanonicalModel):
    join_id: str
    join_kind: Literal["INNER", "LEFT", "RIGHT", "FULL", "CROSS"]
    condition_text: str | None = None
    null_producing_side: Literal["NONE", "LEFT", "RIGHT", "BOTH"]


class QueryClauseSummary(CanonicalModel):
    clause_kind: Literal["WHERE", "HAVING", "GROUP_BY", "ORDER_BY"]
    expression_text: str


class WindowModelStatus(StrEnum):
    WINDOW_MODEL_COMPLETE = "WINDOW_MODEL_COMPLETE"
    WINDOW_MODEL_PARTIAL = "WINDOW_MODEL_PARTIAL"
    WINDOW_INPUT_CARDINALITY_UNKNOWN = "WINDOW_INPUT_CARDINALITY_UNKNOWN"
    WINDOW_OVER_SINGLE_ROW_PARTITION = "WINDOW_OVER_SINGLE_ROW_PARTITION"
    WINDOW_ORDER_NONDETERMINISTIC = "WINDOW_ORDER_NONDETERMINISTIC"


class WindowFunctionSummary(CanonicalModel):
    window_id: str
    function_name: str
    argument_text: str | None = None
    partition_by: tuple[str, ...] = ()
    order_by: tuple[str, ...] = ()
    input_relation_ref: str | None = None
    input_filter_text: str | None = None
    input_cardinality: Literal["ZERO_OR_ONE", "UNKNOWN", "MULTIPLE_POSSIBLE"] = "UNKNOWN"
    order_deterministic: bool | None = None
    model_status: WindowModelStatus
    evidence_refs: tuple[str, ...] = ()


class QueryUniqueKey(CanonicalModel):
    relation_name: str
    column_names: tuple[str, ...]


class QuerySemanticsCatalog(CanonicalModel):
    schema_version: Literal["query-semantics-catalog-1.0"] = "query-semantics-catalog-1.0"
    catalog_id: str
    unique_keys: tuple[QueryUniqueKey, ...] = ()
    content_digest: str


class QuerySourceSummary(CanonicalModel):
    query_summary_id: str
    source_node_ref: str
    summary_kind: QuerySummaryKind
    cursor_name: str | None = None
    query_text_digest: str
    projection_expressions: tuple[str, ...]
    relation_refs: tuple[str, ...]
    joins: tuple[QueryJoinSummary, ...]
    cte_names: tuple[str, ...]
    clauses: tuple[QueryClauseSummary, ...]
    window_functions: tuple[str, ...]
    window_models: tuple[WindowFunctionSummary, ...] = ()
    window_model_status: WindowModelStatus | None = None
    subquery_count: int = Field(ge=0)
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    evidence_refs: tuple[str, ...]


class QueryBindingFact(CanonicalModel):
    binding_id: str
    source_node_ref: str
    query_summary_ref: str | None
    binding_kind: QueryBindingKind
    target_symbol: str
    projection_index: int = Field(ge=0)
    projection_expression: str | None = None
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]


class PredicateNodeKind(StrEnum):
    ATOMIC = "ATOMIC"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class PredicateExpression(CanonicalModel):
    expression_id: str
    node_kind: PredicateNodeKind
    operand_refs: tuple[str, ...] = ()
    technical_expression: str | None = None


class PredicateGraph(CanonicalModel):
    predicate_graph_id: str
    controlling_region_ref: str
    action_scope: BehaviorActionScope = BehaviorActionScope.PROCEDURE_INVOCATION
    action_scope_ref: str | None = None
    root_ref: str
    expressions: tuple[PredicateExpression, ...]
    source_node_refs: tuple[str, ...]
    normalization_status: Literal["COMPLETE", "PARTIAL"]


class ConstraintAssessmentStatus(StrEnum):
    SYNTACTICALLY_CONSISTENT = "SYNTACTICALLY_CONSISTENT"
    OBVIOUS_CONTRADICTION = "OBVIOUS_CONTRADICTION"
    DATA_STATE_ASSUMPTION_REQUIRED = "DATA_STATE_ASSUMPTION_REQUIRED"
    CONFIGURATION_ASSUMPTION_REQUIRED = "CONFIGURATION_ASSUMPTION_REQUIRED"
    UNSUPPORTED_CONSTRAINT_THEORY = "UNSUPPORTED_CONSTRAINT_THEORY"
    NOT_ASSESSED = "NOT_ASSESSED"


class ConstraintAssessment(CanonicalModel):
    assessment_id: str
    predicate_graph_ref: str
    status: ConstraintAssessmentStatus
    reason: str
    evidence_refs: tuple[str, ...]


class OrderedDecisionReduction(CanonicalModel):
    reduction_id: str
    controlling_region_ref: str
    preceding_arm_refs: tuple[str, ...]
    current_arm_ref: str
    normalized_concept: Literal["PRECEDING_ARMS_NOT_MATCHED"] = "PRECEDING_ARMS_NOT_MATCHED"
    evidence_refs: tuple[str, ...]


class EffectModality(StrEnum):
    MUST = "MUST"
    MUST_IF_CALLER_CONTRACT_HOLDS = "MUST_IF_CALLER_CONTRACT_HOLDS"
    MAY = "MAY"
    MUST_NOT = "MUST_NOT"
    UNKNOWN = "UNKNOWN"


class EffectObligation(CanonicalModel):
    obligation_id: str
    bundle_ref: str
    effect_ref: str
    relationship: EffectRelationship
    modality: EffectModality
    reason_codes: tuple[str, ...]


class StateDependencyEdge(CanonicalModel):
    edge_id: str
    symbol_name: str
    definition_ref: str
    use_ref: str


class BehaviorSlice(CanonicalModel):
    slice_id: str
    bundle_ref: str
    local_influence_node_refs: tuple[str, ...]
    control_predicate_node_refs: tuple[str, ...]
    state_dependency_edges: tuple[StateDependencyEdge, ...]
    query_summary_refs: tuple[str, ...]
    query_binding_refs: tuple[str, ...]
    parameter_source_names: tuple[str, ...]
    declaration_default_refs: tuple[str, ...]
    unresolved_symbol_names: tuple[str, ...]
    unresolved_influence_refs: tuple[str, ...] = ()
    unresolved_influences: tuple[UnresolvedInfluence, ...] = ()
    predicate_graph_ref: str | None = None
    constraint_assessment_refs: tuple[str, ...] = ()
    effect_obligations: tuple[EffectObligation, ...] = ()
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    representation_mode: Literal["LOCAL_BACKWARD_SLICE"] = "LOCAL_BACKWARD_SLICE"
    evidence_refs: tuple[str, ...]


class DynamicSqlResolutionStatus(StrEnum):
    STATICALLY_RECONSTRUCTED = "STATICALLY_RECONSTRUCTED"
    ENUMERABLE_VARIANTS = "ENUMERABLE_VARIANTS"
    PARTIALLY_RECONSTRUCTED = "PARTIALLY_RECONSTRUCTED"
    RUNTIME_CAPTURE_REQUIRED = "RUNTIME_CAPTURE_REQUIRED"
    UNRESOLVED_DYNAMIC_SQL = "UNRESOLVED_DYNAMIC_SQL"
    DYNAMIC_VARIANT_BUDGET_EXCEEDED = "DYNAMIC_VARIANT_BUDGET_EXCEEDED"


class DynamicSqlStatementKind(StrEnum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    MERGE = "MERGE"
    CALL = "CALL"
    VALUES = "VALUES"
    UNKNOWN = "UNKNOWN"


class DynamicIdentifierResolutionStatus(StrEnum):
    RESOLVED_LITERAL = "RESOLVED_LITERAL"
    RESOLVED_ENUMERATED = "RESOLVED_ENUMERATED"
    UNRESOLVED_DYNAMIC_IDENTIFIER = "UNRESOLVED_DYNAMIC_IDENTIFIER"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class DynamicObjectVerificationStatus(StrEnum):
    VERIFIED_CATALOG = "VERIFIED_CATALOG"
    VERIFIED_SOURCE = "VERIFIED_SOURCE"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class DynamicSqlVariant(CanonicalModel):
    variant_id: str
    template_text: str
    concrete_sql: str | None = None
    placeholder_names: tuple[str, ...] = ()
    statement_kind: DynamicSqlStatementKind
    relation_refs: tuple[str, ...] = ()
    call_target: str | None = None
    source_definition_refs: tuple[str, ...] = ()
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    content_digest: str


class DynamicQueryOutputBinding(CanonicalModel):
    binding_id: str
    site_ref: str
    target_symbol: str
    projection_index: int = Field(ge=0)
    projection_expression: str | None = None
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]


class DynamicSqlSite(CanonicalModel):
    site_id: str
    execute_node_ref: str
    execution_kind: Literal["PREPARED", "IMMEDIATE"]
    prepared_statement_name: str | None = None
    source_expression: str | None = None
    resolution_status: DynamicSqlResolutionStatus
    variant_refs: tuple[str, ...]
    into_target_names: tuple[str, ...] = ()
    using_expressions: tuple[str, ...] = ()
    statement_kinds: tuple[DynamicSqlStatementKind, ...] = ()
    relation_resolution_status: DynamicIdentifierResolutionStatus
    call_resolution_status: DynamicIdentifierResolutionStatus
    analysis_completeness: Literal["COMPLETE", "PARTIAL"]
    evidence_refs: tuple[str, ...]


class DynamicRelationResolution(CanonicalModel):
    resolution_id: str
    site_ref: str
    relation_name: str
    role: Literal["SOURCE", "TARGET"]
    status: DynamicIdentifierResolutionStatus
    verification_status: DynamicObjectVerificationStatus = DynamicObjectVerificationStatus.NOT_VERIFIED
    variant_refs: tuple[str, ...]


class DynamicCallResolution(CanonicalModel):
    resolution_id: str
    site_ref: str
    call_target: str
    status: DynamicIdentifierResolutionStatus
    verification_status: DynamicObjectVerificationStatus = DynamicObjectVerificationStatus.NOT_VERIFIED
    variant_refs: tuple[str, ...]


class DynamicResolutionCatalog(CanonicalModel):
    schema_version: Literal["dynamic-resolution-catalog-1.0"] = "dynamic-resolution-catalog-1.0"
    catalog_id: str
    source_kind: Literal["CATALOG", "SOURCE"]
    relation_names: tuple[str, ...] = ()
    routine_names: tuple[str, ...] = ()
    content_digest: str


class TenantIsolationRule(CanonicalModel):
    relation_name: str
    tenant_column: str
    accepted_parameter_names: tuple[str, ...] = ("P_TENANT_ID",)
    required_scope: Literal["READ", "WRITE", "BOTH"] = "WRITE"


class TenantIsolationCatalog(CanonicalModel):
    schema_version: Literal["tenant-isolation-catalog-1.0"] = "tenant-isolation-catalog-1.0"
    catalog_id: str
    source_kind: Literal["CATALOG", "MOCK"]
    rules: tuple[TenantIsolationRule, ...]
    content_digest: str


class RuntimeCaptureContract(CanonicalModel):
    capture_contract_id: str
    site_ref: str
    status: Literal["CONTRACT_ONLY_DEFERRED"] = "CONTRACT_ONLY_DEFERRED"
    reason: str
    required_fields: tuple[str, ...]
    evidence_refs: tuple[str, ...]



class NullabilityStatus(StrEnum):
    DEFINITELY_NON_NULL = "DEFINITELY_NON_NULL"
    POSSIBLY_NULL = "POSSIBLY_NULL"
    DEFINITELY_NULL = "DEFINITELY_NULL"
    UNKNOWN = "UNKNOWN"


class SymbolNullabilityFact(CanonicalModel):
    fact_id: str
    symbol_name: str
    status: NullabilityStatus
    declaration_default_ref: str | None = None
    assignment_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    reason: str


class Phase1SemanticResult(CanonicalModel):
    schema_version: Literal["phase1-semantic-0.9"] = "phase1-semantic-0.9"
    parser_result_digest: str
    tenant_isolation_catalog_digest: str | None = None
    query_semantics_catalog_digest: str | None = None
    caller_transaction_contract_ref: str | None = None
    caller_transaction_contract_digest: str | None = None
    cfg: ControlFlowGraph
    effects: tuple[EffectCandidate, ...]
    transaction_regions: tuple[TransactionRegion, ...]
    transaction_analyses: tuple[EffectTransactionAnalysis, ...]
    behavior_bundles: tuple[BehaviorEffectBundle, ...]
    loop_summaries: tuple[LoopSummaryCandidate, ...]
    query_summaries: tuple[QuerySourceSummary, ...]
    query_bindings: tuple[QueryBindingFact, ...]
    dynamic_sql_variants: tuple[DynamicSqlVariant, ...]
    dynamic_sql_sites: tuple[DynamicSqlSite, ...]
    dynamic_query_bindings: tuple[DynamicQueryOutputBinding, ...]
    dynamic_relation_resolutions: tuple[DynamicRelationResolution, ...]
    dynamic_call_resolutions: tuple[DynamicCallResolution, ...]
    runtime_capture_contracts: tuple[RuntimeCaptureContract, ...]
    predicate_graphs: tuple[PredicateGraph, ...]
    constraint_assessments: tuple[ConstraintAssessment, ...]
    ordered_decision_reductions: tuple["OrderedDecisionReduction", ...] = ()
    effect_obligations: tuple[EffectObligation, ...]
    behavior_slices: tuple[BehaviorSlice, ...]
    handler_coverage: tuple[HandlerCoverageFact, ...] = ()
    handler_semantics: tuple[HandlerSemanticsFact, ...] = ()
    symbol_nullability: tuple[SymbolNullabilityFact, ...] = ()
    findings: tuple[SemanticFinding, ...]
    parser_findings: tuple[ParseFinding, ...] = ()
    content_digest: str
