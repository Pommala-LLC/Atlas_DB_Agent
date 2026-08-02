from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from ..core.models import CanonicalModel
from ..type_system.models import DeclaredSymbolType


class ParseOutcome(StrEnum):
    PARSES_COMPLETE = "PARSES_COMPLETE"
    PARSES_PARTIAL = "PARSES_PARTIAL"
    REFUSES_EXPECTED = "REFUSES_EXPECTED"
    REFUSES_UNEXPECTED = "REFUSES_UNEXPECTED"


class NodeKind(StrEnum):
    PROCEDURE = "PROCEDURE"
    COMPOUND = "COMPOUND"
    DECLARE_VARIABLE = "DECLARE_VARIABLE"
    DECLARE_CURSOR = "DECLARE_CURSOR"
    DECLARE_CONDITION = "DECLARE_CONDITION"
    SET = "SET"
    IF = "IF"
    ELSEIF = "ELSEIF"
    ELSE = "ELSE"
    SELECT_INTO = "SELECT_INTO"
    SIGNAL = "SIGNAL"
    RESIGNAL = "RESIGNAL"
    GET_DIAGNOSTICS = "GET_DIAGNOSTICS"
    CALL = "CALL"
    DML = "DML"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"
    SAVEPOINT = "SAVEPOINT"
    RETURN = "RETURN"
    OPEN_CURSOR = "OPEN_CURSOR"
    FETCH_CURSOR = "FETCH_CURSOR"
    CLOSE_CURSOR = "CLOSE_CURSOR"
    LEAVE = "LEAVE"
    ITERATE = "ITERATE"
    PREPARE = "PREPARE"
    EXECUTE = "EXECUTE"
    EXECUTE_IMMEDIATE = "EXECUTE_IMMEDIATE"
    HANDLER_REGION = "HANDLER_REGION"
    LOOP_REGION = "LOOP_REGION"
    IF_REGION = "IF_REGION"
    IF_ARM = "IF_ARM"
    OPAQUE = "OPAQUE"


class ParserFindingCode(StrEnum):
    UNSUPPORTED_PROCEDURAL_CONSTRUCT = "UNSUPPORTED_PROCEDURAL_CONSTRUCT"
    OPAQUE_REGION_EMITTED = "OPAQUE_REGION_EMITTED"
    SELECT_INTO_TARGETS_NOT_FOUND = "SELECT_INTO_TARGETS_NOT_FOUND"
    QUERY_REWRITE_ARITY_MISMATCH = "QUERY_REWRITE_ARITY_MISMATCH"
    EMBEDDED_QUERY_PARSE_REJECTED = "EMBEDDED_QUERY_PARSE_REJECTED"
    SEMANTIC_PRESERVATION_FAILED = "SEMANTIC_PRESERVATION_FAILED"
    PROCEDURE_HEADER_PARSE_FAILED = "PROCEDURE_HEADER_PARSE_FAILED"
    UNBALANCED_COMPOUND_STATEMENT = "UNBALANCED_COMPOUND_STATEMENT"
    HANDLER_STRUCTURE_PARTIAL = "HANDLER_STRUCTURE_PARTIAL"
    LOOP_STRUCTURE_PARTIAL = "LOOP_STRUCTURE_PARTIAL"
    IF_STRUCTURE_PARTIAL = "IF_STRUCTURE_PARTIAL"
    FETCH_BINDING_NOT_FOUND = "FETCH_BINDING_NOT_FOUND"
    MERGE_ACTIONS_PARTIAL = "MERGE_ACTIONS_PARTIAL"
    NAMED_CONDITION_UNRESOLVED = "NAMED_CONDITION_UNRESOLVED"
    MULTIPLE_PROCEDURE_SOURCE_UNITS = "MULTIPLE_PROCEDURE_SOURCE_UNITS"
    SOURCE_UNIT_COUNT_MISMATCH = "SOURCE_UNIT_COUNT_MISMATCH"
    RESULT_SET_CAPACITY_EXCEEDED = "RESULT_SET_CAPACITY_EXCEEDED"
    RETURNED_CURSOR_NOT_OPENED = "RETURNED_CURSOR_NOT_OPENED"


class SourceRange(CanonicalModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    start_offset: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    end_offset: int = Field(ge=0)


class ParseFinding(CanonicalModel):
    code: ParserFindingCode
    message: str
    source_range: SourceRange | None = None
    consequence: str


class ProcedureParameter(CanonicalModel):
    name: str
    mode: Literal["IN", "OUT", "INOUT"]
    type_text: str
    source_range: SourceRange


class SelectIntoBinding(CanonicalModel):
    target_names: tuple[str, ...]
    projection_count: int | None = Field(default=None, ge=0)
    arity_status: Literal[
        "ARITY_MATCHED",
        "TOO_FEW_PROJECTIONS",
        "TOO_MANY_PROJECTIONS",
        "PROJECTION_COUNT_UNRESOLVED",
    ]
    original_statement_text: str
    residual_query_text: str
    removed_range: SourceRange


class AssignmentBinding(CanonicalModel):
    target_name: str
    expression_text: str


class FetchBinding(CanonicalModel):
    cursor_name: str
    target_names: tuple[str, ...]


class DynamicPrepareBinding(CanonicalModel):
    statement_name: str
    source_expression: str


class DynamicExecuteBinding(CanonicalModel):
    execution_kind: Literal["PREPARED", "IMMEDIATE"]
    statement_name: str | None = None
    source_expression: str | None = None
    into_target_names: tuple[str, ...] = ()
    using_expressions: tuple[str, ...] = ()


class ConditionDeclaration(CanonicalModel):
    condition_name: str
    sqlstate: str
    lexical_scope_ref: str


class CompoundRegion(CanonicalModel):
    label: str | None = None
    lexical_scope_ref: str
    body_node_refs: tuple[str, ...]
    local_declaration_refs: tuple[str, ...] = ()
    condition_declaration_refs: tuple[str, ...] = ()
    analysis_completeness: Literal["STRUCTURE_COMPLETE", "STRUCTURE_PARTIAL"] = "STRUCTURE_COMPLETE"


class HandlerKind(StrEnum):
    CONTINUE = "CONTINUE"
    EXIT = "EXIT"
    UNDO = "UNDO"


class HandlerRegion(CanonicalModel):
    handler_kind: HandlerKind
    handled_condition_text: str
    lexical_scope_ref: str
    named_condition_ref: str | None = None
    resolved_sqlstate: str | None = None
    condition_resolution_status: Literal[
        "DIRECT_SQLSTATE",
        "BUILTIN_CONDITION",
        "NAMED_CONDITION_RESOLVED",
        "NAMED_CONDITION_UNRESOLVED",
        "CONDITION_CLASS",
    ] = "CONDITION_CLASS"
    body_node_refs: tuple[str, ...]
    continuation_semantics: Literal[
        "AFTER_RAISING_STATEMENT",
        "EXIT_DECLARING_COMPOUND",
        "UNDO_AND_EXIT_DECLARING_COMPOUND",
    ]
    continuation_target_ref: str | None = None
    state_assignment_refs: tuple[str, ...] = ()
    analysis_completeness: Literal["STRUCTURE_COMPLETE", "STRUCTURE_PARTIAL"] = "STRUCTURE_COMPLETE"


class LoopKind(StrEnum):
    LOOP = "LOOP"
    WHILE = "WHILE"
    REPEAT = "REPEAT"
    FOR = "FOR"


class LoopRegion(CanonicalModel):
    loop_kind: LoopKind
    label: str | None = None
    condition_text: str | None = None
    body_node_refs: tuple[str, ...]
    analysis_completeness: Literal["STRUCTURE_COMPLETE", "STRUCTURE_PARTIAL"] = "STRUCTURE_COMPLETE"


class IfArm(CanonicalModel):
    arm_id: str
    arm_kind: Literal["IF", "ELSEIF", "ELSE"]
    ordered_precedence: int = Field(ge=0)
    condition_text: str | None = None
    body_node_refs: tuple[str, ...]
    source_range: SourceRange


class IfRegion(CanonicalModel):
    arms: tuple[IfArm, ...]
    source_construct: Literal["IF", "SIMPLE_CASE", "SEARCHED_CASE"] = "IF"
    selector_expression: str | None = None
    analysis_completeness: Literal["STRUCTURE_COMPLETE", "STRUCTURE_PARTIAL"] = "STRUCTURE_COMPLETE"


class ReturnedCursorDeclaration(CanonicalModel):
    cursor_name: str
    return_scope: Literal["CLIENT", "CALLER", "UNSPECIFIED"]
    declaration_node_ref: str
    source_range: SourceRange


class CursorOpenEffect(CanonicalModel):
    cursor_name: str
    open_node_ref: str
    source_range: SourceRange
    returned_cursor: bool


class MergeAction(CanonicalModel):
    match_kind: Literal["MATCHED", "NOT_MATCHED"]
    condition_text: str | None = None
    action_kind: Literal["UPDATE", "INSERT", "DELETE", "SIGNAL", "UNKNOWN"]


class MergeStructure(CanonicalModel):
    target_text: str
    actions: tuple[MergeAction, ...]
    analysis_completeness: Literal["STRUCTURE_COMPLETE", "STRUCTURE_PARTIAL"] = "STRUCTURE_COMPLETE"


class StateAccessKind(StrEnum):
    DEF = "DEF"
    USE = "USE"


class StateAccessFact(CanonicalModel):
    fact_id: str
    symbol_name: str
    access_kind: StateAccessKind
    context_kind: Literal[
        "ASSIGNMENT",
        "HANDLER_ASSIGNMENT",
        "FETCH_BINDING",
        "SELECT_INTO_BINDING",
        "IF_CONDITION",
        "LOOP_CONDITION",
        "PREPARE_SOURCE",
        "EXECUTE_SOURCE",
        "EXECUTE_INTO_BINDING",
        "EXECUTE_USING",
    ]
    source_node_ref: str
    region_ref: str | None = None


class AstNode(CanonicalModel):
    node_id: str
    kind: NodeKind
    source_range: SourceRange
    text: str
    child_refs: tuple[str, ...] = ()
    select_into_binding: SelectIntoBinding | None = None
    assignment_binding: AssignmentBinding | None = None
    fetch_binding: FetchBinding | None = None
    dynamic_prepare_binding: DynamicPrepareBinding | None = None
    dynamic_execute_binding: DynamicExecuteBinding | None = None
    handler_region: HandlerRegion | None = None
    condition_declaration: ConditionDeclaration | None = None
    compound_region: CompoundRegion | None = None
    lexical_scope_ref: str | None = None
    loop_region: LoopRegion | None = None
    if_region: IfRegion | None = None
    if_arm: IfArm | None = None
    merge_structure: MergeStructure | None = None
    opaque_reason: str | None = None


class ProcedureAst(CanonicalModel):
    node_id: str
    schema_name: str | None = None
    procedure_name: str
    specific_name: str | None = None
    routine_version_id: str | None = None
    commit_on_return: str | None = None
    parameters: tuple[ProcedureParameter, ...]
    body_node_refs: tuple[str, ...]
    nodes: tuple[AstNode, ...]
    state_access_facts: tuple[StateAccessFact, ...] = ()
    declared_symbol_types: tuple[DeclaredSymbolType, ...] = ()
    declared_result_set_capacity: int | None = Field(default=None, ge=0)
    returned_cursor_declarations: tuple[ReturnedCursorDeclaration, ...] = ()
    cursor_open_effects: tuple[CursorOpenEffect, ...] = ()
    source_range: SourceRange


class ProcedureParseResult(CanonicalModel):
    schema_version: Literal["procedure-parse-0.7"] = "procedure-parse-0.7"
    parser_adapter: str
    parser_version: str
    artifact_id: str
    artifact_revision_id: str
    source_name: str
    source_digest: str
    normalized_ast_digest: str | None
    outcome: ParseOutcome
    ast: ProcedureAst | None
    findings: tuple[ParseFinding, ...]


class EmbeddedQueryRequest(CanonicalModel):
    statement_kind: Literal["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "VALUES"]
    residual_sql: str
    original_statement_text: str
    source_range: SourceRange
    expected_projection_count: int | None = Field(default=None, ge=0)


class EmbeddedQueryParseResult(CanonicalModel):
    schema_version: Literal["embedded-query-parse-0.1"] = "embedded-query-parse-0.1"
    adapter: str
    adapter_version: str
    accepted: bool
    statement_kind: str | None = None
    projection_count: int | None = Field(default=None, ge=0)
    semantic_guard_results: dict[str, bool] = Field(default_factory=dict)
    findings: tuple[ParseFinding, ...] = ()
    opaque_tree: dict[str, object] | None = None


class ExplainRecord(CanonicalModel):
    result: Literal["SUCCEEDED", "PARTIAL", "BLOCKED", "FAILED"]
    failed_gate: str | None = None
    finding_codes: tuple[str, ...] = ()
    evidence_ranges: tuple[SourceRange, ...] = ()
    affected_outputs: tuple[str, ...] = ()
    withheld_outputs: tuple[str, ...] = ()
    consequence: str
    recommended_action: str
