from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AtlasModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DialectId(StrEnum):
    DB2_SQL_PL = "DB2_SQL_PL"
    ORACLE_PLSQL = "ORACLE_PLSQL"
    SQLSERVER_TSQL = "SQLSERVER_TSQL"
    POSTGRESQL_PLPGSQL = "POSTGRESQL_PLPGSQL"
    MYSQL_STORED_PROGRAM = "MYSQL_STORED_PROGRAM"


class RoutineKind(StrEnum):
    PROCEDURE = "PROCEDURE"
    FUNCTION = "FUNCTION"
    TRIGGER = "TRIGGER"
    PACKAGE_ROUTINE = "PACKAGE_ROUTINE"


class SemanticNodeKind(StrEnum):
    ENTRY = "ENTRY"
    EXIT = "EXIT"
    BLOCK = "BLOCK"
    DECLARE = "DECLARE"
    ASSIGNMENT = "ASSIGNMENT"
    CONDITION = "CONDITION"
    CASE = "CASE"
    LOOP = "LOOP"
    LOOP_CONTROL = "LOOP_CONTROL"
    QUERY = "QUERY"
    SELECT_INTO = "SELECT_INTO"
    RESULT_SET = "RESULT_SET"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    MERGE = "MERGE"
    UPSERT = "UPSERT"
    CALL = "CALL"
    DYNAMIC_SQL = "DYNAMIC_SQL"
    CURSOR_DECLARE = "CURSOR_DECLARE"
    CURSOR_OPEN = "CURSOR_OPEN"
    CURSOR_FETCH = "CURSOR_FETCH"
    CURSOR_CLOSE = "CURSOR_CLOSE"
    ERROR_RAISE = "ERROR_RAISE"
    ERROR_HANDLER = "ERROR_HANDLER"
    DIAGNOSTICS = "DIAGNOSTICS"
    TRANSACTION_BEGIN = "TRANSACTION_BEGIN"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"
    SAVEPOINT = "SAVEPOINT"
    RETURN = "RETURN"
    TEMP_OBJECT = "TEMP_OBJECT"
    SECURITY_CONTEXT = "SECURITY_CONTEXT"
    CONDITION_DECLARE = "CONDITION_DECLARE"
    PRAGMA = "PRAGMA"
    ASSERT = "ASSERT"
    BULK_OPERATION = "BULK_OPERATION"
    LABEL = "LABEL"
    GOTO = "GOTO"
    LOCK = "LOCK"
    TRANSACTION_SETTING = "TRANSACTION_SETTING"
    MESSAGE = "MESSAGE"
    TRUNCATE = "TRUNCATE"
    DDL = "DDL"
    CALL_TARGET = "CALL_TARGET"
    OPAQUE = "OPAQUE"


class EdgeKind(StrEnum):
    NEXT = "NEXT"
    TRUE = "TRUE"
    FALSE = "FALSE"
    BRANCH = "BRANCH"
    LOOP_BODY = "LOOP_BODY"
    LOOP_BACK = "LOOP_BACK"
    EXCEPTION = "EXCEPTION"
    CALLS = "CALLS"
    DATA_DEPENDENCY = "DATA_DEPENDENCY"


class EffectModality(StrEnum):
    MUST = "MUST"
    MAY = "MAY"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"


class SourceSpan(AtlasModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0)


class RoutineParameter(AtlasModel):
    name: str
    mode: Literal["IN", "OUT", "INOUT", "VARIADIC", "RETURN"]
    type_text: str
    default_text: str | None = None


class SemanticNode(AtlasModel):
    node_id: str
    kind: SemanticNodeKind
    text: str
    source_span: SourceSpan
    parent_ref: str | None = None
    condition_text: str | None = None
    target_name: str | None = None
    expression_text: str | None = None
    relation_refs: tuple[str, ...] = ()
    variable_reads: tuple[str, ...] = ()
    variable_writes: tuple[str, ...] = ()
    call_target: str | None = None
    cursor_name: str | None = None
    error_code: str | None = None
    modality: EffectModality = EffectModality.MUST
    attributes: dict[str, Any] = Field(default_factory=dict)


class SemanticEdge(AtlasModel):
    edge_id: str
    source_ref: str
    target_ref: str
    kind: EdgeKind
    condition_text: str | None = None


class SemanticFinding(AtlasModel):
    code: str
    severity: Literal["INFO", "WARNING", "ERROR"]
    message: str
    source_span: SourceSpan | None = None
    consequence: str


class RoutineIR(AtlasModel):
    schema_version: str = "atlas-routine-ir-1.0"
    atlas_version: str
    dialect: DialectId
    adapter_id: str
    routine_kind: RoutineKind
    schema_name: str | None = None
    routine_name: str
    parameters: tuple[RoutineParameter, ...]
    routine_attributes: dict[str, Any] = Field(default_factory=dict)
    source_name: str
    source_digest: str
    body_digest: str
    nodes: tuple[SemanticNode, ...]
    edges: tuple[SemanticEdge, ...]
    findings: tuple[SemanticFinding, ...] = ()
    entry_node_ref: str
    exit_node_ref: str
    content_digest: str

    @model_validator(mode="after")
    def validate_references(self) -> "RoutineIR":
        node_ids = {node.node_id for node in self.nodes}
        if self.entry_node_ref not in node_ids or self.exit_node_ref not in node_ids:
            raise ValueError("Entry and exit references must resolve.")
        for edge in self.edges:
            if edge.source_ref not in node_ids or edge.target_ref not in node_ids:
                raise ValueError(f"Unresolved edge {edge.edge_id}")
        return self


class DecisionArm(AtlasModel):
    arm_id: str
    precedence: int = Field(ge=0)
    predicate_node_ref: str
    condition_text: str
    effect_node_refs: tuple[str, ...]
    terminal: bool


class EffectSummary(AtlasModel):
    effect_id: str
    node_ref: str
    kind: SemanticNodeKind
    target: str | None = None
    expression: str | None = None
    modality: EffectModality
    condition_refs: tuple[str, ...] = ()
    relation_refs: tuple[str, ...] = ()


class RoutineSemanticReport(AtlasModel):
    schema_version: str = "atlas-routine-semantic-report-1.0"
    atlas_version: str
    dialect: DialectId
    routine_ref: str
    routine_ir_digest: str
    parse_status: Literal["COMPLETE", "PARTIAL", "BLOCKED"]
    decision_arms: tuple[DecisionArm, ...]
    effects: tuple[EffectSummary, ...]
    call_targets: tuple[str, ...]
    relation_refs: tuple[str, ...]
    dynamic_sql_node_refs: tuple[str, ...]
    result_set_node_refs: tuple[str, ...]
    transaction_node_refs: tuple[str, ...]
    handler_node_refs: tuple[str, ...]
    opaque_node_refs: tuple[str, ...]
    finding_counts: dict[str, int]
    content_digest: str


class ScenarioCandidate(AtlasModel):
    scenario_id: str
    name: str
    given: tuple[str, ...]
    when: str
    then: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    authority_scope: Literal["NON_AUTHORITATIVE_TECHNICAL_CANDIDATE"] = "NON_AUTHORITATIVE_TECHNICAL_CANDIDATE"


class ScenarioCandidateBatch(AtlasModel):
    schema_version: str = "atlas-scenario-candidate-batch-1.0"
    routine_ref: str
    dialect: DialectId
    scenarios: tuple[ScenarioCandidate, ...]
    source_ir_digest: str
    content_digest: str


class RoutineAnalysisBundle(AtlasModel):
    schema_version: str = "atlas-routine-analysis-bundle-1.0"
    routine_ref: str
    routine_ir: RoutineIR
    semantic_report: RoutineSemanticReport
    scenario_candidates: ScenarioCandidateBatch
    content_digest: str


class SourceUnitAnalysis(AtlasModel):
    schema_version: str = "atlas-source-unit-analysis-1.0"
    atlas_version: str
    dialect: DialectId
    source_name: str
    source_digest: str
    routines: tuple[RoutineAnalysisBundle, ...]
    discovery_findings: tuple[SemanticFinding, ...] = ()
    content_digest: str

class DialectSemanticCoverage(AtlasModel):
    dialect: DialectId
    adapter_id: str
    status: Literal["DIALECT_BOUNDED_SEMANTICS"] = "DIALECT_BOUNDED_SEMANTICS"
    routine_kinds: tuple[RoutineKind, ...]
    common_constructs: tuple[str, ...]
    vendor_constructs: tuple[str, ...]
    explicit_boundaries: tuple[str, ...]
    reference_urls: tuple[str, ...] = ()


class AtlasSemanticCoverageManifest(AtlasModel):
    schema_version: str = "atlas-semantic-coverage-manifest-1.0"
    atlas_version: str
    product_name: Literal["Atlas"] = "Atlas"
    semantic_contract: tuple[str, ...]
    dialects: tuple[DialectSemanticCoverage, ...]
    content_digest: str
