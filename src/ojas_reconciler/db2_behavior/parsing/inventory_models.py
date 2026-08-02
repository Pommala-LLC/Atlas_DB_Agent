from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Eligibility(StrEnum):
    POC_FULLY_ELIGIBLE = "POC_FULLY_ELIGIBLE"
    POC_PARSE_ONLY = "POC_PARSE_ONLY"
    POC_PARTIAL_SLICE_EXPECTED = "POC_PARTIAL_SLICE_EXPECTED"
    POC_INELIGIBLE = "POC_INELIGIBLE"


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: Severity
    message: str
    line: int | None = None
    column: int | None = None


class SourceIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    filename: str
    content_digest: str
    byte_count: int
    line_count: int
    code_line_count: int
    source_unit_index: int | None = Field(default=None, ge=1)
    source_unit_count: int | None = Field(default=None, ge=1)
    source_unit_start_offset: int | None = Field(default=None, ge=0)
    source_unit_end_offset: int | None = Field(default=None, ge=0)
    detected_terminator: str | None = None


class ProcedureHeader(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_name: str | None = None
    name: str | None = None
    specific_name: str | None = None
    language: str | None = None
    routine_version_id: str | None = None
    commit_on_return: str | None = None
    parameter_names: tuple[str, ...] = ()
    out_parameter_names: tuple[str, ...] = ()
    inout_parameter_names: tuple[str, ...] = ()


class QueryComplexityProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    query_count: int = 0
    select_count: int = 0
    insert_count: int = 0
    update_count: int = 0
    delete_count: int = 0
    merge_count: int = 0
    with_clause_count: int = 0
    recursive_cte_count: int = 0
    subquery_count: int = 0
    max_parenthesis_depth: int = 0
    join_count: int = 0
    inner_join_count: int = 0
    left_join_count: int = 0
    right_join_count: int = 0
    full_join_count: int = 0
    cross_join_count: int = 0
    lateral_join_count: int = 0
    window_function_count: int = 0
    aggregate_function_count: int = 0
    weighted_score: int = 0


class ControlComplexityProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    if_count: int = 0
    elseif_count: int = 0
    case_count: int = 0
    case_when_arm_count: int = 0
    merge_when_arm_count: int = 0
    handler_count: int = 0
    continue_handler_count: int = 0
    exit_handler_count: int = 0
    undo_handler_count: int = 0
    loop_count: int = 0
    for_count: int = 0
    while_count: int = 0
    repeat_count: int = 0
    generic_loop_count: int = 0
    max_control_nesting: int = 0
    cursor_declaration_count: int = 0
    fetch_count: int = 0
    cursor_loop_count: int = 0


class EffectInventory(BaseModel):
    model_config = ConfigDict(frozen=True)

    set_assignment_count: int = 0
    out_assignment_count: int = 0
    computed_out_assignment_count: int = 0
    signal_count: int = 0
    resignal_count: int = 0
    call_count: int = 0
    prepare_count: int = 0
    execute_count: int = 0
    execute_immediate_count: int = 0
    commit_count: int = 0
    rollback_count: int = 0
    dml_effect_count: int = 0
    direct_effect_site_count: int = 0
    first_effect_line: int | None = None
    shared_prologue_code_lines: int = 0
    computed_output_derivations: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class InventoryBudgets(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_source_lines: int = 300
    max_view_expansion_depth: int = 3
    max_call_depth: int = 1
    analysis_timeout_seconds: float = 5.0
    memory_ceiling_mb: int = 256


class ProcedureInventory(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["gate0-1.1"] = "gate0-1.1"
    source: SourceIdentity
    procedure: ProcedureHeader
    statement_count: int
    query_complexity: QueryComplexityProfile
    control_complexity: ControlComplexityProfile
    effects: EffectInventory
    dynamic_sql_present: bool
    temporary_table_present: bool
    transaction_control_present: bool
    unresolved_call_count: int
    eligibility: Eligibility
    eligibility_reasons: tuple[str, ...]
    findings: tuple[Finding, ...]
    analyzer_version: str = "gate0-inventory-0.3.1"


class Db2ScriptInventoryReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["gate0-db2-script-1.0"] = "gate0-db2-script-1.0"
    source: SourceIdentity
    detected_terminator: str
    terminator_detection: Literal["DIRECTIVE", "INFERRED", "DEFAULT"]
    expected_source_unit_count: int = Field(ge=0)
    discovered_source_unit_count: int = Field(ge=0)
    procedure_reports: tuple[ProcedureInventory, ...]
    unclassified_script_fragment_count: int = Field(ge=0)
    source_unit_count_matches: bool
    findings: tuple[Finding, ...] = ()


class EstateInventoryReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["gate0-estate-1.0"] = "gate0-estate-1.0"
    root: str
    procedure_reports: tuple[ProcedureInventory, ...]
    eligibility_distribution: dict[Eligibility, int]
    sample_coverage_status: str
    findings: tuple[Finding, ...] = ()
    script_reports: tuple[Db2ScriptInventoryReport, ...] = ()
    source_file_count: int = Field(default=0, ge=0)
    expected_source_unit_count: int = Field(default=0, ge=0)
    discovered_source_unit_count: int = Field(default=0, ge=0)
    source_unit_count_mismatch_files: tuple[str, ...] = ()
    unclassified_script_fragment_count: int = Field(default=0, ge=0)

    @classmethod
    def from_reports(cls, root: Path, reports: list[ProcedureInventory]) -> "EstateInventoryReport":
        distribution = {eligibility: 0 for eligibility in Eligibility}
        for report in reports:
            distribution[report.eligibility] += 1
        coverage = (
            "SAMPLE_COVERAGE_INSUFFICIENT_FOR_ESTATE_CONCLUSION"
            if len(reports) < 4
            else "STRATIFIED_SAMPLE_REVIEW_REQUIRED"
        )
        return cls(
            root=str(root),
            procedure_reports=tuple(reports),
            eligibility_distribution=distribution,
            sample_coverage_status=coverage,
            source_file_count=len(reports),
            expected_source_unit_count=len(reports),
            discovered_source_unit_count=len(reports),
        )

    @classmethod
    def from_script_reports(
        cls,
        root: Path,
        script_reports: list[Db2ScriptInventoryReport],
    ) -> "EstateInventoryReport":
        reports = [report for script in script_reports for report in script.procedure_reports]
        distribution = {eligibility: 0 for eligibility in Eligibility}
        for report in reports:
            distribution[report.eligibility] += 1
        mismatches = tuple(
            script.source.path
            for script in script_reports
            if not script.source_unit_count_matches
        )
        expected = sum(script.expected_source_unit_count for script in script_reports)
        discovered = sum(script.discovered_source_unit_count for script in script_reports)
        fragments = sum(script.unclassified_script_fragment_count for script in script_reports)
        findings: list[Finding] = []
        if mismatches:
            findings.append(
                Finding(
                    code="SOURCE_UNIT_COUNT_MISMATCH",
                    severity=Severity.ERROR,
                    message=f"{len(mismatches)} files did not segment every CREATE PROCEDURE unit.",
                )
            )
        if fragments:
            findings.append(
                Finding(
                    code="UNCLASSIFIED_SCRIPT_FRAGMENTS",
                    severity=Severity.WARNING,
                    message=f"{fragments} non-comment script fragments were not classified as procedure units.",
                )
            )
        coverage = (
            "SAMPLE_COVERAGE_INSUFFICIENT_FOR_ESTATE_CONCLUSION"
            if len(reports) < 4
            else "STRATIFIED_SAMPLE_REVIEW_REQUIRED"
        )
        return cls(
            root=str(root),
            procedure_reports=tuple(reports),
            eligibility_distribution=distribution,
            sample_coverage_status=coverage,
            findings=tuple(findings),
            script_reports=tuple(script_reports),
            source_file_count=len(script_reports),
            expected_source_unit_count=expected,
            discovered_source_unit_count=discovered,
            source_unit_count_mismatch_files=mismatches,
            unclassified_script_fragment_count=fragments,
        )
