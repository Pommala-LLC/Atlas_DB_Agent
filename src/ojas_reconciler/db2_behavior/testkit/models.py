"""Canonical contracts for external BDD test-asset packages."""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from ..core.models import CanonicalModel
from ..core.canonical_json import canonical_digest
from ..type_system.models import CanonicalSqlType, RelationDefinition

JsonScalar = str | int | bool | None
RowValue = JsonScalar


class ExecutionMode(StrEnum):
    GENERATE_ONLY = "GENERATE_ONLY"
    SCRIPTED_MODEL = "SCRIPTED_MODEL"
    DB2_LUW = "DB2_LUW"
    DB2_ZOS_EXTERNAL = "DB2_ZOS_EXTERNAL"


class TestCaseStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EXECUTED = "NOT_EXECUTED"


class AssertionKind(StrEnum):
    OUTPUT_EQUALS = "OUTPUT_EQUALS"
    SQLSTATE_EQUALS = "SQLSTATE_EQUALS"
    ROW_EQUALS = "ROW_EQUALS"
    ROW_ABSENT = "ROW_ABSENT"
    EVENT_OCCURRED = "EVENT_OCCURRED"
    EVENT_NOT_OCCURRED = "EVENT_NOT_OCCURRED"


class TypedValue(CanonicalModel):
    database_type: str
    canonical_value: str | None

    @field_validator("database_type")
    @classmethod
    def nonblank_type(cls, value: str) -> str:
        text = value.strip().upper()
        if not text:
            raise ValueError("database_type cannot be blank")
        return text


class ProcedureInvocationSpec(CanonicalModel):
    procedure_schema: str | None = None
    procedure_name: str
    parameters: dict[str, TypedValue]


class TestAssertion(CanonicalModel):
    assertion_id: str
    kind: AssertionKind
    target: str
    expected_value: RowValue = None
    key: dict[str, RowValue] = Field(default_factory=dict)
    expected_columns: dict[str, RowValue] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_shape(self) -> "TestAssertion":
        if self.kind in {AssertionKind.ROW_EQUALS, AssertionKind.ROW_ABSENT} and not self.key:
            raise ValueError(f"{self.kind} requires a row key")
        if self.kind is AssertionKind.ROW_EQUALS and not self.expected_columns:
            raise ValueError("ROW_EQUALS requires expected_columns")
        return self


class BddTestCase(CanonicalModel):
    test_case_id: str
    feature_name: str
    scenario_name: str
    dataset_ref: str
    invocation: ProcedureInvocationSpec
    assertions: tuple[TestAssertion, ...]
    expected_status: TestCaseStatus = TestCaseStatus.PASSED
    tags: tuple[str, ...] = ()
    behavior_ref: str | None = None
    evidence_refs: tuple[str, ...] = ()
    content_digest: str


class BddTestCaseBatch(CanonicalModel):
    schema_version: Literal["bdd-test-case-batch-1.0"] = "bdd-test-case-batch-1.0"
    package_id: str
    test_cases: tuple[BddTestCase, ...]
    content_digest: str


class BddTestDataset(CanonicalModel):
    schema_version: Literal["bdd-test-dataset-1.0"] = "bdd-test-dataset-1.0"
    dataset_id: str
    facts: dict[str, JsonScalar]
    relations: dict[str, tuple[dict[str, RowValue], ...]]
    content_digest: str




class ProcedureTestContract(CanonicalModel):
    schema_version: Literal["procedure-test-contract-1.0"] = "procedure-test-contract-1.0"
    procedure_schema: str | None = None
    procedure_name: str
    parameter_types: dict[str, CanonicalSqlType]
    parameter_modes: dict[str, Literal["IN", "OUT", "INOUT"]]
    content_digest: str

    @model_validator(mode="after")
    def validate_parameter_keys(self) -> "ProcedureTestContract":
        if set(self.parameter_types) != set(self.parameter_modes):
            raise ValueError("parameter_types and parameter_modes must contain the same names")
        return self


class BddTestCatalog(CanonicalModel):
    schema_version: Literal["bdd-test-catalog-1.0"] = "bdd-test-catalog-1.0"
    provider_ref: str
    relations: tuple[RelationDefinition, ...]
    content_digest: str


class BddTestPackageManifest(CanonicalModel):
    schema_version: Literal["bdd-test-package-manifest-1.0"] = "bdd-test-package-manifest-1.0"
    package_id: str
    package_version: str
    source_procedure: str
    source_file: str
    source_digest: str
    execution_mode: ExecutionMode
    adapter_factory: str
    feature_files: tuple[str, ...]
    test_cases_file: str
    dataset_files: tuple[str, ...]
    procedure_contract_file: str
    catalog_file: str
    metadata_files: tuple[str, ...] = ()
    generated_by: str
    content_digest: str

    @field_validator("adapter_factory")
    @classmethod
    def adapter_shape(cls, value: str) -> str:
        text = value.strip()
        if ":" not in text:
            raise ValueError("adapter_factory must use module:function syntax")
        return text


class ProcedureExecutionObservation(CanonicalModel):
    output_parameters: dict[str, RowValue]
    sqlstate: str | None = None
    before_relations: dict[str, tuple[dict[str, RowValue], ...]] = Field(default_factory=dict)
    after_relations: dict[str, tuple[dict[str, RowValue], ...]] = Field(default_factory=dict)
    events: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class AssertionResult(CanonicalModel):
    assertion_id: str
    kind: AssertionKind
    passed: bool
    detail: str


class TestCaseExecutionResult(CanonicalModel):
    test_case_id: str
    scenario_name: str
    actual_status: TestCaseStatus
    expected_status: TestCaseStatus
    expectation_matched: bool
    assertion_results: tuple[AssertionResult, ...]
    observation: ProcedureExecutionObservation | None = None
    blockers: tuple[str, ...] = ()
    content_digest: str


class TestPackageExecutionResult(CanonicalModel):
    schema_version: Literal["bdd-test-execution-result-1.0"] = "bdd-test-execution-result-1.0"
    package_id: str
    execution_mode: ExecutionMode
    case_results: tuple[TestCaseExecutionResult, ...]
    actual_passed: int
    actual_failed: int
    actual_blocked: int
    expectation_mismatches: int
    suite_status: Literal["PASSED", "FAILED"]
    live_database_executed: bool
    content_digest: str


def verify_content_digest(model: CanonicalModel) -> bool:
    payload = model.model_dump(mode="python", exclude={"content_digest"})
    return canonical_digest(payload) == getattr(model, "content_digest")
