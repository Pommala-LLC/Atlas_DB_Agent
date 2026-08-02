from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.testkit.boundary_values import BoundaryValueGenerator
from ojas_reconciler.db2_behavior.testkit.gherkin import GherkinParser
from ojas_reconciler.db2_behavior.testkit.models import (
    AssertionKind,
    BddTestCase,
    BddTestCaseBatch,
    BddTestCatalog,
    BddTestDataset,
    BddTestPackageManifest,
    ProcedureTestContract,
    ExecutionMode,
    ProcedureInvocationSpec,
    TestAssertion as BddAssertion,
    TestCaseStatus as BddCaseStatus,
    TypedValue,
)
from ojas_reconciler.db2_behavior.testkit.runner import BddTestPackageRunner
from ojas_reconciler.db2_behavior.type_system.models import (
    CanonicalSqlType,
    ResolutionCompleteness,
    SqlTypeFamily,
    TypeResolutionStatus,
)


def _with_digest(model_type, payload):
    return model_type(**payload, content_digest=canonical_digest(payload))


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def test_generated_gherkin_subset_requires_when_and_then() -> None:
    document = GherkinParser().parse(
        """Feature: Example\n\nScenario: Works\n  Given a fact\n  When it runs\n  Then it succeeds\n"""
    )
    assert document.feature_name == "Example"
    assert document.scenario_names() == frozenset({"Works"})


def test_boundary_generator_preserves_integer_and_decimal_boundaries() -> None:
    integer_type = CanonicalSqlType(
        family=SqlTypeFamily.INTEGER,
        database_type="INTEGER",
        resolution_status=TypeResolutionStatus.DECLARED,
        completeness=ResolutionCompleteness.COMPLETE,
        source_refs=("parameter:P_SCORE",),
    )
    decimal_type = CanonicalSqlType(
        family=SqlTypeFamily.DECIMAL,
        database_type="DECIMAL",
        precision=15,
        scale=2,
        resolution_status=TypeResolutionStatus.CATALOG_RESOLVED,
        completeness=ResolutionCompleteness.COMPLETE,
        source_refs=("column:CLAIM.AMOUNT",),
    )
    generator = BoundaryValueGenerator()
    assert generator.around(sql_type=integer_type, operator=">=", threshold="950") == ("949", "950", "951")
    assert generator.around(sql_type=decimal_type, operator=">", threshold="75000.00") == (
        "74999.99",
        "75000.00",
        "75000.01",
    )


def test_runner_loads_a_separate_test_asset_package(tmp_path: Path) -> None:
    (tmp_path / "features").mkdir()
    (tmp_path / "specs").mkdir()
    (tmp_path / "data").mkdir()
    adapter_package = tmp_path / "src" / "sample_asset"
    adapter_package.mkdir(parents=True)
    (adapter_package / "__init__.py").write_text("", encoding="utf-8")
    (adapter_package / "adapter.py").write_text(
        """from ojas_reconciler.db2_behavior.testkit.models import ProcedureExecutionObservation

class Adapter:
    def execute(self, *, test_case, dataset):
        return ProcedureExecutionObservation(output_parameters={"P_RESULT": "OK"})

def create_adapter():
    return Adapter()
""",
        encoding="utf-8",
    )
    (tmp_path / "features" / "sample.feature").write_text(
        "Feature: Sample\n\nScenario: Returns OK\n  When the procedure runs\n  Then the result is OK\n",
        encoding="utf-8",
    )

    dataset_payload = {
        "schema_version": "bdd-test-dataset-1.0",
        "dataset_id": "ds-1",
        "facts": {},
        "relations": {},
    }
    dataset = _with_digest(BddTestDataset, dataset_payload)
    _write(tmp_path / "data" / "ds-1.json", dataset)

    assertion = BddAssertion(
        assertion_id="a-1",
        kind=AssertionKind.OUTPUT_EQUALS,
        target="P_RESULT",
        expected_value="OK",
    )
    case_payload = {
        "test_case_id": "tc-1",
        "feature_name": "Sample",
        "scenario_name": "Returns OK",
        "dataset_ref": "ds-1",
        "invocation": ProcedureInvocationSpec(
            procedure_name="SAMPLE",
            parameters={"P_RESULT": TypedValue(database_type="VARCHAR(10)", canonical_value=None)},
        ),
        "assertions": (assertion,),
        "expected_status": BddCaseStatus.PASSED,
        "tags": (),
        "behavior_ref": None,
        "evidence_refs": (),
    }
    case = _with_digest(BddTestCase, case_payload)
    batch_payload = {
        "schema_version": "bdd-test-case-batch-1.0",
        "package_id": "sample-tests",
        "test_cases": (case,),
    }
    batch = _with_digest(BddTestCaseBatch, batch_payload)
    _write(tmp_path / "specs" / "test-cases.json", batch)

    parameter_type = CanonicalSqlType(
        family=SqlTypeFamily.CHARACTER,
        database_type="VARCHAR",
        length=10,
        nullable=True,
        resolution_status=TypeResolutionStatus.DECLARED,
        completeness=ResolutionCompleteness.COMPLETE,
        source_refs=("procedure:P_RESULT",),
    )
    contract_payload = {
        "schema_version": "procedure-test-contract-1.0",
        "procedure_schema": None,
        "procedure_name": "SAMPLE",
        "parameter_types": {"P_RESULT": parameter_type},
        "parameter_modes": {"P_RESULT": "OUT"},
    }
    contract = _with_digest(ProcedureTestContract, contract_payload)
    _write(tmp_path / "data" / "procedure-contract.json", contract)
    catalog_payload = {
        "schema_version": "bdd-test-catalog-1.0",
        "provider_ref": "EMPTY_TEST_CATALOG",
        "relations": (),
    }
    catalog = _with_digest(BddTestCatalog, catalog_payload)
    _write(tmp_path / "data" / "catalog.json", catalog)

    manifest_payload = {
        "schema_version": "bdd-test-package-manifest-1.0",
        "package_id": "sample-tests",
        "package_version": "1.0.0",
        "source_procedure": "SAMPLE",
        "source_file": "procedure.sql",
        "source_digest": canonical_digest({"source_text": "CREATE PROCEDURE SAMPLE"}),
        "execution_mode": ExecutionMode.SCRIPTED_MODEL,
        "adapter_factory": "sample_asset.adapter:create_adapter",
        "feature_files": ("features/sample.feature",),
        "test_cases_file": "specs/test-cases.json",
        "dataset_files": ("data/ds-1.json",),
        "procedure_contract_file": "data/procedure-contract.json",
        "catalog_file": "data/catalog.json",
        "metadata_files": ("data/procedure-contract.json", "data/catalog.json"),
        "generated_by": "test",
    }
    manifest = _with_digest(BddTestPackageManifest, manifest_payload)
    _write(tmp_path / "test-package.json", manifest)
    (tmp_path / "procedure.sql").write_text("CREATE PROCEDURE SAMPLE", encoding="utf-8")

    result = BddTestPackageRunner().run(tmp_path)
    assert result.suite_status == "PASSED"
    assert result.actual_passed == 1
    assert result.actual_failed == 0
    assert result.live_database_executed is False
