"""Load and execute a standalone BDD test-assets package."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Protocol, cast

from ..core.canonical_json import canonical_digest
from .gherkin import GherkinParser
from .models import (
    AssertionKind,
    AssertionResult,
    BddTestCase,
    BddTestCaseBatch,
    BddTestCatalog,
    BddTestDataset,
    BddTestPackageManifest,
    ProcedureTestContract,
    ExecutionMode,
    ProcedureExecutionObservation,
    TestCaseExecutionResult,
    TestCaseStatus,
    TestPackageExecutionResult,
    verify_content_digest,
)
from .validation import validate_dataset, validate_invocation


class ProcedureTestAdapter(Protocol):
    def execute(self, *, test_case: BddTestCase, dataset: BddTestDataset) -> ProcedureExecutionObservation: ...


def load_adapter_factory(reference: str, *, package_root: Path | None = None) -> ProcedureTestAdapter:
    module_name, _, attribute = reference.partition(":")
    if not module_name or not attribute:
        raise ValueError("Adapter reference must use module:function syntax")
    if package_root is not None:
        source_root = package_root / "src"
        if source_root.exists() and str(source_root) not in sys.path:
            sys.path.insert(0, str(source_root))
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute)
    return cast(ProcedureTestAdapter, factory())


class BddTestPackageRunner:
    VERSION = "bdd-test-runner-1.0"

    def run(self, package_root: Path) -> TestPackageExecutionResult:
        manifest = BddTestPackageManifest.model_validate_json(
            (package_root / "test-package.json").read_text(encoding="utf-8")
        )
        if not verify_content_digest(manifest):
            raise ValueError("Test package manifest digest is invalid")
        source_path = package_root / manifest.source_file
        if not source_path.exists():
            raise ValueError(f"Source procedure file is missing: {manifest.source_file}")
        if canonical_digest({"source_text": source_path.read_text(encoding="utf-8")}) != manifest.source_digest:
            raise ValueError("Source procedure digest does not match the package manifest")
        for relative in manifest.metadata_files:
            if not (package_root / relative).exists():
                raise ValueError(f"Declared metadata file is missing: {relative}")
        contract = ProcedureTestContract.model_validate_json(
            (package_root / manifest.procedure_contract_file).read_text(encoding="utf-8")
        )
        catalog = BddTestCatalog.model_validate_json(
            (package_root / manifest.catalog_file).read_text(encoding="utf-8")
        )
        if not verify_content_digest(contract):
            raise ValueError("Procedure test contract digest is invalid")
        if not verify_content_digest(catalog):
            raise ValueError("BDD test catalog digest is invalid")
        cases = BddTestCaseBatch.model_validate_json(
            (package_root / manifest.test_cases_file).read_text(encoding="utf-8")
        )
        if not verify_content_digest(cases):
            raise ValueError("Test case batch digest is invalid")
        datasets: dict[str, BddTestDataset] = {}
        for relative in manifest.dataset_files:
            dataset = BddTestDataset.model_validate_json((package_root / relative).read_text(encoding="utf-8"))
            if not verify_content_digest(dataset):
                raise ValueError(f"Dataset digest is invalid: {dataset.dataset_id}")
            if dataset.dataset_id in datasets:
                raise ValueError(f"Duplicate dataset ID: {dataset.dataset_id}")
            validate_dataset(dataset, catalog)
            datasets[dataset.dataset_id] = dataset

        features = [GherkinParser().parse_file(package_root / value) for value in manifest.feature_files]
        known_scenarios = {(feature.feature_name, name) for feature in features for name in feature.scenario_names()}
        for case in cases.test_cases:
            if (case.feature_name, case.scenario_name) not in known_scenarios:
                raise ValueError(f"Test case {case.test_case_id} has no matching Gherkin scenario")
            if not verify_content_digest(case):
                raise ValueError(f"Test case digest is invalid: {case.test_case_id}")
            validate_invocation(case, contract)

        if manifest.execution_mode is not ExecutionMode.SCRIPTED_MODEL:
            return self._blocked_external(manifest, cases)

        adapter = load_adapter_factory(manifest.adapter_factory, package_root=package_root)
        results: list[TestCaseExecutionResult] = []
        for case in cases.test_cases:
            dataset = datasets.get(case.dataset_ref)
            if dataset is None:
                results.append(self._blocked_case(case, "DATASET_NOT_FOUND"))
                continue
            try:
                observation = adapter.execute(test_case=case, dataset=dataset)
                assertion_results = tuple(self._assert(assertion, observation) for assertion in case.assertions)
                actual = TestCaseStatus.PASSED if all(value.passed for value in assertion_results) else TestCaseStatus.FAILED
                payload = {
                    "test_case_id": case.test_case_id,
                    "scenario_name": case.scenario_name,
                    "actual_status": actual,
                    "expected_status": case.expected_status,
                    "expectation_matched": actual is case.expected_status,
                    "assertion_results": assertion_results,
                    "observation": observation,
                    "blockers": (),
                }
                results.append(TestCaseExecutionResult(**payload, content_digest=canonical_digest(payload)))
            except Exception as exc:  # noqa: BLE001 - execution defect is an artifact
                results.append(self._blocked_case(case, f"ADAPTER_ERROR:{type(exc).__name__}:{exc}"))
        return self._batch(manifest, tuple(results), live_database_executed=False)

    def _blocked_external(
        self,
        manifest: BddTestPackageManifest,
        cases: BddTestCaseBatch,
    ) -> TestPackageExecutionResult:
        reason = (
            "GENERATE_ONLY_NO_EXECUTION"
            if manifest.execution_mode is ExecutionMode.GENERATE_ONLY
            else "LIVE_EXECUTION_NOT_CONFIGURED"
        )
        results = tuple(self._blocked_case(case, reason) for case in cases.test_cases)
        return self._batch(manifest, results, live_database_executed=False)

    @staticmethod
    def _blocked_case(case: BddTestCase, reason: str) -> TestCaseExecutionResult:
        payload = {
            "test_case_id": case.test_case_id,
            "scenario_name": case.scenario_name,
            "actual_status": TestCaseStatus.BLOCKED,
            "expected_status": case.expected_status,
            "expectation_matched": case.expected_status is TestCaseStatus.BLOCKED,
            "assertion_results": (),
            "observation": None,
            "blockers": (reason,),
        }
        return TestCaseExecutionResult(**payload, content_digest=canonical_digest(payload))

    def _batch(
        self,
        manifest: BddTestPackageManifest,
        results: tuple[TestCaseExecutionResult, ...],
        *,
        live_database_executed: bool,
    ) -> TestPackageExecutionResult:
        passed = sum(value.actual_status is TestCaseStatus.PASSED for value in results)
        failed = sum(value.actual_status is TestCaseStatus.FAILED for value in results)
        blocked = sum(value.actual_status is TestCaseStatus.BLOCKED for value in results)
        mismatches = sum(not value.expectation_matched for value in results)
        payload = {
            "schema_version": "bdd-test-execution-result-1.0",
            "package_id": manifest.package_id,
            "execution_mode": manifest.execution_mode,
            "case_results": results,
            "actual_passed": passed,
            "actual_failed": failed,
            "actual_blocked": blocked,
            "expectation_mismatches": mismatches,
            "suite_status": "PASSED" if mismatches == 0 else "FAILED",
            "live_database_executed": live_database_executed,
        }
        return TestPackageExecutionResult(**payload, content_digest=canonical_digest(payload))

    @staticmethod
    def _find_row(
        relations: dict[str, tuple[dict[str, object], ...]],
        target: str,
        key: dict[str, object],
    ) -> dict[str, object] | None:
        rows = relations.get(target, ())
        for row in rows:
            if all(row.get(name) == value for name, value in key.items()):
                return row
        return None

    def _assert(self, assertion: object, observation: ProcedureExecutionObservation) -> AssertionResult:
        from .models import TestAssertion

        item = cast(TestAssertion, assertion)
        passed = False
        actual: object = None
        if item.kind is AssertionKind.OUTPUT_EQUALS:
            actual = observation.output_parameters.get(item.target)
            passed = actual == item.expected_value
        elif item.kind is AssertionKind.SQLSTATE_EQUALS:
            actual = observation.sqlstate
            passed = actual == item.expected_value
        elif item.kind is AssertionKind.EVENT_OCCURRED:
            actual = item.target in observation.events
            passed = bool(actual)
        elif item.kind is AssertionKind.EVENT_NOT_OCCURRED:
            actual = item.target in observation.events
            passed = not bool(actual)
        elif item.kind is AssertionKind.ROW_ABSENT:
            actual = self._find_row(cast(dict, observation.after_relations), item.target, cast(dict, item.key))
            passed = actual is None
        elif item.kind is AssertionKind.ROW_EQUALS:
            row = self._find_row(cast(dict, observation.after_relations), item.target, cast(dict, item.key))
            actual = row
            passed = row is not None and all(row.get(name) == value for name, value in item.expected_columns.items())
        expected = item.expected_columns if item.kind is AssertionKind.ROW_EQUALS else item.expected_value
        detail = f"target={item.target!r} expected={expected!r} actual={actual!r}"
        return AssertionResult(assertion_id=item.assertion_id, kind=item.kind, passed=passed, detail=detail)
