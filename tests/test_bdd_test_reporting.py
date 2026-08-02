from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.testkit.models import (
    ExecutionMode,
    TestCaseExecutionResult as BddCaseExecutionResult,
    TestCaseStatus as BddCaseStatus,
    TestPackageExecutionResult as BddPackageExecutionResult,
)
from ojas_reconciler.db2_behavior.testkit.reporting import junit_xml_bytes


def _case(case_id: str, status: BddCaseStatus, expected: BddCaseStatus) -> BddCaseExecutionResult:
    payload = {
        "test_case_id": case_id,
        "scenario_name": case_id,
        "actual_status": status,
        "expected_status": expected,
        "expectation_matched": status is expected,
        "assertion_results": (),
        "observation": None,
        "blockers": (),
    }
    return BddCaseExecutionResult(**payload, content_digest=canonical_digest(payload))


def test_junit_reports_actual_failures_even_when_the_known_defect_baseline_matches() -> None:
    cases = (
        _case("passing", BddCaseStatus.PASSED, BddCaseStatus.PASSED),
        _case("known-defect", BddCaseStatus.FAILED, BddCaseStatus.FAILED),
    )
    payload = {
        "schema_version": "bdd-test-execution-result-1.0",
        "package_id": "sample",
        "execution_mode": ExecutionMode.SCRIPTED_MODEL,
        "case_results": cases,
        "actual_passed": 1,
        "actual_failed": 1,
        "actual_blocked": 0,
        "expectation_mismatches": 0,
        "suite_status": "PASSED",
        "live_database_executed": False,
    }
    result = BddPackageExecutionResult(**payload, content_digest=canonical_digest(payload))
    xml = junit_xml_bytes(result).decode("utf-8")
    assert 'tests="2"' in xml
    assert 'failures="1"' in xml
    assert 'baseline_expectation_status" value="PASSED"' in xml
