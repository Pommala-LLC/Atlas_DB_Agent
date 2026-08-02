"""Portable reports for BDD test execution results."""
from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, tostring

from .models import TestCaseStatus, TestPackageExecutionResult


def junit_xml_bytes(result: TestPackageExecutionResult) -> bytes:
    suite = Element(
        "testsuite",
        {
            "name": result.package_id,
            "tests": str(len(result.case_results)),
            "failures": str(result.actual_failed),
            "errors": "0",
            "skipped": str(result.actual_blocked),
        },
    )
    properties = SubElement(suite, "properties")
    SubElement(properties, "property", {"name": "execution_mode", "value": result.execution_mode.value})
    SubElement(
        properties,
        "property",
        {"name": "live_database_executed", "value": str(result.live_database_executed).lower()},
    )
    SubElement(properties, "property", {"name": "baseline_expectation_status", "value": result.suite_status})

    for case in result.case_results:
        test = SubElement(
            suite,
            "testcase",
            {
                "classname": result.package_id,
                "name": case.scenario_name,
            },
        )
        props = SubElement(test, "properties")
        SubElement(props, "property", {"name": "test_case_id", "value": case.test_case_id})
        SubElement(props, "property", {"name": "expected_status", "value": case.expected_status.value})
        SubElement(props, "property", {"name": "expectation_matched", "value": str(case.expectation_matched).lower()})
        if case.actual_status is TestCaseStatus.FAILED:
            failure = SubElement(test, "failure", {"message": "BDD assertions failed"})
            failure.text = "\n".join(item.detail for item in case.assertion_results if not item.passed)
        elif case.actual_status is TestCaseStatus.BLOCKED:
            skipped = SubElement(test, "skipped", {"message": ", ".join(case.blockers) or "blocked"})
            skipped.text = "Execution was blocked."
        output = SubElement(test, "system-out")
        output.text = "\n".join(item.detail for item in case.assertion_results)
    return tostring(suite, encoding="utf-8", xml_declaration=True) + b"\n"
