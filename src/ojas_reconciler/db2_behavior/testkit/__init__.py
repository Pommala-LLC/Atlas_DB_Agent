"""Reusable BDD test-asset compilation and execution tools.

Procedure-specific features, test cases, datasets, adapters, and results belong in
separate test-asset packages. This package defines only stable models and engines.
"""
from .boundary_values import BoundaryValueGenerator
from .gherkin import GherkinDocument, GherkinParser
from .models import (
    AssertionKind,
    BddTestCase,
    BddTestCaseBatch,
    BddTestDataset,
    BddTestPackageManifest,
    BddTestCatalog,
    ProcedureTestContract,
    ExecutionMode,
    ProcedureExecutionObservation,
    TestCaseExecutionResult,
    TestCaseStatus,
    TestPackageExecutionResult,
)
from .runner import BddTestPackageRunner, ProcedureTestAdapter, load_adapter_factory
from .reporting import junit_xml_bytes

__all__ = [
    "AssertionKind",
    "BddTestCase",
    "BddTestCaseBatch",
    "BddTestDataset",
    "BddTestPackageManifest",
    "BddTestCatalog",
    "ProcedureTestContract",
    "BddTestPackageRunner",
    "BoundaryValueGenerator",
    "ExecutionMode",
    "GherkinDocument",
    "GherkinParser",
    "ProcedureExecutionObservation",
    "ProcedureTestAdapter",
    "TestCaseExecutionResult",
    "TestCaseStatus",
    "TestPackageExecutionResult",
    "load_adapter_factory",
    "junit_xml_bytes",
]
