from __future__ import annotations

import importlib
import importlib.metadata
from dataclasses import dataclass, asdict


@dataclass(frozen=True, slots=True)
class ToolStatus:
    package: str
    import_name: str
    installed: bool
    version: str | None
    role: str
    phase: str
    decision: str


def _version(package: str, import_name: str) -> tuple[bool, str | None]:
    try:
        importlib.import_module(import_name)
    except Exception:
        return False, None
    try:
        return True, importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        module = importlib.import_module(import_name)
        return True, getattr(module, "__version__", None)


def inspect_tools() -> list[ToolStatus]:
    specs = [
        ("pydantic", "pydantic", "Immutable evidence and inventory models", "Gate 0+", "SELECTED"),
        ("lark", "lark", "DB2 SQL PL grammar engine candidate", "Phase 1", "SELECTED_FOR_POC"),
        ("networkx", "networkx", "Transparent CFG/DFG graph adapter", "Phase 1-3", "SELECTED_FOR_POC"),
        ("gherkin-official", "gherkin", "Mandatory official readable-BDD parse gate", "BDD emission", "SELECTED_MANDATORY"),
        ("sqlfluff", "sqlfluff", "Optional IBM Db2 embedded-query parser", "Phase 2", "EVALUATE_WITH_CORPUS"),
        ("ibm_db", "ibm_db", "Optional Db2 LUW/zOS catalog adapter", "Gate 0/Phase 2", "OPTIONAL"),
        ("rustworkx", "rustworkx", "High-performance graph backend", "After benchmarks", "BENCHMARK_IF_NEEDED"),
        ("z3-solver", "z3", "Bounded local constraint evaluator", "Later Phase 3/5A", "DEFERRED"),
    ]
    results: list[ToolStatus] = []
    for package, import_name, role, phase, decision in specs:
        installed, version = _version(package, import_name)
        results.append(
            ToolStatus(
                package=package,
                import_name=import_name,
                installed=installed,
                version=version,
                role=role,
                phase=phase,
                decision=decision,
            )
        )
    return results


def inspect_tools_json() -> list[dict[str, object]]:
    return [asdict(item) for item in inspect_tools()]
