from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parent.parent / "src/ojas_reconciler/db2_behavior"
BASE = "ojas_reconciler.db2_behavior."

ALLOWED_DEPENDENCIES: dict[str, set[str]] = {
    "core": set(),
    "type_system": {"core"},
    "parsing": {"core", "type_system"},
    "analysis": {"core", "parsing", "type_system"},
    "bdd": {"analysis", "core", "parsing", "type_system"},
    "compiler": {"analysis", "bdd", "core", "parsing", "type_system"},
    "runtime": {"analysis", "bdd", "compiler", "core", "parsing", "type_system"},
    "testkit": {"core", "type_system"},
    "governance": {"bdd", "core", "parsing", "runtime", "type_system"},
    "contracts": {"analysis", "bdd", "core", "parsing", "type_system"},
    "application": {
        "analysis",
        "bdd",
        "compiler",
        "contracts",
        "core",
        "governance",
        "parsing",
        "runtime",
        "type_system",
        "testkit",
    },
    "interfaces": {
        "analysis",
        "application",
        "bdd",
        "compiler",
        "contracts",
        "core",
        "governance",
        "parsing",
        "runtime",
        "type_system",
        "testkit",
    },
}


def _module_name(path: Path) -> str:
    relative = path.relative_to(ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return "ojas_reconciler.db2_behavior" + ("." + ".".join(parts) if parts else "")


def _resolve_relative(current_module: str, imported: str, level: int) -> str:
    package_parts = current_module.split(".")[:-1]
    if current_module.endswith(".__init__"):
        package_parts = current_module.split(".")[:-1]
    if level > 1:
        package_parts = package_parts[: -(level - 1)]
    return ".".join(package_parts + ([imported] if imported else []))


def imported_bounded_packages(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    current = _module_name(path)
    dependencies: set[str] = set()
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.ImportFrom):
            if node.level:
                modules.append(_resolve_relative(current, node.module or "", node.level))
            elif node.module:
                modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        for module in modules:
            if not module.startswith(BASE):
                continue
            relative = module[len(BASE) :]
            dependency = relative.split(".", 1)[0]
            if dependency in ALLOWED_DEPENDENCIES:
                dependencies.add(dependency)
    return dependencies


def test_bounded_packages_follow_dependency_direction() -> None:
    violations: list[str] = []
    for package, allowed in ALLOWED_DEPENDENCIES.items():
        package_root = ROOT / package
        if not package_root.exists():
            continue
        for source in package_root.rglob("*.py"):
            for dependency in imported_bounded_packages(source) - {package} - allowed:
                violations.append(f"{source.relative_to(ROOT)} -> {dependency}")
    assert violations == []


def test_static_layers_do_not_import_runtime_adapters() -> None:
    forbidden = {
        "ojas_reconciler.db2_behavior.runtime.adapters.db2_luw",
        "ojas_reconciler.db2_behavior.runtime.adapters.db2_zos_ifcid",
    }
    offenders: list[str] = []
    for package in ("core", "type_system", "parsing", "analysis", "bdd", "compiler", "testkit"):
        for source in (ROOT / package).rglob("*.py"):
            text = source.read_text(encoding="utf-8")
            if any(name in text for name in forbidden):
                offenders.append(str(source.relative_to(ROOT)))
    assert offenders == []


def test_legacy_root_modules_are_only_compatibility_facades() -> None:
    implementation_names = {
        "agent",
        "authority",
        "authority_models",
        "bdd_explain",
        "bdd_models",
        "bundles",
        "caller_contract",
        "canonical_json",
        "cfg",
        "cli",
        "corpus",
        "decision_reduction",
        "doctor",
        "dynamic_sql",
        "effects",
        "explain",
        "fixture_authority",
        "gherkin",
        "governance_models",
        "governance_ports",
        "governance_store",
        "inventory",
        "lexer",
        "loop_summaries",
        "modalities",
        "models",
        "parser_models",
        "pipeline",
        "predicates",
        "query_semantics",
        "query_summaries",
        "release_models",
        "resources",
        "runtime_evidence_properties",
        "runtime_executor",
        "runtime_models",
        "runtime_plan",
        "runtime_ports",
        "runtime_probe",
        "runtime_safety",
        "runtime_verify",
        "runtime_workflow",
        "scenario_models",
        "semantic",
        "semantic_models",
        "slicing",
        "tenant_isolation",
        "tooling",
        "transaction",
        "window_reachability",
        "zos_ifcid_consumer",
    }
    oversized: list[str] = []
    for name in implementation_names:
        source = ROOT / f"{name}.py"
        if source.exists() and len(source.read_text(encoding="utf-8").splitlines()) > 8:
            oversized.append(source.name)
    assert oversized == []
