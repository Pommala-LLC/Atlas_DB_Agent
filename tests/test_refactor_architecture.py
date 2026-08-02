from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMALL_MODULE_ROOTS = (
    ROOT / "src" / "atlas" / "commands",
    ROOT / "src" / "atlas" / "web",
    ROOT / "src" / "atlas" / "web" / "procedure",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "interfaces" / "commands" / "support_parts",
)
SMALL_MODULES = (
    ROOT / "src" / "atlas" / "application" / "segmentation.py",
    ROOT / "src" / "atlas" / "application" / "source_unit.py",
    ROOT / "src" / "atlas" / "application" / "unit.py",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "application" / "multi_unit_pipeline.py",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "interfaces" / "commands" / "support.py",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "interfaces" / "dispatcher.py",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "interfaces" / "dialect_selection.py",
    ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "runner.py",
)


def test_refactored_python_modules_do_not_exceed_100_lines() -> None:
    paths = list(SMALL_MODULES)
    for root in SMALL_MODULE_ROOTS:
        paths.extend(root.rglob("*.py"))
    paths.append(ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "procedure_analysis.py")
    violations = {path.relative_to(ROOT).as_posix(): len(path.read_text().splitlines()) for path in paths
                  if len(path.read_text().splitlines()) > 100}
    assert not violations


def test_canonical_web_runner_imports_canonical_app() -> None:
    source = (ROOT / "src" / "atlas" / "web" / "runner.py").read_text(encoding="utf-8")
    assert "from .app import create_app" in source
    assert "ojas_reconciler" not in source
    legacy = ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "runner.py"
    assert "from atlas.web.runner import main" in legacy.read_text(encoding="utf-8")


def test_release_assurance_test_uses_structured_evidence() -> None:
    source = (ROOT / "tests" / "test_rc21_official_parser_assurance.py").read_text(encoding="utf-8")
    assert "legacy_pytest_terminal_parser" not in source
    assert "outcome_counts(evidence)" in source


def test_console_scripts_use_canonical_web_runner() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'atlas-console = "atlas.web.runner:main"' in project
    assert 'commercial-behavior-console = "atlas.web.runner:main"' in project


def test_new_procedure_feature_lives_under_atlas_web() -> None:
    canonical = ROOT / "src" / "atlas" / "web" / "procedure"
    assert (canonical / "service.py").is_file()
    legacy = ROOT / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "procedure_analysis.py"
    text = legacy.read_text(encoding="utf-8")
    assert "from atlas.web.procedure import" in text
    assert len(text.splitlines()) <= 100
