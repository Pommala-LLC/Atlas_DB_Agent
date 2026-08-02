from __future__ import annotations

import hashlib
import importlib.metadata
import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from atlas.release_environment import build_environment_report

PytestLauncher = Literal["module", "console"]

__all__ = [
    "PytestLauncher",
    "PytestRun",
    "build_release_evidence",
    "collected_node_ids",
    "collection_footer_count",
    "distribution_version",
    "pytest_command",
    "release_evidence_exit_code",
    "run_pytest",
    "test_inventory_digest",
    "write_release_evidence",
]


@dataclass(frozen=True)
class PytestRun:
    launcher: PytestLauncher
    command: tuple[str, ...]
    completed: subprocess.CompletedProcess[str]
    structured: dict[str, object]


def distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "UNAVAILABLE"


def collected_node_ids(stdout: str) -> list[str]:
    return [
        line.strip()
        for line in stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    ]


def test_inventory_digest(node_ids: Sequence[str]) -> str:
    payload = "\n".join(node_ids).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def collection_footer_count(stdout: str) -> int | None:
    match = re.search(r"(\d+) tests collected", stdout)
    return int(match.group(1)) if match else None


def _console_pytest_executable() -> str:
    name = "pytest.exe" if sys.platform == "win32" else "pytest"
    adjacent = Path(sys.executable).resolve().parent / name
    if adjacent.is_file():
        return str(adjacent)
    discovered = shutil.which("pytest")
    if discovered:
        return discovered
    raise FileNotFoundError(
        "The pytest console entry point is unavailable. Install the project dev dependencies."
    )


def pytest_command(launcher: PytestLauncher, args: Sequence[str]) -> tuple[str, ...]:
    if launcher == "module":
        return (sys.executable, "-m", "pytest", "-o", "addopts=", *args)
    if launcher == "console":
        return (_console_pytest_executable(), "-o", "addopts=", *args)
    raise ValueError(f"Unsupported pytest launcher: {launcher}")


def run_pytest(
    root: Path,
    *,
    launcher: PytestLauncher,
    args: Sequence[str],
) -> PytestRun:
    with tempfile.TemporaryDirectory(prefix="pytest-evidence-") as temporary:
        evidence_path = Path(temporary) / "evidence.json"
        plugin_args = (
            "-p", "atlas.pytest_evidence_plugin",
            "--atlas-evidence-json", str(evidence_path),
        )
        command = pytest_command(launcher, (*plugin_args, *args))
        stdout_path = Path(temporary) / "stdout.txt"
        stderr_path = Path(temporary) / "stderr.txt"
        with stdout_path.open("w", encoding="utf-8", newline="") as stdout_file, stderr_path.open(
            "w", encoding="utf-8", newline=""
        ) as stderr_file:
            raw = subprocess.run(
                command,
                cwd=root,
                check=False,
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
            )
        completed = subprocess.CompletedProcess(
            command,
            raw.returncode,
            stdout_path.read_text(encoding="utf-8"),
            stderr_path.read_text(encoding="utf-8"),
        )
        structured = json.loads(evidence_path.read_text(encoding="utf-8")) if evidence_path.is_file() else {
            "schema_version": "atlas-pytest-evidence-1.0",
            "pytest_exit_status": raw.returncode,
            "tests_collected": 0,
            "collected_node_ids": [],
            "outcomes": {key: 0 for key in ("passed", "failed", "skipped", "errors", "xfailed", "xpassed")},
            "skip_reason_groups": [],
            "collection_errors": [{"longrepr": "Structured pytest evidence was not emitted."}],
            "test_failures": [],
            "internal_errors": [],
        }
    return PytestRun(launcher=launcher, command=command, completed=completed, structured=structured)


def _run_isolated_pytest(
    root: Path,
    *,
    launcher: PytestLauncher,
    args: Sequence[str],
) -> PytestRun:
    """Run one evidence lane in a fresh Python parent process.

    Some pytest plugins or subprocess descendants can retain inherited process
    state after a lane exits. A one-lane helper process prevents that state from
    affecting the next launcher and makes release evidence reproducible.
    """
    with tempfile.TemporaryDirectory(prefix="pytest-isolated-lane-") as temporary:
        output_path = Path(temporary) / "lane.json"
        command = (
            sys.executable,
            "-m",
            "atlas.pytest_evidence_lane",
            "--root",
            str(root),
            "--launcher",
            launcher,
            "--output",
            str(output_path),
            "--",
            *args,
        )
        helper_stdout_path = Path(temporary) / "helper-stdout.txt"
        helper_stderr_path = Path(temporary) / "helper-stderr.txt"
        with helper_stdout_path.open("w", encoding="utf-8", newline="") as helper_stdout, helper_stderr_path.open(
            "w", encoding="utf-8", newline=""
        ) as helper_stderr:
            environment = dict(os.environ)
            source_root = str((root / "src").resolve())
            existing_path = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = source_root if not existing_path else source_root + os.pathsep + existing_path
            helper = subprocess.run(
                command,
                cwd=root,
                check=False,
                stdout=helper_stdout,
                stderr=helper_stderr,
                text=True,
                env=environment,
            )
        helper_stdout_text = helper_stdout_path.read_text(encoding="utf-8")
        helper_stderr_text = helper_stderr_path.read_text(encoding="utf-8")
        if helper.returncode != 0 or not output_path.is_file():
            fallback = {
                "schema_version": "atlas-pytest-evidence-1.0",
                "pytest_exit_status": helper.returncode,
                "tests_collected": 0,
                "collected_node_ids": [],
                "outcomes": {key: 0 for key in ("passed", "failed", "skipped", "errors", "xfailed", "xpassed")},
                "skip_reason_groups": [],
                "collection_errors": [{"longrepr": helper_stderr_text or "Isolated pytest evidence lane failed."}],
                "test_failures": [],
                "internal_errors": [],
            }
            completed = subprocess.CompletedProcess(command, helper.returncode or 1, helper_stdout_text, helper_stderr_text)
            return PytestRun(launcher=launcher, command=command, completed=completed, structured=fallback)
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        completed = subprocess.CompletedProcess(
            tuple(payload["command"]),
            int(payload["returncode"]),
            str(payload.get("stdout", "")),
            str(payload.get("stderr", "")),
        )
        return PytestRun(
            launcher=launcher,
            command=tuple(str(value) for value in payload["command"]),
            completed=completed,
            structured=dict(payload["structured"]),
        )


def _run_release_lanes(root: Path) -> tuple[PytestRun, PytestRun, PytestRun]:
    """Execute release lanes in isolated Python parents concurrently.

    Each lane has its own pytest process, output files, plugin state and temporary
    directory. Starting the lanes together avoids the platform-specific third-run
    stall observed when multiple complete pytest invocations are launched
    sequentially from one long-lived parent.
    """
    jobs = (
        ("module", ("-p", "no:cacheprovider", "--collect-only", "-q")),
        ("console", ("-p", "no:cacheprovider", "--collect-only", "-q")),
        ("module", ("-p", "no:cacheprovider", "-q", "-ra")),
    )
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="atlas-pytest-evidence") as executor:
        futures = [
            executor.submit(_run_isolated_pytest, root, launcher=launcher, args=args)
            for launcher, args in jobs
        ]
        values = tuple(future.result() for future in futures)
    return values[0], values[1], values[2]


def _collection_record(run: PytestRun) -> dict[str, object]:
    node_ids = [str(value) for value in run.structured.get("collected_node_ids", [])]
    reported_count = int(run.structured.get("tests_collected", 0))
    return {
        "launcher": run.launcher,
        "command": list(run.command),
        "exit_code": run.completed.returncode,
        "tests_collected": len(node_ids),
        "collection_footer_count": reported_count,
        "collection_consistent": reported_count == len(node_ids),
        "test_inventory_digest": test_inventory_digest(node_ids),
        "collected_node_ids": node_ids,
        "structured_evidence": run.structured,
        "stdout": run.completed.stdout,
        "stderr": run.completed.stderr,
    }


def _project_release(root: Path) -> str:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        return str(project["project"]["version"])
    except Exception:
        return "UNKNOWN"


def _quality_gate(root: Path, module: str, args: Sequence[str]) -> dict[str, object]:
    if distribution_version(module) == "UNAVAILABLE":
        return {
            "status": "NOT_EXECUTED",
            "command": [sys.executable, "-m", module, *args],
            "exit_code": None,
            "stdout": "",
            "stderr": f"{module} is not installed in the release environment.",
        }
    command = (sys.executable, "-m", module, *args)
    completed = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "command": list(command),
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def build_release_evidence(root: Path) -> dict[str, object]:
    resolved_root = root.resolve()
    environment = build_environment_report(resolved_root)
    module_run, console_run, executed = _run_release_lanes(resolved_root)
    module_collection = _collection_record(module_run)
    console_collection = _collection_record(console_run)

    module_nodes = list(module_collection["collected_node_ids"])
    console_nodes = list(console_collection["collected_node_ids"])
    launcher_inventory_match = module_nodes == console_nodes
    launcher_digest_match = (
        module_collection["test_inventory_digest"]
        == console_collection["test_inventory_digest"]
    )
    outcomes = {key: int(executed.structured.get("outcomes", {}).get(key, 0)) for key in ("passed", "failed", "skipped", "errors", "xfailed", "xpassed")}
    outcomes["deselected"] = 0
    skip_reason_groups = list(executed.structured.get("skip_reason_groups", []))
    tests_by_file = Counter(node_id.split("::", 1)[0] for node_id in module_nodes)
    ruff = _quality_gate(resolved_root, "ruff", ("check", "src", "tests"))
    mypy = _quality_gate(resolved_root, "mypy", ("src/atlas",))
    collection_pass = (
        module_run.completed.returncode == 0
        and console_run.completed.returncode == 0
        and bool(module_collection["collection_consistent"])
        and bool(console_collection["collection_consistent"])
        and launcher_inventory_match
        and launcher_digest_match
    )
    execution_pass = executed.completed.returncode == 0 and outcomes["failed"] == 0 and outcomes["errors"] == 0
    skip_gate = "PASS" if outcomes["skipped"] == 0 else "INCOMPLETE"
    dependency_gate = "PASS" if environment["test_dependencies_complete"] else "INCOMPLETE"
    gate_summary = {
        "test_dependency_environment": dependency_gate,
        "pytest_collection": "PASS" if collection_pass else "FAIL",
        "pytest_execution": "PASS" if execution_pass else "FAIL",
        "required_test_coverage": skip_gate,
        "static_analysis": ruff["status"],
        "type_checking": mypy["status"],
    }
    blockers: list[str] = []
    if dependency_gate != "PASS":
        blockers.append("RELEASE_TEST_DEPENDENCIES_INCOMPLETE")
    if not collection_pass:
        blockers.append("PYTEST_COLLECTION_GATE_FAILED")
    if not execution_pass:
        blockers.append("PYTEST_EXECUTION_GATE_FAILED")
    if outcomes["skipped"]:
        blockers.append("REQUIRED_ASSURANCE_TESTS_SKIPPED")
    if ruff["status"] != "PASS":
        blockers.append("STATIC_ANALYSIS_NOT_PASSED")
    if mypy["status"] != "PASS":
        blockers.append("TYPE_CHECKING_NOT_PASSED")
    if not collection_pass or not execution_pass:
        status = "FAIL"
    elif blockers:
        status = "CONDITIONAL"
    else:
        status = "PASS"

    return {
        "schema_version": "pytest-release-evidence-2.0",
        "evidence_source": "PROJECT_OWNED_PYTEST_PLUGIN",
        "release": _project_release(resolved_root),
        "status": status,
        "required_assurance_complete": status == "PASS",
        "gate_summary": gate_summary,
        "blocking_conditions": blockers,
        "release_environment": environment,
        "quality_execution": {"ruff": ruff, "mypy": mypy},
        "python_version": sys.version.split()[0],
        "gherkin_official_version": distribution_version("gherkin-official"),
        "collection_launchers": {
            "python_module": module_collection,
            "console_entry_point": console_collection,
        },
        "launcher_inventory_match": launcher_inventory_match,
        "launcher_digest_match": launcher_digest_match,
        "tests_collected": len(module_nodes),
        "collection_footer_count": module_collection["collection_footer_count"],
        "collection_consistent": bool(module_collection["collection_consistent"]),
        "test_inventory_digest": module_collection["test_inventory_digest"],
        "tests_by_file": dict(sorted(tests_by_file.items())),
        "collected_node_ids": module_nodes,
        "execution_launcher": executed.launcher,
        "execution_command": list(executed.command),
        "pytest_exit_code": executed.completed.returncode,
        "tests_passed": outcomes["passed"],
        "tests_failed": outcomes["failed"],
        "tests_skipped": outcomes["skipped"],
        "tests_errors": outcomes["errors"],
        "tests_xfailed": outcomes["xfailed"],
        "tests_xpassed": outcomes["xpassed"],
        "tests_deselected": outcomes["deselected"],
        "skip_reason_groups": skip_reason_groups,
        "skip_reason_count_total": sum(int(item["count"]) for item in skip_reason_groups),
        "structured_execution_evidence": executed.structured,
        "run_stdout": executed.completed.stdout,
        "run_stderr": executed.completed.stderr,
    }


def release_evidence_exit_code(payload: dict[str, object]) -> int:
    collections = payload["collection_launchers"]
    assert isinstance(collections, dict)
    for record in collections.values():
        assert isinstance(record, dict)
        exit_code = int(record["exit_code"])
        if exit_code != 0:
            return exit_code
        if not bool(record["collection_consistent"]):
            return 1
    if not bool(payload["launcher_inventory_match"]):
        return 1
    if not bool(payload["launcher_digest_match"]):
        return 1
    pytest_exit = int(payload["pytest_exit_code"])
    if pytest_exit != 0:
        return pytest_exit
    status = str(payload.get("status", "CONDITIONAL"))
    if status == "PASS":
        return 0
    if status == "FAIL":
        return 1
    return 2


def write_release_evidence(*, root: Path, output: Path) -> int:
    payload = build_release_evidence(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return release_evidence_exit_code(payload)
