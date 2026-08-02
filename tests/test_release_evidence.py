from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from atlas import release_evidence


def test_terminal_summary_parsers_are_not_public_release_evidence_api() -> None:
    assert not hasattr(release_evidence, "parse_pytest_outcome_counts")
    assert not hasattr(release_evidence, "parse_pytest_skip_reason_groups")


def test_public_release_evidence_inventory_digest_is_order_sensitive() -> None:
    first = release_evidence.test_inventory_digest(["tests/a.py::test_a", "tests/b.py::test_b"])
    second = release_evidence.test_inventory_digest(["tests/b.py::test_b", "tests/a.py::test_a"])
    assert first.startswith("sha256:")
    assert first != second


def test_release_evidence_exit_code_rejects_launcher_inventory_drift() -> None:
    payload: dict[str, object] = {
        "collection_launchers": {
            "python_module": {"exit_code": 0, "collection_consistent": True},
            "console_entry_point": {"exit_code": 0, "collection_consistent": True},
        },
        "launcher_inventory_match": False,
        "launcher_digest_match": False,
        "pytest_exit_code": 0,
    }
    assert release_evidence.release_evidence_exit_code(payload) == 1


def test_run_pytest_uses_requested_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[tuple[str, ...], Path]] = []

    def fake_run(
        command: tuple[str, ...],
        *,
        cwd: Path,
        check: bool,
        stdout,
        stderr,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((tuple(command), cwd))
        stdout.write("")
        stderr.write("")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(release_evidence.subprocess, "run", fake_run)
    monkeypatch.setattr(release_evidence, "_console_pytest_executable", lambda: "pytest")

    module = release_evidence.run_pytest(
        tmp_path, launcher="module", args=("--collect-only", "-q")
    )
    console = release_evidence.run_pytest(
        tmp_path, launcher="console", args=("--collect-only", "-q")
    )

    assert module.command[1:3] == ("-m", "pytest")
    assert console.command[0] == "pytest"
    assert calls[0][1] == tmp_path
    assert calls[1][1] == tmp_path
