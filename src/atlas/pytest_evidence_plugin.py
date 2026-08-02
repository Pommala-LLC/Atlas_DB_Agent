"""Project-owned pytest evidence plugin.

Emits canonical machine-readable collection and outcome data. It deliberately
avoids parsing pytest's terminal summary, which is a human presentation format.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

_STATE: dict[str, Any] = {}


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("atlas-release-evidence")
    group.addoption("--atlas-evidence-json", action="store", default=None, help="Write structured Atlas pytest evidence JSON.")


def pytest_sessionstart(session: pytest.Session) -> None:
    _STATE.clear()
    _STATE.update({
        "node_ids": [],
        "outcomes": Counter(),
        "skip_reasons": Counter(),
        "seen_skips": set(),
        "collection_errors": [],
        "test_failures": [],
        "internal_errors": [],
    })


def pytest_collection_finish(session: pytest.Session) -> None:
    _STATE["node_ids"] = [item.nodeid for item in session.items]


def _skip_reason(report: pytest.TestReport) -> str:
    if isinstance(report.longrepr, tuple) and len(report.longrepr) >= 3:
        return str(report.longrepr[2])
    return str(report.longrepr)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    outcomes: Counter[str] = _STATE["outcomes"]
    was_xfail = getattr(report, "wasxfail", None)
    if report.skipped:
        key = (report.nodeid, report.when)
        if key not in _STATE["seen_skips"]:
            _STATE["seen_skips"].add(key)
            if was_xfail:
                outcomes["xfailed"] += 1
            else:
                outcomes["skipped"] += 1
            _STATE["skip_reasons"][_skip_reason(report)] += 1
        return
    if report.when == "call":
        if report.passed and was_xfail:
            outcomes["xpassed"] += 1
        elif report.passed:
            outcomes["passed"] += 1
        elif report.failed:
            outcomes["failed"] += 1
            _STATE["test_failures"].append({"node_id": report.nodeid, "longrepr": str(report.longrepr)})
    elif report.failed:
        outcomes["errors"] += 1
        _STATE["test_failures"].append({"node_id": report.nodeid, "phase": report.when, "longrepr": str(report.longrepr)})


def pytest_collectreport(report: pytest.CollectReport) -> None:
    if report.failed:
        _STATE["outcomes"]["errors"] += 1
        _STATE["collection_errors"].append({"node_id": report.nodeid, "longrepr": str(report.longrepr)})


def pytest_internalerror(excrepr: object, excinfo: object) -> None:
    _STATE["outcomes"]["errors"] += 1
    _STATE["internal_errors"].append(str(excrepr))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    destination = session.config.getoption("--atlas-evidence-json")
    if not destination:
        return
    counts = {key: int(_STATE["outcomes"].get(key, 0)) for key in ("passed", "failed", "skipped", "errors", "xfailed", "xpassed")}
    payload = {
        "schema_version": "atlas-pytest-evidence-1.0",
        "pytest_exit_status": int(exitstatus),
        "tests_collected": len(_STATE["node_ids"]),
        "collected_node_ids": list(_STATE["node_ids"]),
        "outcomes": counts,
        "skip_reason_groups": [
            {"reason": reason, "count": count}
            for reason, count in sorted(_STATE["skip_reasons"].items())
        ],
        "collection_errors": _STATE["collection_errors"],
        "test_failures": _STATE["test_failures"],
        "internal_errors": _STATE["internal_errors"],
    }
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
