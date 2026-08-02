"""Deprecated compatibility helpers for old pytest terminal evidence.

The authoritative release path uses `pytest_evidence_plugin`. These functions
are retained only for reading historical artifacts and are not exported from
`release_evidence`.
"""
from __future__ import annotations

import re
import warnings


def parse_pytest_outcome_counts(stdout: str) -> dict[str, int]:
    warnings.warn("Terminal-summary parsing is deprecated; use structured pytest evidence.", DeprecationWarning, stacklevel=2)
    counts = {key: 0 for key in ("passed", "failed", "skipped", "errors", "xfailed", "xpassed", "deselected")}
    for key in counts:
        matches = re.findall(rf"(\d+) {key}", stdout)
        if matches:
            counts[key] = int(matches[-1])
    return counts


def parse_pytest_skip_reason_groups(stdout: str) -> list[dict[str, object]]:
    warnings.warn("Terminal-summary parsing is deprecated; use structured pytest evidence.", DeprecationWarning, stacklevel=2)
    return [
        {"count": int(match.group(1)), "reason": match.group(2)}
        for match in re.finditer(r"^SKIPPED \[(\d+)\] (.+)$", stdout, re.MULTILINE)
    ]
