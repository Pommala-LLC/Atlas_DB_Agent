"""Unconfigured external execution adapter marker.

Generated test-asset packages reference this factory while they remain in
GENERATE_ONLY mode. The package runner never loads it in that mode. If a caller
forces execution without selecting a real adapter, fail closed.
"""
from __future__ import annotations


class UnconfiguredExternalAdapter:
    def execute(self, *, test_case, dataset):  # pragma: no cover - fail-closed guard
        raise RuntimeError(
            "No live DB2 or customer scripted adapter is configured for this generated package."
        )


def create_unconfigured_adapter() -> UnconfiguredExternalAdapter:
    return UnconfiguredExternalAdapter()
