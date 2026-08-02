from __future__ import annotations

from typing import Mapping

OUTCOME_KEYS = ("passed", "failed", "skipped", "errors", "xfailed", "xpassed")


def outcome_counts(evidence: Mapping[str, object]) -> dict[str, int]:
    outcomes = evidence.get("outcomes", {})
    values = outcomes if isinstance(outcomes, Mapping) else {}
    return {key: int(values.get(key, 0)) for key in OUTCOME_KEYS}


def skip_reason_groups(evidence: Mapping[str, object]) -> list[dict[str, object]]:
    groups = evidence.get("skip_reason_groups", [])
    return [dict(item) for item in groups if isinstance(item, Mapping)] if isinstance(groups, list) else []
