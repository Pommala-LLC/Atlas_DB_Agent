from __future__ import annotations

from atlas.core.models import ScenarioCandidateBatch


def render_gherkin(batch: ScenarioCandidateBatch) -> str:
    lines = [
        "@technical_candidate @non_authoritative @requires_vocabulary_approval",
        f"Feature: {batch.routine_ref} {batch.dialect.value} behavior candidates",
        "",
        "  Rule: Extracted ordered behavior",
    ]
    for scenario in batch.scenarios:
        lines.extend(["", f"    Scenario: {scenario.name}"])
        for index, value in enumerate(scenario.given):
            lines.append(f"      {'Given' if index == 0 else 'And'} {value}")
        lines.append(f"      When {scenario.when}")
        for index, value in enumerate(scenario.then):
            lines.append(f"      {'Then' if index == 0 else 'And'} {value}")
    return "\n".join(lines) + "\n"
