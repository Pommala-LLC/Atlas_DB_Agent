"""Small deterministic parser for the generated English Gherkin subset.

This intentionally validates only the feature/scenario/step constructs emitted by
this application. It is not a replacement for the full Cucumber grammar.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class GherkinStep:
    keyword: str
    text: str
    line: int


@dataclass(frozen=True, slots=True)
class GherkinScenario:
    name: str
    tags: tuple[str, ...]
    steps: tuple[GherkinStep, ...]
    line: int


@dataclass(frozen=True, slots=True)
class GherkinDocument:
    feature_name: str
    scenarios: tuple[GherkinScenario, ...]

    def scenario_names(self) -> frozenset[str]:
        return frozenset(value.name for value in self.scenarios)


class GherkinParser:
    STEP_KEYWORDS = ("Given", "When", "Then", "And", "But")

    def parse_file(self, path: Path) -> GherkinDocument:
        return self.parse(path.read_text(encoding="utf-8"))

    def parse(self, text: str) -> GherkinDocument:
        feature_name: str | None = None
        scenarios: list[GherkinScenario] = []
        pending_tags: list[str] = []
        current_name: str | None = None
        current_line = 0
        current_tags: tuple[str, ...] = ()
        current_steps: list[GherkinStep] = []

        def flush() -> None:
            nonlocal current_name, current_line, current_tags, current_steps
            if current_name is None:
                return
            if not any(step.keyword == "When" for step in current_steps):
                raise ValueError(f"Scenario {current_name!r} has no When step")
            if not any(step.keyword == "Then" for step in current_steps):
                raise ValueError(f"Scenario {current_name!r} has no Then step")
            scenarios.append(
                GherkinScenario(
                    name=current_name,
                    tags=current_tags,
                    steps=tuple(current_steps),
                    line=current_line,
                )
            )
            current_name = None
            current_steps = []
            current_tags = ()

        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):
                pending_tags.extend(part for part in line.split() if part.startswith("@"))
                continue
            if line.startswith("Feature:"):
                if feature_name is not None:
                    raise ValueError("Only one Feature is allowed per generated feature file")
                feature_name = line.partition(":")[2].strip()
                if not feature_name:
                    raise ValueError("Feature name cannot be blank")
                continue
            if line.startswith(("Scenario:", "Scenario Outline:")):
                flush()
                current_name = line.partition(":")[2].strip()
                current_line = number
                current_tags = tuple(pending_tags)
                pending_tags.clear()
                if not current_name:
                    raise ValueError("Scenario name cannot be blank")
                continue
            keyword = next((key for key in self.STEP_KEYWORDS if line.startswith(key + " ")), None)
            if keyword is not None:
                if current_name is None:
                    raise ValueError(f"Step outside a scenario at line {number}")
                current_steps.append(GherkinStep(keyword=keyword, text=line[len(keyword) + 1 :], line=number))
                continue
            if line.startswith(("Rule:", "Background:", "Examples:", "|")):
                continue
            # Feature descriptions are allowed before the first scenario.
            if current_name is None:
                continue
            raise ValueError(f"Unsupported generated Gherkin syntax at line {number}: {line}")

        flush()
        if feature_name is None:
            raise ValueError("Feature declaration is required")
        if not scenarios:
            raise ValueError("At least one scenario is required")
        names = [value.name for value in scenarios]
        if len(names) != len(set(names)):
            raise ValueError("Scenario names must be unique within a feature")
        return GherkinDocument(feature_name=feature_name, scenarios=tuple(scenarios))
