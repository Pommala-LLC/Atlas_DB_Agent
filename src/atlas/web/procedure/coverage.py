from __future__ import annotations

from atlas.application import SourceCandidate


def coverage(candidate: SourceCandidate, spans: list[dict[str, int]]) -> tuple[int, int, float]:
    code_lines = {
        number for number, line in enumerate(candidate.text.splitlines(), start=candidate.start_line)
        if line.strip()
    }
    opaque_lines: set[int] = set()
    for span in spans:
        opaque_lines.update(range(span["start_line"], span["end_line"] + 1))
    covered = len(code_lines & opaque_lines)
    percent = round((covered / len(code_lines)) * 100, 1) if code_lines else 0.0
    return len(code_lines), covered, percent


def primary_status(parse_status: str, findings: list[dict[str, object]]) -> str:
    if parse_status == "BLOCKED":
        return "ERROR"
    if any(item["finding_class"] == "STRUCTURAL_BLOCKER" for item in findings):
        return "STRUCTURAL"
    return "PARTIAL" if parse_status == "PARTIAL" else "COMPLETE"


def analysis_eligibility(parse_status: str) -> str:
    return {
        "COMPLETE": "POC_FULLY_ELIGIBLE",
        "PARTIAL": "POC_PARTIAL_SLICE_EXPECTED",
        "BLOCKED": "POC_INELIGIBLE",
    }[parse_status]


def composition_status(call_targets: tuple[str, ...]) -> str:
    return "UNRESOLVED" if call_targets else "NOT_APPLICABLE"
