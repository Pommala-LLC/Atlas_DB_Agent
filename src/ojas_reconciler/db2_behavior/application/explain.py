from __future__ import annotations

from ojas_reconciler.db2_behavior.parsing.models import ExplainRecord, ParseOutcome, ProcedureParseResult


def explain_parse_result(result: ProcedureParseResult) -> ExplainRecord:
    ranges = tuple(
        finding.source_range
        for finding in result.findings
        if finding.source_range is not None
    )
    if result.outcome == ParseOutcome.PARSES_COMPLETE:
        return ExplainRecord(
            result="SUCCEEDED",
            consequence="A complete procedural-shell AST was emitted for the admitted grammar subset.",
            recommended_action="Continue with CFG and direct-effect construction through parser ports.",
        )
    if result.outcome == ParseOutcome.PARSES_PARTIAL:
        return ExplainRecord(
            result="PARTIAL",
            failed_gate="PROCEDURAL_SHELL_COMPLETENESS",
            finding_codes=tuple(f.code.value for f in result.findings),
            evidence_ranges=ranges,
            withheld_outputs=("complete CFG", "canonical DFG", "ScenarioSpec", "Gherkin"),
            consequence="Supported regions were parsed; unsupported regions remain explicit opaque nodes.",
            recommended_action="Add a measured grammar rule or preserve the region as opaque.",
        )
    return ExplainRecord(
        result="BLOCKED" if result.outcome == ParseOutcome.REFUSES_EXPECTED else "FAILED",
        failed_gate="PROCEDURAL_PARSE",
        finding_codes=tuple(f.code.value for f in result.findings),
        evidence_ranges=ranges,
        withheld_outputs=("AST", "CFG", "DFG", "effects", "ScenarioSpec", "Gherkin"),
        consequence="No downstream semantic artifacts were emitted from the refused parse.",
        recommended_action="Inspect the named finding and its source range.",
    )
