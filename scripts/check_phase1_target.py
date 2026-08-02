from __future__ import annotations

import argparse
from pathlib import Path

from ojas_reconciler.db2_behavior.parser_models import NodeKind, ParseOutcome
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.semantic_models import SemanticFindingCode
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.tenant_isolation import load_tenant_isolation_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the Phase 1 target acceptance gates.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--tenant-isolation-catalog", type=Path)
    parser.add_argument("--require-unreachable-branch", action="store_true")
    parser.add_argument("--expected-unreachable-line", type=int)
    args = parser.parse_args()

    parsed = LarkSqlPlSpikeParser().parse_file(args.source)
    failures: list[str] = []
    if parsed.outcome != ParseOutcome.PARSES_COMPLETE:
        failures.append(f"parse outcome was {parsed.outcome.value}, expected PARSES_COMPLETE")
    if parsed.ast is None:
        failures.append("no AST was emitted")
    elif any(node.kind == NodeKind.OPAQUE for node in parsed.ast.nodes):
        failures.append("one or more opaque regions were emitted")

    if parsed.ast is not None:
        semantic = Phase1SemanticAnalyzer(
            tenant_isolation_catalog=load_tenant_isolation_catalog(args.tenant_isolation_catalog)
        ).analyze(parsed)
        unreachable = [
            finding for finding in semantic.findings
            if finding.code == SemanticFindingCode.UNREACHABLE_BRANCH
        ]
        if args.require_unreachable_branch and not unreachable:
            failures.append("UNREACHABLE_BRANCH was not emitted")
        if args.expected_unreachable_line is not None and unreachable:
            lines = [source_range.start_line for finding in unreachable for source_range in finding.source_ranges]
            if not any(abs(line - args.expected_unreachable_line) <= 3 for line in lines):
                failures.append(
                    f"UNREACHABLE_BRANCH lines {lines} were not near {args.expected_unreachable_line}"
                )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: Phase 1 target acceptance gates satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
