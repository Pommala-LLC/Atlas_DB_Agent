from __future__ import annotations

import argparse

from ojas_reconciler.db2_behavior.application.corpus import CorpusRunner
from ojas_reconciler.db2_behavior.application.gate0 import Gate0Agent
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.core.resources import packaged_contract_path

def handle(args: argparse.Namespace) -> int | None:
    if args.command not in {"run-corpus", "inventory", "inventory-dir"}:
        return None
    if args.command == "run-corpus":
        schema = args.schema or packaged_contract_path("corpus-manifest-1.0.schema.json")
        report = CorpusRunner().run(args.manifest, schema)
        payload = canonical_json_bytes(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Corpus report: {args.output}")
        else:
            print(payload.decode("utf-8"))
        return 0 if report["passed"] else 3

    agent = Gate0Agent()
    if args.command == "inventory":
        report = agent.inventory_file(args.source, args.output_dir)
        json_path = args.output_dir / f"{args.source.stem}.gate0.json"
        md_path = args.output_dir / f"{args.source.stem}.gate0.md"
        if hasattr(report, "eligibility"):
            print(f"Eligibility: {report.eligibility}")
            print(f"JSON: {json_path}")
            print(f"Markdown: {md_path}")
            return 0 if report.eligibility.value != "POC_INELIGIBLE" else 2
        script_path = args.output_dir / f"{args.source.stem}.gate0.script.json"
        print(f"Source units: {report.discovered_source_unit_count}/{report.expected_source_unit_count}")
        print(f"JSON: {script_path}")
        return 0 if report.source_unit_count_matches else 2

    report = agent.inventory_directory(args.root, args.output_dir)
    json_path = args.output_dir / "estate.gate0.json"
    print(f"Files: {report.source_file_count}")
    print(f"Procedures: {len(report.procedure_reports)}")
    print(f"Source units: {report.discovered_source_unit_count}/{report.expected_source_unit_count}")
    print(f"Coverage: {report.sample_coverage_status}")
    print(f"JSON: {json_path}")
    return 0
