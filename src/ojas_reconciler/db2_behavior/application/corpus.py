from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.parsing.models import ProcedureParseResult
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser


class CorpusRunner:
    def __init__(self, parser: LarkSqlPlSpikeParser | None = None) -> None:
        self.parser = parser or LarkSqlPlSpikeParser()

    def run(self, manifest_path: Path, schema_path: Path) -> dict[str, Any]:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(manifest)
        root = manifest_path.parent
        case_results: list[dict[str, Any]] = []
        by_construct: dict[str, Counter[str]] = defaultdict(Counter)
        for case in sorted(manifest["cases"], key=lambda item: item["case_id"]):
            source_path = (root / case["source_path"]).resolve()
            result = self.parser.parse_file(source_path)
            actual_findings = {finding.code.value for finding in result.findings}
            expected_findings = set(case.get("expected_findings", []))
            forbidden_findings = set(case.get("forbidden_findings", []))
            passed = (
                result.outcome.value == case["expected_result"]
                and expected_findings.issubset(actual_findings)
                and not forbidden_findings.intersection(actual_findings)
            )
            entry = {
                "case_id": case["case_id"],
                "source_path": source_path.as_posix(),
                "expected_result": case["expected_result"],
                "actual_result": result.outcome.value,
                "actual_findings": sorted(actual_findings),
                "passed": passed,
            }
            case_results.append(entry)
            for tag in sorted(case["construct_tags"]):
                by_construct[tag]["total"] += 1
                by_construct[tag]["passed" if passed else "failed"] += 1
        return {
            "corpus_version": manifest["corpus_version"],
            "case_results": case_results,
            "by_construct": {
                tag: dict(counts)
                for tag, counts in sorted(by_construct.items())
            },
            "passed": all(entry["passed"] for entry in case_results),
        }
