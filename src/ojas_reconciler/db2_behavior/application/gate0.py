from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.parsing.inventory import InventoryAnalyzer, write_markdown, write_report
from ojas_reconciler.db2_behavior.parsing.inventory_models import Db2ScriptInventoryReport, EstateInventoryReport, ProcedureInventory


class Gate0Agent:
    """Orchestrates the admitted zero-build inventory workflow."""

    def __init__(self, analyzer: InventoryAnalyzer | None = None) -> None:
        self.analyzer = analyzer or InventoryAnalyzer()

    def inventory_file(self, source: Path, output_dir: Path) -> ProcedureInventory | Db2ScriptInventoryReport:
        script = self.analyzer.analyze_script_path(source)
        output_dir.mkdir(parents=True, exist_ok=True)
        if script.discovered_source_unit_count == 1 and script.procedure_reports:
            report = script.procedure_reports[0]
            write_report(report, output_dir / f"{source.stem}.gate0.json")
            write_markdown(report, output_dir / f"{source.stem}.gate0.md")
            return report
        write_report(script, output_dir / f"{source.stem}.gate0.script.json")
        for report in script.procedure_reports:
            index = report.source.source_unit_index or 0
            write_report(report, output_dir / f"{source.stem}.unit-{index:03d}.gate0.json")
            write_markdown(report, output_dir / f"{source.stem}.unit-{index:03d}.gate0.md")
        return script

    def inventory_directory(self, root: Path, output_dir: Path) -> EstateInventoryReport:
        report = self.analyzer.analyze_directory(root)
        output_dir.mkdir(parents=True, exist_ok=True)
        write_report(report, output_dir / "estate.gate0.json")
        return report
