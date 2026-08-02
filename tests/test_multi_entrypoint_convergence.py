from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "db2_multi_procedure.db2"


def test_atlas_analyze_fans_out_all_routines(tmp_path: Path) -> None:
    output = tmp_path / "atlas"
    result = subprocess.run([
        sys.executable, "-m", "atlas", "analyze", str(SOURCE),
        "--dialect", "DB2", "--output", str(output),
    ], cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["routine_refs"] == ["APP.VALIDATE_PAYOUT_REQUEST", "APP.SETTLE_PAYOUT_REQUEST"]
    assert len(list((output / "routines").glob("*/routine-ir.json"))) == 2


def test_run_end_to_end_fans_out_all_routines(tmp_path: Path) -> None:
    output = tmp_path / "e2e"
    result = subprocess.run([
        sys.executable, "-m", "ojas_reconciler.db2_behavior", "run-end-to-end",
        str(SOURCE), "--dialect", "DB2_SQL_PL", "--output-dir", str(output),
    ], cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode in {0, 8}, result.stderr
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "atlas-multi-unit-e2e-run-1.0"
    assert manifest["routine_count"] == 2
    assert [item["routine_ref"] for item in manifest["routines"]] == [
        "APP.VALIDATE_PAYOUT_REQUEST", "APP.SETTLE_PAYOUT_REQUEST",
    ]


def test_run_end_to_end_requires_explicit_db2_dialect(tmp_path: Path) -> None:
    missing = subprocess.run([
        sys.executable, "-m", "ojas_reconciler.db2_behavior", "run-end-to-end",
        str(SOURCE), "--output-dir", str(tmp_path / "missing"),
    ], cwd=ROOT, capture_output=True, text=True, check=False)
    assert missing.returncode != 0
    assert "EXPLICIT_DIALECT_REQUIRED" in (missing.stderr + missing.stdout)
    mismatch = subprocess.run([
        sys.executable, "-m", "ojas_reconciler.db2_behavior", "run-end-to-end",
        str(SOURCE), "--dialect", "POSTGRESQL_PLPGSQL", "--output-dir", str(tmp_path / "mismatch"),
    ], cwd=ROOT, capture_output=True, text=True, check=False)
    assert mismatch.returncode != 0
    assert "DIALECT_PROVIDER_MISMATCH" in (mismatch.stderr + mismatch.stdout)
