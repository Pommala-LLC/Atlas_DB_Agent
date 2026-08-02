from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "db2_multi_procedure.db2"


def test_ui_cli_and_pipeline_share_source_unit_identity(tmp_path: Path) -> None:
    cli_dir = tmp_path / "cli"
    _run([sys.executable, "-m", "atlas", "analyze", str(SOURCE), "--dialect", "DB2", "--output", str(cli_dir)])
    e2e_dir = tmp_path / "e2e"
    _run([sys.executable, "-m", "ojas_reconciler.db2_behavior", "run-end-to-end",
          str(SOURCE), "--dialect", "DB2_SQL_PL", "--output-dir", str(e2e_dir)], allowed={0, 8})
    workspace = tmp_path / "ui"
    client = TestClient(create_app(CommercialUiSettings(
        workspace=workspace, tenant_ref="tenant:test", actor_ref="actor:test", role=UiRole.ADMIN,
    )))
    response = client.post("/runs/analyze", data={"database_type": "DB2", "sql_text": ""},
        files=[("files", (SOURCE.name, SOURCE.read_bytes(), "text/plain"))], follow_redirects=False)
    assert response.status_code == 303
    analysis_id = response.headers["location"].split("/runs/", 1)[1].split("?", 1)[0]
    ui_path = workspace / "tenants" / "tenant-test" / "procedure-analyses" / analysis_id
    ui_unit = next((ui_path / "analysis").glob("*-source-unit-analysis.json"))
    payloads = [_load(cli_dir / "source-unit-analysis.json"), _load(e2e_dir / "source-unit-analysis.json"), _load(ui_unit)]
    assert len({item["content_digest"] for item in payloads}) == 1
    routine_digests = [[routine["routine_ir"]["content_digest"] for routine in item["routines"]] for item in payloads]
    assert routine_digests[0] == routine_digests[1] == routine_digests[2]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run(command: list[str], allowed: set[int] = {0}) -> None:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode in allowed, result.stderr
