from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "db2_multi_procedure.db2"


def test_routine_eligibility_is_separate_from_composition_completeness(tmp_path: Path) -> None:
    client = TestClient(create_app(CommercialUiSettings(
        workspace=tmp_path, tenant_ref="tenant:test", actor_ref="actor:test", role=UiRole.ADMIN,
    )))
    response = client.post("/runs/analyze", data={"database_type": "DB2", "sql_text": ""},
        files=[("files", (SOURCE.name, SOURCE.read_bytes(), "text/plain"))], follow_redirects=False)
    assert response.status_code == 303
    analysis_id = response.headers["location"].split("/runs/", 1)[1].split("?", 1)[0]
    manifest = tmp_path / "tenants" / "tenant-test" / "procedure-analyses" / analysis_id / "analysis.json"
    routines = json.loads(manifest.read_text(encoding="utf-8"))["routines"]
    first, second = routines
    assert first["analysis_eligibility"] == "POC_FULLY_ELIGIBLE"
    assert first["composition_completeness"] == "NOT_APPLICABLE"
    assert second["analysis_eligibility"] == "POC_FULLY_ELIGIBLE"
    assert second["composition_completeness"] == "UNRESOLVED"
    assert "UNRESOLVED_CALL_EFFECT_BOUNDARY" in {item["code"] for item in second["findings"]}
