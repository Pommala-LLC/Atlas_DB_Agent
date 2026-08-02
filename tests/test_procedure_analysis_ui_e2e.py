from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from atlas.dialects.db2.clp import Db2ClpScriptSegmenter
from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app


DB2_MULTI = """--#SET TERMINATOR @
CREATE PROCEDURE APP.P_ONE (IN P_ID INT)
LANGUAGE SQL
BEGIN
  UPDATE APP.T SET STATUS = 'A' WHERE ID = P_ID;
END@

CREATE PROCEDURE APP.P_TWO (IN P_ID INT)
LANGUAGE SQL
BEGIN
  IF P_ID > 0 THEN
    INSERT INTO APP.LOG(ID) VALUES (P_ID);
  END IF;
END@
"""

DB2_FIRST = """--#SET TERMINATOR @
CREATE PROCEDURE APP.FILE_ONE (IN P_ID INT)
LANGUAGE SQL
BEGIN
  DELETE FROM APP.T WHERE ID = P_ID;
END@
"""

DB2_SECOND = """--#SET TERMINATOR @
CREATE PROCEDURE APP.FILE_TWO (IN P_ID INT)
LANGUAGE SQL
BEGIN
  INSERT INTO APP.T(ID) VALUES (P_ID);
END@
"""


def _client(tmp_path: Path, role: UiRole = UiRole.ADMIN, **settings) -> TestClient:
    return TestClient(create_app(CommercialUiSettings(
        workspace=tmp_path,
        tenant_ref="tenant:test",
        actor_ref="actor:e2e",
        role=role,
        **settings,
    )))


def _analysis_id(location: str) -> str:
    return location.split("/runs/", 1)[1].split("?", 1)[0]


def _analysis_payload(tmp_path: Path, analysis_id: str) -> dict:
    path = tmp_path / "tenants" / "tenant-test" / "procedure-analyses" / analysis_id / "analysis.json"
    return json.loads(path.read_text(encoding="utf-8"))




def test_root_opens_png_style_procedure_analysis_not_legacy_review(tmp_path: Path) -> None:
    client = _client(tmp_path)
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 307
    assert root.headers["location"] == "/runs"
    page = client.get("/runs")
    assert page.status_code == 200
    assert "procedure-app-topbar" in page.text
    assert "Stored Procedure Analysis" in page.text
    assert "Procedure review workbench" not in page.text
    assert 'class="sidebar"' not in page.text


def test_runs_page_is_the_lean_existing_ui_entry_point(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/runs")
    assert response.status_code == 200
    for value in ("IBM Db2", "Oracle Database", "Microsoft SQL Server", "PostgreSQL", "MySQL"):
        assert value in response.text
    assert 'action="/runs/analyze"' in response.text
    assert 'name="database_type"' in response.text
    assert 'name="sql_text"' in response.text
    assert 'name="files"' in response.text
    assert 'multiple accept=".sql,.db2,.ddl,.txt"' in response.text
    assert "does not infer or switch the dialect" in response.text
    assert "Native validation" not in response.text
    assert "connection profile" not in response.text.lower()
    assert "DB Agent" not in response.text


def test_paste_multi_procedure_e2e_and_loopback_origin_alias(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "paste", "sql_text": DB2_MULTI},
        headers={"host": "127.0.0.1:8765", "origin": "http://localhost:8765"},
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    analysis_id = _analysis_id(submitted.headers["location"])

    page = client.get(submitted.headers["location"])
    assert page.status_code == 200
    assert "APP.P_ONE" in page.text
    assert "APP.P_TWO" in page.text
    assert "IBM Db2" in page.text
    assert "selected explicitly" in page.text

    payload = _analysis_payload(tmp_path, analysis_id)
    assert payload["schema_version"] == "atlas-procedure-analysis-1.0"
    assert payload["database_type"] == "DB2"
    assert payload["declared_dialect"] == "DB2_SQL_PL"
    assert payload["dialect_selection_mode"] == "USER_EXPLICIT"
    assert payload["dialect_locked"] is True
    assert payload["counts"] == {
        "blocked": 0,
        "complete": 2,
        "file_errors": 0,
        "findings": 0,
        "partial": 0,
        "routines": 2,
        "sources": 1,
    }
    assert [item["routine_ref"] for item in payload["routines"]] == ["APP.P_ONE", "APP.P_TWO"]
    assert "native_validation" not in payload
    audit = (tmp_path / "tenants" / "tenant-test" / "audit" / "events.ndjson").read_text(encoding="utf-8")
    assert "STORED_PROCEDURES_ANALYZED" in audit


def test_multiple_uploaded_files_e2e(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "upload", "sql_text": ""},
        files=[
            ("files", ("first.sql", DB2_FIRST.encode("utf-8"), "text/sql")),
            ("files", ("second.sql", DB2_SECOND.encode("utf-8"), "text/sql")),
        ],
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    payload = _analysis_payload(tmp_path, _analysis_id(submitted.headers["location"]))
    assert payload["counts"]["sources"] == 2
    assert payload["counts"]["routines"] == 2
    assert [item["source_name"] for item in payload["sources"]] == ["first.sql", "second.sql"]
    assert [item["routine_ref"] for item in payload["routines"]] == ["APP.FILE_ONE", "APP.FILE_TWO"]


def test_selected_database_is_never_changed_from_sql_text(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "POSTGRESQL", "input_mode": "paste", "sql_text": DB2_FIRST},
        follow_redirects=False,
    )
    payload = _analysis_payload(tmp_path, _analysis_id(submitted.headers["location"]))
    assert payload["database_type"] == "POSTGRESQL"
    assert payload["declared_dialect"] == "POSTGRESQL_PLPGSQL"
    assert payload["counts"]["routines"] == 0
    assert payload["counts"]["file_errors"] == 1


def test_cross_origin_write_is_rejected_but_explicit_allowed_origin_works(tmp_path: Path) -> None:
    client = _client(tmp_path)
    rejected = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "paste", "sql_text": DB2_FIRST},
        headers={"host": "127.0.0.1:8765", "origin": "https://evil.example"},
    )
    assert rejected.status_code == 403
    assert "Cross-origin commercial write rejected" in rejected.json()["detail"]

    allowed = _client(tmp_path / "allowed", allowed_origins=("https://trusted.example",))
    accepted = allowed.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "paste", "sql_text": DB2_FIRST},
        headers={"origin": "https://trusted.example"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303


def test_rejects_unsupported_upload_type_and_viewer_write(tmp_path: Path) -> None:
    client = _client(tmp_path)
    rejected = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "upload"},
        files=[("files", ("procedure.bin", b"CREATE PROCEDURE X() BEGIN END", "application/octet-stream"))],
        follow_redirects=False,
    )
    assert rejected.status_code == 303
    assert rejected.headers["location"].startswith("/runs?error=")
    assert "Unsupported+file+type" in rejected.headers["location"]

    viewer = _client(tmp_path / "viewer", UiRole.VIEWER)
    denied = viewer.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "paste", "sql_text": DB2_FIRST},
    )
    assert denied.status_code == 403


def test_db2_segmenter_accepts_attached_custom_terminator_for_multiple_procedures() -> None:
    result = Db2ClpScriptSegmenter().segment_text(DB2_MULTI, source_name="multi.sql")
    assert result.expected_source_unit_count == 2
    assert result.discovered_source_unit_count == 2
    assert [unit.declared_name for unit in result.source_units] == ["APP.P_ONE", "APP.P_TWO"]


def test_root_and_runs_use_png_top_navigation_not_commercial_sidebar(tmp_path: Path) -> None:
    client = _client(tmp_path)
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 307
    assert root.headers["location"] == "/runs"
    page = client.get("/runs")
    assert page.status_code == 200
    assert 'class="procedure-app-topbar"' in page.text
    assert '>ATLAS<' in page.text
    assert 'class="sidebar"' not in page.text
    assert "Commercial overview" not in page.text
    assert "Procedure review workbench" not in page.text


def test_png_contract_layout_is_visible_before_analysis(tmp_path: Path) -> None:
    page = _client(tmp_path).get("/runs")
    assert page.status_code == 200
    assert 'class="analysis-summary-strip"' in page.text
    assert 'class="analysis-intake-strip"' in page.text
    assert 'class="analysis-workbench"' in page.text
    assert 'id="procedure-routine-list"' in page.text
    assert 'id="procedure-source"' in page.text
    assert 'data-tab="decision"' in page.text
    assert 'data-tab="scenarios"' in page.text
    assert 'data-tab="lineage"' in page.text
    assert 'data-tab="audit"' in page.text
    assert "No analysis selected yet" not in page.text


def test_any_loopback_ui_origin_can_post_to_loopback_console(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "sql_text": DB2_FIRST},
        headers={"host": "127.0.0.1:8765", "origin": "http://localhost:49152"},
        follow_redirects=False,
    )
    assert submitted.status_code == 303


def test_paste_and_upload_can_be_analyzed_in_one_submission(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "sql_text": DB2_FIRST},
        files=[("files", ("second.sql", DB2_SECOND.encode("utf-8"), "text/sql"))],
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    payload = _analysis_payload(tmp_path, _analysis_id(submitted.headers["location"]))
    assert payload["counts"]["sources"] == 2
    assert payload["counts"]["routines"] == 2


def test_browser_same_origin_fetch_metadata_prevents_false_cross_origin_rejection(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "sql_text": DB2_FIRST},
        headers={
            "host": "127.0.0.1:8765",
            "origin": "http://local-proxy.invalid:49152",
            "sec-fetch-site": "same-origin",
        },
        follow_redirects=False,
    )
    assert submitted.status_code == 303


def test_cross_site_fetch_metadata_remains_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    rejected = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "sql_text": DB2_FIRST},
        headers={
            "host": "127.0.0.1:8765",
            "origin": "https://evil.example",
            "sec-fetch-site": "cross-site",
        },
    )
    assert rejected.status_code == 403


def test_nested_scalar_case_fixture_is_complete_in_ui_path(tmp_path: Path) -> None:
    source = (Path(__file__).parent / "fixtures" / "reconcile_settlement_batch_nested_case.sql").read_text(encoding="utf-8")
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "input_mode": "paste", "sql_text": source},
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    payload = _analysis_payload(tmp_path, _analysis_id(submitted.headers["location"]))
    assert payload["counts"]["complete"] == 1
    assert payload["counts"]["partial"] == 0
    assert payload["counts"]["findings"] == 0
    routine = payload["routines"][0]
    assert routine["routine_ref"] == "CLAIMS.RECONCILE_SETTLEMENT_BATCH"
    assert routine["status"] == "COMPLETE"
    assert routine["opaque_node_count"] == 0
    assert routine["opaque_coverage_percent"] == 0.0
    assert routine["end_line"] == len(source.splitlines())


def test_stored_procedure_source_pane_is_bounded_and_scrollable() -> None:
    css_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ojas_reconciler"
        / "db2_behavior"
        / "commercial_ui"
        / "static"
        / "procedure_analysis.css"
    )
    css = css_path.read_text(encoding="utf-8")
    assert "grid-template-rows:450px 210px" in css
    assert "height:660px;min-height:0;max-height:660px;overflow:hidden" in css
    assert ".source-column{grid-column:2/4;grid-row:1;min-width:0;min-height:0;height:450px;overflow:hidden}" in css
    assert ".source-editor{height:100%;min-height:0;max-height:100%;overflow:auto" in css
    assert "scrollbar-gutter:stable both-edges" in css
    assert ".source-code{white-space:pre;min-width:max-content" in css


def test_native_db2_extensions_are_accepted(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/runs/analyze",
        data={"database_type": "DB2", "sql_text": ""},
        files=[
            ("files", ("first.db2", DB2_FIRST.encode("utf-8"), "text/plain")),
            ("files", ("second.DB2", DB2_SECOND.encode("utf-8"), "text/plain")),
        ],
        follow_redirects=False,
    )
    assert submitted.status_code in {200, 303}
    analysis_id = _analysis_id(submitted.headers.get("location", submitted.url.path))
    payload = _analysis_payload(tmp_path, analysis_id)
    assert payload["counts"]["routines"] == 2
    assert [item["source_name"] for item in payload["sources"]] == ["first.db2", "second.DB2"]
