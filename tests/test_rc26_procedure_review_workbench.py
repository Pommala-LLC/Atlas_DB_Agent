from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app
from ojas_reconciler.db2_behavior.commercial_ui.review_dashboard import build_review_dashboard


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _run(workspace: Path) -> Path:
    run = workspace / "runs" / "claim-review"
    _write(
        run / "extraction" / "02-parse.json",
        {
            "source_name": "claim.sql",
            "source_digest": "sha256:source",
            "ast": {
                "schema_name": "CLAIMS",
                "procedure_name": "P",
                "nodes": [
                    {
                        "node_id": "node-condition",
                        "kind": "IF_ARM",
                        "text": "IF V_FRAUD_FLAG = 'Y' THEN",
                        "source_range": {"start_line": 80, "end_line": 80},
                    },
                    {
                        "node_id": "node-effect",
                        "kind": "SET",
                        "text": "SET P_FINAL_DECISION = 'REJECTED_FRAUD'",
                        "source_range": {"start_line": 82, "end_line": 82},
                    },
                ],
            },
        },
    )
    _write(
        run / "extraction" / "03-semantic-phase2-4.json",
        {
            "findings": [],
            "effects": [
                {
                    "effect_id": "effect-final",
                    "effect_kind": "OUT_PARAMETER_ASSIGNMENT",
                    "target": "P_FINAL_DECISION",
                    "value_expression": "'REJECTED_FRAUD'",
                    "observability": "ESCAPING_EFFECT",
                    "evidence_refs": ["node-effect"],
                }
            ],
            "effect_obligations": [{"effect_ref": "effect-final", "modality": "MUST"}],
            "query_summaries": [
                {
                    "analysis_completeness": "COMPLETE",
                    "summary_kind": "SELECT_INTO_QUERY",
                    "relation_refs": ["CLAIMS.FRAUD_WATCHLIST"],
                    "clauses": [{"clause_kind": "WHERE", "expression_text": "ACTIVE_IND = 'Y'"}],
                    "joins": [],
                    "projection_expressions": ["ACTIVE_IND"],
                    "evidence_refs": ["node-condition"],
                }
            ],
            "loop_summaries": [],
        },
    )
    _write(
        run / "bdd" / "readable-bdd-document.json",
        {
            "feature": {
                "name": "CLAIMS.P readable technical candidates",
                "tags": ["@technical_candidate", "@requires_vocabulary_approval"],
                "rules": [
                    {
                        "name": "Fraud decision",
                        "scenarios": [
                            {
                                "name": "Reject when fraud applies",
                                "kind": "Scenario",
                                "analysis_status": "CONDITIONAL_TECHNICAL_CANDIDATE",
                                "proposal_kind": "BEHAVIOR",
                                "proposal_id": "proposal-fraud",
                                "source_behavior_refs": ["behavior-fraud"],
                                "source_bundle_refs": ["bundle-fraud"],
                                "tags": ["@conditional_technical_candidate"],
                                "examples": [],
                                "steps": [
                                    {"keyword": "Given", "text": "the active fraud condition holds"},
                                    {"keyword": "When", "text": "CLAIMS.P is invoked"},
                                    {"keyword": "Then", "text": 'P_FINAL_DECISION is set to "REJECTED_FRAUD"'},
                                ],
                            }
                        ],
                    }
                ],
            },
            "semantic_digest": "sha256:semantic",
        },
    )
    _write(
        run / "bdd" / "proposal-manifest.json",
        {
            "procedure": "CLAIMS.P",
            "review_required": True,
            "authority_scope": "NON_AUTHORITATIVE_PROPOSAL",
            "semantic_digest": "sha256:semantic",
            "gherkin_content_digest": "sha256:feature",
            "quality": {
                "status": "PASSED_WITH_WARNINGS",
                "parser_name": "gherkin-official",
                "parser_version": "42.0.0",
                "warning_count": 1,
            },
            "artifacts": [
                {
                    "proposal_id": "proposal-fraud",
                    "evidence_refs": ["node-condition", "node-effect"],
                    "blocker_codes": [],
                    "blocker_details": [],
                }
            ],
        },
    )
    _write(run / "bdd" / "lint-report.json", {"warning_count": 1})
    _write(run / "bdd" / "feature-validation-report.json", {"feature_count": 2})
    return run


def test_review_model_is_built_from_emitted_artifacts(tmp_path: Path) -> None:
    run = _run(tmp_path)
    review = build_review_dashboard(run)
    assert review["procedure"] == "CLAIMS.P"
    assert review["decision_rows"][0]["outcome"] == '"REJECTED_FRAUD"'
    assert review["decision_rows"][0]["source_evidence"][0]["start_line"] == 80
    assert review["effects"][0]["modality"] == "MUST"
    assert review["relations"][0]["relation"] == "CLAIMS.FRAUD_WATCHLIST"
    assert review["what_if_supported"] is False


def test_review_dashboard_matches_requested_review_surfaces(tmp_path: Path) -> None:
    _run(tmp_path)
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, role=UiRole.ADMIN)))
    response = client.get("/review/claim-review")
    assert response.status_code == 200
    for text in ("Decision Requirements", "Decision Table", "Scenarios", "Lineage", "Side Effects", "Audit Trail"):
        assert text in response.text
    assert "What‑If Mode" in response.text
    assert "Not admitted" in response.text
    assert "Source lines 80–80" in response.text
    assert "not an authoritative DMN model" in response.text


def test_root_opens_stored_procedure_analysis_and_review_remains_available(tmp_path: Path) -> None:
    _run(tmp_path)
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, role=UiRole.ADMIN)))
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/runs"
    review = client.get("/review/claim-review")
    assert review.status_code == 200
    assert "Commercial readiness overview" in client.get("/commercial").text


def test_review_api_and_path_boundary(tmp_path: Path) -> None:
    _run(tmp_path)
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, role=UiRole.ADMIN)))
    payload = client.get("/api/review/claim-review").json()
    assert payload["decision_rows"][0]["proposal_id"] == "proposal-fraud"
    assert client.get("/review/%2E%2E").status_code in {403, 404}


def test_review_javascript_contains_no_hand_written_business_ladder() -> None:
    script = Path(__file__).parents[1] / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "static" / "review.js"
    text = script.read_text(encoding="utf-8")
    assert "vals.fraud" not in text
    assert "REJECTED_FRAUD" not in text


def test_review_workbench_integrates_commercial_controls(tmp_path: Path) -> None:
    _run(tmp_path)
    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN))
    client = TestClient(app)
    response = client.get("/review/claim-review?tab=controls")
    assert response.status_code == 200
    for text in (
        "Commercial Control Center",
        "Commercial maturity",
        "Organic source custody",
        "Organic estate evidence",
        "Commercial readiness",
        "Procedure Check Matrix",
        "Authority and governance",
        "Quick Controls",
        "Recent Commercial Audit Events",
    ):
        assert text in response.text
    assert "ORGANIC VALIDATION REQUIRED" in response.text
    assert "NOT APPROVED" in response.text
    assert "No finding does not equal pass" in response.text


def test_review_api_includes_fail_closed_commercial_control_projection(tmp_path: Path) -> None:
    _run(tmp_path)
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN)))
    controls = client.get("/api/review/claim-review").json()["commercial_controls"]
    assert controls["overall_status"] == "BLOCKED"
    assert controls["custody"]["status"] == "NOT_APPROVED"
    assert controls["organic"]["status"] == "NOT_PERFORMED"
    assert "READINESS_NOT_ASSESSED" in controls["readiness"]["blockers"]
    assert controls["procedure_checks"]["status"] == "EVALUATED"


def test_review_controls_render_latest_tenant_evidence(tmp_path: Path) -> None:
    _run(tmp_path)
    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN))
    store = app.state.commercial.store
    store.put(
        category="custody",
        artifact_id="custody-1",
        payload={
            "agreement_id": "custody-1",
            "status": "APPROVED",
            "approval_evidence_mode": "VERIFIED_EXTERNAL_ENVELOPE",
            "processing_location": "CUSTOMER_ENVIRONMENT",
            "allowed_source_roots": ["C:/customer/source"],
            "derived_artifact_retention_days": 30,
            "deletion_request_sla_days": 5,
            "deletion_attestation_required": True,
            "backup_policy": "EXCLUDED_FROM_VENDOR_BACKUPS",
        },
        actor_ref="actor:admin",
        role="ADMIN",
    )
    store.put(
        category="organic-reports",
        artifact_id="pilot-1",
        payload={
            "validation_id": "pilot-1",
            "validation_level": "DISCOVERY_SAMPLE",
            "status": "DISCOVERY_COMPLETED",
            "source_count": 5,
            "semantic_completed": 4,
            "admitted_scenarios": 18,
            "blocked_scenarios": 3,
            "materially_false_confident_behaviors": 0,
            "pause_reasons": [],
            "recurring_blocker_codes": [],
        },
        actor_ref="actor:analyst",
        role="ANALYST",
    )
    store.put(
        category="readiness",
        artifact_id="readiness-1",
        payload={
            "commercial_maturity": "COMMERCIALIZATION_CANDIDATE",
            "naming_status": "PROVISIONAL_PENDING_NAMING_BASELINE",
            "blockers": ["NATIVE_WINDOWS_PYTHON_3_14"],
            "verified_gate_ids": ["SOURCE_CUSTODY"],
            "deployment_gates": [],
            "customer_boundary_gates": ["SOURCE_CUSTODY"],
        },
        actor_ref="actor:admin",
        role="ADMIN",
    )
    client = TestClient(app)
    html = client.get("/review/claim-review?tab=controls").text
    assert "custody-1" in html
    assert "VERIFIED EXTERNAL ENVELOPE" in html
    assert "DISCOVERY COMPLETED" in html
    assert "NATIVE_WINDOWS_PYTHON_3_14" in html
    assert "ARTIFACT_CREATED" in html


def test_review_quick_controls_are_role_gated_and_audited(tmp_path: Path) -> None:
    _run(tmp_path)
    viewer = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.VIEWER)))
    assert viewer.post("/review/claim-review/controls/checks", follow_redirects=False).status_code == 403

    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN))
    client = TestClient(app)
    response = client.post("/review/claim-review/controls/checks", follow_redirects=False)
    assert response.status_code == 303
    assert "?tab=controls&message=" in response.headers["location"]
    assert app.state.commercial.store.latest("procedure-checks") is not None
    assert any(event["action"] == "PROCEDURE_CHECKS_BUILT_FROM_REVIEW" for event in app.state.commercial.store.audit_events())


def test_review_javascript_opens_control_tab_without_business_logic() -> None:
    script = Path(__file__).parents[1] / "src" / "ojas_reconciler" / "db2_behavior" / "commercial_ui" / "static" / "review.js"
    text = script.read_text(encoding="utf-8")
    assert "data-open-controls" in text
    assert "activateTab('controls')" in text
    assert "REJECTED_FRAUD" not in text
