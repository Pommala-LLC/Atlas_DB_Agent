from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ojas_reconciler.db2_behavior.commercial.models import (
    CheckState,
    CompositionKind,
    CompositionResolution,
    CompositionTransactionRelationship,
    ConditionMapping,
    OrganicCaseOutcome,
    OrganicPauseDisposition,
    OrganicValidationLevel,
    OrganicValidationReport,
    OrganicValidationStatus,
    ParameterMapping,
    PauseCause,
    PauseDispositionDecision,
    PauseResponsibility,
    ProcedureCompositionContract,
)
from ojas_reconciler.db2_behavior.commercial.workflows import (
    CommercialOperationsService,
    CommercialWorkflowError,
    CompositionContractService,
    ImmutableArtifactStore,
    OrganicPauseDispositionService,
    ProcedureCheckService,
    ProcedureKnowledgeGraphService, RelationalFixturePlanningService, CommercialDataLifecycleService,
)
from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.interfaces.argparse_builder import build_parser


def _organic_report(*, pause_reasons: tuple[str, ...] = ("THREE_OF_FIRST_FIVE_FAILED_BEFORE_SEMANTIC_ANALYSIS",)) -> OrganicValidationReport:
    outcome = OrganicCaseOutcome(
        case_id="case-1",
        source_path="C:/customer/source.sql",
        source_digest_before="sha256:source",
        source_digest_after="sha256:source",
        source_unmodified=True,
        parse_outcome="REFUSES_UNEXPECTED",
        parse_findings=("UNSUPPORTED_SYNTAX",),
        semantic_status="BLOCKED",
        admitted_scenarios=0,
        blocked_scenarios=0,
        blocker_codes=("UNSUPPORTED_SYNTAX",),
        materially_false_confident_behaviors=0,
        owner_rule_confirmation_complete=False,
    )
    payload = {
        "schema_version": "organic-validation-report-1.0",
        "validation_id": "validation-1",
        "validation_level": OrganicValidationLevel.DISCOVERY_SAMPLE,
        "status": OrganicValidationStatus.PILOT_PAUSED_PRODUCT_GAP if pause_reasons else OrganicValidationStatus.DISCOVERY_COMPLETED,
        "customer_ref": "customer:test",
        "estate_ref": "estate:test",
        "custody_agreement_id": "custody-1",
        "source_count": 1,
        "unique_source_digests": 1,
        "parsed_complete": 0,
        "parsed_partial": 0,
        "refused_expected": 0,
        "refused_unexpected": 1,
        "semantic_completed": 0,
        "semantic_blocked": 1,
        "admitted_scenarios": 0,
        "blocked_scenarios": 0,
        "source_modification_count": 0,
        "materially_false_confident_behaviors": 0,
        "owner_rule_confirmations_complete": 0,
        "reviewed_procedure_count": 0,
        "total_review_effort_minutes": 0,
        "procedures_with_admitted_scenarios": 0,
        "procedures_with_blocked_scenarios": 0,
        "parsed_complete_rate": 0.0,
        "semantic_completion_rate": 0.0,
        "classification_counts": {},
        "recurring_blocker_codes": ("UNSUPPORTED_SYNTAX",),
        "pause_reasons": pause_reasons,
        "case_outcomes": (outcome,),
        "commercial_claim_eligible": False,
    }
    return OrganicValidationReport(**payload, content_digest=canonical_digest(payload))


def _composition() -> ProcedureCompositionContract:
    payload = {
        "schema_version": "procedure-composition-contract-1.0",
        "contract_id": "contract-1",
        "composition_kind": CompositionKind.EXTERNAL_SEQUENCE,
        "upstream_procedure_ref": "CLAIMS.VALIDATE",
        "downstream_procedure_ref": "CLAIMS.RULES",
        "upstream_semantic_digest": "sha256:upstream",
        "downstream_semantic_digest": "sha256:downstream",
        "orchestration_definition_digest": None,
        "transaction_contract_digest": None,
        "invocation_site_ref": "app:claim-flow",
        "parameter_mappings": (ParameterMapping(upstream_ref="P_ID", downstream_ref="P_ID", evidence_refs=("source:app",)),),
        "condition_mappings": (ConditionMapping(exported_postcondition_ref="VALID", imported_precondition_ref="VALID", entailment_status="PROVEN", evidence_refs=("review:1",)),),
        "sqlstate_mappings": {},
        "output_status_mappings": {},
        "transaction_relationship": CompositionTransactionRelationship.CALLER_CONTROLLED,
        "failure_disposition": "Do not invoke downstream on failed validation.",
        "authority_ref": "authority:architecture",
        "evidence_refs": ("orchestration:1",),
        "effective_from": "2026-07-29T00:00:00Z",
        "expires_at": None,
    }
    return ProcedureCompositionContract(**payload, content_digest=canonical_digest(payload))


def test_immutable_artifact_store_chains_audit_events(tmp_path: Path) -> None:
    store = ImmutableArtifactStore(tmp_path, tenant_ref="tenant:test")
    first = store.put(category="reports", artifact_id="one", payload={"a": 1}, actor_ref="actor:1", role="ADMIN")
    second = store.put(category="reports", artifact_id="two", payload={"b": 2}, actor_ref="actor:1", role="ADMIN")
    assert first.is_file() and second.is_file()
    events = store.audit_events()
    assert len(events) == 2
    assert events[1]["previous_event_digest"] == events[0]["event_digest"]


def test_pause_disposition_binds_report_and_source_digests(tmp_path: Path) -> None:
    report = _organic_report()
    path = tmp_path / "organic-report.json"
    path.write_bytes(canonical_json_bytes(report) + b"\n")
    disposition = OrganicPauseDispositionService().build(
        report_path=path,
        decision=PauseDispositionDecision.PAUSE_FOR_PRODUCT_FIX,
        cause=PauseCause.DIALECT_GAP,
        responsibility=PauseResponsibility.PRODUCT,
        rationale="Three discovery procedures use the same unsupported handler syntax.",
        remediation_actions=("Implement and regression-test the construct.",),
        owner_ref="actor:product",
        approved_by_ref=None,
        decided_at="2026-07-29T00:00:00Z",
    )
    assert disposition.validation_report_digest == report.content_digest
    assert disposition.source_digests == ("sha256:source",)


def test_pause_disposition_rejects_unpaused_report(tmp_path: Path) -> None:
    report = _organic_report(pause_reasons=())
    path = tmp_path / "organic-report.json"
    path.write_bytes(canonical_json_bytes(report) + b"\n")
    with pytest.raises(CommercialWorkflowError, match="without a pause"):
        OrganicPauseDispositionService().build(
            report_path=path,
            decision=PauseDispositionDecision.PAUSE_FOR_PRODUCT_FIX,
            cause=PauseCause.PRODUCT_DEFECT,
            responsibility=PauseResponsibility.PRODUCT,
            rationale="No pause exists.",
            remediation_actions=("None",),
            owner_ref="actor:product",
            approved_by_ref=None,
            decided_at="2026-07-29T00:00:00Z",
        )


def test_continue_pilot_requires_approving_authority() -> None:
    with pytest.raises(ValidationError, match="approving authority"):
        OrganicPauseDisposition(
            schema_version="organic-pause-disposition-1.0",
            disposition_id="d1",
            validation_report_ref="report.json",
            validation_report_digest="sha256:report",
            validation_id="v1",
            source_digests=("sha256:source",),
            pause_reasons=("RECURRING_MATERIAL_BLOCKER",),
            dominant_cause=PauseCause.CATALOG_INPUT_GAP,
            responsibility=PauseResponsibility.CUSTOMER,
            decision=PauseDispositionDecision.CONTINUE_PILOT,
            rationale="Continue after customer input.",
            remediation_actions=("Supply catalog",),
            owner_ref="actor:reviewer",
            decided_at="2026-07-29T00:00:00Z",
            content_digest="sha256:any",
        )


def test_composition_stale_digest_is_explicit() -> None:
    assessment = CompositionContractService().assess(
        _composition(), upstream_semantic_digest="sha256:changed", downstream_semantic_digest="sha256:downstream"
    )
    assert assessment.resolution is CompositionResolution.STALE_CONTRACT_DIGEST
    assert "UPSTREAM_SEMANTIC_DIGEST_STALE" in assessment.blockers


def test_procedure_check_report_never_treats_no_tenant_finding_as_pass(tmp_path: Path) -> None:
    (tmp_path / "02-parse.json").write_text(json.dumps({"outcome": "PARSES_COMPLETE", "findings": []}), encoding="utf-8")
    (tmp_path / "03-semantic.json").write_text(json.dumps({"procedure_ref": "CLAIMS.P", "findings": []}), encoding="utf-8")
    (tmp_path / "04-scenario-specs.json").write_text(json.dumps({"procedure_ref": "CLAIMS.P", "scenario_specs": [], "compilation_results": []}), encoding="utf-8")
    report = ProcedureCheckService().build(tmp_path)
    tenant = next(item for item in report.checks if item.check_id == "TENANT_ISOLATION")
    assert tenant.state is CheckState.INCONCLUSIVE
    assert report.counts_by_state["PASS"] >= 1


def test_knowledge_graph_keeps_unresolved_boundary_visible(tmp_path: Path) -> None:
    (tmp_path / "03-semantic.json").write_text(
        json.dumps({"procedure_ref": "CLAIMS.P", "findings": [{"code": "DYNAMIC_RELATION_UNRESOLVED"}], "effects": [{"relation_ref": "CLAIMS.CLAIM"}]}),
        encoding="utf-8",
    )
    graph = ProcedureKnowledgeGraphService().build(tmp_path)
    assert "DYNAMIC_RELATION_UNRESOLVED" in graph.unresolved_boundaries
    assert any(node.node_type == "RELATION" for node in graph.nodes)


def test_support_bundle_excludes_source_by_default(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "procedure.sql").write_text("VALUES 1", encoding="utf-8")
    (run / "report.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "support.zip"
    CommercialOperationsService().build_support_bundle(run_dir=run, output=output)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "artifacts/report.json" in names
    assert "artifacts/procedure.sql" not in names


def test_sbom_generation_has_components(tmp_path: Path) -> None:
    path = CommercialOperationsService().generate_sbom(tmp_path / "sbom.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["components"]


def test_ui_dashboard_and_health_are_available(tmp_path: Path) -> None:
    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN))
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "UP"
    response = client.get("/commercial")
    assert response.status_code == 200
    assert "Organic validation remains the gate" in response.text


def test_ui_role_gates_write_actions(tmp_path: Path) -> None:
    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.VIEWER))
    client = TestClient(app)
    response = client.post("/operations/sbom", follow_redirects=False)
    assert response.status_code == 403


def test_ui_exports_new_commercial_templates(tmp_path: Path) -> None:
    create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test"))
    names = {path.name for path in (tmp_path / "templates").iterdir()}
    assert "procedure-composition-contract-template.json" in names
    assert "organic-pause-disposition-template.json" in names
    assert "naming-compatibility-policy-template.json" in names


def test_cli_registers_commercial_console_and_workflows() -> None:
    parser = build_parser()
    commands = {
        "commercial-serve": ["commercial-serve"],
        "commercial-build-procedure-checks": ["commercial-build-procedure-checks", "run", "--output", "out.json"],
        "commercial-build-knowledge-graph": ["commercial-build-knowledge-graph", "run", "--output", "out.json"],
        "commercial-generate-sbom": ["commercial-generate-sbom", "--output", "sbom.json"],
    }
    for command, argv in commands.items():
        assert parser.parse_args(argv).command == command


def test_all_commercial_console_navigation_routes_render(tmp_path: Path) -> None:
    app = create_app(CommercialUiSettings(workspace=tmp_path, tenant_ref="tenant:test", role=UiRole.ADMIN))
    client = TestClient(app)
    for path in (
        "/", "/review", "/commercial", "/capabilities", "/custody", "/organic", "/reviews", "/dispositions",
        "/runs", "/checks", "/authority", "/catalog", "/composition", "/baseline",
        "/runtime", "/graph", "/fixtures", "/readiness", "/operations", "/support", "/artifacts", "/audit",
    ):
        response = client.get(path)
        assert response.status_code == 200, (path, response.text)


def test_relational_fixture_planner_orders_parent_before_child_and_emits_no_sql(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.type_system.models import (
        CanonicalSqlType, ColumnDefinition, ForeignKeyDefinition, RelationDefinition,
        ResolutionCompleteness, SqlTypeFamily, TypeResolutionStatus,
    )
    from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
    sql_type = CanonicalSqlType(
        family=SqlTypeFamily.BIG_INTEGER, database_type="BIGINT", nullable=False,
        resolution_status=TypeResolutionStatus.CATALOG_RESOLVED, completeness=ResolutionCompleteness.COMPLETE,
        source_refs=("catalog:test",),
    )
    parent_payload = {
        "schema_name": "CUSTOMER", "relation_name": "CUSTOMER",
        "columns": (ColumnDefinition(relation_name="CUSTOMER", column_name="CUSTOMER_ID", sql_type=sql_type, nullable=False, source_refs=("catalog:test",)),),
        "primary_key": ("CUSTOMER_ID",), "provider_ref": "catalog:test",
    }
    parent_draft = RelationDefinition(**parent_payload, content_digest="sha256:draft")
    parent_payload = parent_draft.model_dump(mode="python", exclude={"content_digest"})
    parent = RelationDefinition(**parent_payload, content_digest=canonical_digest(parent_payload))
    child_payload = {
        "schema_name": "CLAIMS", "relation_name": "CLAIM",
        "columns": (ColumnDefinition(relation_name="CLAIM", column_name="CUSTOMER_ID", sql_type=sql_type, nullable=False, source_refs=("catalog:test",)),),
        "foreign_keys": (ForeignKeyDefinition(local_columns=("CUSTOMER_ID",), referenced_schema="CUSTOMER", referenced_relation="CUSTOMER", referenced_columns=("CUSTOMER_ID",)),),
        "provider_ref": "catalog:test",
    }
    child_draft = RelationDefinition(**child_payload, content_digest="sha256:draft")
    child_payload = child_draft.model_dump(mode="python", exclude={"content_digest"})
    child = RelationDefinition(**child_payload, content_digest=canonical_digest(child_payload))
    parent_path=tmp_path/"parent.json"; child_path=tmp_path/"child.json"
    parent_path.write_bytes(canonical_json_bytes(parent)+b"\n"); child_path.write_bytes(canonical_json_bytes(child)+b"\n")
    plan = RelationalFixturePlanningService().build(
        procedure_ref="CLAIMS.PROCESS", relation_refs=("CLAIMS.CLAIM", "CUSTOMER.CUSTOMER"), catalog_paths=(parent_path, child_path),
    )
    assert [item.relation_ref for item in plan.relation_requirements] == ["CUSTOMER.CUSTOMER", "CLAIMS.CLAIM"]
    assert plan.generated_sql == ()


def test_artifact_backup_excludes_run_workspace_and_deletion_is_attested(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.commercial.models import CommercialDeletionRequest, DeletionScope
    store = ImmutableArtifactStore(tmp_path, tenant_ref="tenant:test")
    artifact = store.put(category="reports", artifact_id="delete-me", payload={"value": 1}, actor_ref="actor:creator", role="ADMIN")
    run_source = store.tenant_root / "runs" / "one" / "procedure.sql"
    run_source.parent.mkdir(parents=True, exist_ok=True); run_source.write_text("VALUES 1", encoding="utf-8")
    backup = CommercialDataLifecycleService().backup_tenant_artifacts(store=store, output=tmp_path/"backup.zip")
    with zipfile.ZipFile(backup) as archive:
        names=set(archive.namelist())
    assert not any(name.endswith("procedure.sql") for name in names)
    request_payload={
        "schema_version":"commercial-deletion-request-1.0", "request_id":"delete-1",
        "tenant_ref":"tenant:test", "scope":DeletionScope.DERIVED_ARTIFACTS,
        "target_artifact_refs":(artifact.relative_to(store.tenant_root).as_posix(),),
        "custody_agreement_ref":None, "requested_by_ref":"actor:requester",
        "approved_by_ref":"actor:approver", "requested_at":"2026-07-28T00:00:00Z",
        "execute_after":"2026-07-29T00:00:00Z", "reason":"Customer deletion request",
    }
    request=CommercialDeletionRequest(**request_payload,content_digest=canonical_digest(request_payload))
    attestation=CommercialDataLifecycleService().execute_deletion(
        store=store,request=request,executed_by_ref="actor:executor",executed_role="ADMIN",as_of="2026-07-29T01:00:00Z"
    )
    assert not artifact.exists()
    assert len(attestation.deleted_artifacts)==1
    assert store.audit_path.exists()


def test_procedure_check_service_reads_generated_extraction_layout(tmp_path: Path) -> None:
    extraction = tmp_path / "extraction"
    bdd = tmp_path / "bdd"
    extraction.mkdir()
    bdd.mkdir()
    (extraction / "02-parse.json").write_text(
        json.dumps({"outcome": "PARSES_COMPLETE", "source_digest": "sha256:source", "findings": []}),
        encoding="utf-8",
    )
    (extraction / "03-semantic-phase2-4.json").write_text(
        json.dumps({"findings": [], "effects": []}), encoding="utf-8"
    )
    (extraction / "04-scenario-specs.json").write_text(
        json.dumps({"scenario_specs": [], "compilation_results": []}), encoding="utf-8"
    )
    (extraction / "run-manifest.json").write_text(
        json.dumps({"source_digest": "sha256:source"}), encoding="utf-8"
    )
    (bdd / "proposal-manifest.json").write_text(
        json.dumps({"procedure": "CLAIMS.ORGANIC_PROCEDURE"}), encoding="utf-8"
    )
    report = ProcedureCheckService().build(tmp_path)
    assert report.procedure_ref == "CLAIMS.ORGANIC_PROCEDURE"
    assert report.source_digest == "sha256:source"
    assert next(item for item in report.checks if item.check_id == "PARSE").state is CheckState.PASS
