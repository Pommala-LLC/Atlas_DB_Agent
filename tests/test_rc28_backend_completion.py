from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from ojas_reconciler.db2_behavior.catalog import CatalogLineageResolver, DdlCatalogProvider
from ojas_reconciler.db2_behavior.composition import (
    CompositionCandidateStatus,
    DirectCallCompositionInferenceService,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.decision import (
    DecisionEvaluationRequest,
    ExtractedDecisionModelBuilder,
    ModelDrivenDecisionEvaluator,
    TruthValue,
)
from ojas_reconciler.db2_behavior.dialects import DialectAdapterRegistry, DialectId
from ojas_reconciler.db2_behavior.graph import PersistentKnowledgeGraphStore
from ojas_reconciler.db2_behavior.identity import (
    EnterpriseRole,
    SignedTrustedHeaderIdentityProvider,
    TrustedHeaderIdentityConfig,
)
from ojas_reconciler.db2_behavior.commercial.models import GraphEdge, GraphNode, ProcedureKnowledgeGraph
from ojas_reconciler.db2_behavior.testkit.fixture_compiler import (
    ApprovedFixtureValue,
    ExecutableRelationalFixtureCompiler,
    FixtureBundleStatus,
)


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    return path


def test_ddl_catalog_lineage_and_executable_fixture_compiler(tmp_path: Path) -> None:
    ddl = tmp_path / "schema.sql"
    ddl.write_text(
        """
        CREATE TABLE CLAIMS.CUSTOMER (
          CUSTOMER_ID BIGINT NOT NULL PRIMARY KEY,
          NAME VARCHAR(40) NOT NULL
        );
        CREATE TABLE CLAIMS.CLAIM (
          CLAIM_ID BIGINT NOT NULL PRIMARY KEY,
          CUSTOMER_ID BIGINT NOT NULL,
          STATUS VARCHAR(20) NOT NULL,
          CONSTRAINT FK_CLAIM_CUSTOMER FOREIGN KEY (CUSTOMER_ID)
            REFERENCES CLAIMS.CUSTOMER (CUSTOMER_ID)
        );
        CREATE VIEW CLAIMS.OPEN_CLAIM AS
          SELECT C.CLAIM_ID, C.CUSTOMER_ID FROM CLAIMS.CLAIM C WHERE C.STATUS = 'OPEN';
        CREATE VIEW CLAIMS.OPEN_CUSTOMER AS
          SELECT O.CUSTOMER_ID FROM CLAIMS.OPEN_CLAIM O;
        CREATE ALIAS APP.OPEN_CUSTOMER FOR CLAIMS.OPEN_CUSTOMER;
        """,
        encoding="utf-8",
    )
    snapshot = DdlCatalogProvider([ddl]).load()
    assert len(snapshot.relations) == 5
    lineage = CatalogLineageResolver(snapshot).resolve(["APP.OPEN_CUSTOMER"])
    assert "CLAIMS.CLAIM" in lineage.base_relation_refs
    assert not lineage.unresolved_boundaries

    approved = (
        ApprovedFixtureValue(
            relation_ref="CLAIMS.CUSTOMER",
            column_name="CUSTOMER_ID",
            canonical_value=101,
            authority_ref="test-authority:fixture",
            evidence_refs=("test",),
        ),
        ApprovedFixtureValue(
            relation_ref="CLAIMS.CLAIM",
            column_name="CLAIM_ID",
            canonical_value=202,
            authority_ref="test-authority:fixture",
            evidence_refs=("test",),
        ),
    )
    bundle = ExecutableRelationalFixtureCompiler().compile(
        procedure_ref="CLAIMS.TEST",
        catalog=snapshot,
        relation_refs=("CLAIMS.CUSTOMER", "CLAIMS.CLAIM"),
        approved_values=approved,
    )
    assert bundle.status is FixtureBundleStatus.EXECUTABLE
    assert bundle.setup_sql[0].startswith('INSERT INTO "CLAIMS"."CUSTOMER"')
    assert '"CUSTOMER_ID"' in bundle.setup_sql[1]
    assert bundle.teardown_sql[0].startswith('DELETE FROM "CLAIMS"."CLAIM"')


def test_fixture_compiler_blocks_check_constraints_without_acknowledgement(tmp_path: Path) -> None:
    ddl = tmp_path / "schema.sql"
    ddl.write_text(
        "CREATE TABLE X.T (ID INTEGER NOT NULL PRIMARY KEY, AMOUNT DECIMAL(10,2) NOT NULL, CHECK (AMOUNT > 0));",
        encoding="utf-8",
    )
    snapshot = DdlCatalogProvider([ddl]).load()
    bundle = ExecutableRelationalFixtureCompiler().compile(
        procedure_ref="X.P",
        catalog=snapshot,
        relation_refs=("X.T",),
    )
    assert bundle.status is FixtureBundleStatus.BLOCKED
    assert any(value.startswith("CHECK_CONSTRAINT_REQUIRES_ACKNOWLEDGEMENT") for value in bundle.blockers)
    assert not bundle.setup_sql


def _make_run(root: Path, procedure: str, *, call: str | None = None) -> Path:
    schema, name = procedure.split(".")
    node = {
        "node_id": "call-node" if call else "node-1",
        "kind": "CALL" if call else "SET",
        "text": call or "SET P_RESULT = 'OK'",
        "source_range": {"start_line": 10, "end_line": 10},
    }
    parse = {
        "outcome": "PARSES_COMPLETE",
        "source_digest": "sha256:source",
        "ast": {
            "schema_name": schema,
            "procedure_name": name,
            "parameters": [
                {"name": "P_ID", "parameter_mode": "IN", "type_text": "BIGINT"},
                {"name": "P_REASON", "parameter_mode": "IN", "type_text": "VARCHAR(40)"},
            ],
            "nodes": [node],
        },
    }
    effects = []
    if call:
        effects.append(
            {
                "effect_id": "effect-call",
                "effect_kind": "CALL",
                "target": call.split("(", 1)[0].split(None, 1)[1],
                "source_node_ref": "call-node",
                "evidence_refs": ["call-node"],
            }
        )
    semantic_without = {
        "effects": effects,
        "behavior_slices": [],
        "behavior_bundles": [],
        "findings": [],
    }
    semantic = {**semantic_without, "content_digest": canonical_digest(semantic_without)}
    _write(root / "extraction" / "02-parse.json", parse)
    _write(root / "extraction" / "03-semantic-phase2-4.json", semantic)
    return root


def test_direct_call_composition_inference_resolves_target_and_parameter_mapping(tmp_path: Path) -> None:
    upstream = _make_run(
        tmp_path / "upstream",
        "CLAIMS.UPSTREAM",
        call="CALL CLAIMS.DOWNSTREAM(P_ID, 'REVIEW')",
    )
    downstream = _make_run(tmp_path / "downstream", "CLAIMS.DOWNSTREAM")
    batch = DirectCallCompositionInferenceService().infer([upstream, downstream])
    assert len(batch.candidates) == 1
    candidate = batch.candidates[0]
    assert candidate.status is CompositionCandidateStatus.SOURCE_CALL_RESOLVED
    assert candidate.downstream_semantic_digest
    assert [value.downstream_ref for value in candidate.parameter_mappings] == ["P_ID", "P_REASON"]


def test_model_driven_decision_evaluator_uses_extracted_predicates(tmp_path: Path) -> None:
    run = tmp_path / "run"
    parse = {
        "ast": {
            "schema_name": "CLAIMS",
            "procedure_name": "DECIDE",
            "nodes": [
                {"node_id": "pred-1", "kind": "IF", "text": "P_RISK > 90", "source_range": {"start_line": 10}},
                {"node_id": "effect-node", "kind": "SET", "text": "SET P_DECISION='REJECT'", "source_range": {"start_line": 11}},
            ],
        }
    }
    semantic_without = {
        "effects": [
            {
                "effect_id": "effect-1",
                "effect_kind": "ASSIGNMENT",
                "target": "P_DECISION",
                "value_expression": "'REJECT'",
                "evidence_refs": ["effect-node"],
            }
        ],
        "behavior_bundles": [{"bundle_id": "bundle-1", "evidence_refs": ["pred-1", "effect-node"]}],
        "behavior_slices": [
            {
                "slice_id": "slice-1",
                "bundle_ref": "bundle-1",
                "control_predicate_node_refs": ["pred-1"],
                "analysis_completeness": "COMPLETE",
                "effect_obligations": [{"effect_ref": "effect-1"}],
            }
        ],
    }
    semantic = {**semantic_without, "content_digest": canonical_digest(semantic_without)}
    _write(run / "extraction" / "02-parse.json", parse)
    _write(run / "extraction" / "03-semantic-phase2-4.json", semantic)
    model = ExtractedDecisionModelBuilder().build(run)
    assert len(model.rules) == 1
    pid = model.predicates[0].predicate_id
    request = DecisionEvaluationRequest(model_digest=model.content_digest, predicate_values={pid: TruthValue.TRUE})
    result = ModelDrivenDecisionEvaluator().evaluate(model=model, request=request)
    assert result.status == "MATCHED"
    assert result.outputs[0].target == "P_DECISION"


def test_signed_trusted_header_identity_is_verified(monkeypatch) -> None:
    config = TrustedHeaderIdentityConfig(shared_secret_env="OJAS_TEST_HEADER_SECRET")
    monkeypatch.setenv("OJAS_TEST_HEADER_SECRET", "secret")
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    roles = "ANALYST,REVIEWER"
    message = "\n".join(("actor:1", "tenant:1", roles, timestamp)).encode()
    signature = hmac.new(b"secret", message, hashlib.sha256).hexdigest()
    principal = SignedTrustedHeaderIdentityProvider(config).authenticate(
        headers={
            "x-ojas-actor": "actor:1",
            "x-ojas-tenant": "tenant:1",
            "x-ojas-roles": roles,
            "x-ojas-timestamp": timestamp,
            "x-ojas-signature": signature,
        }
    )
    assert principal.roles == (EnterpriseRole.ANALYST, EnterpriseRole.REVIEWER)
    assert principal.claims_digest and principal.claims_digest.startswith("sha256:")


def test_persistent_graph_store_ingests_searches_and_expands_neighborhood(tmp_path: Path) -> None:
    payload = {
        "schema_version": "procedure-knowledge-graph-1.0",
        "graph_id": "graph-1",
        "procedure_ref": "CLAIMS.P",
        "nodes": (
            GraphNode(node_id="procedure:CLAIMS.P", node_type="PROCEDURE", label="CLAIMS.P"),
            GraphNode(node_id="relation:CLAIMS.T", node_type="RELATION", label="CLAIMS.T"),
        ),
        "edges": (
            GraphEdge(edge_id="edge-1", source="procedure:CLAIMS.P", target="relation:CLAIMS.T", edge_type="READS"),
        ),
        "unresolved_boundaries": (),
    }
    graph = ProcedureKnowledgeGraph(**payload, content_digest=canonical_digest(payload))
    store = PersistentKnowledgeGraphStore(tmp_path / "graph.sqlite3", tenant_ref="tenant:1")
    result = store.ingest(graph)
    assert result["nodes_ingested"] == 2
    assert store.search_nodes("CLAIMS.T")[0]["node_id"] == "relation:CLAIMS.T"
    neighborhood = store.neighborhood("procedure:CLAIMS.P", depth=1)
    assert len(neighborhood["nodes"]) == 2
    assert len(neighborhood["edges"]) == 1


def test_non_db2_dialect_inventory_is_explicitly_header_only(tmp_path: Path) -> None:
    source = tmp_path / "p.sql"
    source.write_text(
        "CREATE OR REPLACE PROCEDURE claims.process_claim(p_id IN NUMBER, p_result OUT VARCHAR2) AS BEGIN NULL; END;",
        encoding="utf-8",
    )
    registry = DialectAdapterRegistry.default()
    inventory = registry.adapter(DialectId.ORACLE_PLSQL).inventory(source)
    assert inventory.routine_name == "PROCESS_CLAIM"
    assert inventory.body_status == "OPAQUE_REQUIRES_DIALECT_SEMANTIC_ADAPTER"
    assert "FULL_SEMANTIC_PIPELINE_NOT_ADMITTED" in inventory.blockers


def test_new_backend_artifacts_validate_against_packaged_contracts(tmp_path: Path) -> None:
    from jsonschema import Draft202012Validator
    from ojas_reconciler.db2_behavior.identity import OidcIdentityConfig

    ddl = tmp_path / "schema.sql"
    ddl.write_text("CREATE TABLE X.T (ID INTEGER NOT NULL PRIMARY KEY);", encoding="utf-8")
    snapshot = DdlCatalogProvider([ddl]).load()
    lineage = CatalogLineageResolver(snapshot).resolve(["X.T"])
    fixtures = ExecutableRelationalFixtureCompiler().compile(
        procedure_ref="X.P", catalog=snapshot, relation_refs=("X.T",)
    )
    registry = DialectAdapterRegistry.default().snapshot()
    oidc = OidcIdentityConfig(
        issuer="https://issuer.example",
        audience="ojas",
        algorithms=("RS256",),
        public_key_file=str(tmp_path / "key.pem"),
        role_mapping={"ojas-reviewer": EnterpriseRole.REVIEWER},
    )
    cases = {
        "catalog-snapshot-1.0.schema.json": snapshot.model_dump(mode="json"),
        "relation-lineage-report-1.0.schema.json": lineage.model_dump(mode="json"),
        "executable-fixture-bundle-1.0.schema.json": fixtures.model_dump(mode="json"),
        "dialect-registry-snapshot-1.0.schema.json": registry.model_dump(mode="json"),
        "oidc-identity-config-1.0.schema.json": oidc.model_dump(mode="json"),
    }
    root = Path(__file__).parents[1]
    for schema_name, payload in cases.items():
        schema = json.loads((root / "contracts" / schema_name).read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        assert not errors, (schema_name, errors)


def test_runtime_reconciliation_emits_typed_falsification_candidate() -> None:
    from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
    from ojas_reconciler.db2_behavior.runtime_executor import ScriptedRuntimeExecutor
    from ojas_reconciler.db2_behavior.runtime_models import (
        RuntimeExecutionStatus,
        RuntimeInvocation,
        RuntimeInvocationParameter,
        RuntimeObservedParameter,
        RuntimeObservationScript,
        RuntimeValue,
        RuntimeValueKind,
    )
    from ojas_reconciler.db2_behavior.runtime_plan import RuntimeVerificationPlanner
    from ojas_reconciler.db2_behavior.runtime_safety import RuntimeSafetyAssessor
    from ojas_reconciler.db2_behavior.runtime.reconcile import RuntimeReconciliationService
    from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
    from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

    fixture = Path(__file__).parent / "fixtures" / "constraint_contradiction.sql"
    parsed = LarkSqlPlSpikeParser().parse_file(fixture)
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    safety = RuntimeSafetyAssessor().assess(parsed, semantic, scenarios.procedure_identity_ref)
    plans = RuntimeVerificationPlanner().plan_all(
        parse_result=parsed, semantic_result=semantic, scenario_batch=scenarios, safety=safety
    )
    plan = plans.plans[0]
    inv_payload = {
        "invocation_id": "invocation-reconcile-001",
        "procedure_schema": "CLAIMS",
        "procedure_name": "CONSTRAINT_CONTRADICTION",
        "parameters": (
            RuntimeInvocationParameter(
                parameter_name="P_VALUE", parameter_mode="IN", type_text="DECIMAL(10,2)",
                value=RuntimeValue(value_kind=RuntimeValueKind.DECIMAL, canonical_value="1.00"),
            ),
            RuntimeInvocationParameter(
                parameter_name="P_RESULT", parameter_mode="OUT", type_text="VARCHAR(20)",
                value=RuntimeValue(value_kind=RuntimeValueKind.NULL),
            ),
        ),
    }
    invocation = RuntimeInvocation(**inv_payload, content_digest=canonical_digest(inv_payload))
    script_payload = {
        "schema_version": "runtime-observation-script-1.0",
        "script_id": "script-reconcile-001",
        "plan_ref": plan.plan_id,
        "plan_digest": plan.content_digest,
        "invocation": invocation,
        "execution_status": RuntimeExecutionStatus.SUCCEEDED,
        "output_parameters": (
            RuntimeObservedParameter(
                parameter_name="P_RESULT",
                value=RuntimeValue(value_kind=RuntimeValueKind.STRING, canonical_value="WRONG"),
            ),
        ),
        "sqlstate": None,
        "observed_effect_refs": tuple(item.scenario_effect_ref for item in plan.expected_observations),
        "row_changes": (), "called_routines": (), "transaction_events": (), "result_set_digests": (),
        "error_message": None,
        "started_at": "2026-07-30T00:00:00.000000Z", "ended_at": "2026-07-30T00:00:01.000000Z",
    }
    script = RuntimeObservationScript(**script_payload, content_digest=canonical_digest(script_payload))
    execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
    batch, report = RuntimeReconciliationService().reconcile(
        plan_batch=plans, execution_records=(execution,)
    )
    assert batch.verification_results[0].verification_status.value == "MISMATCH"
    assert len(report.falsification_candidates) == 1
    assert report.falsification_candidates[0].authority_scope == "RUNTIME_EVIDENCE_ONLY"
    assert report.automatic_promotion is False


def test_enterprise_cli_commands_emit_digest_bound_artifacts(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.interfaces.dispatcher import main

    ddl = tmp_path / "schema.sql"
    ddl.write_text("CREATE TABLE X.T (ID INTEGER NOT NULL PRIMARY KEY);", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    assert main(["catalog-build-from-ddl", str(ddl), "--output", str(catalog)]) == 0
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    assert payload["content_digest"].startswith("sha256:")

    lineage = tmp_path / "lineage.json"
    assert main([
        "catalog-resolve-lineage", str(catalog), "--relation-ref", "X.T", "--output", str(lineage)
    ]) == 0
    assert json.loads(lineage.read_text(encoding="utf-8"))["base_relation_refs"] == ["X.T"]

    fixtures = tmp_path / "fixtures.json"
    assert main([
        "commercial-compile-executable-fixtures", str(catalog), "--procedure-ref", "X.P",
        "--relation-ref", "X.T", "--output", str(fixtures),
    ]) == 0
    assert json.loads(fixtures.read_text(encoding="utf-8"))["status"] == "EXECUTABLE"

    registry = tmp_path / "dialects.json"
    assert main(["dialect-registry", "--output", str(registry)]) == 0
    assert len(json.loads(registry.read_text(encoding="utf-8"))["adapters"]) == 4


def _decision_review_run(workspace: Path) -> Path:
    run = workspace / "runs" / "decision-review"
    parse = {
        "source_name": "decision.sql", "source_digest": "sha256:source",
        "ast": {"schema_name": "CLAIMS", "procedure_name": "DECIDE", "nodes": [
            {"node_id": "pred-1", "kind": "IF_ARM", "text": "P_RISK > 90", "source_range": {"start_line": 10, "end_line": 10}},
            {"node_id": "effect-1-node", "kind": "SET", "text": "SET P_DECISION='REJECT'", "source_range": {"start_line": 11, "end_line": 11}},
        ]},
    }
    semantic_without = {
        "findings": [],
        "effects": [{"effect_id": "effect-1", "effect_kind": "ASSIGNMENT", "target": "P_DECISION", "value_expression": "'REJECT'", "observability": "ESCAPING_EFFECT", "evidence_refs": ["effect-1-node"]}],
        "effect_obligations": [{"effect_ref": "effect-1", "modality": "MUST"}],
        "behavior_bundles": [{"bundle_id": "bundle-1", "evidence_refs": ["pred-1", "effect-1-node"]}],
        "behavior_slices": [{"slice_id": "slice-1", "bundle_ref": "bundle-1", "control_predicate_node_refs": ["pred-1"], "analysis_completeness": "COMPLETE", "effect_obligations": [{"effect_ref": "effect-1"}]}],
        "query_summaries": [], "loop_summaries": [],
    }
    semantic = {**semantic_without, "content_digest": canonical_digest(semantic_without)}
    readable = {"feature": {"name": "CLAIMS.DECIDE readable technical candidates", "tags": ["@technical_candidate"], "rules": [{"name": "Decision", "scenarios": [{"name": "Reject high risk", "kind": "Scenario", "analysis_status": "CONDITIONAL_TECHNICAL_CANDIDATE", "proposal_kind": "BEHAVIOR", "proposal_id": "proposal-1", "source_behavior_refs": ["slice-1"], "source_bundle_refs": ["bundle-1"], "tags": [], "examples": [], "steps": [{"keyword": "Given", "text": "P_RISK > 90"}, {"keyword": "When", "text": "CLAIMS.DECIDE is invoked"}, {"keyword": "Then", "text": "P_DECISION is set to REJECT"}]}]}]}, "semantic_digest": "sha256:semantic"}
    proposal = {"procedure": "CLAIMS.DECIDE", "review_required": True, "authority_scope": "NON_AUTHORITATIVE_PROPOSAL", "semantic_digest": "sha256:semantic", "gherkin_content_digest": "sha256:feature", "quality": {"status": "PASSED", "parser_name": "gherkin-official", "parser_version": "42.0.0", "warning_count": 0}, "artifacts": [{"proposal_id": "proposal-1", "evidence_refs": ["pred-1", "effect-1-node"], "blocker_codes": [], "blocker_details": []}]}
    _write(run / "extraction" / "02-parse.json", parse)
    _write(run / "extraction" / "03-semantic-phase2-4.json", semantic)
    _write(run / "bdd" / "readable-bdd-document.json", readable)
    _write(run / "bdd" / "proposal-manifest.json", proposal)
    _write(run / "bdd" / "lint-report.json", {"warning_count": 0})
    _write(run / "bdd" / "feature-validation-report.json", {"feature_count": 1})
    return run


def test_model_driven_what_if_is_available_through_ui_api(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app

    _decision_review_run(tmp_path)
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, role=UiRole.ADMIN)))
    model_response = client.get("/api/review/decision-review/decision-model")
    assert model_response.status_code == 200
    model = model_response.json()
    pid = model["predicates"][0]["predicate_id"]
    result = client.post(
        "/api/review/decision-review/decision-evaluate",
        json={"predicate_values": {pid: "TRUE"}},
    )
    assert result.status_code == 200
    assert result.json()["status"] == "MATCHED"
    page = client.get("/review/decision-review")
    assert "Model-driven What‑If" in page.text
    assert "Hand-coded decision logic" not in page.text


def test_enterprise_api_exposes_catalog_fixture_graph_and_dialect_services(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app

    ddl = tmp_path / "schema.sql"
    ddl.write_text("CREATE TABLE X.T (ID INTEGER NOT NULL PRIMARY KEY);", encoding="utf-8")
    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path, role=UiRole.ADMIN)))
    snapshot_response = client.post("/api/enterprise/catalog/ddl", json={"paths": [str(ddl)]})
    assert snapshot_response.status_code == 200
    snapshot = snapshot_response.json()
    snapshot_path = tmp_path / "catalog.json"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    lineage = client.post("/api/enterprise/catalog/lineage", json={"catalog_path": str(snapshot_path), "relation_refs": ["X.T"]})
    assert lineage.status_code == 200
    fixture = client.post("/api/enterprise/fixtures/compile", json={"catalog_path": str(snapshot_path), "procedure_ref": "X.P", "relation_refs": ["X.T"]})
    assert fixture.status_code == 200
    assert fixture.json()["status"] == "EXECUTABLE"
    registry = client.get("/api/enterprise/dialects")
    assert registry.status_code == 200
    assert len(registry.json()["adapters"]) == 4


def test_live_db2_catalog_provider_uses_optional_adapter_and_builds_snapshot(monkeypatch) -> None:
    from ojas_reconciler.db2_behavior.catalog import Db2CatalogProvider

    responses = {
        "SYSCAT.TABLES": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "TYPE": "T", "TBSPACE": "TS1"},
        ],
        "SYSCAT.COLUMNS": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "COLNAME": "CLAIM_ID", "TYPENAME": "BIGINT", "LENGTH": 8, "SCALE": 0, "NULLS": "N", "DEFAULT": None, "GENERATED": "N", "IDENTITY": "N", "CODEPAGE": 0},
        ],
        "SYSCAT.VIEWS": [],
        "TYPE='A'": [],
        "SYSCAT.KEYCOLUSE K JOIN SYSCAT.TABCONST": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "CONSTNAME": "PK_CLAIM", "COLNAME": "CLAIM_ID", "COLSEQ": 1, "TYPE": "P"},
        ],
        "SYSCAT.REFERENCES": [],
    }

    class FakeIbmDb:
        @staticmethod
        def connect(connection_string, user, password):
            assert connection_string == "DATABASE=TEST"
            return object()

        @staticmethod
        def close(connection):
            return True

        @staticmethod
        def exec_immediate(connection, sql):
            for marker, rows in responses.items():
                if marker in sql:
                    return {"rows": list(rows), "index": 0}
            raise AssertionError(sql)

        @staticmethod
        def fetch_assoc(statement):
            if statement["index"] >= len(statement["rows"]):
                return False
            value = statement["rows"][statement["index"]]
            statement["index"] += 1
            return value

    provider = Db2CatalogProvider(
        connection_string="DATABASE=TEST", platform="DB2_LUW", schemas=("CLAIMS",)
    )
    monkeypatch.setattr(provider, "_module", lambda: FakeIbmDb)
    snapshot = provider.load()
    assert snapshot.source_kind.value == "DB2_LUW_CATALOG"
    assert snapshot.relations[0].relation_ref == "CLAIMS.CLAIM"
    assert snapshot.relations[0].definition.primary_key == ("CLAIM_ID",)


def test_oidc_jwt_identity_verifies_pinned_key_and_role_mapping(tmp_path: Path) -> None:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import timedelta
    from ojas_reconciler.db2_behavior.identity import OidcIdentityConfig, OidcJwtIdentityProvider

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "ojas",
            "sub": "actor:oidc",
            "tenant": "tenant:oidc",
            "roles": ["ojas-reviewer"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        key,
        algorithm="RS256",
    )
    provider = OidcJwtIdentityProvider(OidcIdentityConfig(
        issuer="https://issuer.example",
        audience="ojas",
        public_key_file=str(public_path),
        role_mapping={"ojas-reviewer": EnterpriseRole.REVIEWER},
    ))
    principal = provider.authenticate(headers={"authorization": f"Bearer {token}"})
    assert principal.actor_ref == "actor:oidc"
    assert principal.tenant_ref == "tenant:oidc"
    assert principal.roles == (EnterpriseRole.REVIEWER,)


def test_zos_live_catalog_captures_keys_and_foreign_key_column_mapping(monkeypatch) -> None:
    from ojas_reconciler.db2_behavior.catalog import Db2CatalogProvider

    responses = {
        "SYSIBM.SYSTABLES": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CUSTOMER", "TYPE": "T", "TBSPACE": "DB1"},
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "TYPE": "T", "TBSPACE": "DB1"},
        ],
        "SYSIBM.SYSCOLUMNS": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CUSTOMER", "COLNAME": "CUSTOMER_ID", "TYPENAME": "BIGINT", "LENGTH": 8, "SCALE": 0, "NULLS": "N", "DEFAULT": None, "GENERATED": "", "IDENTITY": "", "CODEPAGE": 0},
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "COLNAME": "CLAIM_ID", "TYPENAME": "BIGINT", "LENGTH": 8, "SCALE": 0, "NULLS": "N", "DEFAULT": None, "GENERATED": "", "IDENTITY": "", "CODEPAGE": 0},
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "COLNAME": "CUSTOMER_ID", "TYPENAME": "BIGINT", "LENGTH": 8, "SCALE": 0, "NULLS": "N", "DEFAULT": None, "GENERATED": "", "IDENTITY": "", "CODEPAGE": 0},
        ],
        "SYSIBM.SYSVIEWS": [],
        "SYSIBM.SYSSYNONYMS": [],
        "SYSIBM.SYSKEYCOLUSE": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CUSTOMER", "CONSTNAME": "PK_CUSTOMER", "COLNAME": "CUSTOMER_ID", "COLSEQ": 1, "TYPE": "P"},
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "CONSTNAME": "PK_CLAIM", "COLNAME": "CLAIM_ID", "COLSEQ": 1, "TYPE": "P"},
        ],
        "SYSIBM.SYSRELS": [
            {"TABSCHEMA": "CLAIMS", "TABNAME": "CLAIM", "CONSTNAME": "FK_CLAIM_CUSTOMER", "REFTABSCHEMA": "CLAIMS", "REFTABNAME": "CUSTOMER", "COLNAME": "CUSTOMER_ID", "COLSEQ": 1, "IXOWNER": "", "IXNAME": ""},
        ],
        "SYSIBM.SYSKEYS": [],
    }

    class FakeIbmDb:
        @staticmethod
        def connect(connection_string, user, password):
            return object()

        @staticmethod
        def close(connection):
            return True

        @staticmethod
        def exec_immediate(connection, sql):
            for marker, rows in responses.items():
                if marker in sql:
                    return {"rows": list(rows), "index": 0}
            raise AssertionError(sql)

        @staticmethod
        def fetch_assoc(statement):
            if statement["index"] >= len(statement["rows"]):
                return False
            value = statement["rows"][statement["index"]]
            statement["index"] += 1
            return value

    provider = Db2CatalogProvider(connection_string="LOCATION=TEST", platform="DB2_ZOS", schemas=("CLAIMS",))
    monkeypatch.setattr(provider, "_module", lambda: FakeIbmDb)
    snapshot = provider.load()
    relations = {item.relation_ref: item for item in snapshot.relations}
    assert relations["CLAIMS.CUSTOMER"].definition.primary_key == ("CUSTOMER_ID",)
    fk = relations["CLAIMS.CLAIM"].definition.foreign_keys[0]
    assert fk.local_columns == ("CUSTOMER_ID",)
    assert fk.referenced_columns == ("CUSTOMER_ID",)


def test_graph_neighborhood_public_cli_and_api(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from ojas_reconciler.db2_behavior.cli import main
    from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app

    without = {
        "schema_version": "procedure-knowledge-graph-1.0",
        "graph_id": "graph-neighborhood-test",
        "procedure_ref": "CLAIMS.TEST",
        "nodes": (
            GraphNode(node_id="n1", node_type="PROCEDURE", label="CLAIMS.TEST", authority="STATIC", status="RESOLVED", attributes={}),
            GraphNode(node_id="n2", node_type="RELATION", label="CLAIMS.CLAIM", authority="STATIC", status="RESOLVED", attributes={}),
        ),
        "edges": (
            GraphEdge(edge_id="e1", source="n1", target="n2", edge_type="READS", attributes={}),
        ),
        "unresolved_boundaries": (),
    }
    graph = ProcedureKnowledgeGraph(**without, content_digest=canonical_digest(without))
    graph_path = _write(tmp_path / "graph.json", graph)
    db = tmp_path / "graph.sqlite"
    assert main(["graph-ingest", str(graph_path), "--db", str(db), "--tenant-ref", "tenant:1"]) == 0
    output = tmp_path / "neighborhood.json"
    assert main(["graph-neighborhood", "n1", "--db", str(db), "--tenant-ref", "tenant:1", "--output", str(output)]) == 0
    assert {item["node_id"] for item in json.loads(output.read_text())["nodes"]} == {"n1", "n2"}

    client = TestClient(create_app(CommercialUiSettings(workspace=tmp_path / "ui", role=UiRole.ADMIN)))
    api_graph = graph.model_dump(mode="json")
    assert client.post("/api/enterprise/graph/ingest", json=api_graph).status_code == 200
    result = client.post("/api/enterprise/graph/neighborhood", json={"node_id": "n1", "depth": 1})
    assert result.status_code == 200
    assert {item["node_id"] for item in result.json()["nodes"]} == {"n1", "n2"}


def test_dependency_profiles_keep_ui_optional_and_declare_testclient_backend() -> None:
    import tomllib

    payload = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    core = payload["project"]["dependencies"]
    extras = payload["project"]["optional-dependencies"]
    assert not any(value.startswith(("fastapi", "uvicorn", "jinja2", "python-multipart")) for value in core)
    assert {value.split(">", 1)[0] for value in extras["ui"]} >= {"fastapi", "uvicorn", "jinja2", "python-multipart"}
    assert any(value.startswith("httpx") for value in extras["test"])
    assert any(value.startswith("PyJWT[crypto]") for value in extras["test"])
    assert any(value.startswith("gherkin-official") for value in extras["test"])


def test_authoritative_release_module_does_not_export_terminal_regex_parsers() -> None:
    from atlas import release_evidence

    assert "parse_pytest_outcome_counts" not in release_evidence.__all__
    assert "parse_pytest_skip_reason_groups" not in release_evidence.__all__
    source = Path(release_evidence.__file__).read_text(encoding="utf-8")
    assert "re.findall" not in source
