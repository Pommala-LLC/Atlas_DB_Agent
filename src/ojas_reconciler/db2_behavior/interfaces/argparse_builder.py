from __future__ import annotations

import argparse
from pathlib import Path

from ..core.release_models import AuthorityMode

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="db2-behavior",
        description="Provisional fail-closed DB2 behavior extraction framework; organic validation pending.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser("inventory", help="Inventory one DB2 procedure source file.")
    one.add_argument("source", type=Path)
    one.add_argument("--output-dir", type=Path, default=Path("reports/gate0"))

    estate = sub.add_parser("inventory-dir", help="Inventory DB2 source files under a directory.")
    estate.add_argument("root", type=Path)
    estate.add_argument("--output-dir", type=Path, default=Path("reports/gate0-estate"))

    parse = sub.add_parser("parse-spike", help="Run the non-production Lark procedural-shell spike.")
    parse.add_argument("source", type=Path)
    parse.add_argument("--output", type=Path)
    parse.add_argument("--explain", action="store_true")
    parse.add_argument("--explain-json", action="store_true")

    parse_script = sub.add_parser(
        "parse-db2-script",
        help="Segment a Db2 CLP script and parse every CREATE PROCEDURE source unit.",
    )
    parse_script.add_argument("source", type=Path)
    parse_script.add_argument("--output", type=Path)

    semantic = sub.add_parser("analyze-phase1", help="Build static CFG, effects, dynamic SQL resolution, and semantic findings.")
    semantic.add_argument("source", type=Path)
    semantic.add_argument("--output", type=Path)
    semantic.add_argument("--dynamic-resolution-catalog", type=Path)
    semantic.add_argument("--tenant-isolation-catalog", type=Path)
    semantic.add_argument("--query-semantics-catalog", type=Path)
    semantic.add_argument("--caller-transaction-contract", type=Path)

    phase4 = sub.add_parser("analyze-phase4", help="Run bounded dynamic SQL reconstruction and full static identifier resolution.")
    phase4.add_argument("source", type=Path)
    phase4.add_argument("--output", type=Path)
    phase4.add_argument("--dynamic-resolution-catalog", type=Path)
    phase4.add_argument("--tenant-isolation-catalog", type=Path)
    phase4.add_argument("--query-semantics-catalog", type=Path)
    phase4.add_argument("--caller-transaction-contract", type=Path)
    phase4.add_argument("--explain", action="store_true")

    scenarios = sub.add_parser(
        "compile-scenarios",
        help="Compile eligible Phase 1 semantic facts into technical ScenarioSpec 1.1 artifacts.",
    )
    scenarios.add_argument("source", type=Path)
    scenarios.add_argument("--output", type=Path)
    scenarios.add_argument("--dynamic-resolution-catalog", type=Path)
    scenarios.add_argument("--tenant-isolation-catalog", type=Path)
    scenarios.add_argument("--query-semantics-catalog", type=Path)
    scenarios.add_argument("--caller-transaction-contract", type=Path)

    bdd = sub.add_parser(
        "compile-bdd",
        help="Compile technical ScenarioSpec into snapshot-gated candidate Gherkin.",
    )
    bdd.add_argument("source", type=Path)
    bdd.add_argument("--output", type=Path)
    bdd.add_argument("--gherkin-dir", type=Path)
    bdd.add_argument("--fixture-authority", action="store_true")
    bdd.add_argument("--vocabulary-snapshot", type=Path)
    bdd.add_argument("--classification-snapshot", type=Path)
    bdd.add_argument("--authority-validation-output", type=Path)
    bdd.add_argument("--explain-output", type=Path)
    bdd.add_argument("--explain", action="store_true")
    bdd.add_argument("--dynamic-resolution-catalog", type=Path)
    bdd.add_argument("--tenant-isolation-catalog", type=Path)
    bdd.add_argument("--query-semantics-catalog", type=Path)
    bdd.add_argument("--caller-transaction-contract", type=Path)

    authority_requirements = sub.add_parser(
        "export-authority-requirements",
        help="Export immutable vocabulary and classification requirements without inventing approvals.",
    )
    authority_requirements.add_argument("source", type=Path)
    authority_requirements.add_argument("--output", type=Path)
    authority_requirements.add_argument("--dynamic-resolution-catalog", type=Path)
    authority_requirements.add_argument("--tenant-isolation-catalog", type=Path)
    authority_requirements.add_argument("--query-semantics-catalog", type=Path)
    authority_requirements.add_argument("--caller-transaction-contract", type=Path)

    authority_validation = sub.add_parser(
        "validate-authority",
        help="Validate external vocabulary and classification snapshots before compilation.",
    )
    authority_validation.add_argument("--vocabulary-snapshot", type=Path, required=True)
    authority_validation.add_argument("--classification-snapshot", type=Path, required=True)
    authority_validation.add_argument("--output", type=Path)

    runtime_evidence_status_parser = sub.add_parser(
        "runtime-evidence-status",
        help="Report property-gated DB2 runtime-evidence availability without connecting.",
    )
    runtime_evidence_status_parser.add_argument("--properties", type=Path)
    runtime_evidence_status_parser.add_argument("--load-backend", action="store_true")

    runtime_plan = sub.add_parser(
        "plan-runtime-verification",
        help="EXPERIMENTAL/DEFERRED: build runtime-verification plans without executing DB2.",
    )
    runtime_plan.add_argument("source", type=Path)
    runtime_plan.add_argument("--output", type=Path)
    runtime_plan.add_argument("--dynamic-resolution-catalog", type=Path)
    runtime_plan.add_argument("--tenant-isolation-catalog", type=Path)
    runtime_plan.add_argument("--query-semantics-catalog", type=Path)
    runtime_plan.add_argument("--caller-transaction-contract", type=Path)
    runtime_plan.add_argument("--explain", action="store_true")
    runtime_plan.add_argument("--enable-experimental-runtime", action="store_true")

    runtime_scripted = sub.add_parser(
        "verify-runtime-scripted",
        help="EXPERIMENTAL/DEFERRED: verify a plan against a scripted observation.",
    )
    runtime_scripted.add_argument("source", type=Path)
    runtime_scripted.add_argument("--script", type=Path, required=True)
    runtime_scripted.add_argument("--output", type=Path)
    runtime_scripted.add_argument("--dynamic-resolution-catalog", type=Path)
    runtime_scripted.add_argument("--tenant-isolation-catalog", type=Path)
    runtime_scripted.add_argument("--query-semantics-catalog", type=Path)
    runtime_scripted.add_argument("--caller-transaction-contract", type=Path)
    runtime_scripted.add_argument("--explain", action="store_true")
    runtime_scripted.add_argument("--enable-experimental-runtime", action="store_true")

    runtime_live = sub.add_parser(
        "verify-runtime-db2",
        help="EXPERIMENTAL/DEFERRED: execute one guarded plan against an attested DB2 sandbox.",
    )
    runtime_live.add_argument("source", type=Path)
    runtime_live.add_argument("--plan-id", required=True)
    runtime_live.add_argument("--invocation", type=Path, required=True)
    runtime_live.add_argument("--output", type=Path)
    runtime_live.add_argument("--sandbox-config", type=Path)
    runtime_live.add_argument("--connection-ref")
    runtime_live.add_argument("--connection-env", default="ATLAS_DB2_CONNECTION_STRING")
    runtime_live.add_argument("--sandbox-attestation")
    runtime_live.add_argument("--manual-approval-ref")
    runtime_live.add_argument("--execute-live", action="store_true")
    runtime_live.add_argument("--dynamic-resolution-catalog", type=Path)
    runtime_live.add_argument("--tenant-isolation-catalog", type=Path)
    runtime_live.add_argument("--query-semantics-catalog", type=Path)
    runtime_live.add_argument("--caller-transaction-contract", type=Path)
    runtime_live.add_argument("--explain", action="store_true")
    runtime_live.add_argument("--enable-experimental-runtime", action="store_true")
    runtime_live.add_argument("--runtime-evidence-properties", type=Path)

    governance_init = sub.add_parser("governance-init", help="Initialize the non-authoritative Phase 7 SQLite evidence cache.")
    governance_init.add_argument("--db", type=Path, required=True)
    governance_init.add_argument("--at", required=True)

    admit_scenarios = sub.add_parser("governance-admit-scenarios", help="Cache a ScenarioSpec batch and its child specs as non-authoritative evidence.")
    admit_scenarios.add_argument("batch", type=Path)
    admit_scenarios.add_argument("--db", type=Path, required=True)
    admit_scenarios.add_argument("--actor-ref", required=True)
    admit_scenarios.add_argument("--at", required=True)
    admit_scenarios.add_argument("--output", type=Path)

    admit_bdd = sub.add_parser("governance-admit-bdd", help="Cache a BDD compilation batch atomically as non-authoritative evidence.")
    admit_bdd.add_argument("batch", type=Path)
    admit_bdd.add_argument("--db", type=Path, required=True)
    admit_bdd.add_argument("--actor-ref", required=True)
    admit_bdd.add_argument("--at", required=True)
    admit_bdd.add_argument("--output", type=Path)

    admit_runtime = sub.add_parser("governance-admit-runtime", help="Cache a runtime verification batch as non-authoritative evidence.")
    admit_runtime.add_argument("batch", type=Path)
    admit_runtime.add_argument("--db", type=Path, required=True)
    admit_runtime.add_argument("--actor-ref", required=True)
    admit_runtime.add_argument("--at", required=True)
    admit_runtime.add_argument("--output", type=Path)

    baseline = sub.add_parser("governance-register-baseline", help="Cache an externally asserted reference baseline; this command does not approve it.")
    baseline.add_argument("--db", type=Path, required=True)
    baseline.add_argument("--artifact-id", required=True)
    baseline.add_argument("--authority-ref", required=True)
    baseline.add_argument("--effective-from", required=True)
    baseline.add_argument("--actor-ref", required=True)
    baseline.add_argument("--output", type=Path)

    compare = sub.add_parser("governance-compare-baseline", help="Compare cached evidence with the latest cached external baseline assertion.")
    compare.add_argument("--db", type=Path, required=True)
    compare.add_argument("--artifact-id", required=True)
    compare.add_argument("--compared-at", required=True)
    compare.add_argument("--actor-ref", required=True)
    compare.add_argument("--output", type=Path)

    amend = sub.add_parser("governance-amend-scenario", help="Create a non-authoritative immutable review amendment revision.")
    amend.add_argument("amended_spec", type=Path)
    amend.add_argument("--db", type=Path, required=True)
    amend.add_argument("--artifact-id", required=True)
    amend.add_argument("--editor-ref", required=True)
    amend.add_argument("--reason", required=True)
    amend.add_argument("--amended-at", required=True)
    amend.add_argument("--output", type=Path)

    decision = sub.add_parser("governance-bind-decision", help="Cache an external platform governance decision bound to an artifact digest.")
    decision.add_argument("envelope", type=Path)
    decision.add_argument("--db", type=Path, required=True)
    decision.add_argument("--output", type=Path)

    certification = sub.add_parser("governance-bind-certification", help="Cache an external certification artifact bound to an artifact digest.")
    certification.add_argument("envelope", type=Path)
    certification.add_argument("--db", type=Path, required=True)
    certification.add_argument("--output", type=Path)

    history = sub.add_parser("governance-history", help="Export an artifact's local non-authoritative evidence and external-binding history.")
    history.add_argument("--db", type=Path, required=True)
    history.add_argument("--artifact-id", required=True)
    history.add_argument("--output", type=Path)

    corpus = sub.add_parser("run-corpus", help="Run the versioned parser corpus manifest.")
    corpus.add_argument("manifest", type=Path)
    corpus.add_argument(
        "--schema",
        type=Path,
        default=None,
    )
    corpus.add_argument("--output", type=Path)

    easy = sub.add_parser(
        "generate",
        help="One-command generation of analysis, technical BDD, and a separate candidate test-assets package.",
    )
    easy.add_argument("source", type=Path)
    easy.add_argument("--output-dir", type=Path)
    easy.add_argument(
        "--authority-mode",
        choices=[value.value for value in AuthorityMode],
        default=AuthorityMode.TEST_FIXTURE_ONLY.value,
    )
    easy.add_argument("--vocabulary-snapshot", type=Path)
    easy.add_argument("--classification-snapshot", type=Path)
    easy.add_argument("--dynamic-resolution-catalog", type=Path)
    easy.add_argument("--tenant-isolation-catalog", type=Path)
    easy.add_argument("--query-semantics-catalog", type=Path)
    easy.add_argument("--caller-transaction-contract", type=Path)
    easy.add_argument("--bdd-warning-policy", type=Path)

    e2e = sub.add_parser(
        "run-end-to-end",
        help="Run Gate 0 through Phase 5 plus optional local evidence caching; experimental Phase 6 is disabled by default.",
    )
    e2e.add_argument("source", type=Path)
    e2e.add_argument("--output-dir", type=Path, required=True)
    e2e.add_argument(
        "--authority-mode",
        choices=[value.value for value in AuthorityMode],
        default=AuthorityMode.NONE.value,
    )
    e2e.add_argument("--vocabulary-snapshot", type=Path)
    e2e.add_argument("--classification-snapshot", type=Path)
    e2e.add_argument("--dynamic-resolution-catalog", type=Path)
    e2e.add_argument("--tenant-isolation-catalog", type=Path)
    e2e.add_argument("--query-semantics-catalog", type=Path)
    e2e.add_argument("--caller-transaction-contract", type=Path)
    e2e.add_argument("--governance-db", type=Path)
    e2e.add_argument("--actor-ref", default="actor:local-pipeline")
    e2e.add_argument("--event-at", default="2026-01-01T00:00:00.000000Z")
    e2e.add_argument("--enable-experimental-runtime", action="store_true")

    bdd_tests = sub.add_parser(
        "run-bdd-test-package",
        help="Run a standalone procedure-specific BDD test-assets package.",
    )
    bdd_tests.add_argument("package_root", type=Path)
    bdd_tests.add_argument("--output", type=Path)
    bdd_tests.add_argument("--junit-output", type=Path)


    commercial_export = sub.add_parser(
        "commercial-export-templates",
        help="Export packaged commercial capability, custody, gate, organic, and review templates.",
    )
    commercial_export.add_argument("--output-dir", type=Path, required=True)

    commercial_seal = sub.add_parser(
        "commercial-seal-artifact",
        help="Validate and add a canonical digest to a commercial boundary artifact.",
    )
    commercial_seal.add_argument(
        "--artifact-type",
        required=True,
        choices=(
            "CAPABILITY_MANIFEST",
            "CUSTODY_AGREEMENT",
            "ORGANIC_VALIDATION_MANIFEST",
            "ORGANIC_REVIEW_BATCH",
            "COMMERCIAL_GATE_EVIDENCE",
            "ORGANIC_PAUSE_DISPOSITION",
            "PROCEDURE_CHECK_REPORT",
            "PROCEDURE_COMPOSITION_CONTRACT",
            "COMPOSITION_ASSESSMENT",
            "NAMING_COMPATIBILITY_POLICY",
            "METERING_SNAPSHOT",
            "PROCEDURE_KNOWLEDGE_GRAPH",
            "RELATIONAL_FIXTURE_PLAN",
            "COMMERCIAL_DELETION_REQUEST",
            "COMMERCIAL_DELETION_ATTESTATION",
        ),
    )
    commercial_seal.add_argument("input", type=Path)
    commercial_seal.add_argument("--output", type=Path, required=True)

    commercial_capabilities = sub.add_parser(
        "commercial-validate-capabilities",
        help="Validate machine-readable capability claims without promoting designed features.",
    )
    commercial_capabilities.add_argument("manifest", type=Path)
    commercial_capabilities.add_argument("--output", type=Path)

    commercial_custody = sub.add_parser(
        "commercial-validate-custody",
        help="Validate an approved organic-source custody agreement before source intake.",
    )
    commercial_custody.add_argument("agreement", type=Path)
    commercial_custody.add_argument("--as-of", required=True)
    commercial_custody.add_argument("--output", type=Path)

    commercial_organic = sub.add_parser(
        "commercial-run-organic-validation",
        help="Run unmodified organic source through smoke, discovery, or estate-pilot validation.",
    )
    commercial_organic.add_argument("manifest", type=Path)
    commercial_organic.add_argument("--custody-agreement", type=Path, required=True)
    commercial_organic.add_argument("--as-of", required=True)
    commercial_organic.add_argument("--reviews", type=Path)
    commercial_organic.add_argument("--output-dir", type=Path, required=True)

    public_organic = sub.add_parser(
        "commercial-run-public-repository-validation",
        help=(
            "Run pinned, licensed third-party public repository source without a customer custody agreement."
        ),
    )
    public_organic.add_argument("manifest", type=Path)
    public_organic.add_argument("--repository-root", type=Path, required=True)
    public_organic.add_argument("--output", type=Path, required=True)

    commercial_readiness = sub.add_parser(
        "commercial-assess-readiness",
        help="Assess commercial readiness while preserving provisional naming and organic-validation gates.",
    )
    commercial_readiness.add_argument("--capabilities", type=Path, required=True)
    commercial_readiness.add_argument("--custody-agreement", type=Path)
    commercial_readiness.add_argument("--organic-report", type=Path)
    commercial_readiness.add_argument("--gate-evidence", type=Path)
    commercial_readiness.add_argument("--as-of", required=True)
    commercial_readiness.add_argument("--deployment-gate", action="append", default=[])
    commercial_readiness.add_argument("--customer-boundary-gate", action="append", default=[])
    commercial_readiness.add_argument("--output", type=Path)

    commercial_disposition = sub.add_parser(
        "commercial-create-disposition",
        help="Create a digest-bound disposition for a paused organic validation run.",
    )
    commercial_disposition.add_argument("report", type=Path)
    commercial_disposition.add_argument("--decision", required=True)
    commercial_disposition.add_argument("--cause", required=True)
    commercial_disposition.add_argument("--responsibility", required=True)
    commercial_disposition.add_argument("--rationale", required=True)
    commercial_disposition.add_argument("--remediation-action", action="append", default=[])
    commercial_disposition.add_argument("--owner-ref", required=True)
    commercial_disposition.add_argument("--approved-by-ref")
    commercial_disposition.add_argument("--decided-at", required=True)
    commercial_disposition.add_argument("--target-reassessment-at")
    commercial_disposition.add_argument("--output", type=Path, required=True)

    commercial_checks = sub.add_parser(
        "commercial-build-procedure-checks",
        help="Build a six-state per-procedure check report from one generated run.",
    )
    commercial_checks.add_argument("run_dir", type=Path)
    commercial_checks.add_argument("--output", type=Path, required=True)

    commercial_fixture_plan = sub.add_parser(
        "commercial-plan-relational-fixtures",
        help="Plan relation requirements and FK order without generating executable SQL.",
    )
    commercial_fixture_plan.add_argument("--procedure-ref", required=True)
    commercial_fixture_plan.add_argument("--relation-ref", action="append", default=[], required=True)
    commercial_fixture_plan.add_argument("--catalog", type=Path, action="append", default=[], required=True)
    commercial_fixture_plan.add_argument("--output", type=Path, required=True)

    commercial_composition = sub.add_parser(
        "commercial-assess-composition",
        help="Assess a digest-bound procedure composition contract.",
    )
    commercial_composition.add_argument("contract", type=Path)
    commercial_composition.add_argument("--upstream-digest", required=True)
    commercial_composition.add_argument("--downstream-digest", required=True)
    commercial_composition.add_argument("--transaction-digest")
    commercial_composition.add_argument("--orchestration-digest")
    commercial_composition.add_argument("--output", type=Path, required=True)

    commercial_graph = sub.add_parser(
        "commercial-build-knowledge-graph",
        help="Build a conservative graph projection from emitted evidence.",
    )
    commercial_graph.add_argument("run_dir", type=Path)
    commercial_graph.add_argument("--output", type=Path, required=True)

    commercial_sbom = sub.add_parser("commercial-generate-sbom", help="Generate an offline CycloneDX SBOM.")
    commercial_sbom.add_argument("--output", type=Path, required=True)

    commercial_support = sub.add_parser("commercial-build-support-bundle", help="Build a source-excluding support bundle.")
    commercial_support.add_argument("run_dir", type=Path)
    commercial_support.add_argument("--output", type=Path, required=True)
    commercial_support.add_argument("--include-source", action="store_true")

    commercial_serve = sub.add_parser(
        "commercial-serve",
        help="Run the integrated governed commercial web console.",
    )
    commercial_serve.add_argument("--host", default="127.0.0.1")
    commercial_serve.add_argument("--port", type=int, default=8765)
    commercial_serve.add_argument("--workspace", type=Path, default=Path("reports/commercial-ui"))
    commercial_serve.add_argument("--tenant-ref", default="tenant:local")
    commercial_serve.add_argument("--actor-ref", default="actor:local-ui")
    commercial_serve.add_argument("--role", choices=("VIEWER", "ANALYST", "REVIEWER", "ADMIN"), default="ADMIN")
    commercial_serve.add_argument("--trust-identity-headers", action="store_true")


    catalog_ddl = sub.add_parser("catalog-build-from-ddl", help="Build a canonical catalog snapshot from DDL files.")
    catalog_ddl.add_argument("ddl", type=Path, nargs="+")
    catalog_ddl.add_argument("--platform", default="DB2_LUW")
    catalog_ddl.add_argument("--provider-ref", default="ddl-catalog")
    catalog_ddl.add_argument("--output", type=Path, required=True)

    catalog_live = sub.add_parser("catalog-capture-db2", help="Capture a live DB2 catalog snapshot using the optional catalog adapter.")
    catalog_live.add_argument("--connection-env", default="ATLAS_DB2_CATALOG_CONNECTION_STRING")
    catalog_live.add_argument("--platform", choices=("DB2_LUW", "DB2_ZOS"), required=True)
    catalog_live.add_argument("--schema", action="append", required=True)
    catalog_live.add_argument("--provider-ref", default="db2-live-catalog")
    catalog_live.add_argument("--output", type=Path, required=True)

    catalog_lineage = sub.add_parser("catalog-resolve-lineage", help="Resolve views, synonyms, and base-relation lineage from a catalog snapshot.")
    catalog_lineage.add_argument("catalog", type=Path)
    catalog_lineage.add_argument("--relation-ref", action="append", required=True)
    catalog_lineage.add_argument("--max-depth", type=int, default=8)
    catalog_lineage.add_argument("--output", type=Path, required=True)

    fixture_compile = sub.add_parser("commercial-compile-executable-fixtures", help="Compile executable DB2 fixture SQL for the admitted catalog subset.")
    fixture_compile.add_argument("catalog", type=Path)
    fixture_compile.add_argument("--procedure-ref", required=True)
    fixture_compile.add_argument("--relation-ref", action="append", required=True)
    fixture_compile.add_argument("--approved-values", type=Path)
    fixture_compile.add_argument("--acknowledge-check", action="append", default=[])
    fixture_compile.add_argument("--output", type=Path, required=True)

    composition_infer = sub.add_parser("commercial-infer-composition", help="Infer non-authoritative direct-call composition candidates from generated runs.")
    composition_infer.add_argument("run_dir", type=Path, nargs="+")
    composition_infer.add_argument("--output", type=Path, required=True)

    decision_model = sub.add_parser("commercial-build-decision-model", help="Build a model-driven decision evaluator artifact from extracted semantic evidence.")
    decision_model.add_argument("run_dir", type=Path)
    decision_model.add_argument("--output", type=Path, required=True)

    decision_eval = sub.add_parser("commercial-evaluate-decision", help="Evaluate a decision model from explicit TRUE/FALSE/UNKNOWN predicate inputs.")
    decision_eval.add_argument("model", type=Path)
    decision_eval.add_argument("request", type=Path)
    decision_eval.add_argument("--output", type=Path, required=True)

    runtime_reconcile = sub.add_parser("runtime-reconcile", help="Reconcile runtime execution records against a verification-plan batch.")
    runtime_reconcile.add_argument("plan_batch", type=Path)
    runtime_reconcile.add_argument("execution_record", type=Path, nargs="+")
    runtime_reconcile.add_argument("--batch-output", type=Path, required=True)
    runtime_reconcile.add_argument("--report-output", type=Path, required=True)

    graph_ingest = sub.add_parser("graph-ingest", help="Persist a procedure knowledge graph in a tenant-scoped SQLite graph store.")
    graph_ingest.add_argument("graph", type=Path)
    graph_ingest.add_argument("--db", type=Path, required=True)
    graph_ingest.add_argument("--tenant-ref", required=True)
    graph_ingest.add_argument("--output", type=Path)

    graph_search = sub.add_parser("graph-search", help="Search persisted knowledge-graph nodes.")
    graph_search.add_argument("query")
    graph_search.add_argument("--db", type=Path, required=True)
    graph_search.add_argument("--tenant-ref", required=True)
    graph_search.add_argument("--limit", type=int, default=100)
    graph_search.add_argument("--output", type=Path)

    graph_neighborhood = sub.add_parser("graph-neighborhood", help="Expand a bounded neighborhood around a persisted knowledge-graph node.")
    graph_neighborhood.add_argument("node_id")
    graph_neighborhood.add_argument("--db", type=Path, required=True)
    graph_neighborhood.add_argument("--tenant-ref", required=True)
    graph_neighborhood.add_argument("--depth", type=int, default=1)
    graph_neighborhood.add_argument("--limit", type=int, default=500)
    graph_neighborhood.add_argument("--output", type=Path)

    dialect_registry = sub.add_parser("dialect-registry", help="Emit the installed database-dialect adapter registry.")
    dialect_registry.add_argument("--output", type=Path)

    dialect_inventory = sub.add_parser("dialect-inventory", help="Inventory a non-DB2 stored-procedure header without making body-semantic claims.")
    dialect_inventory.add_argument("source", type=Path)
    dialect_inventory.add_argument("--dialect", required=True)
    dialect_inventory.add_argument("--output", type=Path)

    doctor = sub.add_parser("doctor", help="Validate local installation, contracts, and migrations.")
    doctor.add_argument("--project-root", type=Path, default=Path.cwd())
    doctor.add_argument("--output", type=Path)

    sub.add_parser("check-tools", help="Report installed and optional implementation tools.")
    return parser
