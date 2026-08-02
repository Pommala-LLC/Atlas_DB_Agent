from __future__ import annotations

import hashlib
from pathlib import Path

from ojas_reconciler.db2_behavior.bdd.authority import AuthorityRequirementsExporter, AuthoritySnapshotValidator
from ojas_reconciler.db2_behavior.bdd.authority_models import AuthorityValidationStatus
from ojas_reconciler.db2_behavior.bdd.models import AuthorityScope, ClassificationSnapshot, VocabularySnapshot
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.analysis.dynamic_sql import validate_dynamic_resolution_catalog
from ojas_reconciler.db2_behavior.bdd.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.governance.adapters.sqlite import GovernanceStore
from ojas_reconciler.db2_behavior.parsing.inventory import InventoryAnalyzer
from ojas_reconciler.db2_behavior.core.release_models import (
    AuthorityMode,
    EndToEndRunManifest,
    PipelineStageRecord,
    PipelineStageStatus,
)
from ojas_reconciler.db2_behavior.runtime.plan import RuntimeVerificationPlanner
from ojas_reconciler.db2_behavior.runtime.safety import RuntimeSafetyAssessor
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.analysis.models import DynamicResolutionCatalog
from ojas_reconciler.db2_behavior.analysis.tenant_isolation import load_tenant_isolation_catalog
from ojas_reconciler.db2_behavior.analysis.query_semantics import load_query_semantics_catalog
from ojas_reconciler.db2_behavior.analysis.caller_contract import load_caller_transaction_contract
from .components import PipelineComponents


class EndToEndPipeline:
    """Runs the complete self-contained DB2 behavior pipeline.

    External enterprise governance remains authoritative. The local SQLite
    repository is a non-authoritative evidence cache and review staging boundary.
    """

    VERSION = "end-to-end-pipeline-1.0.1rc23"

    def __init__(self, components: PipelineComponents | None = None) -> None:
        self._components = components or PipelineComponents.defaults()

    @staticmethod
    def _write(path: Path, value: object) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_json_bytes(value)
        path.write_bytes(payload + b"\n")
        return canonical_digest(value)

    @staticmethod
    def _load_catalog(path: Path | None) -> DynamicResolutionCatalog | None:
        if path is None:
            return None
        catalog = DynamicResolutionCatalog.model_validate_json(path.read_text(encoding="utf-8"))
        validate_dynamic_resolution_catalog(catalog)
        return catalog

    @staticmethod
    def _load_authority(
        vocabulary_path: Path,
        classification_path: Path,
    ) -> tuple[VocabularySnapshot, ClassificationSnapshot]:
        return (
            VocabularySnapshot.model_validate_json(vocabulary_path.read_text(encoding="utf-8")),
            ClassificationSnapshot.model_validate_json(classification_path.read_text(encoding="utf-8")),
        )

    def run(
        self,
        *,
        source: Path,
        output_dir: Path,
        authority_mode: AuthorityMode = AuthorityMode.NONE,
        vocabulary_snapshot: Path | None = None,
        classification_snapshot: Path | None = None,
        dynamic_resolution_catalog: Path | None = None,
        tenant_isolation_catalog: Path | None = None,
        query_semantics_catalog: Path | None = None,
        caller_transaction_contract: Path | None = None,
        governance_db: Path | None = None,
        actor_ref: str = "actor:local-pipeline",
        event_at: str = "2026-01-01T00:00:00.000000Z",
        enable_experimental_runtime: bool = False,
    ) -> EndToEndRunManifest:
        source = source.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        source_digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
        run_id = "db2-run-" + hashlib.sha256(
            f"{source.as_posix()}\0{source_digest}\0{authority_mode.value}".encode("utf-8")
        ).hexdigest()[:24]
        records: list[PipelineStageRecord] = []
        emitted: list[str] = []

        def record(
            stage: str,
            status: PipelineStageStatus,
            path: Path | None = None,
            digest: str | None = None,
            blockers: tuple[str, ...] = (),
            details: tuple[str, ...] = (),
        ) -> None:
            display_path: str | None = None
            if path is not None:
                try:
                    display_path = path.resolve().relative_to(output_dir.resolve()).as_posix()
                except ValueError:
                    display_path = path.as_posix()
            records.append(
                PipelineStageRecord(
                    stage=stage,
                    status=status,
                    artifact_path=display_path,
                    artifact_digest=digest,
                    blocker_codes=blockers,
                    details=details,
                )
            )
            if display_path is not None:
                emitted.append(display_path)

        inventory = self._components.inventory_analyzer.analyze_path(source)
        path = output_dir / "01-gate0.json"
        record("GATE_0_INVENTORY", PipelineStageStatus.SUCCEEDED, path, self._write(path, inventory))

        parse_result = self._components.procedure_parser.parse_file(source)
        path = output_dir / "02-parse.json"
        parse_digest = self._write(path, parse_result)
        parse_ok = parse_result.ast is not None and parse_result.outcome.value.startswith("PARSES")
        record(
            "PHASE_1_PARSE_EVIDENCE",
            PipelineStageStatus.SUCCEEDED if parse_ok else PipelineStageStatus.BLOCKED,
            path,
            parse_digest,
            tuple(f.code.value for f in parse_result.findings) if not parse_ok else (),
        )
        if not parse_ok or parse_result.ast is None:
            return self._finish(
                run_id=run_id,
                source=source,
                source_digest=source_digest,
                authority_mode=authority_mode,
                governance_db=governance_db,
                records=records,
                emitted=emitted,
                output_dir=output_dir,
            )

        analyzer = self._components.semantic_analyzer_factory(
            self._load_catalog(dynamic_resolution_catalog),
            load_tenant_isolation_catalog(tenant_isolation_catalog),
            load_query_semantics_catalog(query_semantics_catalog),
            load_caller_transaction_contract(caller_transaction_contract),
        )
        semantic_result = analyzer.analyze(parse_result)
        path = output_dir / "03-semantic-phase2-4.json"
        record("PHASE_2_3_4_SEMANTIC", PipelineStageStatus.SUCCEEDED, path, self._write(path, semantic_result))

        scenario_batch = self._components.scenario_compiler.compile_all(parse_result, semantic_result)
        path = output_dir / "04-scenario-specs.json"
        scenario_digest = self._write(path, scenario_batch)
        scenario_status = (
            PipelineStageStatus.SUCCEEDED
            if scenario_batch.scenario_specs
            else PipelineStageStatus.BLOCKED
        )
        record(
            "PHASE_5A_SCENARIO_SPEC",
            scenario_status,
            path,
            scenario_digest,
            tuple(sorted({code for result in scenario_batch.compilation_results for code in result.blockers})),
            (f"scenario_specs={len(scenario_batch.scenario_specs)}",),
        )

        requirements = self._components.authority_requirements_exporter.export(scenario_batch)
        path = output_dir / "05-authority-requirements.json"
        record("AUTHORITY_REQUIREMENTS", PipelineStageStatus.SUCCEEDED, path, self._write(path, requirements))

        bdd_batch = None
        if authority_mode == AuthorityMode.NONE:
            record(
                "PHASE_5B_BDD_COMPILER",
                PipelineStageStatus.BLOCKED,
                blockers=("AUTHORITY_SNAPSHOT_NOT_SUPPLIED",),
                details=("Technical ScenarioSpec remains available.",),
            )
        else:
            if authority_mode == AuthorityMode.TEST_FIXTURE_ONLY:
                vocabulary, classification = self._components.fixture_authority_builder.build(
                    scenario_batch,
                    authority_scope=AuthorityScope.TEST_FIXTURE_ONLY,
                )
            else:
                if vocabulary_snapshot is None or classification_snapshot is None:
                    raise ValueError(
                        "EXTERNAL_SNAPSHOT mode requires vocabulary_snapshot and classification_snapshot"
                    )
                vocabulary, classification = self._load_authority(
                    vocabulary_snapshot, classification_snapshot
                )
            validation = self._components.authority_validator.validate(vocabulary, classification)
            path = output_dir / "06-authority-validation.json"
            record(
                "AUTHORITY_VALIDATION",
                PipelineStageStatus.SUCCEEDED
                if validation.validation_status == AuthorityValidationStatus.VALID
                else PipelineStageStatus.BLOCKED,
                path,
                self._write(path, validation),
                tuple(issue.code.value for issue in validation.issues),
            )
            if validation.validation_status == AuthorityValidationStatus.VALID:
                bdd_batch = self._components.bdd_compiler.compile_all(scenario_batch, vocabulary, classification)
                path = output_dir / "07-bdd-compilation.json"
                status = (
                    PipelineStageStatus.SUCCEEDED
                    if bdd_batch.candidate_bdds
                    else PipelineStageStatus.BLOCKED
                )
                record(
                    "PHASE_5B_BDD_COMPILER",
                    status,
                    path,
                    self._write(path, bdd_batch),
                    tuple(sorted({b.value for result in bdd_batch.compilation_results for b in result.blockers})),
                    (f"candidate_bdds={len(bdd_batch.candidate_bdds)}",),
                )
                gherkin_dir = output_dir / "gherkin"
                for artifact in bdd_batch.gherkin_artifacts:
                    gherkin_path = gherkin_dir / f"{artifact.artifact_id}.feature"
                    gherkin_path.parent.mkdir(parents=True, exist_ok=True)
                    gherkin_path.write_text(artifact.text, encoding="utf-8", newline="\n")
                    emitted.append(gherkin_path.relative_to(output_dir).as_posix())

        if enable_experimental_runtime:
            safety = self._components.runtime_safety_assessor.assess(
                parse_result, semantic_result, scenario_batch.procedure_identity_ref
            )
            runtime_plans = self._components.runtime_planner.plan_all(
                parse_result=parse_result,
                semantic_result=semantic_result,
                scenario_batch=scenario_batch,
                safety=safety,
            )
            path = output_dir / "08-experimental-runtime-plans.json"
            record(
                "PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION",
                PipelineStageStatus.SUCCEEDED,
                path,
                self._write(path, runtime_plans),
                blockers=("DEFERRED_CAPABILITY_NOT_PRODUCT_BASELINE",),
                details=(f"live_eligibility={safety.live_eligibility.value}",),
            )
        else:
            record(
                "PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION",
                PipelineStageStatus.SKIPPED,
                blockers=("DEFERRED_CAPABILITY_DISABLED",),
                details=("Phase 6 is implemented experimentally but excluded from the admitted baseline.",),
            )

        if governance_db is None:
            record(
                "PHASE_7_LOCAL_EVIDENCE_CACHE",
                PipelineStageStatus.SKIPPED,
                blockers=("LOCAL_GOVERNANCE_DB_NOT_REQUESTED",),
            )
        else:
            store = self._components.governance_store_factory(governance_db)
            store.initialize(applied_at=event_at)
            admitted = store.admit_scenario_batch(
                scenario_batch, created_at=event_at, actor_ref=actor_ref
            )
            bdd_admitted = 0
            if bdd_batch is not None and bdd_batch.candidate_bdds:
                bdd_result = store.admit_bdd_batch(
                    bdd_batch, created_at=event_at, actor_ref=actor_ref
                )
                bdd_admitted = len(bdd_result.records)
            scenario_spec_count = len(scenario_batch.scenario_specs)
            scenario_blocked_count = sum(
                1 for result in scenario_batch.compilation_results
                if result.compilation_status.value == "BLOCKED"
            )
            candidate_bdd_count = len(bdd_batch.candidate_bdds) if bdd_batch is not None else 0
            gherkin_artifact_count = len(bdd_batch.gherkin_artifacts) if bdd_batch is not None else 0
            traceability_manifest_count = len(bdd_batch.traceability_manifests) if bdd_batch is not None else 0
            primary_count = scenario_spec_count + candidate_bdd_count + gherkin_artifact_count + traceability_manifest_count
            governance_result = {
                "database": governance_db.as_posix(),
                "scenario_spec_count": scenario_spec_count,
                "scenario_compilation_blocked_count": scenario_blocked_count,
                "candidate_bdd_count": candidate_bdd_count,
                "gherkin_artifact_count": gherkin_artifact_count,
                "traceability_manifest_count": traceability_manifest_count,
                "supporting_artifact_count": max(0, len(admitted.records) + bdd_admitted - primary_count),
                "authority_scope": "LOCAL_NON_AUTHORITATIVE_EVIDENCE",
                "external_enterprise_connector_required_for_authority": True,
            }
            path = output_dir / "09-local-governance.json"
            record(
                "PHASE_7_LOCAL_EVIDENCE_CACHE",
                PipelineStageStatus.SUCCEEDED,
                path,
                self._write(path, governance_result),
            )

        return self._finish(
            run_id=run_id,
            source=source,
            source_digest=source_digest,
            authority_mode=authority_mode,
            governance_db=governance_db,
            records=records,
            emitted=emitted,
            output_dir=output_dir,
        )

    def _finish(
        self,
        *,
        run_id: str,
        source: Path,
        source_digest: str,
        authority_mode: AuthorityMode,
        governance_db: Path | None,
        records: list[PipelineStageRecord],
        emitted: list[str],
        output_dir: Path,
    ) -> EndToEndRunManifest:
        without_digest = {
            "schema_version": "db2-e2e-run-1.0",
            "run_id": run_id,
            "source_path": source.as_posix(),
            "source_digest": source_digest,
            "authority_mode": authority_mode,
            "governance_mode": "LOCAL_NON_AUTHORITATIVE_EVIDENCE" if governance_db else "NONE",
            "stage_records": tuple(records),
            "emitted_artifact_paths": tuple(sorted(emitted)),
            "input_dependent_checks": (
                "ORGANIC_ESTATE_VALIDATION_REQUIRES_REAL_PROCEDURE_SOURCE",
                "LIVE_DB2_EXECUTION_REQUIRES_CUSTOMER_SANDBOX_CONNECTION",
            ),
        }
        manifest = EndToEndRunManifest(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )
        manifest_path = output_dir / "run-manifest.json"
        manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
        return manifest
