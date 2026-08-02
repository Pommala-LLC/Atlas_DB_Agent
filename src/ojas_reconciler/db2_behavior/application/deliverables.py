"""One-command generation of analysis, BDD, and external test assets."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.compiler.readable_candidate import ReadableCandidateRenderer
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode
from ojas_reconciler.db2_behavior.testkit.gherkin import GherkinParser
from ojas_reconciler.db2_behavior.testkit.models import (
    AssertionKind,
    BddTestCase,
    BddTestCaseBatch,
    BddTestCatalog,
    BddTestDataset,
    BddTestPackageManifest,
    ExecutionMode,
    ProcedureInvocationSpec,
    ProcedureTestContract,
    TestAssertion,
    TestCaseStatus,
    TypedValue,
)
from ojas_reconciler.db2_behavior.testkit.reporting import junit_xml_bytes
from ojas_reconciler.db2_behavior.testkit.runner import BddTestPackageRunner
from ojas_reconciler.db2_behavior.testkit.validation import type_signature
from ojas_reconciler.db2_behavior.type_system.models import CanonicalSqlType, SqlTypeFamily

from .pipeline import EndToEndPipeline


class DeliverablesGenerationBlocked(RuntimeError):
    """Raised when an upstream pipeline stage blocks required deliverables."""


@dataclass(frozen=True)
class DeliverablesResult:
    output_dir: Path
    extraction_dir: Path
    bdd_dir: Path
    test_package_dir: Path
    summary_path: Path
    admitted_scenarios: int
    blocked_scenarios: int
    generated_bdd_files: int
    readable_candidate_files: int
    generated_test_cases: int
    test_execution_status: str


class DeliverablesGenerator:
    """User-facing orchestration with fail-closed generic test assets.

    The generator never fabricates relational rows or business expectations.
    It emits typed invocation skeletons and explicit data requirements. Test
    execution remains blocked until a live DB2 or customer adapter and catalog
    are supplied.
    """

    VERSION = "deliverables-generator-1.0.1rc23"

    def __init__(self, pipeline: EndToEndPipeline | None = None) -> None:
        self._pipeline = pipeline or EndToEndPipeline()

    @staticmethod
    def default_output_dir(source: Path) -> Path:
        return source.with_name(f"{source.stem}-agent-output")

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(value) + b"\n")

    @staticmethod
    def _with_digest(model_type: type[Any], payload: dict[str, Any]) -> Any:
        return model_type(**payload, content_digest=canonical_digest(payload))

    @staticmethod
    def _load_required_stage_json(
        *,
        extraction: Path,
        filename: str,
        stage: str,
        run_manifest: Any,
        parse_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        path = extraction / filename
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))

        stage_record = next(
            (record for record in run_manifest.stage_records if record.stage == stage),
            None,
        )
        if stage_record is None:
            last_record = run_manifest.stage_records[-1] if run_manifest.stage_records else None
            stage_name = last_record.stage if last_record is not None else stage
            status = last_record.status.value if last_record is not None else "NOT_STARTED"
            blockers = tuple(last_record.blocker_codes) if last_record is not None else ()
            details = tuple(last_record.details) if last_record is not None else ()
        else:
            stage_name = stage_record.stage
            status = stage_record.status.value
            blockers = tuple(stage_record.blocker_codes)
            details = tuple(stage_record.details)

        diagnostics: list[str] = []
        payload = parse_payload
        parse_path = extraction / "02-parse.json"
        if payload is None and parse_path.is_file():
            payload = json.loads(parse_path.read_text(encoding="utf-8"))
        if payload is not None:
            for finding in payload.get("findings", []):
                code = finding.get("code", "PARSE_FINDING")
                message = finding.get("message", "")
                diagnostics.append(f"{code}: {message}".strip())

        lines = [
            "Generation was blocked before all required deliverables were emitted.",
            f"Stage: {stage_name}",
            f"Status: {status}",
            f"Required artifact: {path}",
            f"Run manifest: {extraction / 'run-manifest.json'}",
        ]
        if blockers:
            lines.append("Blockers: " + ", ".join(blockers))
        if details:
            lines.append("Details: " + "; ".join(details))
        if diagnostics:
            lines.append("Diagnostics:")
            lines.extend(f"  - {diagnostic}" for diagnostic in diagnostics)
        raise DeliverablesGenerationBlocked("\n".join(lines))

    @staticmethod
    def _default_parameter_value(name: str, sql_type: CanonicalSqlType, mode: str) -> str | None:
        if mode == "OUT":
            return None
        family = sql_type.family
        if family in {SqlTypeFamily.SMALL_INTEGER, SqlTypeFamily.INTEGER, SqlTypeFamily.BIG_INTEGER}:
            return "1"
        if family is SqlTypeFamily.DECIMAL:
            scale = sql_type.scale or 0
            return f"{0:.{scale}f}"
        if family in {SqlTypeFamily.CHARACTER, SqlTypeFamily.GRAPHIC}:
            candidate = "TEN00001" if "TENANT" in name.upper() else "TEST"
            if sql_type.length is not None:
                candidate = candidate[: sql_type.length]
            return candidate
        if family is SqlTypeFamily.DATE:
            return date(2026, 1, 1).isoformat()
        if family is SqlTypeFamily.TIMESTAMP:
            return "2026-01-01T00:00:00"
        return None

    def generate(
        self,
        *,
        source: Path,
        output_dir: Path | None = None,
        authority_mode: AuthorityMode = AuthorityMode.TEST_FIXTURE_ONLY,
        vocabulary_snapshot: Path | None = None,
        classification_snapshot: Path | None = None,
        dynamic_resolution_catalog: Path | None = None,
        tenant_isolation_catalog: Path | None = None,
        query_semantics_catalog: Path | None = None,
        caller_transaction_contract: Path | None = None,
        bdd_warning_policy: Path | None = None,
    ) -> DeliverablesResult:
        source = source.resolve()
        if not source.is_file():
            raise FileNotFoundError(f"SQL source file not found: {source}")
        root = (output_dir or self.default_output_dir(source)).resolve()
        extraction = root / "extraction"
        bdd_dir = root / "bdd"
        test_root = root / "test-package"
        results_dir = root / "results"
        root.mkdir(parents=True, exist_ok=True)

        run_manifest = self._pipeline.run(
            source=source,
            output_dir=extraction,
            authority_mode=authority_mode,
            vocabulary_snapshot=vocabulary_snapshot,
            classification_snapshot=classification_snapshot,
            dynamic_resolution_catalog=dynamic_resolution_catalog,
            tenant_isolation_catalog=tenant_isolation_catalog,
            query_semantics_catalog=query_semantics_catalog,
            caller_transaction_contract=caller_transaction_contract,
            governance_db=extraction / "evidence-cache.sqlite3",
        )

        parse_payload = self._load_required_stage_json(
            extraction=extraction,
            filename="02-parse.json",
            stage="PHASE_1_PARSE_EVIDENCE",
            run_manifest=run_manifest,
        )
        semantic_payload = self._load_required_stage_json(
            extraction=extraction,
            filename="03-semantic-phase2-4.json",
            stage="PHASE_2_3_4_SEMANTIC",
            run_manifest=run_manifest,
            parse_payload=parse_payload,
        )
        scenario_payload = self._load_required_stage_json(
            extraction=extraction,
            filename="04-scenario-specs.json",
            stage="PHASE_5A_SCENARIO_SPEC",
            run_manifest=run_manifest,
            parse_payload=parse_payload,
        )
        bdd_path = extraction / "07-bdd-compilation.json"
        bdd_payload = json.loads(bdd_path.read_text(encoding="utf-8")) if bdd_path.exists() else {
            "gherkin_artifacts": [],
            "candidate_bdds": [],
        }

        if bdd_dir.exists():
            shutil.rmtree(bdd_dir)
        technical_dir = bdd_dir / "technical"
        readable_dir = bdd_dir / "readable-candidates"
        technical_dir.mkdir(parents=True, exist_ok=True)
        readable_dir.mkdir(parents=True, exist_ok=True)
        gherkin_artifacts = bdd_payload.get("gherkin_artifacts", [])
        for artifact in gherkin_artifacts:
            (technical_dir / f"{artifact['artifact_id']}.feature").write_text(
                artifact["text"], encoding="utf-8", newline="\n"
            )

        warning_policy_payload: dict[str, Any] | None = None
        if bdd_warning_policy is not None:
            warning_policy_path = bdd_warning_policy.resolve()
            if not warning_policy_path.is_file():
                raise FileNotFoundError(
                    f"Readable BDD warning policy not found: {warning_policy_path}"
                )
            warning_policy_payload = json.loads(
                warning_policy_path.read_text(encoding="utf-8")
            )
            policy_schema_path = (
                Path(__file__).resolve().parents[1]
                / "contracts_schemas"
                / "readable-bdd-warning-policy-1.0.schema.json"
            )
            policy_schema = json.loads(policy_schema_path.read_text(encoding="utf-8"))
            errors = sorted(
                Draft202012Validator(policy_schema).iter_errors(warning_policy_payload),
                key=lambda item: tuple(str(value) for value in item.path),
            )
            if errors:
                detail = "; ".join(error.message for error in errors)
                raise DeliverablesGenerationBlocked(
                    "READABLE_BDD_WARNING_POLICY_INVALID: " + detail
                )

        try:
            readable_batch = ReadableCandidateRenderer().render(
                parse_payload=parse_payload,
                semantic_payload=semantic_payload,
                scenario_payload=scenario_payload,
                bdd_payload=bdd_payload,
                warning_policy=warning_policy_payload,
            )
        except Exception as exc:
            from ojas_reconciler.db2_behavior.bdd.readable_quality import (
                ReadableBddQualityError,
            )

            if not isinstance(exc, ReadableBddQualityError):
                raise
            if exc.report:
                self._write_json(bdd_dir / "lint-report.json", exc.report)
            raise DeliverablesGenerationBlocked(
                "READABLE_BDD_QUALITY_GATE_FAILED: " + str(exc)
            ) from exc
        for artifact in readable_batch["artifacts"]:
            (readable_dir / f"{artifact['proposal_id']}.feature").write_text(
                artifact["text"], encoding="utf-8", newline="\n"
            )
        (bdd_dir / "READABLE_CANDIDATES.feature").write_text(
            readable_batch["combined_text"], encoding="utf-8", newline="\n"
        )
        self._write_json(
            bdd_dir / "readable-bdd-document.json",
            readable_batch["_readable_document"],
        )
        self._write_json(
            bdd_dir / "gherkin-document.json",
            readable_batch["_gherkin_document"],
        )
        self._write_json(
            bdd_dir / "lint-report.json",
            readable_batch["_lint_report"],
        )
        self._write_json(
            bdd_dir / "feature-validation-report.json",
            readable_batch["_feature_validation_report"],
        )
        proposal_manifest = {
            key: value for key, value in readable_batch.items() if not key.startswith("_")
        }
        self._write_json(bdd_dir / "proposal-manifest.json", proposal_manifest)
        (bdd_dir / "README.txt").write_text(
            "OPEN READABLE_CANDIDATES.feature FIRST.\n\n"
            "readable-candidates/ contains deterministic reviewer-facing technical proposals.\n"
            "They are NON-AUTHORITATIVE and require vocabulary/business approval.\n\n"
            "technical/ contains authority-bound compiler output for admitted ScenarioSpecs only.\n"
            "proposal-manifest.json preserves IDs, admission status, blocker details, evidence bindings, and quality digests.\n"
            "readable-bdd-document.json is the Atlas-owned readable IR.\n"
            "gherkin-document.json is the normalized official-parser projection.\n"
            "lint-report.json records Atlas structural-policy findings and warning governance.\n"
            "feature-validation-report.json proves every emitted .feature file passed the parser gate.\n"
            "The readable proposal never replaces or changes an authority-bound technical artifact.\n",
            encoding="utf-8",
            newline="\r\n",
        )

        self._generate_test_package(
            source=source,
            parse_payload=parse_payload,
            scenario_payload=scenario_payload,
            bdd_payload=bdd_payload,
            bdd_dir=bdd_dir,
            package_root=test_root,
        )
        test_result = BddTestPackageRunner().run(test_root)
        self._write_json(test_root / "results" / "execution.json", test_result)
        (test_root / "results" / "junit.xml").write_bytes(junit_xml_bytes(test_result))

        admitted = len(scenario_payload.get("scenario_specs", []))
        blocked = sum(
            1
            for item in scenario_payload.get("compilation_results", [])
            if item.get("compilation_status") == "BLOCKED"
        )
        summary_data = {
            "schema_version": "easy-deliverables-summary-1.1",
            "pipeline_execution_status": "COMPLETED_WITHOUT_EXECUTION_FAILURE",
            "source": source.as_posix(),
            "output_dir": root.as_posix(),
            "parse_status": parse_payload.get("outcome"),
            "admitted_scenarios": admitted,
            "blocked_scenarios": blocked,
            "generated_bdd_files": len(gherkin_artifacts),
            "readable_candidate_files": len(readable_batch["artifacts"]),
            "behavior_accounting": readable_batch["accounting"],
            "generated_test_cases": test_result.actual_blocked,
            "test_execution_status": "BLOCKED_PENDING_DB2_AND_RELATIONAL_DATA",
            "live_database_executed": False,
            "important_paths": {
                "readable_bdd": "bdd/READABLE_CANDIDATES.feature",
                "readable_proposals": "bdd/readable-candidates/",
                "technical_bdd": "bdd/technical/",
                "proposal_manifest": "bdd/proposal-manifest.json",
                "readable_bdd_document": "bdd/readable-bdd-document.json",
                "gherkin_document": "bdd/gherkin-document.json",
                "readable_bdd_lint_report": "bdd/lint-report.json",
                "feature_validation_report": "bdd/feature-validation-report.json",
                "analysis": "extraction/03-semantic-phase2-4.json",
                "scenario_specs": "extraction/04-scenario-specs.json",
                "test_cases": "test-package/specs/test-cases.json",
                "test_data": "test-package/data/",
                "test_requirements": "test-package/data/test-data-requirements.json",
                "test_results": "test-package/results/execution.json",
            },
        }
        self._write_json(results_dir / "summary.json", summary_data)
        summary_path = root / "OPEN_ME_FIRST.txt"
        summary_path.write_text(self._summary_text(summary_data), encoding="utf-8", newline="\r\n")
        return DeliverablesResult(
            output_dir=root,
            extraction_dir=extraction,
            bdd_dir=bdd_dir,
            test_package_dir=test_root,
            summary_path=summary_path,
            admitted_scenarios=admitted,
            blocked_scenarios=blocked,
            generated_bdd_files=len(gherkin_artifacts),
            readable_candidate_files=len(readable_batch["artifacts"]),
            generated_test_cases=test_result.actual_blocked,
            test_execution_status="BLOCKED_PENDING_DB2_AND_RELATIONAL_DATA",
        )

    def _generate_test_package(
        self,
        *,
        source: Path,
        parse_payload: dict[str, Any],
        scenario_payload: dict[str, Any],
        bdd_payload: dict[str, Any],
        bdd_dir: Path,
        package_root: Path,
    ) -> None:
        if package_root.exists():
            shutil.rmtree(package_root)
        for relative in ("features", "specs", "data", "results"):
            (package_root / relative).mkdir(parents=True, exist_ok=True)
        (package_root / "procedure.sql").write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")

        ast = parse_payload["ast"]
        procedure_name = ast["procedure_name"]
        schema_name = ast.get("schema_name")
        declared = [
            value
            for value in ast.get("declared_symbol_types", [])
            if value.get("symbol_kind") == "PROCEDURE_PARAMETER"
        ]
        parameter_types = {
            value["symbol_name"]: CanonicalSqlType.model_validate_json(json.dumps(value["sql_type"]))
            for value in declared
        }
        parameter_modes = {value["symbol_name"]: value["parameter_mode"] for value in declared}
        contract_payload = {
            "schema_version": "procedure-test-contract-1.0",
            "procedure_schema": schema_name,
            "procedure_name": procedure_name,
            "parameter_types": parameter_types,
            "parameter_modes": parameter_modes,
        }
        contract = self._with_digest(ProcedureTestContract, contract_payload)
        self._write_json(package_root / "data" / "procedure-contract.json", contract)

        catalog_payload = {
            "schema_version": "bdd-test-catalog-1.0",
            "provider_ref": "CATALOG_NOT_SUPPLIED",
            "relations": (),
        }
        catalog = self._with_digest(BddTestCatalog, catalog_payload)
        self._write_json(package_root / "data" / "catalog.json", catalog)

        scenarios_by_behavior = {
            value["behavior_id"]: value for value in scenario_payload.get("scenario_specs", [])
        }
        candidates_by_behavior = {
            value["behavior_id"]: value for value in bdd_payload.get("candidate_bdds", [])
        }
        feature_files: list[str] = []
        cases: list[BddTestCase] = []
        datasets: list[BddTestDataset] = []
        requirements: list[dict[str, Any]] = []
        for index, artifact in enumerate(bdd_payload.get("gherkin_artifacts", []), start=1):
            feature_name = f"generated-{index:03d}.feature"
            relative_feature = f"features/{feature_name}"
            (package_root / relative_feature).write_text(artifact["text"], encoding="utf-8", newline="\n")
            feature_files.append(relative_feature)
            document = GherkinParser().parse(artifact["text"])
            scenario_name = next(iter(sorted(document.scenario_names())))
            behavior_id = artifact["behavior_id"]
            spec = scenarios_by_behavior[behavior_id]
            candidate = candidates_by_behavior.get(behavior_id, {})
            dataset_id = f"dataset-{index:03d}"
            invocation_parameters = {
                name: TypedValue(
                    database_type=type_signature(sql_type),
                    canonical_value=self._default_parameter_value(name, sql_type, parameter_modes[name]),
                )
                for name, sql_type in parameter_types.items()
            }
            assertions = tuple(
                TestAssertion(
                    assertion_id=f"assert-{index:03d}-{effect_index:02d}",
                    kind=AssertionKind.EVENT_OCCURRED,
                    target=effect["effect_ref"],
                    evidence_refs=tuple(effect.get("evidence_refs", [])),
                )
                for effect_index, effect in enumerate(spec.get("expected_effects", []), start=1)
            )
            case_payload = {
                "test_case_id": f"tc-{index:03d}-{behavior_id[-8:]}",
                "feature_name": document.feature_name,
                "scenario_name": scenario_name,
                "dataset_ref": dataset_id,
                "invocation": ProcedureInvocationSpec(
                    procedure_schema=schema_name,
                    procedure_name=procedure_name,
                    parameters=invocation_parameters,
                ),
                "assertions": assertions,
                "expected_status": TestCaseStatus.BLOCKED,
                "tags": ("generated", "candidate", "requires-catalog", "requires-db2"),
                "behavior_ref": behavior_id,
                "evidence_refs": tuple(spec.get("evidence_refs", [])),
            }
            case = self._with_digest(BddTestCase, case_payload)
            cases.append(case)
            dataset_payload = {
                "schema_version": "bdd-test-dataset-1.0",
                "dataset_id": dataset_id,
                "facts": {
                    "behavior_ref": behavior_id,
                    "scenario_spec_ref": candidate.get("scenario_spec_ref"),
                    "generation_status": "TYPED_INVOCATION_SKELETON_ONLY",
                },
                "relations": {},
            }
            dataset = self._with_digest(BddTestDataset, dataset_payload)
            datasets.append(dataset)
            self._write_json(package_root / "data" / f"{dataset_id}.json", dataset)
            requirements.append(
                {
                    "test_case_id": case.test_case_id,
                    "behavior_ref": behavior_id,
                    "status": "BLOCKED",
                    "blockers": [
                        "RELATION_CATALOG_NOT_SUPPLIED",
                        "SCENARIO_TO_RELATIONAL_DATA_CONSTRAINTS_NOT_RESOLVED",
                        "LIVE_DB2_OR_CUSTOMER_ADAPTER_NOT_CONFIGURED",
                    ],
                    "typed_parameter_skeleton": {
                        name: value.model_dump(mode="json") for name, value in invocation_parameters.items()
                    },
                    "precondition_refs": [value.get("technical_fact_ref") for value in spec.get("preconditions", [])],
                    "effect_refs": [value.get("effect_ref") for value in spec.get("expected_effects", [])],
                }
            )

        package_id = f"{procedure_name.lower().replace('_', '-')}-generated-tests"
        batch_payload = {
            "schema_version": "bdd-test-case-batch-1.0",
            "package_id": package_id,
            "test_cases": tuple(cases),
        }
        batch = self._with_digest(BddTestCaseBatch, batch_payload)
        self._write_json(package_root / "specs" / "test-cases.json", batch)
        requirements_payload = {
            "schema_version": "test-data-requirements-1.0",
            "overall_status": "BLOCKED_PENDING_CATALOG_AND_EXECUTION_ADAPTER",
            "procedure": f"{schema_name}.{procedure_name}" if schema_name else procedure_name,
            "requirements": requirements,
        }
        self._write_json(package_root / "data" / "test-data-requirements.json", requirements_payload)

        source_text = source.read_text(encoding="utf-8")
        manifest_payload = {
            "schema_version": "bdd-test-package-manifest-1.0",
            "package_id": package_id,
            "package_version": "0.1.0",
            "source_procedure": f"{schema_name}.{procedure_name}" if schema_name else procedure_name,
            "source_file": "procedure.sql",
            "source_digest": canonical_digest({"source_text": source_text}),
            "execution_mode": ExecutionMode.GENERATE_ONLY,
            "adapter_factory": "ojas_reconciler.db2_behavior.testkit.external:create_unconfigured_adapter",
            "feature_files": tuple(feature_files),
            "test_cases_file": "specs/test-cases.json",
            "dataset_files": tuple(f"data/{value.dataset_id}.json" for value in datasets),
            "procedure_contract_file": "data/procedure-contract.json",
            "catalog_file": "data/catalog.json",
            "metadata_files": (
                "data/procedure-contract.json",
                "data/catalog.json",
                "data/test-data-requirements.json",
            ),
            "generated_by": self.VERSION,
        }
        manifest = self._with_digest(BddTestPackageManifest, manifest_payload)
        self._write_json(package_root / "test-package.json", manifest)
        (package_root / "README.txt").write_text(
            "Generated candidate BDD test assets.\n\n"
            "The package contains typed invocation skeletons and technical assertions.\n"
            "Relational test rows and execution are blocked until catalog metadata and\n"
            "a DB2/customer adapter are configured. No business data was invented.\n",
            encoding="utf-8",
            newline="\r\n",
        )

    @staticmethod
    def _summary_text(data: dict[str, Any]) -> str:
        return (
            "DB2 BEHAVIOR AGENT - GENERATION COMPLETE\n"
            "========================================\n\n"
            f"Source: {data['source']}\n"
            f"Pipeline execution: {data['pipeline_execution_status']}\n"
            f"Parse status: {data['parse_status']}\n"
            f"Admitted scenarios: {data['admitted_scenarios']}\n"
            f"Blocked scenarios: {data['blocked_scenarios']}\n"
            f"Semantic behavior bundles: {data['behavior_accounting']['semantic_behavior_bundles']}\n"
            f"Readable behavior candidates: {data['behavior_accounting']['readable_behavior_candidates']}\n"
            f"Readable unhandled-condition candidates: {data['behavior_accounting']['readable_unhandled_condition_candidates']}\n"
            f"Omitted semantic behavior bundles: {data['behavior_accounting']['omitted_semantic_behavior_bundles']}\n"
            f"Technical BDD files: {data['generated_bdd_files']}\n"
            f"Readable candidate files: {data['readable_candidate_files']}\n"
            f"Test cases generated: {data['generated_test_cases']}\n\n"
            "OPEN THESE FOLDERS\n"
            "------------------\n"
            "Readable BDD:      bdd\\READABLE_CANDIDATES.feature\n"
            "Readable proposals: bdd\\readable-candidates\\\n"
            "Technical BDD:      bdd\\technical\\\n"
            "Findings/analysis: extraction\\03-semantic-phase2-4.json\n"
            "Scenario decisions: extraction\\04-scenario-specs.json\n"
            "Test cases:        test-package\\specs\\test-cases.json\n"
            "Test data:         test-package\\data\\\n"
            "Test requirements: test-package\\data\\test-data-requirements.json\n"
            "Test result:       test-package\\results\\execution.json\n\n"
            "IMPORTANT\n"
            "---------\n"
            "Readable candidates are NON-AUTHORITATIVE technical proposals and require review.\n"
            "Blocked readable candidates remain blocked; they do not receive authority-bound artifacts.\n"
            "The technical folder contains compiler output for admitted ScenarioSpecs only.\n"
            "Generated test execution is blocked until catalog metadata and a DB2 or customer\n"
            "execution adapter are configured. The agent does not invent customer rows.\n"
        )
