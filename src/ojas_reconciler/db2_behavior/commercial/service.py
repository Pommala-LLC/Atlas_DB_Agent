from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator

from ..application.pipeline import EndToEndPipeline
from ..catalog.models import CatalogSnapshot, RelationLineageReport
from ..composition.models import CompositionCandidateBatch
from ..decision.models import DecisionEvaluationRequest, DecisionEvaluationResult, ExtractedDecisionModel
from ..dialects.models import DialectRegistrySnapshot, RoutineInventory
from ..identity.models import OidcIdentityConfig, TrustedHeaderIdentityConfig
from ..runtime.reconcile import RuntimeReconciliationReport
from ..testkit.fixture_compiler import ExecutableFixtureBundle
from ..core.canonical_json import canonical_digest, canonical_json_bytes
from ..core.release_models import AuthorityMode, PipelineStageStatus
from ..core.resources import packaged_contract_path
from .models import (
    CommercialCapabilityManifest,
    CommercialGateEvidence,
    CommercialGateStatus,
    CommercialMaturity,
    CommercialReadinessReport,
    CustodyAgreementStatus,
    NamingStatus,
    OrganicCaseOutcome,
    OrganicReviewBatch,
    OrganicSourceCustodyAgreement,
    OrganicValidationLevel,
    OrganicValidationManifest,
    OrganicValidationReport,
    OrganicValidationStatus,
    ReviewConfirmation,
    OrganicPauseDisposition,
    ProcedureCheckReport,
    ProcedureCompositionContract,
    CompositionAssessment,
    NamingCompatibilityPolicy,
    MeteringSnapshot,
    ProcedureKnowledgeGraph,
    RelationalFixturePlan,
    CommercialDeletionRequest,
    CommercialDeletionAttestation,
)


class CommercialValidationError(RuntimeError):
    """Raised when a customer-boundary or commercialization contract fails closed."""


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_schema(payload: dict[str, Any], schema_name: str) -> None:
    schema = json.loads(packaged_contract_path(schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(payload)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CommercialValidationError(f"Timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")


REQUIRED_COMMERCIAL_GATE_IDS: tuple[str, ...] = (
    "NATIVE_WINDOWS_PYTHON_3_14",
    "OFFLINE_WHEELHOUSE_SHA256_INSTALL",
    "SBOM",
    "VULNERABILITY_SCAN",
    "UPGRADE_AND_ROLLBACK",
    "BACKUP_AND_DELETION",
    "SUPPORT_BUNDLE",
    "SUPPORT_SLA",
    "METERING_MODEL",
)


class CommercialReadinessService:
    """Validates commercial claims without promoting designed capabilities to availability."""

    def export_templates(self, output_dir: Path) -> tuple[Path, ...]:
        output_dir.mkdir(parents=True, exist_ok=True)
        resource_root = files("ojas_reconciler.db2_behavior.commercial_templates")
        emitted: list[Path] = []
        for resource in sorted(resource_root.iterdir(), key=lambda item: item.name):
            if resource.name == "__init__.py" or not resource.is_file():
                continue
            destination = output_dir / resource.name
            destination.write_bytes(resource.read_bytes())
            emitted.append(destination)
        return tuple(emitted)

    def seal_artifact(self, path: Path, *, artifact_type: str) -> object:
        model_map = {
            "CAPABILITY_MANIFEST": (CommercialCapabilityManifest, "commercial-capability-manifest-1.0.schema.json"),
            "CUSTODY_AGREEMENT": (OrganicSourceCustodyAgreement, "organic-source-custody-agreement-1.0.schema.json"),
            "ORGANIC_VALIDATION_MANIFEST": (OrganicValidationManifest, "organic-validation-manifest-1.0.schema.json"),
            "ORGANIC_REVIEW_BATCH": (OrganicReviewBatch, "organic-review-batch-1.0.schema.json"),
            "COMMERCIAL_GATE_EVIDENCE": (CommercialGateEvidence, "commercial-gate-evidence-1.0.schema.json"),
            "ORGANIC_PAUSE_DISPOSITION": (OrganicPauseDisposition, "organic-pause-disposition-1.0.schema.json"),
            "PROCEDURE_CHECK_REPORT": (ProcedureCheckReport, "procedure-check-report-1.0.schema.json"),
            "PROCEDURE_COMPOSITION_CONTRACT": (ProcedureCompositionContract, "procedure-composition-contract-1.0.schema.json"),
            "COMPOSITION_ASSESSMENT": (CompositionAssessment, "composition-assessment-1.0.schema.json"),
            "NAMING_COMPATIBILITY_POLICY": (NamingCompatibilityPolicy, "naming-compatibility-policy-1.0.schema.json"),
            "METERING_SNAPSHOT": (MeteringSnapshot, "metering-snapshot-1.0.schema.json"),
            "PROCEDURE_KNOWLEDGE_GRAPH": (ProcedureKnowledgeGraph, "procedure-knowledge-graph-1.0.schema.json"),
            "RELATIONAL_FIXTURE_PLAN": (RelationalFixturePlan, "relational-fixture-plan-1.0.schema.json"),
            "COMMERCIAL_DELETION_REQUEST": (CommercialDeletionRequest, "commercial-deletion-request-1.0.schema.json"),
            "COMMERCIAL_DELETION_ATTESTATION": (CommercialDeletionAttestation, "commercial-deletion-attestation-1.0.schema.json"),
            "CATALOG_SNAPSHOT": (CatalogSnapshot, "catalog-snapshot-1.0.schema.json"),
            "RELATION_LINEAGE_REPORT": (RelationLineageReport, "relation-lineage-report-1.0.schema.json"),
            "EXECUTABLE_FIXTURE_BUNDLE": (ExecutableFixtureBundle, "executable-fixture-bundle-1.0.schema.json"),
            "COMPOSITION_CANDIDATE_BATCH": (CompositionCandidateBatch, "composition-candidate-batch-1.0.schema.json"),
            "EXTRACTED_DECISION_MODEL": (ExtractedDecisionModel, "extracted-decision-model-1.0.schema.json"),
            "DECISION_EVALUATION_REQUEST": (DecisionEvaluationRequest, "decision-evaluation-request-1.0.schema.json"),
            "DECISION_EVALUATION_RESULT": (DecisionEvaluationResult, "decision-evaluation-result-1.0.schema.json"),
            "RUNTIME_RECONCILIATION_REPORT": (RuntimeReconciliationReport, "runtime-reconciliation-report-1.0.schema.json"),
            "DIALECT_REGISTRY_SNAPSHOT": (DialectRegistrySnapshot, "dialect-registry-snapshot-1.0.schema.json"),
            "ROUTINE_INVENTORY": (RoutineInventory, "routine-inventory-1.0.schema.json"),
            "TRUSTED_HEADER_IDENTITY_CONFIG": (TrustedHeaderIdentityConfig, "trusted-header-identity-config-1.0.schema.json"),
            "OIDC_IDENTITY_CONFIG": (OidcIdentityConfig, "oidc-identity-config-1.0.schema.json"),
        }
        try:
            model_type, schema_name = model_map[artifact_type]
        except KeyError as exc:
            raise CommercialValidationError(f"Unsupported commercial artifact type: {artifact_type}") from exc
        payload = _load_json(path)
        payload.pop("content_digest", None)
        payload["content_digest"] = canonical_digest(payload)
        encoded = canonical_json_bytes(payload)
        model = model_type.model_validate_json(encoded)
        _validate_schema(json.loads(encoded.decode("utf-8")), schema_name)
        return model

    def load_capability_manifest(self, path: Path) -> CommercialCapabilityManifest:
        payload = _load_json(path)
        _validate_schema(payload, "commercial-capability-manifest-1.0.schema.json")
        manifest = CommercialCapabilityManifest.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = manifest.model_dump(mode="python", exclude={"content_digest"})
        if manifest.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Capability manifest content_digest mismatch.")
        return manifest

    def load_custody_agreement(
        self,
        path: Path,
        *,
        as_of: str,
    ) -> OrganicSourceCustodyAgreement:
        payload = _load_json(path)
        _validate_schema(payload, "organic-source-custody-agreement-1.0.schema.json")
        agreement = OrganicSourceCustodyAgreement.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = agreement.model_dump(mode="python", exclude={"content_digest"})
        if agreement.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Custody agreement content_digest mismatch.")
        if agreement.status is not CustodyAgreementStatus.APPROVED:
            raise CommercialValidationError(
                f"Organic source processing requires APPROVED custody status; got {agreement.status.value}."
            )
        timestamp = _parse_utc(as_of)
        if timestamp < _parse_utc(agreement.effective_from):
            raise CommercialValidationError("Custody agreement is not yet effective.")
        if agreement.expires_at and timestamp >= _parse_utc(agreement.expires_at):
            raise CommercialValidationError("Custody agreement has expired.")
        return agreement

    def load_organic_report(self, path: Path) -> OrganicValidationReport:
        payload = _load_json(path)
        _validate_schema(payload, "organic-validation-report-1.0.schema.json")
        report = OrganicValidationReport.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = report.model_dump(mode="python", exclude={"content_digest"})
        if report.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Organic validation report content_digest mismatch.")
        return report

    def load_gate_evidence(self, path: Path) -> CommercialGateEvidence:
        payload = _load_json(path)
        _validate_schema(payload, "commercial-gate-evidence-1.0.schema.json")
        evidence = CommercialGateEvidence.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = evidence.model_dump(mode="python", exclude={"content_digest"})
        if evidence.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Commercial gate evidence content_digest mismatch.")
        return evidence

    def assess(
        self,
        *,
        capabilities: CommercialCapabilityManifest,
        custody: OrganicSourceCustodyAgreement | None,
        organic: OrganicValidationReport | None,
        gate_evidence: CommercialGateEvidence | None,
        deployment_gates: tuple[str, ...],
        customer_boundary_gates: tuple[str, ...],
    ) -> CommercialReadinessReport:
        blockers: list[str] = []
        verified_gate_ids: tuple[str, ...] = ()
        if gate_evidence is None:
            blockers.extend(f"COMMERCIAL_GATE_UNVERIFIED:{gate_id}" for gate_id in REQUIRED_COMMERCIAL_GATE_IDS)
        else:
            if gate_evidence.distribution_name != capabilities.distribution_name:
                blockers.append("COMMERCIAL_GATE_DISTRIBUTION_MISMATCH")
            if gate_evidence.distribution_version != capabilities.distribution_version:
                blockers.append("COMMERCIAL_GATE_VERSION_MISMATCH")
            gate_map = {gate.gate_id: gate for gate in gate_evidence.gates}
            verified_gate_ids = tuple(
                sorted(
                    gate_id
                    for gate_id, gate in gate_map.items()
                    if gate.status is CommercialGateStatus.VERIFIED
                )
            )
            for gate_id in REQUIRED_COMMERCIAL_GATE_IDS:
                gate = gate_map.get(gate_id)
                if gate is None or gate.status is not CommercialGateStatus.VERIFIED:
                    blockers.append(f"COMMERCIAL_GATE_UNVERIFIED:{gate_id}")
        if custody is None:
            blockers.append("SOURCE_CUSTODY_NOT_APPROVED")
        if organic is None:
            blockers.append("ORGANIC_VALIDATION_NOT_PERFORMED")
        elif organic.validation_level is not OrganicValidationLevel.ESTATE_PILOT:
            blockers.append("ESTATE_PILOT_NOT_MEASURED")
        elif organic.status is not OrganicValidationStatus.ESTATE_PILOT_MEASURED:
            blockers.append("ESTATE_PILOT_PRODUCT_GAP")
        if organic and organic.materially_false_confident_behaviors:
            blockers.append("MATERIALLY_FALSE_CONFIDENT_BEHAVIOR")
        if any(
            surface.status is NamingStatus.PROVISIONAL_PENDING_NAMING_BASELINE
            for surface in capabilities.naming_surfaces
        ):
            blockers.append("NAMING_BASELINE_PENDING")
        if deployment_gates:
            blockers.extend(deployment_gates)
        if customer_boundary_gates:
            blockers.extend(customer_boundary_gates)

        organic_measured = bool(
            organic
            and organic.validation_level is OrganicValidationLevel.ESTATE_PILOT
            and organic.status is OrganicValidationStatus.ESTATE_PILOT_MEASURED
        )
        maturity = CommercialMaturity.COMMERCIALIZATION_CANDIDATE
        without_digest = {
            "schema_version": "commercial-readiness-report-1.0",
            "distribution_name": capabilities.distribution_name,
            "distribution_version": capabilities.distribution_version,
            "commercial_maturity": maturity,
            "capability_manifest_valid": True,
            "custody_ready": custody is not None,
            "organic_validation_status": organic.status if organic else None,
            "organic_estate_pilot_measured": organic_measured,
            "deployment_gates": deployment_gates,
            "verified_gate_ids": verified_gate_ids,
            "customer_boundary_gates": customer_boundary_gates,
            "blockers": tuple(sorted(set(blockers))),
            "naming_status": (
                NamingStatus.FROZEN_WITH_COMPATIBILITY_POLICY
                if all(surface.status is NamingStatus.FROZEN_WITH_COMPATIBILITY_POLICY for surface in capabilities.naming_surfaces)
                else NamingStatus.PROVISIONAL_PENDING_NAMING_BASELINE
            ),
            "editions_status": "DEFERRED",
        }
        return CommercialReadinessReport(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )


class OrganicValidationService:
    """Runs unmodified organic source through the admitted static pipeline.

    A grammar gap is recorded as a product outcome. Customer source is never
    rewritten to satisfy the parser.
    """

    def __init__(self, pipeline: EndToEndPipeline | None = None) -> None:
        self._pipeline = pipeline or EndToEndPipeline()
        self._commercial = CommercialReadinessService()

    def load_manifest(self, path: Path) -> OrganicValidationManifest:
        payload = _load_json(path)
        _validate_schema(payload, "organic-validation-manifest-1.0.schema.json")
        manifest = OrganicValidationManifest.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = manifest.model_dump(mode="python", exclude={"content_digest"})
        if manifest.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Organic validation manifest content_digest mismatch.")
        return manifest

    def load_reviews(self, path: Path | None) -> OrganicReviewBatch | None:
        if path is None:
            return None
        payload = _load_json(path)
        _validate_schema(payload, "organic-review-batch-1.0.schema.json")
        reviews = OrganicReviewBatch.model_validate_json(path.read_text(encoding="utf-8"))
        without_digest = reviews.model_dump(mode="python", exclude={"content_digest"})
        if reviews.content_digest != canonical_digest(without_digest):
            raise CommercialValidationError("Organic review batch content_digest mismatch.")
        return reviews

    @staticmethod
    def _is_under_allowed_root(source: Path, roots: tuple[str, ...]) -> bool:
        resolved = source.resolve()
        for root_text in roots:
            root = Path(root_text).resolve()
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def run(
        self,
        *,
        manifest: OrganicValidationManifest,
        custody: OrganicSourceCustodyAgreement,
        output_dir: Path,
        reviews: OrganicReviewBatch | None = None,
    ) -> OrganicValidationReport:
        if manifest.custody_agreement_id != custody.agreement_id:
            raise CommercialValidationError("Organic manifest custody agreement ID mismatch.")
        if manifest.custody_agreement_digest != custody.content_digest:
            raise CommercialValidationError("Organic manifest custody agreement digest mismatch.")
        if reviews and reviews.validation_id != manifest.validation_id:
            raise CommercialValidationError("Review batch validation_id does not match organic manifest.")

        review_by_case = {review.case_id: review for review in reviews.reviews} if reviews else {}
        outcomes: list[OrganicCaseOutcome] = []
        blocker_counter: Counter[str] = Counter()
        parse_counter: Counter[str] = Counter()
        total_admitted = 0
        total_blocked = 0
        semantic_completed = 0
        semantic_blocked = 0
        source_modification_count = 0
        false_confident_count = 0
        owner_confirmations = 0
        reviewed_procedure_count = 0
        total_review_effort_minutes = 0
        procedures_with_admitted_scenarios = 0
        procedures_with_blocked_scenarios = 0
        classification_counter: Counter[str] = Counter()
        internal_failures = 0

        output_dir.mkdir(parents=True, exist_ok=True)
        for index, case in enumerate(manifest.cases, start=1):
            source = Path(case.source_path).resolve()
            if not self._is_under_allowed_root(source, custody.allowed_source_roots):
                raise CommercialValidationError(
                    f"Organic source {source} is outside every custody-approved source root."
                )
            if not source.is_file():
                raise CommercialValidationError(f"Organic source file not found: {source}")
            before = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            case_output = output_dir / f"{index:03d}-{case.case_id}"
            parse_outcome = "INTERNAL_PRODUCT_FAILURE"
            parse_findings: tuple[str, ...] = ()
            semantic_status = "NOT_STARTED"
            admitted = 0
            blocked = 0
            blockers: tuple[str, ...] = ()
            internal_failure: str | None = None
            try:
                run_manifest = self._pipeline.run(
                    source=source,
                    output_dir=case_output,
                    authority_mode=AuthorityMode.NONE,
                    governance_db=None,
                )
                parse_payload = _load_json(case_output / "02-parse.json")
                parse_outcome = str(parse_payload.get("outcome", "UNKNOWN"))
                parse_findings = tuple(
                    sorted(str(item.get("code", "PARSE_FINDING")) for item in parse_payload.get("findings", []))
                )
                scenario_path = case_output / "04-scenario-specs.json"
                if scenario_path.is_file():
                    scenario_payload = _load_json(scenario_path)
                    admitted = len(scenario_payload.get("scenario_specs", []))
                    blocked = sum(
                        1
                        for item in scenario_payload.get("compilation_results", [])
                        if item.get("compilation_status") == "BLOCKED"
                    )
                    blockers = tuple(
                        sorted(
                            {
                                str(code)
                                for item in scenario_payload.get("compilation_results", [])
                                for code in item.get("blockers", [])
                            }
                        )
                    )
                semantic_record = next(
                    (item for item in run_manifest.stage_records if item.stage == "PHASE_2_3_4_SEMANTIC"),
                    None,
                )
                semantic_status = semantic_record.status.value if semantic_record else "NOT_STARTED"
            except Exception as exc:  # product failures must remain visible, not rewrite customer source
                internal_failure = f"{type(exc).__name__}: {exc}"
                internal_failures += 1

            after = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            source_unmodified = before == after
            if not source_unmodified:
                source_modification_count += 1
            parse_counter[parse_outcome] += 1
            if semantic_status == PipelineStageStatus.SUCCEEDED.value:
                semantic_completed += 1
            else:
                semantic_blocked += 1
            total_admitted += admitted
            total_blocked += blocked
            if admitted:
                procedures_with_admitted_scenarios += 1
            if blocked:
                procedures_with_blocked_scenarios += 1
            if semantic_status != PipelineStageStatus.SUCCEEDED.value or admitted == 0:
                blocker_counter.update(blockers or parse_findings)

            review = review_by_case.get(case.case_id)
            if review:
                reviewed_procedure_count += 1
                total_review_effort_minutes += review.review_effort_minutes
            classifications = tuple(
                item.classification for item in review.assertion_reviews
            ) if review else ()
            classification_counter.update(value.value for value in classifications)
            material_false = sum(
                1 for item in review.assertion_reviews if item.materially_false_confident_behavior
            ) if review else 0
            false_confident_count += material_false
            confirmations = (
                review.decision_arms_confirmed,
                review.precedence_confirmed,
                review.terminal_outcomes_confirmed,
                review.handler_effects_confirmed,
                review.major_mutations_confirmed,
            ) if review else ()
            confirmation_complete = bool(
                confirmations
                and any(value is ReviewConfirmation.CONFIRMED for value in confirmations)
                and all(
                    value in {ReviewConfirmation.CONFIRMED, ReviewConfirmation.NOT_APPLICABLE}
                    for value in confirmations
                )
            )
            if confirmation_complete:
                owner_confirmations += 1

            outcome_payload = {
                "case_id": case.case_id,
                "source_path": source.as_posix(),
                "source_digest_before": before,
                "source_digest_after": after,
                "source_unmodified": source_unmodified,
                "parse_outcome": parse_outcome,
                "parse_findings": parse_findings,
                "semantic_status": semantic_status,
                "admitted_scenarios": admitted,
                "blocked_scenarios": blocked,
                "blocker_codes": blockers,
                "internal_failure": internal_failure,
                "review_classifications": classifications,
                "materially_false_confident_behaviors": material_false,
                "owner_rule_confirmation_complete": confirmation_complete,
            }
            outcomes.append(OrganicCaseOutcome(**outcome_payload))

        first_five = outcomes[:5]
        pre_semantic_failures = sum(1 for item in first_five if item.semantic_status != "SUCCEEDED")
        recurring = tuple(sorted(code for code, count in blocker_counter.items() if count >= 2))
        source_digests = [item.source_digest_before for item in outcomes]
        unique_source_digests = len(set(source_digests))
        pause_reasons: list[str] = []
        if (
            manifest.validation_level is not OrganicValidationLevel.ORGANIC_SMOKE
            and unique_source_digests != len(outcomes)
        ):
            pause_reasons.append("DUPLICATE_SOURCE_DIGESTS_IN_ORGANIC_CORPUS")
        if len(first_five) >= 5 and pre_semantic_failures >= 3:
            pause_reasons.append("THREE_OF_FIRST_FIVE_FAILED_BEFORE_SEMANTIC_ANALYSIS")
        if recurring:
            pause_reasons.append("RECURRING_MATERIAL_BLOCKER")
        if false_confident_count:
            pause_reasons.append("MATERIALLY_FALSE_CONFIDENT_BEHAVIOR")
        if source_modification_count:
            pause_reasons.append("CUSTOMER_SOURCE_MODIFIED")
        if internal_failures:
            pause_reasons.append("INTERNAL_PRODUCT_FAILURE")

        if internal_failures:
            status = OrganicValidationStatus.FAILED_INTERNAL
        elif manifest.validation_level is OrganicValidationLevel.ORGANIC_SMOKE and (
            not outcomes
            or outcomes[0].semantic_status != PipelineStageStatus.SUCCEEDED.value
            or pause_reasons
        ):
            status = OrganicValidationStatus.ORGANIC_SMOKE_FAILED
            if outcomes and outcomes[0].semantic_status != PipelineStageStatus.SUCCEEDED.value:
                if "ORGANIC_SMOKE_DID_NOT_REACH_SEMANTIC_ANALYSIS" not in pause_reasons:
                    pause_reasons.append("ORGANIC_SMOKE_DID_NOT_REACH_SEMANTIC_ANALYSIS")
        elif pause_reasons:
            status = OrganicValidationStatus.PILOT_PAUSED_PRODUCT_GAP
        elif manifest.validation_level is OrganicValidationLevel.ORGANIC_SMOKE:
            status = OrganicValidationStatus.ORGANIC_SMOKE_COMPLETED
        elif manifest.validation_level is OrganicValidationLevel.DISCOVERY_SAMPLE:
            status = OrganicValidationStatus.DISCOVERY_COMPLETED
        else:
            status = OrganicValidationStatus.ESTATE_PILOT_MEASURED

        commercial_claim_eligible = bool(
            manifest.validation_level is OrganicValidationLevel.ESTATE_PILOT
            and status is OrganicValidationStatus.ESTATE_PILOT_MEASURED
            and false_confident_count == 0
            and classification_counter["FALSE"] == 0
            and classification_counter["MISLEADING"] == 0
            and source_modification_count == 0
            and reviewed_procedure_count == len(outcomes)
            and owner_confirmations == len(outcomes)
        )
        without_digest = {
            "schema_version": "organic-validation-report-1.0",
            "validation_id": manifest.validation_id,
            "validation_level": manifest.validation_level,
            "status": status,
            "customer_ref": manifest.customer_ref,
            "estate_ref": manifest.estate_ref,
            "custody_agreement_id": custody.agreement_id,
            "source_count": len(outcomes),
            "unique_source_digests": unique_source_digests,
            "parsed_complete": parse_counter["PARSES_COMPLETE"],
            "parsed_partial": parse_counter["PARSES_PARTIAL"],
            "refused_expected": parse_counter["REFUSES_EXPECTED"],
            "refused_unexpected": parse_counter["REFUSES_UNEXPECTED"],
            "semantic_completed": semantic_completed,
            "semantic_blocked": semantic_blocked,
            "admitted_scenarios": total_admitted,
            "blocked_scenarios": total_blocked,
            "source_modification_count": source_modification_count,
            "materially_false_confident_behaviors": false_confident_count,
            "owner_rule_confirmations_complete": owner_confirmations,
            "reviewed_procedure_count": reviewed_procedure_count,
            "total_review_effort_minutes": total_review_effort_minutes,
            "procedures_with_admitted_scenarios": procedures_with_admitted_scenarios,
            "procedures_with_blocked_scenarios": procedures_with_blocked_scenarios,
            "parsed_complete_rate": (parse_counter["PARSES_COMPLETE"] / len(outcomes)) if outcomes else 0.0,
            "semantic_completion_rate": (semantic_completed / len(outcomes)) if outcomes else 0.0,
            "classification_counts": dict(sorted(classification_counter.items())),
            "recurring_blocker_codes": recurring,
            "pause_reasons": tuple(pause_reasons),
            "case_outcomes": tuple(outcomes),
            "commercial_claim_eligible": commercial_claim_eligible,
        }
        report = OrganicValidationReport(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )
        _write(output_dir / "organic-validation-report.json", report)
        return report
