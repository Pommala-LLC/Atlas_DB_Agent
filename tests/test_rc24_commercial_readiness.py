from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from ojas_reconciler.db2_behavior.commercial.models import (
    AssertionModality,
    AssertionReview,
    CapabilityEntry,
    CapabilityState,
    CommercialCapabilityManifest,
    CommercialMaturity,
    CommercialGateEvidence,
    CommercialGateRecord,
    CommercialGateStatus,
    CustodyAgreementStatus,
    CustodyApprovalEvidenceMode,
    CustomerInputResponsibility,
    NamingStatus,
    NamingSurface,
    OrganicProcedureCase,
    OrganicProcedureReview,
    OrganicReviewBatch,
    OrganicSourceCustodyAgreement,
    OrganicValidationLevel,
    OrganicValidationManifest,
    OrganicValidationStatus,
    ProcessingLocation,
    RegressionFixturePermission,
    ReviewClassification,
    ReviewConfirmation,
)
from ojas_reconciler.db2_behavior.commercial.service import (
    CommercialReadinessService,
    CommercialValidationError,
    OrganicValidationService,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.interfaces.argparse_builder import build_parser


FIXTURES = Path(__file__).parent / "fixtures"


def _with_digest(model_type, payload: dict):
    return model_type(**payload, content_digest=canonical_digest(payload))


def _capability_manifest() -> CommercialCapabilityManifest:
    payload = {
        "schema_version": "commercial-capability-manifest-1.0",
        "distribution_name": "db2-behavior-extraction-framework",
        "distribution_version": "1.0.1rc24",
        "commercial_maturity": CommercialMaturity.ORGANIC_VALIDATION_REQUIRED,
        "naming_surfaces": (
            NamingSurface(
                surface_kind="DISTRIBUTION",
                current_value="db2-behavior-extraction-framework",
                status=NamingStatus.PROVISIONAL_PENDING_NAMING_BASELINE,
            ),
        ),
        "capabilities": (
            CapabilityEntry(
                capability_id="static",
                display_name="Static extraction",
                state=CapabilityState.COMMERCIAL_PREVIEW,
                claim_text="Extract technical behavior evidence.",
                datasheet_eligible=True,
                evidence_refs=("evidence:test",),
            ),
            CapabilityEntry(
                capability_id="vocabulary",
                display_name="Readable candidates",
                state=CapabilityState.CUSTOMER_INPUT_REQUIRED,
                claim_text="Generate readable technical candidates with approved vocabulary.",
                datasheet_eligible=True,
                customer_input_requirements=("Approved vocabulary",),
            ),
        ),
        "prohibited_datasheet_claims": ("Automatic approved BDD promotion",),
        "customer_input_responsibilities": (
            CustomerInputResponsibility(
                input_type="APPROVED_VOCABULARY",
                prepared_by="Product-assisted discovery",
                validated_by="Customer domain authority",
                maintained_by="Customer governance",
                delivery_model="Domain enablement service",
            ),
        ),
        "edition_model_status": "DEFERRED_UNTIL_TWO_SUPPORTED_BUNDLES_EXIST",
    }
    return _with_digest(CommercialCapabilityManifest, payload)


def _custody(root: Path, *, status: CustodyAgreementStatus = CustodyAgreementStatus.APPROVED):
    payload = {
        "schema_version": "organic-source-custody-agreement-1.0",
        "agreement_id": "custody-001",
        "customer_ref": "customer:test",
        "status": status,
        "asserted_approver_ref": "authority:security" if status is CustodyAgreementStatus.APPROVED else None,
        "approval_evidence_mode": CustodyApprovalEvidenceMode.CUSTOMER_ENVIRONMENT_SELF_ASSERTED,
        "approval_evidence_refs": (),
        "approval_envelope_digest": None,
        "effective_from": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "processing_location": ProcessingLocation.CUSTOMER_ENVIRONMENT,
        "authorized_role_refs": ("role:analyst",),
        "encryption_in_transit_required": True,
        "encryption_at_rest_required": True,
        "access_logging_required": True,
        "source_retention_days": 0,
        "derived_artifact_retention_days": 30,
        "deletion_request_sla_days": 5,
        "deletion_attestation_required": True,
        "backup_policy": "EXCLUDED_FROM_VENDOR_BACKUPS",
        "regression_fixture_permission": RegressionFixturePermission.NO_RETENTION,
        "model_training_use": "PROHIBITED",
        "cross_border_processing": "PROHIBITED",
        "incident_notification_hours": 24,
        "subprocessor_policy": "NO_UNAPPROVED_SUBPROCESSORS",
        "allowed_source_roots": (root.resolve().as_posix(),),
    }
    return _with_digest(OrganicSourceCustodyAgreement, payload)


def _manifest(source: Path, custody: OrganicSourceCustodyAgreement, *, level=OrganicValidationLevel.ORGANIC_SMOKE):
    count = 1 if level is OrganicValidationLevel.ORGANIC_SMOKE else 5
    cases = tuple(
        OrganicProcedureCase(
            case_id=f"case-{index:02d}",
            source_path=source.resolve().as_posix(),
            source_origin="ORGANIC_CUSTOMER_SOURCE",
            customer_authorization_ref="authorization:test",
            authored_for_tool=False,
            source_must_remain_unmodified=True,
        )
        for index in range(1, count + 1)
    )
    payload = {
        "schema_version": "organic-validation-manifest-1.0",
        "validation_id": "validation-001",
        "validation_level": level,
        "customer_ref": "customer:test",
        "estate_ref": "estate:test",
        "custody_agreement_id": custody.agreement_id,
        "custody_agreement_digest": custody.content_digest,
        "cases": cases,
    }
    return _with_digest(OrganicValidationManifest, payload)


def _write(path: Path, model) -> Path:
    path.write_bytes(canonical_json_bytes(model) + b"\n")
    return path


def test_capability_states_prevent_designed_feature_datasheet_claim() -> None:
    with pytest.raises(ValidationError, match="cannot be represented as available"):
        CapabilityEntry(
            capability_id="catalog",
            display_name="Catalog lineage",
            state=CapabilityState.DESIGNED_NOT_IMPLEMENTED,
            claim_text="Resolve all views.",
            datasheet_eligible=True,
        )


def test_customer_input_capability_requires_responsibility_matrix() -> None:
    manifest = _capability_manifest()
    payload = manifest.model_dump(mode="python", exclude={"content_digest"})
    payload["customer_input_responsibilities"] = ()
    with pytest.raises(ValidationError, match="responsibility matrix"):
        CommercialCapabilityManifest(**payload, content_digest=canonical_digest(payload))


def test_manifest_cannot_self_promote_to_generally_available() -> None:
    manifest = _capability_manifest()
    payload = manifest.model_dump(mode="python", exclude={"content_digest"})
    payload["commercial_maturity"] = CommercialMaturity.GENERALLY_AVAILABLE
    with pytest.raises(ValidationError, match="cannot self-promote"):
        CommercialCapabilityManifest(**payload, content_digest=canonical_digest(payload))


def test_commercial_templates_export_from_packaged_resources(tmp_path: Path) -> None:
    emitted = CommercialReadinessService().export_templates(tmp_path / "templates")
    names = {path.name for path in emitted}
    assert {
        "capability-manifest.json",
        "custody-agreement-draft.json",
        "commercial-gate-evidence-draft.json",
        "organic-validation-manifest-template.json",
        "organic-review-batch-template.json",
        "README.md",
    }.issubset(names)


def test_commercial_seal_artifact_adds_canonical_digest(tmp_path: Path) -> None:
    manifest = _capability_manifest()
    payload = manifest.model_dump(mode="json", exclude={"content_digest"})
    source = tmp_path / "capabilities-unsealed.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    sealed = CommercialReadinessService().seal_artifact(
        source, artifact_type="CAPABILITY_MANIFEST"
    )

    assert isinstance(sealed, CommercialCapabilityManifest)
    assert sealed.content_digest == canonical_digest(
        sealed.model_dump(mode="python", exclude={"content_digest"})
    )


def test_custody_agreement_is_required_and_expiry_is_enforced(tmp_path: Path) -> None:
    service = CommercialReadinessService()
    draft = _custody(tmp_path, status=CustodyAgreementStatus.DRAFT)
    path = _write(tmp_path / "custody.json", draft)
    with pytest.raises(CommercialValidationError, match="requires APPROVED"):
        service.load_custody_agreement(path, as_of="2026-07-29T00:00:00Z")

    approved = _custody(tmp_path)
    path = _write(tmp_path / "custody-approved.json", approved)
    with pytest.raises(CommercialValidationError, match="expired"):
        service.load_custody_agreement(path, as_of="2027-01-01T00:00:00Z")


def test_vendor_processing_requires_verified_external_custody_envelope(tmp_path: Path) -> None:
    payload = _custody(tmp_path).model_dump(mode="python", exclude={"content_digest"})
    payload["processing_location"] = ProcessingLocation.VENDOR_ISOLATED_WORKSPACE
    with pytest.raises(ValidationError, match="VERIFIED_EXTERNAL_ENVELOPE"):
        OrganicSourceCustodyAgreement(**payload, content_digest=canonical_digest(payload))


def test_organic_case_rejects_source_authored_for_tool(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not organic validation evidence"):
        OrganicProcedureCase(
            case_id="synthetic",
            source_path=(tmp_path / "source.sql").as_posix(),
            customer_authorization_ref="authorization:test",
            authored_for_tool=True,
        )


def test_estate_pilot_requires_twenty_to_fifty_sources(tmp_path: Path) -> None:
    custody = _custody(tmp_path)
    cases = tuple(
        OrganicProcedureCase(
            case_id=f"case-{index}",
            source_path=(tmp_path / f"case-{index}.sql").as_posix(),
            customer_authorization_ref="authorization:test",
        )
        for index in range(19)
    )
    payload = {
        "schema_version": "organic-validation-manifest-1.0",
        "validation_id": "pilot",
        "validation_level": OrganicValidationLevel.ESTATE_PILOT,
        "customer_ref": "customer:test",
        "estate_ref": "estate:test",
        "custody_agreement_id": custody.agreement_id,
        "custody_agreement_digest": custody.content_digest,
        "cases": cases,
    }
    with pytest.raises(ValidationError, match="20 to 50"):
        OrganicValidationManifest(**payload, content_digest=canonical_digest(payload))


def test_organic_smoke_preserves_source_and_cannot_create_estate_claim(tmp_path: Path) -> None:
    customer_root = tmp_path / "customer-source"
    customer_root.mkdir()
    source = customer_root / "organic.sql"
    source.write_bytes((FIXTURES / "eligible_claim.sql").read_bytes())
    before = source.read_bytes()
    custody = _custody(customer_root)
    manifest = _manifest(source, custody)

    report = OrganicValidationService().run(
        manifest=manifest,
        custody=custody,
        output_dir=tmp_path / "report",
    )

    assert report.status is OrganicValidationStatus.ORGANIC_SMOKE_COMPLETED
    assert report.source_count == 1
    assert report.case_outcomes[0].source_unmodified is True
    assert source.read_bytes() == before
    assert report.commercial_claim_eligible is False
    assert report.semantic_completed == 1


def test_unsupported_organic_syntax_is_a_product_finding_not_a_rewrite(tmp_path: Path) -> None:
    customer_root = tmp_path / "customer-source"
    customer_root.mkdir()
    source = customer_root / "unsupported.sql"
    source.write_text("CREATE PROCEDURE X.Y(IN P INTEGER) BEGIN THIS IS NOT SQL;", encoding="utf-8")
    before = source.read_text(encoding="utf-8")
    custody = _custody(customer_root)
    manifest = _manifest(source, custody)

    report = OrganicValidationService().run(
        manifest=manifest,
        custody=custody,
        output_dir=tmp_path / "report",
    )

    assert report.status in {
        OrganicValidationStatus.ORGANIC_SMOKE_FAILED,
        OrganicValidationStatus.FAILED_INTERNAL,
    }
    assert source.read_text(encoding="utf-8") == before
    assert report.case_outcomes[0].source_unmodified is True
    assert report.commercial_claim_eligible is False


def test_source_outside_approved_root_is_blocked_before_pipeline(tmp_path: Path) -> None:
    approved_root = tmp_path / "approved"
    approved_root.mkdir()
    outside = tmp_path / "outside.sql"
    outside.write_bytes((FIXTURES / "eligible_claim.sql").read_bytes())
    custody = _custody(approved_root)
    manifest = _manifest(outside, custody)

    with pytest.raises(CommercialValidationError, match="outside every custody-approved source root"):
        OrganicValidationService().run(
            manifest=manifest,
            custody=custody,
            output_dir=tmp_path / "report",
        )


def test_must_assertion_contradicted_by_source_is_materially_false() -> None:
    review = AssertionReview(
        assertion_ref="assertion:mutation",
        observable_kind="MUTATION",
        modality=AssertionModality.MUST,
        classification=ReviewClassification.FALSE,
        source_contradiction_ref="source:line-20",
    )
    assert review.materially_false_confident_behavior is True

    conditional = AssertionReview(
        assertion_ref="assertion:conditional",
        observable_kind="MUTATION",
        modality=AssertionModality.MUST_IF_CONTRACT_HOLDS,
        classification=ReviewClassification.FALSE,
        source_contradiction_ref="source:line-20",
    )
    assert conditional.materially_false_confident_behavior is False


def test_false_confident_review_fails_organic_smoke(tmp_path: Path) -> None:
    customer_root = tmp_path / "customer-source"
    customer_root.mkdir()
    source = customer_root / "organic.sql"
    source.write_bytes((FIXTURES / "eligible_claim.sql").read_bytes())
    custody = _custody(customer_root)
    manifest = _manifest(source, custody)
    review_payload = {
        "schema_version": "organic-review-batch-1.0",
        "validation_id": manifest.validation_id,
        "reviews": (
            OrganicProcedureReview(
                case_id="case-01",
                reviewer_ref="sme:test",
                decision_arms_confirmed=ReviewConfirmation.DISAGREED,
                precedence_confirmed=ReviewConfirmation.DISAGREED,
                terminal_outcomes_confirmed=ReviewConfirmation.DISAGREED,
                handler_effects_confirmed=ReviewConfirmation.NOT_APPLICABLE,
                major_mutations_confirmed=ReviewConfirmation.NOT_APPLICABLE,
                assertion_reviews=(
                    AssertionReview(
                        assertion_ref="assertion:false",
                        observable_kind="DECISION_PRECEDENCE",
                        modality=AssertionModality.MUST,
                        classification=ReviewClassification.FALSE,
                        source_contradiction_ref="source:reviewed-lineage",
                    ),
                ),
                review_effort_minutes=15,
            ),
        ),
    }
    reviews = _with_digest(OrganicReviewBatch, review_payload)

    report = OrganicValidationService().run(
        manifest=manifest,
        custody=custody,
        output_dir=tmp_path / "report",
        reviews=reviews,
    )

    assert report.status is OrganicValidationStatus.ORGANIC_SMOKE_FAILED
    assert report.materially_false_confident_behaviors == 1
    assert "MATERIALLY_FALSE_CONFIDENT_BEHAVIOR" in report.pause_reasons
    assert report.classification_counts == {"FALSE": 1}


def test_readiness_fails_closed_when_gate_evidence_is_omitted(tmp_path: Path) -> None:
    report = CommercialReadinessService().assess(
        capabilities=_capability_manifest(),
        custody=_custody(tmp_path),
        organic=None,
        gate_evidence=None,
        deployment_gates=(),
        customer_boundary_gates=(),
    )
    assert "COMMERCIAL_GATE_UNVERIFIED:SBOM" in report.blockers
    assert "COMMERCIAL_GATE_UNVERIFIED:NATIVE_WINDOWS_PYTHON_3_14" in report.blockers
    assert report.verified_gate_ids == ()


def test_verified_gate_requires_evidence_reference() -> None:
    with pytest.raises(ValidationError, match="requires evidence refs"):
        CommercialGateRecord(
            gate_id="SBOM",
            status=CommercialGateStatus.VERIFIED,
        )


def test_readiness_remains_candidate_with_provisional_naming(tmp_path: Path) -> None:
    capability = _capability_manifest()
    custody = _custody(tmp_path)
    report = CommercialReadinessService().assess(
        capabilities=capability,
        custody=custody,
        organic=None,
        gate_evidence=None,
        deployment_gates=("WINDOWS_OFFLINE_WHEELHOUSE_UNVERIFIED",),
        customer_boundary_gates=(),
    )

    assert report.commercial_maturity is CommercialMaturity.COMMERCIALIZATION_CANDIDATE
    assert report.naming_status is NamingStatus.PROVISIONAL_PENDING_NAMING_BASELINE
    assert "ORGANIC_VALIDATION_NOT_PERFORMED" in report.blockers
    assert "NAMING_BASELINE_PENDING" in report.blockers
    assert report.editions_status == "DEFERRED"


def test_commercial_commands_are_registered() -> None:
    parser = build_parser()
    assert parser.parse_args([
        "commercial-export-templates",
        "--output-dir",
        "templates",
    ]).command == "commercial-export-templates"
    assert parser.parse_args([
        "commercial-seal-artifact",
        "--artifact-type",
        "CAPABILITY_MANIFEST",
        "capabilities.json",
        "--output",
        "sealed.json",
    ]).command == "commercial-seal-artifact"
    assert parser.parse_args([
        "commercial-validate-capabilities",
        "capabilities.json",
    ]).command == "commercial-validate-capabilities"
    assert parser.parse_args([
        "commercial-validate-custody",
        "custody.json",
        "--as-of",
        "2026-07-29T00:00:00Z",
    ]).command == "commercial-validate-custody"
    assert parser.parse_args([
        "commercial-run-organic-validation",
        "organic.json",
        "--custody-agreement",
        "custody.json",
        "--as-of",
        "2026-07-29T00:00:00Z",
        "--output-dir",
        "reports/organic",
    ]).command == "commercial-run-organic-validation"
