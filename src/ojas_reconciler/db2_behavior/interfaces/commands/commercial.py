from __future__ import annotations

import argparse

from ojas_reconciler.db2_behavior.commercial.models import (
    OrganicValidationReport, OrganicPauseDisposition, PauseDispositionDecision, PauseCause,
    PauseResponsibility, ProcedureCompositionContract,
)
from ojas_reconciler.db2_behavior.commercial.public_repository import PublicRepositoryOrganicValidationService
from ojas_reconciler.db2_behavior.commercial.service import (
    CommercialReadinessService,
    CommercialValidationError,
    OrganicValidationService,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest, canonical_json_bytes
from ojas_reconciler.db2_behavior.commercial.workflows import (
    CommercialOperationsService, CompositionContractService, OrganicPauseDispositionService,
    ProcedureCheckService, ProcedureKnowledgeGraphService, RelationalFixturePlanningService,
)


def _emit(args: argparse.Namespace, value: object) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
        print(f"Commercial artifact: {args.output}")
    else:
        print(payload.decode("utf-8"), end="")


def handle(args: argparse.Namespace) -> int | None:
    service = CommercialReadinessService()
    try:
        if args.command == "commercial-serve":
            try:
                import uvicorn
                from ojas_reconciler.db2_behavior.commercial_ui.app import CommercialUiSettings, UiRole, create_app
            except ModuleNotFoundError as exc:
                raise SystemExit(
                    "UI_EXTRA_REQUIRED: install atlas-procedure-intelligence[ui]."
                ) from exc

            settings = CommercialUiSettings(
                workspace=args.workspace, tenant_ref=args.tenant_ref, actor_ref=args.actor_ref,
                role=UiRole(args.role), trust_identity_headers=args.trust_identity_headers,
            )
            uvicorn.run(create_app(settings), host=args.host, port=args.port)
            return 0

        if args.command == "commercial-create-disposition":
            artifact = OrganicPauseDispositionService().build(
                report_path=args.report, decision=PauseDispositionDecision(args.decision),
                cause=PauseCause(args.cause), responsibility=PauseResponsibility(args.responsibility),
                rationale=args.rationale, remediation_actions=tuple(args.remediation_action),
                owner_ref=args.owner_ref, approved_by_ref=args.approved_by_ref,
                decided_at=args.decided_at, target_reassessment_at=args.target_reassessment_at,
            )
            _emit(args, artifact)
            return 0

        if args.command == "commercial-build-procedure-checks":
            artifact = ProcedureCheckService().build(args.run_dir)
            _emit(args, artifact)
            return 0

        if args.command == "commercial-plan-relational-fixtures":
            artifact = RelationalFixturePlanningService().build(
                procedure_ref=args.procedure_ref, relation_refs=tuple(args.relation_ref), catalog_paths=tuple(args.catalog)
            )
            _emit(args, artifact)
            return 0

        if args.command == "commercial-assess-composition":
            contract = ProcedureCompositionContract.model_validate_json(args.contract.read_text(encoding="utf-8"))
            if contract.content_digest != canonical_digest(contract.model_dump(mode="python", exclude={"content_digest"})):
                raise CommercialValidationError("Composition contract content_digest mismatch.")
            artifact = CompositionContractService().assess(
                contract, upstream_semantic_digest=args.upstream_digest, downstream_semantic_digest=args.downstream_digest,
                transaction_contract_digest=args.transaction_digest, orchestration_definition_digest=args.orchestration_digest,
            )
            _emit(args, artifact)
            return 0

        if args.command == "commercial-build-knowledge-graph":
            artifact = ProcedureKnowledgeGraphService().build(args.run_dir)
            _emit(args, artifact)
            return 0

        if args.command == "commercial-generate-sbom":
            path = CommercialOperationsService().generate_sbom(args.output)
            print(f"Commercial artifact: {path}")
            return 0

        if args.command == "commercial-build-support-bundle":
            path = CommercialOperationsService().build_support_bundle(
                run_dir=args.run_dir, output=args.output, include_source=args.include_source
            )
            print(f"Commercial artifact: {path}")
            return 0

        if args.command == "commercial-export-templates":
            emitted = service.export_templates(args.output_dir)
            print(f"Commercial templates exported: {len(emitted)}")
            for path in emitted:
                print(path)
            return 0

        if args.command == "commercial-seal-artifact":
            artifact = service.seal_artifact(args.input, artifact_type=args.artifact_type)
            _emit(args, artifact)
            return 0

        if args.command == "commercial-validate-capabilities":
            manifest = service.load_capability_manifest(args.manifest)
            _emit(args, manifest)
            return 0

        if args.command == "commercial-validate-custody":
            agreement = service.load_custody_agreement(args.agreement, as_of=args.as_of)
            _emit(args, agreement)
            return 0

        if args.command == "commercial-run-public-repository-validation":
            public_service = PublicRepositoryOrganicValidationService()
            manifest = public_service.load_manifest(args.manifest)
            report = public_service.run(
                manifest=manifest,
                repository_root=args.repository_root,
                output=args.output,
            )
            print(f"Public repository validation: {args.output}")
            print(f"Pause reasons: {', '.join(report.pause_reasons) or 'none'}")
            return 0 if not report.pause_reasons else 12

        if args.command == "commercial-run-organic-validation":
            organic_service = OrganicValidationService()
            agreement = service.load_custody_agreement(args.custody_agreement, as_of=args.as_of)
            manifest = organic_service.load_manifest(args.manifest)
            reviews = organic_service.load_reviews(args.reviews)
            report = organic_service.run(
                manifest=manifest,
                custody=agreement,
                output_dir=args.output_dir,
                reviews=reviews,
            )
            print(f"Organic validation status: {report.status.value}")
            print(f"Organic validation report: {args.output_dir / 'organic-validation-report.json'}")
            return 0 if not report.pause_reasons else 12

        if args.command == "commercial-assess-readiness":
            capabilities = service.load_capability_manifest(args.capabilities)
            custody = (
                service.load_custody_agreement(args.custody_agreement, as_of=args.as_of)
                if args.custody_agreement
                else None
            )
            organic = service.load_organic_report(args.organic_report) if args.organic_report else None
            gate_evidence = service.load_gate_evidence(args.gate_evidence) if args.gate_evidence else None
            report = service.assess(
                capabilities=capabilities,
                custody=custody,
                organic=organic,
                gate_evidence=gate_evidence,
                deployment_gates=tuple(args.deployment_gate),
                customer_boundary_gates=tuple(args.customer_boundary_gate),
            )
            _emit(args, report)
            return 0 if not report.blockers else 13
    except CommercialValidationError as exc:
        print(f"COMMERCIAL_BOUNDARY_BLOCKED: {exc}")
        return 12
    return None
