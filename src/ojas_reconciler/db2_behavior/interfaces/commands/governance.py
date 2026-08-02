from __future__ import annotations

import argparse

from ojas_reconciler.db2_behavior.bdd.models import BddCompilationBatch
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpec, ScenarioSpecBatchResult
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.governance.adapters.sqlite import GovernanceStore, GovernanceStoreError
from ojas_reconciler.db2_behavior.governance.models import CertificationEnvelope, PlatformDecisionEnvelope
from ojas_reconciler.db2_behavior.runtime.models import RuntimeVerificationBatch

def handle(args: argparse.Namespace) -> int | None:
    if args.command.startswith("governance-"):
        store = GovernanceStore(args.db)
        try:
            if args.command == "governance-init":
                store.initialize(applied_at=args.at)
                payload_obj = {"database": args.db.as_posix(), "status": "INITIALIZED"}
            elif args.command == "governance-admit-scenarios":
                store.initialize(applied_at=args.at)
                batch = ScenarioSpecBatchResult.model_validate_json(args.batch.read_text(encoding="utf-8"))
                result = store.admit_scenario_batch(batch, created_at=args.at, actor_ref=args.actor_ref)
                payload_obj = {"records": result.records, "idempotent_artifact_ids": result.idempotent_artifact_ids}
            elif args.command == "governance-admit-bdd":
                store.initialize(applied_at=args.at)
                batch = BddCompilationBatch.model_validate_json(args.batch.read_text(encoding="utf-8"))
                result = store.admit_bdd_batch(batch, created_at=args.at, actor_ref=args.actor_ref)
                payload_obj = {"records": result.records, "idempotent_artifact_ids": result.idempotent_artifact_ids}
            elif args.command == "governance-admit-runtime":
                store.initialize(applied_at=args.at)
                batch = RuntimeVerificationBatch.model_validate_json(args.batch.read_text(encoding="utf-8"))
                result = store.admit_runtime_batch(batch, created_at=args.at, actor_ref=args.actor_ref)
                payload_obj = {"records": result.records, "idempotent_artifact_ids": result.idempotent_artifact_ids}
            elif args.command == "governance-register-baseline":
                result = store.register_baseline(
                    artifact_id=args.artifact_id, authority_ref=args.authority_ref,
                    effective_from=args.effective_from, actor_ref=args.actor_ref
                )
                payload_obj = result
            elif args.command == "governance-compare-baseline":
                result = store.compare_to_baseline(
                    candidate_artifact_id=args.artifact_id, compared_at=args.compared_at,
                    actor_ref=args.actor_ref
                )
                payload_obj = result
            elif args.command == "governance-amend-scenario":
                spec = ScenarioSpec.model_validate_json(args.amended_spec.read_text(encoding="utf-8"))
                record, amendment = store.amend_scenario_spec(
                    original_artifact_id=args.artifact_id, amended_spec=spec,
                    editor_ref=args.editor_ref, reason=args.reason, amended_at=args.amended_at
                )
                payload_obj = {"artifact": record, "amendment": amendment}
            elif args.command == "governance-bind-decision":
                envelope = PlatformDecisionEnvelope.model_validate_json(args.envelope.read_text(encoding="utf-8"))
                store.bind_platform_decision(envelope)
                payload_obj = envelope
            elif args.command == "governance-bind-certification":
                envelope = CertificationEnvelope.model_validate_json(args.envelope.read_text(encoding="utf-8"))
                store.bind_certification(envelope)
                payload_obj = envelope
            else:
                payload_obj = store.history(args.artifact_id)
        except GovernanceStoreError as exc:
            print(f"Governance error: {exc}")
            return 6
        payload = canonical_json_bytes(payload_obj)
        output = getattr(args, "output", None)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload + b"\n")
            print(f"Governance output: {output}")
        else:
            print(payload.decode("utf-8"))
        return 0
    return None
