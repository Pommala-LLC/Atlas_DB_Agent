from __future__ import annotations

from ojas_reconciler.db2_behavior.application.multi_unit_pipeline import MultiUnitEndToEndPipeline
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode


def handle(args) -> int | None:
    if args.command != "run-end-to-end":
        return None
    result = MultiUnitEndToEndPipeline().run(
        source=args.source, output_dir=args.output_dir, declared_dialect=args.dialect,
        authority_mode=AuthorityMode(args.authority_mode),
        vocabulary_snapshot=args.vocabulary_snapshot, classification_snapshot=args.classification_snapshot,
        dynamic_resolution_catalog=args.dynamic_resolution_catalog,
        tenant_isolation_catalog=args.tenant_isolation_catalog, query_semantics_catalog=args.query_semantics_catalog,
        caller_transaction_contract=args.caller_transaction_contract, governance_db=args.governance_db,
        actor_ref=args.actor_ref, event_at=args.event_at, enable_experimental_runtime=args.enable_experimental_runtime,
    )
    print(f"Run manifest: {result.manifest_path}")
    print(f"Routines analyzed: {result.routine_count}")
    for path in result.routine_outputs:
        print(f"Routine output: {path}")
    return 8 if result.failed else 0
