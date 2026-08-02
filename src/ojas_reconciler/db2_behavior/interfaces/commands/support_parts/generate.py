from __future__ import annotations

import sys

from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode


def handle(args) -> int | None:
    if args.command != "generate":
        return None
    from ojas_reconciler.db2_behavior.application.deliverables import DeliverablesGenerationBlocked, DeliverablesGenerator
    try:
        result = DeliverablesGenerator().generate(
            source=args.source, output_dir=args.output_dir, authority_mode=AuthorityMode(args.authority_mode),
            vocabulary_snapshot=args.vocabulary_snapshot, classification_snapshot=args.classification_snapshot,
            dynamic_resolution_catalog=args.dynamic_resolution_catalog,
            tenant_isolation_catalog=args.tenant_isolation_catalog, query_semantics_catalog=args.query_semantics_catalog,
            caller_transaction_contract=args.caller_transaction_contract, bdd_warning_policy=args.bdd_warning_policy,
        )
    except DeliverablesGenerationBlocked as exc:
        print(str(exc), file=sys.stderr)
        return 11
    print("Generation complete.")
    print(f"Output folder: {result.output_dir}")
    print(f"Technical BDD files: {result.generated_bdd_files}")
    print(f"Readable candidate files: {result.readable_candidate_files}")
    print(f"Test cases: {result.generated_test_cases}")
    print(f"Summary: {result.summary_path}")
    return 0
