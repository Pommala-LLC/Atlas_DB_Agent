from __future__ import annotations

from atlas.core.canonical import canonical_json_bytes
from ojas_reconciler.db2_behavior.commercial.public_repository import PublicRepositoryOrganicValidationService


def handle(args) -> int | None:
    if args.command != "validate-public-db2":
        return None
    service = PublicRepositoryOrganicValidationService()
    report = service.run(
        manifest=service.load_manifest(args.manifest.resolve()),
        repository_root=args.repository_root.resolve(), output=args.output.resolve(),
    )
    print(canonical_json_bytes({
        "validation_id": report.validation_id, "source_files": report.source_file_count,
        "source_units": report.source_unit_count, "parsed_complete": report.parsed_complete,
        "parsed_partial": report.parsed_partial, "parsed_blocked": report.parsed_blocked,
        "opaque_nodes": report.opaque_count, "pause_reasons": report.pause_reasons,
        "commercialization_state": report.commercialization_state, "output": args.output.resolve().as_posix(),
    }).decode("utf-8"))
    return 0 if not report.pause_reasons else 12
