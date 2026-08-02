from __future__ import annotations

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.runtime.properties import (
    Db2RuntimeEvidenceProperties, RuntimeEvidenceUnavailable, load_runtime_evidence_backend, runtime_evidence_status,
)


def handle(args) -> int | None:
    if args.command == "run-bdd-test-package":
        return _bdd_package(args)
    if args.command != "runtime-evidence-status":
        return None
    properties = Db2RuntimeEvidenceProperties.from_json_file(args.properties) if args.properties else Db2RuntimeEvidenceProperties.from_env()
    availability, reasons = runtime_evidence_status(properties)
    backend = None
    if args.load_backend:
        try:
            backend = load_runtime_evidence_backend(properties)
        except RuntimeEvidenceUnavailable as exc:
            reasons = reasons if str(exc) in reasons else (*reasons, str(exc))
    payload = {"enabled": properties.enabled, "dialect": properties.dialect.value,
        "platform": properties.platform.value if properties.platform else None,
        "source": properties.source.value if properties.source else None,
        "availability": availability.value, "reasons": reasons,
        "backend": {"module_name": backend.module_name, "implementation_name": backend.implementation_name} if backend else None}
    print(canonical_json_bytes(payload).decode("utf-8"))
    return 0 if availability.value in {"DISABLED", "SKIPPED", "AVAILABLE"} else 9


def _bdd_package(args) -> int:
    from ojas_reconciler.db2_behavior.testkit.runner import BddTestPackageRunner
    from ojas_reconciler.db2_behavior.testkit.reporting import junit_xml_bytes
    result = BddTestPackageRunner().run(args.package_root.resolve())
    payload = canonical_json_bytes(result) + b"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_bytes(payload)
        print(f"BDD test result: {args.output}")
    else:
        print(payload.decode("utf-8"), end="")
    if args.junit_output:
        args.junit_output.parent.mkdir(parents=True, exist_ok=True); args.junit_output.write_bytes(junit_xml_bytes(result))
        print(f"JUnit result: {args.junit_output}")
    return 0 if result.suite_status == "PASSED" else 10
