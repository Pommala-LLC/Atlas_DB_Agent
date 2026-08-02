from __future__ import annotations

import json

from ojas_reconciler.db2_behavior.application.doctor import build_doctor_report
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.core.tooling import inspect_tools_json


def handle(args) -> int | None:
    if args.command == "check-tools":
        print(json.dumps(inspect_tools_json(), indent=2))
        return 0
    if args.command != "doctor":
        return None
    report = build_doctor_report(args.project_root.resolve())
    payload = canonical_json_bytes(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload + b"\n")
        print(f"Doctor report: {args.output}")
    else:
        print(payload.decode("utf-8"))
    return 0 if report.overall_status.value != "FAIL" else 7
