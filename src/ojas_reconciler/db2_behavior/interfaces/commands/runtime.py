from __future__ import annotations

import argparse
import os

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.runtime.executor import IbmDbSandboxExecutor, RuntimeExecutionError, ScriptedRuntimeExecutor
from ojas_reconciler.db2_behavior.runtime.models import Db2SandboxConfig, RuntimeInvocation, RuntimeObservationScript
from ojas_reconciler.db2_behavior.runtime.properties import (
    Db2RuntimeEvidenceProperties,
    RuntimeEvidencePlatform,
    RuntimeEvidenceUnavailable,
    load_runtime_evidence_backend,
)
from ojas_reconciler.db2_behavior.runtime.verify import RuntimeVerifier
from ojas_reconciler.db2_behavior.runtime.workflow import RuntimeWorkflowBuilder

from ..command_support import _print_runtime_plans, _print_runtime_verification, _semantic_analyzer

def handle(args: argparse.Namespace) -> int | None:
    if args.command in {"plan-runtime-verification", "verify-runtime-scripted", "verify-runtime-db2"}:
        runtime_enabled = bool(args.enable_experimental_runtime) and os.environ.get(
            "DB2_BEHAVIOR_ENABLE_EXPERIMENTAL_RUNTIME", ""
        ).strip() == "1"
        if not runtime_enabled:
            raise SystemExit(
                "DEFERRED_CAPABILITY_DISABLED: Phase 6 is experimental and outside the admitted baseline. "
                "Set DB2_BEHAVIOR_ENABLE_EXPERIMENTAL_RUNTIME=1 and pass --enable-experimental-runtime."
            )
        parse_result = LarkSqlPlSpikeParser().parse_file(args.source)
        if parse_result.ast is None:
            print(canonical_json_bytes(parse_result).decode("utf-8"))
            return 2
        semantic_result, scenario_batch, plan_batch = RuntimeWorkflowBuilder().build(
            parse_result, _semantic_analyzer(args)
        )
        if args.command == "plan-runtime-verification":
            payload = canonical_json_bytes(plan_batch)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes(payload + b"\n")
                print(f"Runtime verification plans: {args.output}")
            else:
                print(payload.decode("utf-8"))
            if args.explain:
                _print_runtime_plans(plan_batch)
            return 0

        plans = {value.plan_id: value for value in plan_batch.plans}
        if args.command == "verify-runtime-scripted":
            script = RuntimeObservationScript.model_validate_json(args.script.read_text(encoding="utf-8"))
            plan = plans.get(script.plan_ref)
            if plan is None:
                raise SystemExit(f"Script references unknown plan: {script.plan_ref}")
            try:
                execution = ScriptedRuntimeExecutor().execute_script(plan=plan, script=script)
            except RuntimeExecutionError as exc:
                raise SystemExit(str(exc)) from exc
            result = RuntimeVerifier().verify(plan=plan, execution=execution)
            batch = RuntimeVerifier().verify_batch(
                plan_batch_digest=plan_batch.content_digest,
                pairs=((plan, execution),),
            )
            payload = canonical_json_bytes(batch)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes(payload + b"\n")
                print(f"Runtime verification result: {args.output}")
            else:
                print(payload.decode("utf-8"))
            if args.explain:
                _print_runtime_verification(batch)
            return 0 if result.verification_status.value == "MATCHED" else 5

        properties = (
            Db2RuntimeEvidenceProperties.from_json_file(args.runtime_evidence_properties)
            if args.runtime_evidence_properties
            else Db2RuntimeEvidenceProperties.from_env()
        )
        if args.connection_ref and properties.connection_ref is None:
            properties = properties.model_copy(update={"connection_ref": args.connection_ref.strip() or None})
        try:
            backend = load_runtime_evidence_backend(properties)
        except RuntimeEvidenceUnavailable as exc:
            raise SystemExit(f"DB2_RUNTIME_EVIDENCE_UNAVAILABLE: {exc}") from exc
        if backend is None:
            raise SystemExit(
                "DB2_RUNTIME_EVIDENCE_DISABLED: set ATLAS_DB2_RUNTIME_EVIDENCE_ENABLED=true "
                "or supply --runtime-evidence-properties."
            )
        if backend.platform is not RuntimeEvidencePlatform.DB2_LUW:
            raise SystemExit(
                "verify-runtime-db2 is a DB2_LUW live probe; DB2_ZOS uses the property-gated "
                "offline IFCID consumer."
            )

        plan = plans.get(args.plan_id)
        if plan is None:
            raise SystemExit(f"Unknown plan id: {args.plan_id}")
        invocation = RuntimeInvocation.model_validate_json(args.invocation.read_text(encoding="utf-8"))
        if args.sandbox_config is not None:
            config = Db2SandboxConfig.model_validate_json(
                args.sandbox_config.read_text(encoding="utf-8")
            )
        else:
            if not args.connection_ref or not args.sandbox_attestation:
                raise SystemExit(
                    "verify-runtime-db2 requires --sandbox-config or both "
                    "--connection-ref and --sandbox-attestation."
                )
            config = Db2SandboxConfig(
                connection_ref=args.connection_ref,
                environment_variable=args.connection_env,
                sandbox_attestation=args.sandbox_attestation,
                manual_approval_ref=args.manual_approval_ref,
                rollback_after_call=True,
                execute_live=args.execute_live,
            )
        try:
            execution = IbmDbSandboxExecutor().execute_db2(
                plan=plan,
                invocation=invocation,
                config=config,
                safety_assessment=plan_batch.safety_assessment,
            )
        except RuntimeExecutionError as exc:
            raise SystemExit(str(exc)) from exc
        batch = RuntimeVerifier().verify_batch(
            plan_batch_digest=plan_batch.content_digest,
            pairs=((plan, execution),),
        )
        payload = canonical_json_bytes(batch)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Runtime verification result: {args.output}")
        else:
            print(payload.decode("utf-8"))
        if args.explain:
            _print_runtime_verification(batch)
        return 0
    return None
