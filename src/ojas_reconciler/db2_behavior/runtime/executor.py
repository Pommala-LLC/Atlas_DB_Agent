from __future__ import annotations

import hashlib
import importlib
import os
from datetime import datetime, timezone
from typing import Any

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.runtime.models import (
    Db2SandboxConfig,
    LiveVerificationEligibility,
    RuntimeExecutionMode,
    RuntimeExecutionRecord,
    RuntimeExecutionStatus,
    RuntimeInvocation,
    RuntimeObservedParameter,
    RuntimeObservationScript,
    RuntimePlanStatus,
    RuntimeSafetyAssessment,
    RollbackContainment,
    TransactionOwnership,
    RuntimeTransactionEvent,
    RuntimeValue,
    RuntimeValueKind,
    RuntimeVerificationPlan,
)


class RuntimeExecutionError(RuntimeError):
    pass


class ScriptedRuntimeExecutor:
    NAME = "scripted-runtime-executor"
    VERSION = "1.0"

    def execute_script(
        self,
        *,
        plan: RuntimeVerificationPlan,
        script: RuntimeObservationScript,
    ) -> RuntimeExecutionRecord:
        if canonical_digest(script.model_dump(exclude={"content_digest"})) != script.content_digest:
            raise RuntimeExecutionError("Runtime observation script digest is invalid.")
        self._validate_invocation(plan, script.invocation)
        if script.plan_ref != plan.plan_id or script.plan_digest != plan.content_digest:
            raise RuntimeExecutionError("Runtime observation script does not match the verification plan.")
        payload = {
            "schema_version": "runtime-execution-record-1.0",
            "plan_ref": plan.plan_id,
            "plan_digest": plan.content_digest,
            "invocation_ref": script.invocation.invocation_id,
            "execution_mode": RuntimeExecutionMode.SCRIPTED_FIXTURE,
            "executor_name": self.NAME,
            "executor_version": self.VERSION,
            "execution_status": script.execution_status,
            "output_parameters": script.output_parameters,
            "sqlstate": script.sqlstate,
            "observed_effect_refs": tuple(sorted(set(script.observed_effect_refs))),
            "row_changes": script.row_changes,
            "called_routines": tuple(sorted(set(script.called_routines))),
            "transaction_events": tuple(sorted(script.transaction_events, key=lambda value: value.sequence)),
            "result_set_digests": tuple(sorted(script.result_set_digests)),
            "error_message": script.error_message,
            "started_at": script.started_at,
            "ended_at": script.ended_at,
            "evidence_refs": (script.script_id,),
        }
        execution_id = "runtime-execution-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
        final_payload = {"execution_id": execution_id, **payload}
        return RuntimeExecutionRecord(**final_payload, content_digest=canonical_digest(final_payload))

    @staticmethod
    def _validate_invocation(plan: RuntimeVerificationPlan, invocation: RuntimeInvocation) -> None:
        if canonical_digest(invocation.model_dump(exclude={"content_digest"})) != invocation.content_digest:
            raise RuntimeExecutionError("Runtime invocation digest is invalid.")
        supplied = {value.parameter_name.upper() for value in invocation.parameters}
        missing = [
            value.parameter_name
            for value in plan.input_requirements
            if value.parameter_name.upper() not in supplied
        ]
        if missing:
            raise RuntimeExecutionError(
                "Missing required runtime inputs: " + ", ".join(sorted(missing))
            )


class IbmDbSandboxExecutor:
    NAME = "ibm-db-sandbox-executor"
    VERSION = "1.0"
    _validate_invocation = staticmethod(ScriptedRuntimeExecutor._validate_invocation)

    def execute_db2(
        self,
        *,
        plan: RuntimeVerificationPlan,
        invocation: RuntimeInvocation,
        config: Db2SandboxConfig,
        safety_assessment: RuntimeSafetyAssessment | None = None,
        live_eligibility: LiveVerificationEligibility | None = None,
    ) -> RuntimeExecutionRecord:
        if not config.execute_live:
            raise RuntimeExecutionError("Live DB2 execution requires execute_live=true.")
        if not config.sandbox_attestation.strip():
            raise RuntimeExecutionError("A sandbox attestation is required.")
        if safety_assessment is not None:
            live_eligibility = safety_assessment.live_eligibility
        if live_eligibility is None:
            raise RuntimeExecutionError("A runtime safety assessment or live eligibility is required.")
        if live_eligibility == LiveVerificationEligibility.PROHIBITED:
            raise RuntimeExecutionError("Live verification is prohibited by the static safety assessment.")
        if live_eligibility == LiveVerificationEligibility.MANUAL_APPROVAL_REQUIRED and not config.manual_approval_ref:
            raise RuntimeExecutionError("Manual approval is required for this live verification plan.")
        if not config.rollback_after_call:
            if safety_assessment is None:
                raise RuntimeExecutionError(
                    "NO_ROLLBACK_PROHIBITED: a complete runtime safety assessment is required."
                )
            if (
                safety_assessment.rollback_containment != RollbackContainment.ROLLBACK_SAFE
                or safety_assessment.transaction_ownership != TransactionOwnership.EXECUTOR_OWNED
                or safety_assessment.internal_commit_present
                or safety_assessment.commit_on_return != "NO"
                or safety_assessment.external_side_effects_status != "ABSENT"
            ):
                raise RuntimeExecutionError(
                    "NO_ROLLBACK_PROHIBITED: rollback may be disabled only for an executor-owned, "
                    "rollback-safe unit of work with no internal commit, COMMIT ON RETURN, or external side effects."
                )
        if plan.plan_status == RuntimePlanStatus.BLOCKED:
            raise RuntimeExecutionError("Blocked runtime plans cannot be executed.")
        self._validate_invocation(plan, invocation)
        connection_string = os.environ.get(config.environment_variable)
        if not connection_string:
            raise RuntimeExecutionError(f"Missing DB2 connection string environment variable: {config.environment_variable}")
        try:
            ibm_db = importlib.import_module("ibm_db")
        except ImportError as exc:
            raise RuntimeExecutionError("ibm_db is not installed in the active environment.") from exc

        started = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        conn: Any = None
        output_parameters: list[RuntimeObservedParameter] = []
        row_changes = []
        before_snapshots: dict[str, tuple[str, int]] = {}
        events: list[RuntimeTransactionEvent] = [RuntimeTransactionEvent(event_kind="BEGIN", sequence=0)]
        status = RuntimeExecutionStatus.SUCCEEDED
        error_message: str | None = None
        sqlstate: str | None = None
        try:
            conn = ibm_db.connect(connection_string, "", "")
            ibm_db.autocommit(conn, ibm_db.SQL_AUTOCOMMIT_OFF)
            before_snapshots = {
                probe.probe_id: self._snapshot(ibm_db, conn, probe.snapshot_query)
                for probe in config.observation_probes
            }
            ordered = tuple(self._to_python(value.value) for value in invocation.parameters)
            procname = f"{plan.procedure_schema}.{plan.procedure_name}" if plan.procedure_schema else plan.procedure_name
            returned = ibm_db.callproc(conn, procname, ordered)
            if returned is not None:
                for parameter, value in zip(invocation.parameters, returned, strict=False):
                    if parameter.parameter_mode in {"OUT", "INOUT"}:
                        output_parameters.append(
                            RuntimeObservedParameter(
                                parameter_name=parameter.parameter_name,
                                value=self._from_python(value),
                            )
                        )
            for probe in config.observation_probes:
                after_digest, after_count = self._snapshot(ibm_db, conn, probe.snapshot_query)
                before_digest, before_count = before_snapshots[probe.probe_id]
                if before_digest != after_digest or before_count != after_count:
                    from ojas_reconciler.db2_behavior.runtime.models import RuntimeRowChange

                    row_changes.append(
                        RuntimeRowChange(
                            relation_name=probe.relation_name,
                            operation=probe.operation,
                            before_digest=before_digest,
                            after_digest=after_digest,
                            row_count=after_count,
                            effect_ref=probe.effect_ref,
                        )
                    )
            if config.rollback_after_call:
                ibm_db.rollback(conn)
                events.append(RuntimeTransactionEvent(event_kind="CALLER_ROLLBACK", sequence=1))
            else:
                ibm_db.commit(conn)
                events.append(RuntimeTransactionEvent(event_kind="COMMIT", sequence=1))
        except Exception as exc:  # pragma: no cover - requires a live DB2 environment
            status = RuntimeExecutionStatus.FAILED
            error_message = str(exc)
            sqlstate = self._extract_sqlstate(error_message)
            if conn is not None:
                try:
                    ibm_db.rollback(conn)
                    events.append(RuntimeTransactionEvent(event_kind="CALLER_ROLLBACK", sequence=1))
                except Exception:
                    pass
        finally:
            if conn is not None:
                try:
                    ibm_db.close(conn)
                except Exception:
                    pass
        ended = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        payload = {
            "schema_version": "runtime-execution-record-1.0",
            "plan_ref": plan.plan_id,
            "plan_digest": plan.content_digest,
            "invocation_ref": invocation.invocation_id,
            "execution_mode": RuntimeExecutionMode.DB2_SANDBOX,
            "executor_name": self.NAME,
            "executor_version": self.VERSION,
            "execution_status": status,
            "output_parameters": tuple(output_parameters),
            "sqlstate": sqlstate,
            "observed_effect_refs": (),
            "row_changes": tuple(row_changes),
            "called_routines": (),
            "transaction_events": tuple(events),
            "result_set_digests": (),
            "error_message": error_message,
            "started_at": started,
            "ended_at": ended,
            "evidence_refs": (config.connection_ref, config.sandbox_attestation),
        }
        execution_id = "runtime-execution-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
        final_payload = {"execution_id": execution_id, **payload}
        return RuntimeExecutionRecord(**final_payload, content_digest=canonical_digest(final_payload))

    @staticmethod
    def _snapshot(ibm_db: Any, conn: Any, query: str) -> tuple[str, int]:
        from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest

        stmt = ibm_db.exec_immediate(conn, query)
        rows: list[tuple[object, ...]] = []
        while True:
            row = ibm_db.fetch_tuple(stmt)
            if row is False:
                break
            rows.append(tuple(str(value) if value is not None else None for value in row))
        ordered = tuple(sorted(rows, key=lambda value: repr(value)))
        return canonical_digest(ordered), len(rows)

    @staticmethod
    def _to_python(value: RuntimeValue) -> Any:
        if value.value_kind == RuntimeValueKind.NULL:
            return None
        if value.value_kind == RuntimeValueKind.INTEGER:
            return int(value.canonical_value or "0")
        if value.value_kind == RuntimeValueKind.DECIMAL:
            from decimal import Decimal

            return Decimal(value.canonical_value or "0")
        if value.value_kind == RuntimeValueKind.BOOLEAN:
            return (value.canonical_value or "false").lower() == "true"
        return value.canonical_value

    @staticmethod
    def _from_python(value: Any) -> RuntimeValue:
        if value is None:
            return RuntimeValue(value_kind=RuntimeValueKind.NULL)
        if isinstance(value, bool):
            return RuntimeValue(value_kind=RuntimeValueKind.BOOLEAN, canonical_value="true" if value else "false")
        if isinstance(value, int):
            return RuntimeValue(value_kind=RuntimeValueKind.INTEGER, canonical_value=str(value))
        from decimal import Decimal

        if isinstance(value, Decimal):
            return RuntimeValue(value_kind=RuntimeValueKind.DECIMAL, canonical_value=str(value))
        return RuntimeValue(value_kind=RuntimeValueKind.STRING, canonical_value=str(value))

    @staticmethod
    def _extract_sqlstate(message: str) -> str | None:
        import re

        match = re.search(r"SQLSTATE[=:\s]+([0-9A-Z]{5})", message.upper())
        return match.group(1) if match else None
