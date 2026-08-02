from __future__ import annotations

from typing import Protocol

from ojas_reconciler.db2_behavior.runtime.models import (
    Db2SandboxConfig,
    RuntimeExecutionRecord,
    RuntimeInvocation,
    RuntimeObservationScript,
    RuntimeVerificationPlan,
)


class RuntimeExecutorPort(Protocol):
    def execute(
        self,
        *,
        plan: RuntimeVerificationPlan,
        invocation: RuntimeInvocation,
    ) -> RuntimeExecutionRecord: ...


class ScriptedRuntimeExecutorPort(Protocol):
    def execute_script(
        self,
        *,
        plan: RuntimeVerificationPlan,
        script: RuntimeObservationScript,
    ) -> RuntimeExecutionRecord: ...


class Db2RuntimeExecutorPort(Protocol):
    def execute_db2(
        self,
        *,
        plan: RuntimeVerificationPlan,
        invocation: RuntimeInvocation,
        config: Db2SandboxConfig,
    ) -> RuntimeExecutionRecord: ...
