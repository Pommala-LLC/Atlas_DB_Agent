from __future__ import annotations

import hashlib

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.runtime.models import (
    RuntimeExecutionRecord,
    RuntimeExecutionStatus,
    RuntimeExpectationResult,
    RuntimeExpectedObservation,
    RuntimeObservationKind,
    RuntimeVerificationBatch,
    RuntimeVerificationFinding,
    RuntimeVerificationFindingCode,
    RuntimeVerificationPlan,
    RuntimeVerificationResult,
    RuntimeVerificationStatus,
)
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


class RuntimeVerifier:
    VERSION = "runtime-verifier-1.0"

    def verify(
        self,
        *,
        plan: RuntimeVerificationPlan,
        execution: RuntimeExecutionRecord,
    ) -> RuntimeVerificationResult:
        findings: list[RuntimeVerificationFinding] = []
        expectation_results: list[RuntimeExpectationResult] = []
        if canonical_digest(plan.model_dump(exclude={"content_digest"})) != plan.content_digest:
            findings.append(self._finding(RuntimeVerificationFindingCode.RUNTIME_PLAN_DIGEST_INVALID, plan.plan_id))
        if canonical_digest(execution.model_dump(exclude={"content_digest"})) != execution.content_digest:
            findings.append(self._finding(RuntimeVerificationFindingCode.EXECUTION_RECORD_DIGEST_INVALID, execution.execution_id))
        if execution.plan_ref != plan.plan_id or execution.plan_digest != plan.content_digest:
            findings.append(self._finding(RuntimeVerificationFindingCode.PLAN_SCRIPT_MISMATCH, execution.execution_id))
        if findings:
            return self._result(plan, execution, RuntimeVerificationStatus.BLOCKED, (), findings, False)
        if execution.execution_status == RuntimeExecutionStatus.FAILED:
            findings.append(self._finding(RuntimeVerificationFindingCode.EXECUTION_FAILED, execution.execution_id))
            return self._result(plan, execution, RuntimeVerificationStatus.EXECUTION_FAILED, (), findings, False)
        if execution.execution_status == RuntimeExecutionStatus.BLOCKED:
            return self._result(plan, execution, RuntimeVerificationStatus.BLOCKED, (), (), False)

        conflict = False
        inconclusive = False
        for expected in plan.expected_observations:
            matched, observed = self._match(expected, execution)
            expectation_findings: list[str] = []
            if expected.modality == EffectModality.MUST and matched is not True:
                code = RuntimeVerificationFindingCode.MUST_EFFECT_NOT_OBSERVED
                if expected.observation_kind == RuntimeObservationKind.OUT_PARAMETER and observed:
                    code = RuntimeVerificationFindingCode.OUT_PARAMETER_VALUE_MISMATCH
                finding = self._finding(code, expected.expectation_id)
                findings.append(finding)
                expectation_findings.append(finding.finding_id)
                conflict = True
            elif expected.modality == EffectModality.MUST_NOT and matched is True:
                finding = self._finding(RuntimeVerificationFindingCode.MUST_NOT_EFFECT_OBSERVED, expected.expectation_id)
                findings.append(finding)
                expectation_findings.append(finding.finding_id)
                conflict = True
            elif expected.modality == EffectModality.UNKNOWN:
                inconclusive = True
            expectation_results.append(
                RuntimeExpectationResult(
                    expectation_ref=expected.expectation_id,
                    scenario_effect_ref=expected.scenario_effect_ref,
                    modality=expected.modality,
                    matched=matched,
                    observed_refs=observed,
                    finding_refs=tuple(expectation_findings),
                )
            )
        if conflict:
            findings.append(self._finding(RuntimeVerificationFindingCode.STATIC_RUNTIME_EVIDENCE_CONFLICT, plan.plan_id))
            status = RuntimeVerificationStatus.MISMATCH
        elif inconclusive:
            findings.append(self._finding(RuntimeVerificationFindingCode.RUNTIME_RESULT_INCONCLUSIVE, plan.plan_id))
            status = RuntimeVerificationStatus.INCONCLUSIVE
        else:
            status = RuntimeVerificationStatus.MATCHED
        return self._result(plan, execution, status, tuple(expectation_results), findings, conflict)

    def verify_batch(
        self,
        *,
        plan_batch_digest: str,
        pairs: tuple[tuple[RuntimeVerificationPlan, RuntimeExecutionRecord], ...],
    ) -> RuntimeVerificationBatch:
        records = tuple(value[1] for value in pairs)
        results = tuple(self.verify(plan=value[0], execution=value[1]) for value in pairs)
        payload = {
            "schema_version": "runtime-verification-batch-1.0",
            "plan_batch_digest": plan_batch_digest,
            "execution_records": records,
            "verification_results": results,
        }
        return RuntimeVerificationBatch(**payload, content_digest=canonical_digest(payload))

    def _match(
        self,
        expected: RuntimeExpectedObservation,
        execution: RuntimeExecutionRecord,
    ) -> tuple[bool | None, tuple[str, ...]]:
        if expected.observation_kind == RuntimeObservationKind.OUT_PARAMETER:
            matches = [value for value in execution.output_parameters if value.parameter_name.upper() == (expected.target or "").upper()]
            if not matches:
                return False, ()
            if expected.expected_value is None:
                return True, tuple(value.parameter_name for value in matches)
            return (
                any(value.value == expected.expected_value for value in matches),
                tuple(value.parameter_name for value in matches),
            )
        if expected.observation_kind == RuntimeObservationKind.SQLSTATE:
            if execution.sqlstate is None:
                return False, ()
            return True, (execution.sqlstate,)
        if expected.observation_kind == RuntimeObservationKind.DML_EFFECT:
            refs = set(execution.observed_effect_refs) | {value.effect_ref for value in execution.row_changes if value.effect_ref}
            return expected.scenario_effect_ref in refs, tuple(sorted(refs))
        if expected.observation_kind == RuntimeObservationKind.CALL_EFFECT:
            refs = set(execution.observed_effect_refs)
            if expected.target:
                refs |= {value for value in execution.called_routines if value.upper() == expected.target.upper()}
            return expected.scenario_effect_ref in refs or bool(expected.target and expected.target in refs), tuple(sorted(refs))
        refs = set(execution.observed_effect_refs)
        return expected.scenario_effect_ref in refs, tuple(sorted(refs))

    def _result(
        self,
        plan: RuntimeVerificationPlan,
        execution: RuntimeExecutionRecord,
        status: RuntimeVerificationStatus,
        expectation_results: tuple[RuntimeExpectationResult, ...],
        findings: tuple[RuntimeVerificationFinding, ...] | list[RuntimeVerificationFinding],
        conflict: bool,
    ) -> RuntimeVerificationResult:
        finding_tuple = tuple(findings)
        payload = {
            "behavior_id": plan.behavior_id,
            "source_symbol_id": plan.source_symbol_id,
            "symbol_lineage_id": plan.symbol_lineage_id,
            "artifact_revision_id": plan.artifact_revision_id,
            "schema_version": "runtime-verification-result-1.0",
            "scenario_spec_ref": plan.scenario_spec_ref,
            "plan_ref": plan.plan_id,
            "execution_record_ref": execution.execution_id,
            "verification_status": status,
            "expectation_results": expectation_results,
            "findings": finding_tuple,
            "static_runtime_conflict": conflict,
            "platform_governance_ref": None,
            "input_digest_set": (plan.content_digest, execution.content_digest),
        }
        result_id = "runtime-result-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
        final_payload = {"verification_result_id": result_id, **payload}
        return RuntimeVerificationResult(**final_payload, content_digest=canonical_digest(final_payload))

    @staticmethod
    def _finding(code: RuntimeVerificationFindingCode, evidence_ref: str) -> RuntimeVerificationFinding:
        payload = f"{code.value}|{evidence_ref}"
        finding_id = "runtime-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        messages = {
            RuntimeVerificationFindingCode.RUNTIME_PLAN_DIGEST_INVALID: "Runtime verification plan digest is invalid.",
            RuntimeVerificationFindingCode.EXECUTION_RECORD_DIGEST_INVALID: "Runtime execution record digest is invalid.",
            RuntimeVerificationFindingCode.PLAN_SCRIPT_MISMATCH: "Runtime execution evidence does not match the verification plan.",
            RuntimeVerificationFindingCode.MUST_EFFECT_NOT_OBSERVED: "A statically required effect was not observed.",
            RuntimeVerificationFindingCode.MUST_NOT_EFFECT_OBSERVED: "A statically prohibited effect was observed.",
            RuntimeVerificationFindingCode.OUT_PARAMETER_VALUE_MISMATCH: "An observed OUT parameter value differs from the statically expected literal value.",
            RuntimeVerificationFindingCode.STATIC_RUNTIME_EVIDENCE_CONFLICT: "Runtime evidence conflicts with static behavior evidence.",
            RuntimeVerificationFindingCode.EXECUTION_FAILED: "Runtime execution failed before verification completed.",
            RuntimeVerificationFindingCode.RUNTIME_RESULT_INCONCLUSIVE: "Runtime evidence is insufficient for a definitive match decision.",
        }
        return RuntimeVerificationFinding(
            finding_id=finding_id,
            code=code,
            message=messages.get(code, code.value.replace("_", " ").title()),
            evidence_refs=(evidence_ref,),
            consequence="The result remains technical runtime evidence and is not promoted automatically.",
        )
