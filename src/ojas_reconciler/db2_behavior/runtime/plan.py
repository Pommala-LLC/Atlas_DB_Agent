from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import ProcedureParseResult
from ojas_reconciler.db2_behavior.runtime.models import (
    LiveVerificationEligibility,
    RuntimeExpectedObservation,
    RuntimeInputRequirement,
    RuntimeObservationKind,
    RuntimePlanStatus,
    RuntimeSafetyAssessment,
    RuntimeValue,
    RuntimeValueKind,
    RuntimeVerificationPlan,
    RuntimeVerificationPlanBatch,
)
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpec, ScenarioSpecBatchResult
from ojas_reconciler.db2_behavior.analysis.models import EffectCandidate, EffectKind, Phase1SemanticResult


class RuntimeVerificationPlanner:
    VERSION = "runtime-planner-1.0"

    def plan_all(
        self,
        *,
        parse_result: ProcedureParseResult,
        semantic_result: Phase1SemanticResult,
        scenario_batch: ScenarioSpecBatchResult,
        safety: RuntimeSafetyAssessment,
    ) -> RuntimeVerificationPlanBatch:
        if parse_result.ast is None:
            raise ValueError("Runtime planning requires a procedure AST.")
        ast = parse_result.ast
        effects = {value.effect_id: value for value in semantic_result.effects}
        requirements = tuple(
            RuntimeInputRequirement(
                parameter_name=value.name,
                parameter_mode=value.mode,
                type_text=value.type_text,
            )
            for value in ast.parameters
            if value.mode in {"IN", "INOUT"}
        )
        plans: list[RuntimeVerificationPlan] = []
        for spec in sorted(scenario_batch.scenario_specs, key=lambda value: value.scenario_spec_id):
            expectations = self._expectations(spec, effects)
            blockers: list[str] = []
            if not expectations:
                blockers.append("NO_RUNTIME_OBSERVABLE_EFFECT")
            if safety.live_eligibility == LiveVerificationEligibility.PROHIBITED:
                status = RuntimePlanStatus.READY_SCRIPTED
                blockers.append("LIVE_VERIFICATION_PROHIBITED")
            elif safety.live_eligibility == LiveVerificationEligibility.MANUAL_APPROVAL_REQUIRED:
                status = RuntimePlanStatus.MANUAL_APPROVAL_REQUIRED
            else:
                status = RuntimePlanStatus.READY_DB2_SANDBOX
            if not expectations:
                status = RuntimePlanStatus.BLOCKED
            payload = {
                "behavior_id": spec.behavior_id,
                "source_symbol_id": spec.source_symbol_id,
                "symbol_lineage_id": spec.symbol_lineage_id,
                "artifact_revision_id": spec.artifact_revision_id,
                "schema_version": "runtime-verification-plan-1.0",
                "scenario_spec_ref": spec.scenario_spec_id,
                "scenario_spec_digest": spec.content_digest,
                "procedure_identity_ref": spec.procedure_identity_ref,
                "procedure_schema": ast.schema_name,
                "procedure_name": ast.procedure_name,
                "input_requirements": requirements,
                "expected_observations": expectations,
                "safety_assessment_ref": safety.assessment_id,
                "plan_status": status,
                "blockers": tuple(sorted(set(blockers))),
                "evidence_refs": spec.evidence_refs,
            }
            plan_id = "runtime-plan-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
            final_payload = {"plan_id": plan_id, **payload}
            plans.append(RuntimeVerificationPlan(**final_payload, content_digest=canonical_digest(final_payload)))
        batch_payload = {
            "schema_version": "runtime-verification-plan-batch-1.0",
            "scenario_spec_batch_digest": scenario_batch.content_digest,
            "semantic_result_digest": semantic_result.content_digest,
            "safety_assessment": safety,
            "plans": tuple(plans),
        }
        return RuntimeVerificationPlanBatch(**batch_payload, content_digest=canonical_digest(batch_payload))

    def _expectations(
        self,
        spec: ScenarioSpec,
        effects: dict[str, EffectCandidate],
    ) -> tuple[RuntimeExpectedObservation, ...]:
        result: list[RuntimeExpectedObservation] = []
        for scenario_effect in (*spec.expected_effects, *spec.alternative_or_conditional_effects):
            effect = effects.get(scenario_effect.effect_ref)
            if effect is None:
                continue
            kind = self._kind(effect)
            expected_value = self._literal_value(effect.value_expression) if kind == RuntimeObservationKind.OUT_PARAMETER else None
            payload = {
                "scenario_effect_ref": scenario_effect.effect_ref,
                "modality": scenario_effect.modality,
                "observation_kind": kind,
                "target": effect.target,
                "expected_value": expected_value,
                "evidence_refs": effect.evidence_refs,
            }
            expectation_id = "runtime-expectation-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
            result.append(RuntimeExpectedObservation(expectation_id=expectation_id, **payload))
        return tuple(sorted(result, key=lambda value: value.expectation_id))

    @staticmethod
    def _kind(effect: EffectCandidate) -> RuntimeObservationKind:
        if effect.effect_kind == EffectKind.OUT_PARAMETER_ASSIGNMENT:
            return RuntimeObservationKind.OUT_PARAMETER
        if effect.effect_kind == EffectKind.DML or effect.effect_kind == EffectKind.DYNAMIC_SQL:
            return RuntimeObservationKind.DML_EFFECT
        if effect.effect_kind == EffectKind.CALL:
            return RuntimeObservationKind.CALL_EFFECT
        if effect.effect_kind in {EffectKind.SIGNAL, EffectKind.RESIGNAL}:
            return RuntimeObservationKind.SQLSTATE
        return RuntimeObservationKind.EFFECT_REFERENCE

    @staticmethod
    def _literal_value(expression: str | None) -> RuntimeValue | None:
        if expression is None:
            return None
        text = expression.strip()
        if text.upper() == "NULL":
            return RuntimeValue(value_kind=RuntimeValueKind.NULL)
        if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
            return RuntimeValue(value_kind=RuntimeValueKind.STRING, canonical_value=text[1:-1].replace("''", "'"))
        if re.fullmatch(r"[-+]?\d+", text):
            return RuntimeValue(value_kind=RuntimeValueKind.INTEGER, canonical_value=str(int(text)))
        try:
            value = Decimal(text)
        except InvalidOperation:
            return None
        return RuntimeValue(value_kind=RuntimeValueKind.DECIMAL, canonical_value=str(value))
