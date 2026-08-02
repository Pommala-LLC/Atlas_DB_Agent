from __future__ import annotations

import hashlib
from collections import defaultdict

from ojas_reconciler.db2_behavior.bdd.authority import AuthorityRequirementsExporter
from ojas_reconciler.db2_behavior.bdd.authority_models import BddExplanationBatch, BddGateExplanation
from ojas_reconciler.db2_behavior.bdd.models import (
    BddCompilationBatch,
    BddCompilationStatus,
    ClassificationSnapshot,
    MappingKind,
    VocabularyMapping,
    VocabularySnapshot,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpecBatchResult


class BddExplanationBuilder:
    """Builds deterministic reviewer-facing explanations for BDD gate results."""

    def build(
        self,
        scenario_batch: ScenarioSpecBatchResult,
        bdd_batch: BddCompilationBatch,
        vocabulary: VocabularySnapshot,
        classification: ClassificationSnapshot,
    ) -> BddExplanationBatch:
        specs = {item.scenario_spec_id: item for item in scenario_batch.scenario_specs}
        closures = {item.effect_closure_id: item for item in scenario_batch.effect_closures}
        resolutions = {item.resolution_vector_id: item for item in scenario_batch.resolution_vectors}
        requirements = AuthorityRequirementsExporter().export(scenario_batch)
        requirements_by_spec: dict[str, list[object]] = defaultdict(list)
        for requirement in requirements.vocabulary_requirements:
            requirements_by_spec[requirement.scenario_spec_ref].append(requirement)
        approvals_by_observation: dict[str, list[str]] = defaultdict(list)
        for approval in classification.approvals:
            approvals_by_observation[approval.classification_observation_ref].append(approval.approval_id)

        explanations: list[BddGateExplanation] = []
        for result in sorted(bdd_batch.compilation_results, key=lambda item: item.scenario_spec_ref):
            spec = specs[result.scenario_spec_ref]
            spec_requirements = requirements_by_spec.get(spec.scenario_spec_id, [])
            matching: dict[str, list[str]] = defaultdict(list)
            for requirement in spec_requirements:
                requirement_id = getattr(requirement, "requirement_id")
                for mapping in vocabulary.mappings:
                    if self._mapping_matches(mapping, requirement):
                        matching[requirement_id].append(mapping.mapping_id)
            missing_slots = tuple(
                sorted(
                    getattr(requirement, "slot_id")
                    for requirement in spec_requirements
                    if not matching.get(getattr(requirement, "requirement_id"))
                )
            )
            ambiguous_slots = tuple(
                sorted(
                    getattr(requirement, "slot_id")
                    for requirement in spec_requirements
                    if len(matching.get(getattr(requirement, "requirement_id"), ())) > 1
                )
            )
            observation_refs = tuple(
                sorted(
                    ref
                    for ref in (item.classification_observation_ref for item in spec.preconditions)
                    if ref is not None
                )
            )
            missing_approvals = tuple(sorted(ref for ref in observation_refs if not approvals_by_observation.get(ref)))
            ambiguous_approvals = tuple(
                sorted(ref for ref in observation_refs if len(approvals_by_observation.get(ref, ())) > 1)
            )
            closure = closures.get(spec.effect_closure_ref)
            resolution = resolutions.get(spec.resolution_vector_ref)
            dependency_resolution = (
                {
                    "routine": resolution.routine_resolution,
                    "view": resolution.view_resolution,
                    "udf": resolution.udf_resolution,
                    "trigger": resolution.trigger_resolution,
                    "constraint": resolution.constraint_resolution,
                    "dynamic_relation": resolution.dynamic_relation_resolution,
                }
                if resolution is not None
                else {}
            )
            affected_outputs = tuple(sorted(item.effect_ref for item in spec.expected_effects))
            withheld = () if result.compilation_status == BddCompilationStatus.SUCCEEDED else (
                "GHERKIN_ARTIFACT",
                "TRACEABILITY_MANIFEST",
                "CANDIDATE_BDD",
            )
            actions = self._recommended_actions(
                missing_slots=missing_slots,
                ambiguous_slots=ambiguous_slots,
                missing_approvals=missing_approvals,
                ambiguous_approvals=ambiguous_approvals,
                blockers=tuple(item.value for item in result.blockers),
            )
            without_digest = {
                "explanation_id": self._stable_id("bdd-explanation", bdd_batch.content_digest, spec.scenario_spec_id),
                "scenario_spec_ref": spec.scenario_spec_id,
                "result": result.compilation_status.value,
                "blocker_codes": result.blockers,
                "missing_vocabulary_slots": missing_slots,
                "ambiguous_vocabulary_slots": ambiguous_slots,
                "missing_classification_observation_refs": missing_approvals,
                "ambiguous_classification_observation_refs": ambiguous_approvals,
                "effect_closure_completeness": closure.completeness if closure else None,
                "dependency_resolution": dependency_resolution,
                "affected_outputs": affected_outputs,
                "withheld_outputs": withheld,
                "evidence_refs": spec.evidence_refs,
                "consequence": (
                    "Candidate Gherkin and traceability-bound CandidateBDD artifacts were emitted."
                    if result.compilation_status == BddCompilationStatus.SUCCEEDED
                    else "No partial Gherkin was emitted; CandidateBDD outputs were withheld atomically."
                ),
                "recommended_actions": actions,
            }
            explanations.append(BddGateExplanation(**without_digest, content_digest=canonical_digest(without_digest)))

        without_digest = {
            "schema_version": "bdd-explanation-batch-1.1",
            "bdd_compilation_batch_digest": bdd_batch.content_digest,
            "scenario_spec_batch_digest": scenario_batch.content_digest,
            "vocabulary_snapshot_digest": vocabulary.content_digest,
            "classification_snapshot_digest": classification.content_digest,
            "explanations": tuple(explanations),
        }
        return BddExplanationBatch(**without_digest, content_digest=canonical_digest(without_digest))

    @staticmethod
    def _mapping_matches(mapping: VocabularyMapping, requirement: object) -> bool:
        pattern = getattr(requirement, "normalized_technical_pattern_ref")
        structural = getattr(requirement, "structural_context_digest")
        symbols = tuple(sorted(getattr(requirement, "symbol_binding_refs")))
        requirement_id = getattr(requirement, "requirement_id")
        match mapping.mapping_kind:
            case MappingKind.EXACT_APPROVED_MAPPING:
                return mapping.normalized_technical_pattern_ref == pattern
            case MappingKind.STRUCTURAL_APPROVED_MAPPING:
                return mapping.normalized_technical_pattern_ref == pattern and mapping.structural_context_digest == structural
            case MappingKind.SYMBOL_BOUND_APPROVED_MAPPING:
                return mapping.normalized_technical_pattern_ref == pattern and tuple(sorted(mapping.symbol_binding_refs)) == symbols
            case MappingKind.MANUALLY_APPROVED_MAPPING:
                return mapping.manual_requirement_ref == requirement_id
            case MappingKind.MAPPING_CANDIDATE_ONLY:
                return mapping.normalized_technical_pattern_ref == pattern
        return False

    @staticmethod
    def _recommended_actions(
        *,
        missing_slots: tuple[str, ...],
        ambiguous_slots: tuple[str, ...],
        missing_approvals: tuple[str, ...],
        ambiguous_approvals: tuple[str, ...],
        blockers: tuple[str, ...],
    ) -> tuple[str, ...]:
        actions: list[str] = []
        if missing_slots:
            actions.append("Approve one effective vocabulary mapping for every missing requirement.")
        if ambiguous_slots:
            actions.append("Retire or scope overlapping vocabulary mappings so each requirement resolves once.")
        if missing_approvals:
            actions.append("Approve the missing classification observations through the platform authority spine.")
        if ambiguous_approvals:
            actions.append("Resolve duplicate active classification approvals.")
        if "DEPENDENCY_RESOLUTION_INCOMPLETE" in blockers:
            actions.append("Resolve or mark non-applicable every dependency class required by the ScenarioSpec.")
        if "EFFECT_CLOSURE_INSUFFICIENT" in blockers:
            actions.append("Complete effect-closure analysis for the rendered effect obligations.")
        if "NON_DEFINITIVE_EFFECT" in blockers:
            actions.append("Provide a MUST or MUST_NOT effect obligation supported by admitted summary soundness.")
        if "MAPPING_NOT_EFFECTIVE" in blockers or "CLASSIFICATION_APPROVAL_NOT_EFFECTIVE" in blockers:
            actions.append("Compile against an effective authority snapshot or renew the expired approval.")
        if not actions and blockers:
            actions.append("Inspect blocker codes and revision-bound evidence before retrying compilation.")
        if not actions:
            actions.append("No action required; compilation succeeded.")
        return tuple(actions)

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join(parts)
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
