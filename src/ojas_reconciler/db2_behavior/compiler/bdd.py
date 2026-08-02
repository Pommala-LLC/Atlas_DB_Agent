from __future__ import annotations

import hashlib
from collections import defaultdict
from string import Formatter
from typing import Literal, assert_never, cast

from ojas_reconciler.db2_behavior.bdd.authority import AuthorityRequirementsExporter
from ojas_reconciler.db2_behavior.bdd.authority_models import AuthorityRequirementsManifest, VocabularyRequirement, VocabularySlotKind
from ojas_reconciler.db2_behavior.bdd.models import (
    AuthorityScope,
    BddBlockerCode,
    BddCompilationBatch,
    BddCompilationResult,
    BddCompilationStatus,
    CandidateBdd,
    ClassificationApproval,
    ClassificationSnapshot,
    GherkinArtifact,
    GherkinElementBinding,
    MappingKind,
    TraceabilityManifest,
    VocabularyMapping,
    VocabularySnapshot,
    canonical_timestamp,
    timestamp_active,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.bdd.gherkin import canonical_gherkin_text, gherkin_digest
from ojas_reconciler.db2_behavior.bdd.scenario_models import (
    ClassificationObservation,
    EffectClosureArtifact,
    EffectClosureCompleteness,
    ResolutionStatus,
    ResolutionVectorArtifact,
    ScenarioSpec,
    ScenarioSpecBatchResult,
)
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


class BddCompiler:
    """Deterministic, snapshot-gated BDD compiler.

    The compiler performs no classification, fuzzy matching, or language-model
    wording. It emits CandidateBDD atomically only after authority, digest,
    dependency, Gherkin, and traceability gates all pass.
    """

    VERSION = "bdd-compiler-1.4"
    CONFIGURATION = {
        "dialect": "en",
        "allow_test_fixture_authority": True,
        "platform_requires_full_dependency_resolution": True,
        "unicode_normalization": "NFC",
        "newline": "LF",
    }

    def compile_all(
        self,
        scenario_batch: ScenarioSpecBatchResult,
        vocabulary_snapshot: VocabularySnapshot,
        classification_snapshot: ClassificationSnapshot,
        *,
        effective_timestamp: str | None = None,
    ) -> BddCompilationBatch:
        configuration_digest = canonical_digest(self.CONFIGURATION)
        requirements = AuthorityRequirementsExporter().export(scenario_batch)
        requirement_by_spec: dict[str, list[VocabularyRequirement]] = defaultdict(list)
        for requirement in requirements.vocabulary_requirements:
            requirement_by_spec[requirement.scenario_spec_ref].append(requirement)
        for values in requirement_by_spec.values():
            values.sort(key=lambda value: value.requirement_id)

        approvals_by_observation: dict[str, list[ClassificationApproval]] = defaultdict(list)
        for approval in classification_snapshot.approvals:
            approvals_by_observation[approval.classification_observation_ref].append(approval)
        for values in approvals_by_observation.values():
            values.sort(key=lambda value: value.approval_id)

        observations = {
            value.classification_observation_id: value
            for value in scenario_batch.classification_observations
        }
        closures = {value.effect_closure_id: value for value in scenario_batch.effect_closures}
        resolutions = {value.resolution_vector_id: value for value in scenario_batch.resolution_vectors}
        budgets = {value.budget_report_id: value for value in scenario_batch.budget_reports}

        batch_blockers = self._batch_blockers(scenario_batch)
        snapshot_blockers = self._snapshot_blockers(vocabulary_snapshot, classification_snapshot)
        compile_at = canonical_timestamp(
            effective_timestamp
            or max(vocabulary_snapshot.effective_timestamp, classification_snapshot.effective_timestamp)
        )

        artifacts: list[GherkinArtifact] = []
        manifests: list[TraceabilityManifest] = []
        candidates: list[CandidateBdd] = []
        results: list[BddCompilationResult] = []

        for spec in sorted(scenario_batch.scenario_specs, key=lambda value: value.scenario_spec_id):
            blockers = set(batch_blockers) | set(snapshot_blockers)
            if not self._digest_valid(spec):
                blockers.add(BddBlockerCode.SCENARIO_SPEC_DIGEST_INVALID)

            closure = closures.get(spec.effect_closure_ref)
            resolution = resolutions.get(spec.resolution_vector_ref)
            budget = budgets.get(spec.analysis_budget_report_ref)
            if closure is None or budget is None or resolution is None:
                blockers.add(BddBlockerCode.SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID)
            else:
                if not self._digest_valid(closure) or not self._digest_valid(resolution) or not self._digest_valid(budget):
                    blockers.add(BddBlockerCode.SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID)
                if closure.completeness != EffectClosureCompleteness.CLOSED_WITHIN_SCOPE:
                    blockers.add(BddBlockerCode.EFFECT_CLOSURE_INSUFFICIENT)
                if not self._resolution_sufficient(resolution, vocabulary_snapshot.authority_scope):
                    blockers.add(BddBlockerCode.DEPENDENCY_RESOLUTION_INCOMPLETE)

            classification_approvals, classification_blockers = self._classification_gate(
                spec=spec,
                observations=observations,
                approvals=approvals_by_observation,
                authority_scope=classification_snapshot.authority_scope,
                effective_timestamp=compile_at,
            )
            blockers.update(classification_blockers)

            spec_requirements = tuple(requirement_by_spec.get(spec.scenario_spec_id, ()))
            mappings, mapping_blockers = self._mapping_gate(
                spec=spec,
                requirements=spec_requirements,
                mappings=vocabulary_snapshot.mappings,
                authority_scope=vocabulary_snapshot.authority_scope,
                effective_timestamp=compile_at,
            )
            blockers.update(mapping_blockers)

            if any(
                effect.modality not in {EffectModality.MUST, EffectModality.MUST_NOT, EffectModality.MUST_IF_CALLER_CONTRACT_HOLDS}
                for effect in spec.expected_effects
            ):
                blockers.add(BddBlockerCode.NON_DEFINITIVE_EFFECT)
            if not spec.expected_effects:
                blockers.add(BddBlockerCode.GHERKIN_STRUCTURE_INVALID)

            if blockers:
                results.append(
                    self._result(
                        status=BddCompilationStatus.BLOCKED,
                        spec=spec,
                        requirements=requirements,
                        vocabulary=vocabulary_snapshot,
                        classification=classification_snapshot,
                        configuration_digest=configuration_digest,
                        effective_timestamp=compile_at,
                        blockers=blockers,
                        mappings=mappings,
                        approvals=classification_approvals,
                    )
                )
                continue

            try:
                mapping_lookup = {
                    requirement.requirement_id: mapping
                    for requirement, mapping in mappings
                }
                requirement_lookup = {
                    requirement.requirement_id: requirement
                    for requirement in spec_requirements
                }
                artifact, manifest = self._render(
                    spec=spec,
                    requirements=requirement_lookup,
                    mappings=mapping_lookup,
                    classification_approvals=classification_approvals,
                    vocabulary_snapshot_digest=vocabulary_snapshot.content_digest,
                    classification_snapshot_digest=classification_snapshot.content_digest,
                )
                if not self._digest_valid(manifest) or gherkin_digest(artifact.text) != artifact.content_digest:
                    raise ValueError("Generated artifact or traceability digest did not validate.")
                expected_bindings = 3 + len(spec.preconditions) + len(spec.expected_effects)
                if len(manifest.element_bindings) != expected_bindings:
                    raise ValueError("Traceability manifest does not cover every rendered element.")

                candidate_without_digest = {
                    "candidate_bdd_id": self._stable_id(
                        "candidate-bdd",
                        spec.content_digest,
                        requirements.content_digest,
                        vocabulary_snapshot.content_digest,
                        classification_snapshot.content_digest,
                        artifact.content_digest,
                        manifest.content_digest,
                        configuration_digest,
                    ),
                    "schema_version": "candidate-bdd-1.2",
                    "behavior_id": spec.behavior_id,
                    "source_symbol_id": spec.source_symbol_id,
                    "symbol_lineage_id": spec.symbol_lineage_id,
                    "artifact_revision_id": spec.artifact_revision_id,
                    "scenario_spec_ref": spec.scenario_spec_id,
                    "gherkin_artifact_ref": artifact.artifact_id,
                    "traceability_manifest_ref": manifest.manifest_id,
                    "authority_requirements_digest": requirements.content_digest,
                    "vocabulary_snapshot_digest": vocabulary_snapshot.content_digest,
                    "classification_snapshot_digest": classification_snapshot.content_digest,
                    "compiler_version": self.VERSION,
                    "authority_scope": vocabulary_snapshot.authority_scope,
                    "platform_governance_ref": None,
                }
                candidate = CandidateBdd(
                    **candidate_without_digest,
                    content_digest=canonical_digest(candidate_without_digest),
                )
                if not self._digest_valid(candidate):
                    raise ValueError("CandidateBDD digest did not validate.")
            except (KeyError, ValueError) as exc:
                results.append(
                    self._result(
                        status=BddCompilationStatus.FAILED,
                        spec=spec,
                        requirements=requirements,
                        vocabulary=vocabulary_snapshot,
                        classification=classification_snapshot,
                        configuration_digest=configuration_digest,
                        effective_timestamp=compile_at,
                        blockers={
                            BddBlockerCode.TRACEABILITY_MANIFEST_FAILED
                            if "traceability" in str(exc).lower()
                            else BddBlockerCode.COMPILATION_INTERNAL_ERROR
                        },
                        mappings=mappings,
                        approvals=classification_approvals,
                    )
                )
                continue

            # Atomic emission: append all three artifacts only after all checks pass.
            artifacts.append(artifact)
            manifests.append(manifest)
            candidates.append(candidate)
            results.append(
                self._result(
                    status=BddCompilationStatus.SUCCEEDED,
                    spec=spec,
                    requirements=requirements,
                    vocabulary=vocabulary_snapshot,
                    classification=classification_snapshot,
                    configuration_digest=configuration_digest,
                    effective_timestamp=compile_at,
                    blockers=set(),
                    mappings=mappings,
                    approvals=classification_approvals,
                    candidate_ref=candidate.candidate_bdd_id,
                    output_digest=candidate.content_digest,
                )
            )

        without_digest = {
            "schema_version": "bdd-compilation-batch-1.1",
            "scenario_spec_batch_digest": scenario_batch.content_digest,
            "authority_requirements_ref": requirements.manifest_id,
            "authority_requirements_digest": requirements.content_digest,
            "vocabulary_snapshot_ref": vocabulary_snapshot.snapshot_id,
            "vocabulary_snapshot_digest": vocabulary_snapshot.content_digest,
            "classification_snapshot_ref": classification_snapshot.snapshot_id,
            "classification_snapshot_digest": classification_snapshot.content_digest,
            "authority_scope": vocabulary_snapshot.authority_scope,
            "gherkin_artifacts": tuple(sorted(artifacts, key=lambda value: value.artifact_id)),
            "traceability_manifests": tuple(sorted(manifests, key=lambda value: value.manifest_id)),
            "candidate_bdds": tuple(sorted(candidates, key=lambda value: value.candidate_bdd_id)),
            "compilation_results": tuple(sorted(results, key=lambda value: value.scenario_spec_ref)),
        }
        return BddCompilationBatch(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _batch_blockers(self, batch: ScenarioSpecBatchResult) -> set[BddBlockerCode]:
        blockers: set[BddBlockerCode] = set()
        if not self._digest_valid(batch):
            blockers.add(BddBlockerCode.SCENARIO_SPEC_BATCH_DIGEST_INVALID)
        nested = (
            *batch.scenario_specs,
            *batch.effect_closures,
            *batch.resolution_vectors,
            *batch.budget_reports,
        )
        if any(not self._digest_valid(value) for value in nested):
            blockers.add(BddBlockerCode.SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID)
        return blockers

    def _snapshot_blockers(
        self,
        vocabulary: VocabularySnapshot,
        classification: ClassificationSnapshot,
    ) -> set[BddBlockerCode]:
        blockers: set[BddBlockerCode] = set()
        if not self._digest_valid(vocabulary) or any(not self._digest_valid(value) for value in vocabulary.mappings):
            blockers.add(BddBlockerCode.VOCABULARY_SNAPSHOT_DIGEST_INVALID)
        if not self._digest_valid(classification) or any(not self._digest_valid(value) for value in classification.approvals):
            blockers.add(BddBlockerCode.CLASSIFICATION_SNAPSHOT_DIGEST_INVALID)
        if vocabulary.authority_scope != classification.authority_scope:
            blockers.add(BddBlockerCode.AUTHORITY_SCOPE_MISMATCH)
        if vocabulary.authority_scope == AuthorityScope.TEST_FIXTURE_ONLY and not bool(self.CONFIGURATION["allow_test_fixture_authority"]):
            blockers.add(BddBlockerCode.AUTHORITY_SCOPE_MISMATCH)
        return blockers

    def _classification_gate(
        self,
        *,
        spec: ScenarioSpec,
        observations: dict[str, ClassificationObservation],
        approvals: dict[str, list[ClassificationApproval]],
        authority_scope: AuthorityScope,
        effective_timestamp: str,
    ) -> tuple[tuple[ClassificationApproval, ...], set[BddBlockerCode]]:
        blockers: set[BddBlockerCode] = set()
        selected: list[ClassificationApproval] = []
        for precondition in spec.preconditions:
            observation_ref = precondition.classification_observation_ref
            if observation_ref is None:
                blockers.add(BddBlockerCode.MISSING_CLASSIFICATION_APPROVAL)
                continue
            observation = observations.get(observation_ref)
            candidates = approvals.get(observation_ref, [])
            active = [
                value
                for value in candidates
                if timestamp_active(
                    at=effective_timestamp,
                    valid_from=value.valid_from,
                    valid_to=value.valid_to,
                )
            ]
            if observation is None or not candidates:
                blockers.add(BddBlockerCode.MISSING_CLASSIFICATION_APPROVAL)
                continue
            if candidates and not active:
                blockers.add(BddBlockerCode.CLASSIFICATION_APPROVAL_NOT_EFFECTIVE)
                continue
            if len(active) != 1:
                blockers.add(BddBlockerCode.AMBIGUOUS_CLASSIFICATION_APPROVAL)
                continue
            approval = active[0]
            selected.append(approval)
            if approval.authority_scope != authority_scope:
                blockers.add(BddBlockerCode.AUTHORITY_SCOPE_MISMATCH)
            if approval.approved_candidate != observation.candidate:
                blockers.add(BddBlockerCode.CLASSIFICATION_CANDIDATE_MISMATCH)
            if approval.classification_observation_digest != canonical_digest(observation):
                blockers.add(BddBlockerCode.CLASSIFICATION_OBSERVATION_DIGEST_MISMATCH)
        return tuple(sorted(selected, key=lambda value: value.approval_id)), blockers

    def _mapping_gate(
        self,
        *,
        spec: ScenarioSpec,
        requirements: tuple[VocabularyRequirement, ...],
        mappings: tuple[VocabularyMapping, ...],
        authority_scope: AuthorityScope,
        effective_timestamp: str,
    ) -> tuple[tuple[tuple[VocabularyRequirement, VocabularyMapping], ...], set[BddBlockerCode]]:
        blockers: set[BddBlockerCode] = set()
        selected: list[tuple[VocabularyRequirement, VocabularyMapping]] = []
        effect_modalities = {
            value.effect_ref: value.modality
            for value in (*spec.expected_effects, *spec.alternative_or_conditional_effects)
        }
        for requirement in requirements:
            semantic_candidates = [value for value in mappings if self._mapping_matches(value, requirement)]
            active_candidates = [
                value
                for value in semantic_candidates
                if timestamp_active(
                    at=effective_timestamp,
                    valid_from=value.valid_from,
                    valid_to=value.valid_to,
                )
            ]
            if not semantic_candidates:
                blockers.add(BddBlockerCode.NO_APPROVED_BUSINESS_TERM)
                continue
            if semantic_candidates and not active_candidates:
                blockers.add(BddBlockerCode.MAPPING_NOT_EFFECTIVE)
                continue
            promotable = [
                value
                for value in active_candidates
                if value.mapping_kind != MappingKind.MAPPING_CANDIDATE_ONLY
            ]
            if not promotable:
                blockers.add(BddBlockerCode.NON_PROMOTABLE_MAPPING_KIND)
                continue
            if len(promotable) != 1:
                blockers.add(BddBlockerCode.AMBIGUOUS_APPROVED_BUSINESS_TERM)
                continue
            mapping = promotable[0]
            selected.append((requirement, mapping))
            if mapping.authority_scope != authority_scope:
                blockers.add(BddBlockerCode.AUTHORITY_SCOPE_MISMATCH)
            if requirement.slot_kind == VocabularySlotKind.EFFECT:
                modality = effect_modalities.get(requirement.source_ref)
                if modality is None or modality not in mapping.supported_modalities:
                    blockers.add(BddBlockerCode.MODALITY_NOT_APPROVED_BY_MAPPING)
            if not self._placeholder_bindings_valid(mapping, requirement):
                blockers.add(BddBlockerCode.PLACEHOLDER_BINDING_INVALID)
        return tuple(sorted(selected, key=lambda item: item[0].requirement_id)), blockers

    @staticmethod
    def _mapping_matches(mapping: VocabularyMapping, requirement: VocabularyRequirement) -> bool:
        match mapping.mapping_kind:
            case MappingKind.EXACT_APPROVED_MAPPING:
                return mapping.normalized_technical_pattern_ref == requirement.normalized_technical_pattern_ref
            case MappingKind.STRUCTURAL_APPROVED_MAPPING:
                return (
                    mapping.normalized_technical_pattern_ref == requirement.normalized_technical_pattern_ref
                    and mapping.structural_context_digest == requirement.structural_context_digest
                )
            case MappingKind.SYMBOL_BOUND_APPROVED_MAPPING:
                return (
                    mapping.normalized_technical_pattern_ref == requirement.normalized_technical_pattern_ref
                    and tuple(sorted(mapping.symbol_binding_refs)) == tuple(sorted(requirement.symbol_binding_refs))
                )
            case MappingKind.MANUALLY_APPROVED_MAPPING:
                return mapping.manual_requirement_ref == requirement.requirement_id
            case MappingKind.MAPPING_CANDIDATE_ONLY:
                return mapping.normalized_technical_pattern_ref == requirement.normalized_technical_pattern_ref
            case _:
                assert_never(mapping.mapping_kind)

    @staticmethod
    def _placeholder_bindings_valid(mapping: VocabularyMapping, requirement: VocabularyRequirement) -> bool:
        template_fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(mapping.phrase_template)
            if field_name is not None
        }
        contract_fields = {value.placeholder for value in mapping.placeholder_contract}
        values = {value.placeholder: value.value for value in requirement.placeholder_values}
        required_fields = {value.placeholder for value in mapping.placeholder_contract if value.required}
        return template_fields == contract_fields and required_fields.issubset(values) and set(values).issubset(contract_fields)

    def _render(
        self,
        *,
        spec: ScenarioSpec,
        requirements: dict[str, VocabularyRequirement],
        mappings: dict[str, VocabularyMapping],
        classification_approvals: tuple[ClassificationApproval, ...],
        vocabulary_snapshot_digest: str,
        classification_snapshot_digest: str,
    ) -> tuple[GherkinArtifact, TraceabilityManifest]:
        by_kind: dict[VocabularySlotKind, list[VocabularyRequirement]] = defaultdict(list)
        for requirement in requirements.values():
            by_kind[requirement.slot_kind].append(requirement)
        feature_requirement = self._single_requirement(by_kind, VocabularySlotKind.FEATURE_TITLE)
        scenario_requirement = self._single_requirement(by_kind, VocabularySlotKind.SCENARIO_NAME)
        action_requirement = self._single_requirement(by_kind, VocabularySlotKind.ACTION)

        lines = [
            f"Feature: {self._render_phrase(mappings[feature_requirement.requirement_id], feature_requirement)}",
            "",
            f"  Scenario: {self._render_phrase(mappings[scenario_requirement.requirement_id], scenario_requirement)}",
        ]
        bindings: list[GherkinElementBinding] = [
            self._binding(spec, 0, "FEATURE", feature_requirement, mappings[feature_requirement.requirement_id], (spec.procedure_identity_ref,), spec.evidence_refs),
            self._binding(spec, 1, "SCENARIO_NAME", scenario_requirement, mappings[scenario_requirement.requirement_id], (spec.scenario_spec_id,), spec.evidence_refs),
        ]
        step_index = 2
        precondition_requirements = {
            value.source_ref: value
            for value in by_kind.get(VocabularySlotKind.PRECONDITION, [])
        }
        for position, precondition in enumerate(spec.preconditions):
            requirement = precondition_requirements[precondition.technical_fact_ref]
            mapping = mappings[requirement.requirement_id]
            keyword = "Given" if position == 0 else "And"
            lines.append(f"    {keyword} {self._render_phrase(mapping, requirement)}")
            bindings.append(
                self._binding(
                    spec,
                    step_index,
                    keyword.upper(),
                    requirement,
                    mapping,
                    (precondition.precondition_id,),
                    precondition.evidence_refs,
                    (precondition.technical_fact_ref,),
                )
            )
            step_index += 1

        action_mapping = mappings[action_requirement.requirement_id]
        lines.append(f"    When {self._render_phrase(action_mapping, action_requirement)}")
        bindings.append(
            self._binding(
                spec,
                step_index,
                "WHEN",
                action_requirement,
                action_mapping,
                (spec.action.invocation_contract_ref,),
                spec.action.evidence_refs,
            )
        )
        step_index += 1

        effect_requirements = {
            value.source_ref: value
            for value in by_kind.get(VocabularySlotKind.EFFECT, [])
        }
        for position, effect in enumerate(spec.expected_effects):
            requirement = effect_requirements[effect.effect_ref]
            mapping = mappings[requirement.requirement_id]
            keyword = "Then" if position == 0 else "And"
            lines.append(f"    {keyword} {self._render_phrase(mapping, requirement)}")
            bindings.append(
                self._binding(
                    spec,
                    step_index,
                    keyword.upper(),
                    requirement,
                    mapping,
                    (effect.effect_ref,),
                    effect.evidence_refs,
                    (effect.effect_ref,),
                )
            )
            step_index += 1

        text = canonical_gherkin_text("\n".join(lines))
        artifact_id = self._stable_id("gherkin-artifact", spec.scenario_spec_id, gherkin_digest(text))
        artifact = GherkinArtifact(
            artifact_id=artifact_id,
            behavior_id=spec.behavior_id,
            source_symbol_id=spec.source_symbol_id,
            symbol_lineage_id=spec.symbol_lineage_id,
            artifact_revision_id=spec.artifact_revision_id,
            text=text,
            content_digest=gherkin_digest(text),
        )
        input_digests = tuple(
            sorted(
                {
                    spec.content_digest,
                    vocabulary_snapshot_digest,
                    classification_snapshot_digest,
                    *(value.content_digest for value in mappings.values()),
                    *(value.content_digest for value in classification_approvals),
                }
            )
        )
        manifest_without_digest = {
            "manifest_id": self._stable_id("traceability-manifest", spec.scenario_spec_id, artifact.content_digest),
            "behavior_id": spec.behavior_id,
            "source_symbol_id": spec.source_symbol_id,
            "symbol_lineage_id": spec.symbol_lineage_id,
            "artifact_revision_id": spec.artifact_revision_id,
            "scenario_spec_ref": spec.scenario_spec_id,
            "gherkin_artifact_ref": artifact.artifact_id,
            "element_bindings": tuple(bindings),
            "input_digest_set": input_digests,
        }
        manifest = TraceabilityManifest(
            **manifest_without_digest,
            content_digest=canonical_digest(manifest_without_digest),
        )
        return artifact, manifest

    @staticmethod
    def _single_requirement(
        by_kind: dict[VocabularySlotKind, list[VocabularyRequirement]],
        kind: VocabularySlotKind,
    ) -> VocabularyRequirement:
        values = by_kind.get(kind, [])
        if len(values) != 1:
            raise ValueError(f"Expected exactly one {kind.value} requirement, found {len(values)}.")
        return values[0]

    @staticmethod
    def _render_phrase(mapping: VocabularyMapping, requirement: VocabularyRequirement) -> str:
        values = {value.placeholder: value.value for value in requirement.placeholder_values}
        try:
            return mapping.phrase_template.format(**values)
        except (KeyError, ValueError) as exc:
            raise ValueError("Placeholder rendering failed.") from exc

    def _binding(
        self,
        spec: ScenarioSpec,
        index: int,
        kind: str,
        requirement: VocabularyRequirement,
        mapping: VocabularyMapping,
        element_refs: tuple[str, ...],
        evidence_refs: tuple[str, ...],
        effect_or_precondition_refs: tuple[str, ...] = (),
    ) -> GherkinElementBinding:
        admitted = {"FEATURE", "SCENARIO_NAME", "GIVEN", "WHEN", "THEN", "AND"}
        if kind not in admitted:
            raise ValueError(f"Unsupported Gherkin element kind: {kind}")
        admitted_kind = cast(
            Literal["FEATURE", "SCENARIO_NAME", "GIVEN", "WHEN", "THEN", "AND"],
            kind,
        )
        return GherkinElementBinding(
            element_id=self._stable_id(
                "gherkin-element",
                spec.scenario_spec_id,
                str(index),
                requirement.requirement_id,
                mapping.mapping_id,
            ),
            element_kind=admitted_kind,
            scenario_spec_element_refs=element_refs,
            authority_requirement_ref=requirement.requirement_id,
            mapping_ref=mapping.mapping_id,
            effect_or_precondition_refs=effect_or_precondition_refs,
            evidence_refs=tuple(sorted(evidence_refs)),
        )

    def _result(
        self,
        *,
        status: BddCompilationStatus,
        spec: ScenarioSpec,
        requirements: AuthorityRequirementsManifest,
        vocabulary: VocabularySnapshot,
        classification: ClassificationSnapshot,
        configuration_digest: str,
        effective_timestamp: str,
        blockers: set[BddBlockerCode],
        mappings: tuple[tuple[VocabularyRequirement, VocabularyMapping], ...],
        approvals: tuple[ClassificationApproval, ...],
        candidate_ref: str | None = None,
        output_digest: str | None = None,
    ) -> BddCompilationResult:
        return BddCompilationResult(
            compilation_status=status,
            scenario_spec_ref=spec.scenario_spec_id,
            candidate_bdd_ref=candidate_ref,
            blockers=tuple(sorted(blockers, key=lambda value: value.value)),
            mapping_refs=tuple(sorted(mapping.mapping_id for _, mapping in mappings)),
            classification_approval_refs=tuple(sorted(value.approval_id for value in approvals)),
            finding_refs=spec.finding_refs,
            input_scenario_spec_digest=spec.content_digest,
            authority_requirements_digest=requirements.content_digest,
            vocabulary_snapshot_digest=vocabulary.content_digest,
            classification_snapshot_digest=classification.content_digest,
            compiler_configuration_digest=configuration_digest,
            effective_timestamp=effective_timestamp,
            output_digest=output_digest,
        )

    @staticmethod
    def _resolution_sufficient(
        resolution: ResolutionVectorArtifact,
        authority_scope: AuthorityScope,
    ) -> bool:
        values = (
            resolution.routine_resolution,
            resolution.view_resolution,
            resolution.udf_resolution,
            resolution.trigger_resolution,
            resolution.constraint_resolution,
            resolution.dynamic_relation_resolution,
        )
        if any(value == ResolutionStatus.UNRESOLVED for value in values):
            return False
        if authority_scope == AuthorityScope.PLATFORM:
            allowed = {
                ResolutionStatus.RESOLVED,
                ResolutionStatus.RESOLVED_SOURCE_ONLY,
                ResolutionStatus.NOT_APPLICABLE,
            }
            return all(value in allowed for value in values)
        if authority_scope == AuthorityScope.TEST_FIXTURE_ONLY:
            return True
        assert_never(authority_scope)

    @staticmethod
    def _digest_valid(value: object) -> bool:
        content_digest = getattr(value, "content_digest", None)
        model_dump = getattr(value, "model_dump", None)
        if not isinstance(content_digest, str) or model_dump is None:
            return False
        return canonical_digest(model_dump(mode="python", exclude={"content_digest"})) == content_digest

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join(parts)
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
