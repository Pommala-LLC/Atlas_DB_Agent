from __future__ import annotations

import hashlib
from collections import Counter, defaultdict

from ojas_reconciler.db2_behavior.bdd.authority_models import (
    AuthorityRequirementsManifest,
    AuthoritySnapshotValidationResult,
    AuthorityValidationIssue,
    AuthorityValidationIssueCode,
    AuthorityValidationStatus,
    ClassificationRequirement,
    VocabularyRequirement,
    VocabularySlotKind,
)
from ojas_reconciler.db2_behavior.bdd.models import (
    AuthorityScope,
    ClassificationSnapshot,
    MappingKind,
    VocabularyMapping,
    VocabularySnapshot,
    timestamp_active,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioEffect, ScenarioPrecondition, ScenarioSpec, ScenarioSpecBatchResult


class AuthorityRequirementsExporter:
    """Exports immutable, reusable vocabulary and classification requirements."""

    VERSION = "authority-requirements-exporter-1.1"

    def export(self, batch: ScenarioSpecBatchResult) -> AuthorityRequirementsManifest:
        observations = {
            item.classification_observation_id: item
            for item in batch.classification_observations
        }
        vocabulary: list[VocabularyRequirement] = []
        classification_usage: dict[str, set[str]] = defaultdict(set)

        for spec in sorted(batch.scenario_specs, key=lambda item: item.scenario_spec_id):
            vocabulary.extend(self._vocabulary_requirements(spec))
            for precondition in spec.preconditions:
                observation_ref = precondition.classification_observation_ref
                if observation_ref is None:
                    continue
                observation = observations.get(observation_ref)
                if observation is None:
                    continue
                classification_usage[observation_ref].add(spec.scenario_spec_id)

        classification: list[ClassificationRequirement] = []
        for observation_ref, scenario_refs in sorted(classification_usage.items()):
            observation = observations[observation_ref]
            classification.append(
                ClassificationRequirement(
                    requirement_id=self._stable_id("classification-requirement", observation_ref),
                    scenario_spec_refs=tuple(sorted(scenario_refs)),
                    classification_observation_ref=observation_ref,
                    classification_observation_digest=canonical_digest(observation),
                    candidate=observation.candidate,
                    method=observation.method,
                    method_version=observation.method_version,
                    classification_evidence_refs=observation.classification_evidence_refs,
                )
            )

        vocabulary_sorted = tuple(sorted(vocabulary, key=lambda item: item.requirement_id))
        classification_sorted = tuple(sorted(classification, key=lambda item: item.requirement_id))
        without_digest = {
            "schema_version": "authority-requirements-1.1",
            "manifest_id": self._stable_id("authority-requirements", batch.content_digest, self.VERSION),
            "scenario_spec_batch_digest": batch.content_digest,
            "procedure_identity_ref": batch.procedure_identity_ref,
            "required_authority_scope": "PLATFORM",
            "vocabulary_requirements": vocabulary_sorted,
            "classification_requirements": classification_sorted,
        }
        return AuthorityRequirementsManifest(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _vocabulary_requirements(self, spec: ScenarioSpec) -> list[VocabularyRequirement]:
        preconditions = {item.precondition_id: item for item in spec.preconditions}
        effects = {
            item.effect_ref: item
            for item in (*spec.expected_effects, *spec.alternative_or_conditional_effects)
        }
        definitions: list[tuple[str, VocabularySlotKind, str, ScenarioEffect | ScenarioPrecondition | None, tuple[str, ...]]] = [
            (
                f"{spec.scenario_spec_id}:FEATURE_TITLE",
                VocabularySlotKind.FEATURE_TITLE,
                spec.procedure_identity_ref,
                None,
                spec.evidence_refs,
            ),
            (
                f"{spec.scenario_spec_id}:SCENARIO_NAME",
                VocabularySlotKind.SCENARIO_NAME,
                spec.scenario_spec_id,
                None,
                spec.evidence_refs,
            ),
            (
                f"{spec.scenario_spec_id}:ACTION",
                VocabularySlotKind.ACTION,
                f"{spec.action.action_kind}:{spec.action.action_scope_ref or spec.action.procedure_identity_ref}",
                None,
                spec.action.evidence_refs,
            ),
        ]
        for slot in spec.required_vocabulary_slots:
            if ":PRECONDITION:" in slot:
                precondition = preconditions[slot.rsplit(":", 1)[-1]]
                definitions.append(
                    (slot, VocabularySlotKind.PRECONDITION, precondition.technical_fact_ref, precondition, precondition.evidence_refs)
                )
            elif ":EFFECT:" in slot:
                effect = effects[slot.rsplit(":", 1)[-1]]
                definitions.append((slot, VocabularySlotKind.EFFECT, effect.effect_ref, effect, spec.evidence_refs))

        results: list[VocabularyRequirement] = []
        for slot, kind, source_ref, item, evidence_refs in definitions:
            modality = item.modality if isinstance(item, ScenarioEffect) else None
            pattern_ref = self._stable_id("technical-pattern", kind.value, source_ref)
            structural_digest = canonical_digest(
                {
                    "slot_kind": kind.value,
                    "source_ref": source_ref,
                    "modality": modality.value if modality is not None else None,
                }
            )
            requirement_id = self._stable_id(
                "vocabulary-requirement",
                spec.scenario_spec_id,
                kind.value,
                source_ref,
            )
            results.append(
                VocabularyRequirement(
                    requirement_id=requirement_id,
                    scenario_spec_ref=spec.scenario_spec_id,
                    slot_id=slot,
                    slot_kind=kind,
                    source_ref=source_ref,
                    normalized_technical_pattern_ref=pattern_ref,
                    structural_context_digest=structural_digest,
                    symbol_binding_refs=(source_ref,),
                    required_modality=modality,
                    evidence_refs=tuple(sorted(evidence_refs)),
                )
            )
        return results

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join(parts)
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


class AuthoritySnapshotValidator:
    """Validates immutable authority snapshots before BDD compilation."""

    def validate(
        self,
        vocabulary: VocabularySnapshot,
        classification: ClassificationSnapshot,
    ) -> AuthoritySnapshotValidationResult:
        issues: list[AuthorityValidationIssue] = []
        self._validate_vocabulary(vocabulary, issues)
        self._validate_classification(classification, issues)
        if vocabulary.authority_scope != classification.authority_scope:
            issues.append(
                AuthorityValidationIssue(
                    code=AuthorityValidationIssueCode.AUTHORITY_SCOPE_MISMATCH,
                    artifact_ref=f"{vocabulary.snapshot_id}|{classification.snapshot_id}",
                    message="Vocabulary and classification snapshots use different authority scopes.",
                )
            )

        issues_sorted = tuple(sorted(issues, key=lambda item: (item.code.value, item.artifact_ref)))
        without_digest = {
            "schema_version": "authority-validation-1.1",
            "validation_status": AuthorityValidationStatus.VALID if not issues_sorted else AuthorityValidationStatus.INVALID,
            "vocabulary_snapshot_ref": vocabulary.snapshot_id,
            "vocabulary_snapshot_digest": vocabulary.content_digest,
            "classification_snapshot_ref": classification.snapshot_id,
            "classification_snapshot_digest": classification.content_digest,
            "authority_scope": vocabulary.authority_scope if vocabulary.authority_scope == classification.authority_scope else None,
            "issues": issues_sorted,
        }
        return AuthoritySnapshotValidationResult(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _validate_vocabulary(self, snapshot: VocabularySnapshot, issues: list[AuthorityValidationIssue]) -> None:
        if not self._digest_valid(snapshot):
            issues.append(self._issue(AuthorityValidationIssueCode.VOCABULARY_SNAPSHOT_DIGEST_INVALID, snapshot.snapshot_id, "Vocabulary snapshot digest does not match canonical content."))
        ids = Counter(item.mapping_id for item in snapshot.mappings)
        bindings = Counter(self._mapping_binding_key(item) for item in snapshot.mappings if item.mapping_kind != MappingKind.MAPPING_CANDIDATE_ONLY)
        for mapping in snapshot.mappings:
            if mapping.authority_scope != snapshot.authority_scope:
                issues.append(self._issue(AuthorityValidationIssueCode.AUTHORITY_SCOPE_MISMATCH, mapping.mapping_id, "Vocabulary mapping authority scope differs from its snapshot."))
            if not self._digest_valid(mapping):
                issues.append(self._issue(AuthorityValidationIssueCode.MAPPING_DIGEST_INVALID, mapping.mapping_id, "Vocabulary mapping digest does not match canonical content."))
            if not mapping.approval_ref.strip():
                issues.append(self._issue(AuthorityValidationIssueCode.EMPTY_APPROVAL_REFERENCE, mapping.mapping_id, "Vocabulary mapping has no approval reference."))
            if not mapping.evidence_refs:
                issues.append(self._issue(AuthorityValidationIssueCode.EMPTY_MAPPING_EVIDENCE, mapping.mapping_id, "Vocabulary mapping has no evidence reference."))
            if snapshot.authority_scope == AuthorityScope.PLATFORM and mapping.mapping_kind == MappingKind.MAPPING_CANDIDATE_ONLY:
                issues.append(self._issue(AuthorityValidationIssueCode.NON_PROMOTABLE_PLATFORM_MAPPING, mapping.mapping_id, "A PLATFORM snapshot cannot contain candidate-only mappings."))
            if not timestamp_active(at=snapshot.effective_timestamp, valid_from=mapping.valid_from, valid_to=mapping.valid_to):
                issues.append(self._issue(AuthorityValidationIssueCode.MAPPING_NOT_EFFECTIVE_AT_SNAPSHOT, mapping.mapping_id, "Vocabulary mapping is not effective at the snapshot timestamp."))
        for mapping_id, count in ids.items():
            if count > 1:
                issues.append(self._issue(AuthorityValidationIssueCode.DUPLICATE_MAPPING_ID, mapping_id, f"Mapping ID appears {count} times."))
        for binding, count in bindings.items():
            if count > 1:
                issues.append(self._issue(AuthorityValidationIssueCode.DUPLICATE_ACTIVE_MAPPING_BINDING, binding, f"Mapping binding has {count} active mappings."))

    def _validate_classification(self, snapshot: ClassificationSnapshot, issues: list[AuthorityValidationIssue]) -> None:
        if not self._digest_valid(snapshot):
            issues.append(self._issue(AuthorityValidationIssueCode.CLASSIFICATION_SNAPSHOT_DIGEST_INVALID, snapshot.snapshot_id, "Classification snapshot digest does not match canonical content."))
        ids = Counter(item.approval_id for item in snapshot.approvals)
        observations = Counter(item.classification_observation_ref for item in snapshot.approvals)
        for approval in snapshot.approvals:
            if approval.authority_scope != snapshot.authority_scope:
                issues.append(self._issue(AuthorityValidationIssueCode.AUTHORITY_SCOPE_MISMATCH, approval.approval_id, "Classification approval authority scope differs from its snapshot."))
            if not self._digest_valid(approval):
                issues.append(self._issue(AuthorityValidationIssueCode.CLASSIFICATION_APPROVAL_DIGEST_INVALID, approval.approval_id, "Classification approval digest does not match canonical content."))
            if not approval.approval_ref.strip():
                issues.append(self._issue(AuthorityValidationIssueCode.EMPTY_APPROVAL_REFERENCE, approval.approval_id, "Classification approval has no approval reference."))
            if not approval.evidence_refs:
                issues.append(self._issue(AuthorityValidationIssueCode.EMPTY_CLASSIFICATION_EVIDENCE, approval.approval_id, "Classification approval has no evidence reference."))
            if not timestamp_active(at=snapshot.effective_timestamp, valid_from=approval.valid_from, valid_to=approval.valid_to):
                issues.append(self._issue(AuthorityValidationIssueCode.APPROVAL_NOT_EFFECTIVE_AT_SNAPSHOT, approval.approval_id, "Classification approval is not effective at the snapshot timestamp."))
        for approval_id, count in ids.items():
            if count > 1:
                issues.append(self._issue(AuthorityValidationIssueCode.DUPLICATE_APPROVAL_ID, approval_id, f"Approval ID appears {count} times."))
        for observation_ref, count in observations.items():
            if count > 1:
                issues.append(self._issue(AuthorityValidationIssueCode.DUPLICATE_CLASSIFICATION_APPROVAL, observation_ref, f"Classification observation has {count} active approvals."))

    @staticmethod
    def _mapping_binding_key(mapping: VocabularyMapping) -> str:
        return canonical_digest(
            {
                "kind": mapping.mapping_kind.value,
                "pattern": mapping.normalized_technical_pattern_ref,
                "structural": mapping.structural_context_digest,
                "symbols": mapping.symbol_binding_refs,
                "manual": mapping.manual_requirement_ref,
            }
        )

    @staticmethod
    def _issue(code: AuthorityValidationIssueCode, artifact_ref: str, message: str) -> AuthorityValidationIssue:
        return AuthorityValidationIssue(code=code, artifact_ref=artifact_ref, message=message)

    @staticmethod
    def _digest_valid(value: object) -> bool:
        content_digest = getattr(value, "content_digest", None)
        model_dump = getattr(value, "model_dump", None)
        if not isinstance(content_digest, str) or model_dump is None:
            return False
        return canonical_digest(model_dump(mode="python", exclude={"content_digest"})) == content_digest
