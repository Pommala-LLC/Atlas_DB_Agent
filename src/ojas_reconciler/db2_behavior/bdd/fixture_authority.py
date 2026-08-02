from __future__ import annotations

import hashlib

from ojas_reconciler.db2_behavior.bdd.authority import AuthorityRequirementsExporter
from ojas_reconciler.db2_behavior.bdd.models import (
    AuthorityScope,
    ClassificationApproval,
    ClassificationSnapshot,
    MappingKind,
    VocabularyMapping,
    VocabularySnapshot,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.bdd.scenario_models import ScenarioSpecBatchResult
from ojas_reconciler.db2_behavior.analysis.models import EffectModality


class FixtureAuthorityBuilder:
    """Builds deterministic authority snapshots for compiler testing only.

    TEST_FIXTURE_ONLY is the default and cannot be mistaken for platform
    governance. PLATFORM mode exists only for tests that exercise platform
    gates with explicit fixture references.
    """

    FIXED_EFFECTIVE_TIME = "2026-01-01T00:00:00.000000Z"

    def build(
        self,
        batch: ScenarioSpecBatchResult,
        *,
        authority_scope: AuthorityScope = AuthorityScope.TEST_FIXTURE_ONLY,
    ) -> tuple[VocabularySnapshot, ClassificationSnapshot]:
        requirements = AuthorityRequirementsExporter().export(batch)
        observations = {
            value.classification_observation_id: value
            for value in batch.classification_observations
        }
        approvals: list[ClassificationApproval] = []
        mappings: list[VocabularyMapping] = []

        for requirement in requirements.vocabulary_requirements:
            modalities = (
                (requirement.required_modality,)
                if requirement.required_modality is not None
                else ()
            )
            phrase = self._phrase(requirement.slot_kind.value, requirement.source_ref, requirement.required_modality, authority_scope)
            mapping_id = self._stable_id(
                "fixture-mapping",
                requirement.requirement_id,
                phrase,
                authority_scope.value,
            )
            without_digest = {
                "mapping_id": mapping_id,
                "mapping_version": "fixture-1.1",
                "mapping_kind": MappingKind.MANUALLY_APPROVED_MAPPING,
                "normalized_technical_pattern_ref": requirement.normalized_technical_pattern_ref,
                "structural_context_digest": requirement.structural_context_digest,
                "symbol_binding_refs": requirement.symbol_binding_refs,
                "manual_requirement_ref": requirement.requirement_id,
                "phrase_template": phrase,
                "placeholder_contract": (),
                "supported_modalities": modalities,
                "approval_ref": f"fixture-authority:{authority_scope.value.lower()}:vocabulary",
                "authority_scope": authority_scope,
                "valid_from": self.FIXED_EFFECTIVE_TIME,
                "valid_to": None,
                "evidence_refs": requirement.evidence_refs or (requirement.source_ref,),
            }
            mappings.append(
                VocabularyMapping(
                    **without_digest,
                    content_digest=canonical_digest(without_digest),
                )
            )

        for requirement in requirements.classification_requirements:
            observation = observations[requirement.classification_observation_ref]
            approval_id = self._stable_id(
                "fixture-classification-approval",
                requirement.classification_observation_ref,
                authority_scope.value,
            )
            without_digest = {
                "approval_id": approval_id,
                "classification_observation_ref": requirement.classification_observation_ref,
                "classification_observation_digest": canonical_digest(observation),
                "approved_candidate": observation.candidate,
                "approval_ref": f"fixture-authority:{authority_scope.value.lower()}:classification",
                "authority_scope": authority_scope,
                "valid_from": self.FIXED_EFFECTIVE_TIME,
                "valid_to": None,
                "evidence_refs": observation.classification_evidence_refs or (observation.classification_observation_id,),
            }
            approvals.append(
                ClassificationApproval(
                    **without_digest,
                    content_digest=canonical_digest(without_digest),
                )
            )

        vocabulary_without_digest = {
            "schema_version": "vocabulary-snapshot-1.1",
            "snapshot_id": "fixture-vocabulary-" + self._stable_suffix(batch.content_digest, authority_scope.value),
            "registry_version": "fixture-1.1",
            "effective_timestamp": self.FIXED_EFFECTIVE_TIME,
            "authority_scope": authority_scope,
            "mappings": tuple(sorted(mappings, key=lambda value: value.mapping_id)),
        }
        vocabulary = VocabularySnapshot(
            **vocabulary_without_digest,
            content_digest=canonical_digest(vocabulary_without_digest),
        )

        classification_without_digest = {
            "schema_version": "classification-snapshot-1.1",
            "snapshot_id": "fixture-classification-" + self._stable_suffix(batch.content_digest, authority_scope.value),
            "registry_version": "fixture-1.1",
            "effective_timestamp": self.FIXED_EFFECTIVE_TIME,
            "authority_scope": authority_scope,
            "approvals": tuple(sorted(approvals, key=lambda value: value.approval_id)),
        }
        classification = ClassificationSnapshot(
            **classification_without_digest,
            content_digest=canonical_digest(classification_without_digest),
        )
        return vocabulary, classification

    @staticmethod
    def _phrase(kind: str, source_ref: str, modality: EffectModality | None, authority_scope: AuthorityScope) -> str:
        suffix = source_ref[-12:]
        if kind == "FEATURE_TITLE":
            return (
                "DB2 procedure technical behavior candidates"
                if authority_scope == AuthorityScope.TEST_FIXTURE_ONLY
                else "DB2 procedure behavior candidates"
            )
        if kind == "SCENARIO_NAME":
            return f"Technical behavior {suffix}"
        if kind == "ACTION":
            if source_ref.startswith("CURSOR_ITERATION:"):
                return "one cursor row is evaluated"
            if source_ref.startswith("HANDLER_ACTIVATION:"):
                return "the handler is activated"
            if source_ref.startswith("POST_LOOP_AGGREGATION:"):
                return "post-loop aggregation is evaluated"
            return "the DB2 stored procedure is invoked"
        if kind == "PRECONDITION":
            return f"technical precondition {suffix} holds"
        if kind == "EFFECT":
            if modality == EffectModality.MUST_NOT:
                return f"technical effect {suffix} does not occur"
            return f"technical effect {suffix} occurs"
        raise ValueError(f"Unsupported vocabulary slot kind: {kind}")

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join(parts)
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _stable_suffix(*parts: str) -> str:
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]
