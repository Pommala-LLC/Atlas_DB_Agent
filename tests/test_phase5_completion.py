from __future__ import annotations

from pathlib import Path

import pytest

from ojas_reconciler.db2_behavior.authority import AuthorityRequirementsExporter
from ojas_reconciler.db2_behavior.bdd_models import (
    BddBlockerCode,
    BddCompilationStatus,
    MappingKind,
    PlaceholderContract,
    VocabularyMapping,
    VocabularySnapshot,
)
from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.scenario_models import ScenarioBlockerCode, ScenarioCompilationStatus
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _workflow(name: str = "constraint_contradiction.sql"):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    vocabulary, classification = FixtureAuthorityBuilder().build(scenarios)
    return parsed, semantic, scenarios, vocabulary, classification


def _replace_mapping(snapshot: VocabularySnapshot, old_id: str, replacement: VocabularyMapping) -> VocabularySnapshot:
    mappings = tuple(replacement if item.mapping_id == old_id else item for item in snapshot.mappings)
    payload = snapshot.model_dump(mode="python", exclude={"mappings", "content_digest"})
    payload["mappings"] = mappings
    return VocabularySnapshot(**payload, content_digest=canonical_digest(payload))


@pytest.mark.parametrize(
    "kind",
    [
        MappingKind.EXACT_APPROVED_MAPPING,
        MappingKind.STRUCTURAL_APPROVED_MAPPING,
        MappingKind.SYMBOL_BOUND_APPROVED_MAPPING,
        MappingKind.MANUALLY_APPROVED_MAPPING,
    ],
)
def test_all_promotable_mapping_kinds_are_enforced(kind: MappingKind) -> None:
    _, _, scenarios, vocabulary, classification = _workflow()
    requirements = AuthorityRequirementsExporter().export(scenarios)
    requirement = requirements.vocabulary_requirements[0]
    old = next(item for item in vocabulary.mappings if item.manual_requirement_ref == requirement.requirement_id)
    payload = {
        "mapping_id": old.mapping_id + "-" + kind.value.lower(),
        "mapping_version": "test-1.0",
        "mapping_kind": kind,
        "normalized_technical_pattern_ref": requirement.normalized_technical_pattern_ref,
        "structural_context_digest": (
            requirement.structural_context_digest
            if kind == MappingKind.STRUCTURAL_APPROVED_MAPPING
            else None
        ),
        "symbol_binding_refs": (
            requirement.symbol_binding_refs
            if kind == MappingKind.SYMBOL_BOUND_APPROVED_MAPPING
            else ()
        ),
        "manual_requirement_ref": (
            requirement.requirement_id
            if kind == MappingKind.MANUALLY_APPROVED_MAPPING
            else None
        ),
        "phrase_template": old.phrase_template,
        "placeholder_contract": (),
        "supported_modalities": old.supported_modalities,
        "approval_ref": "test-authority:vocabulary",
        "authority_scope": old.authority_scope,
        "valid_from": old.valid_from,
        "valid_to": old.valid_to,
        "evidence_refs": old.evidence_refs,
    }
    replacement = VocabularyMapping(**payload, content_digest=canonical_digest(payload))
    updated = _replace_mapping(vocabulary, old.mapping_id, replacement)
    result = BddCompiler().compile_all(scenarios, updated, classification)
    assert result.candidate_bdds
    assert all(item.compilation_status == BddCompilationStatus.SUCCEEDED for item in result.compilation_results)


def test_unbound_placeholder_blocks_without_partial_gherkin() -> None:
    _, _, scenarios, vocabulary, classification = _workflow()
    requirements = AuthorityRequirementsExporter().export(scenarios)
    requirement = requirements.vocabulary_requirements[0]
    old = next(item for item in vocabulary.mappings if item.manual_requirement_ref == requirement.requirement_id)
    payload = old.model_dump(mode="python", exclude={"phrase_template", "placeholder_contract", "content_digest"})
    payload["phrase_template"] = "technical {missing_value}"
    payload["placeholder_contract"] = (PlaceholderContract(placeholder="missing_value"),)
    replacement = VocabularyMapping(**payload, content_digest=canonical_digest(payload))
    updated = _replace_mapping(vocabulary, old.mapping_id, replacement)
    result = BddCompiler().compile_all(scenarios, updated, classification)
    assert not result.candidate_bdds
    assert any(BddBlockerCode.PLACEHOLDER_BINDING_INVALID in item.blockers for item in result.compilation_results)


def test_classification_approval_is_bound_to_observation_digest() -> None:
    _, _, scenarios, vocabulary, classification = _workflow("settle_customer_claims.sql")
    approval = classification.approvals[0]
    payload = approval.model_dump(mode="python", exclude={"classification_observation_digest", "content_digest"})
    payload["classification_observation_digest"] = "sha256:" + "0" * 64
    tampered = approval.__class__(**payload, content_digest=canonical_digest(payload))
    snapshot_payload = classification.model_dump(mode="python", exclude={"approvals", "content_digest"})
    snapshot_payload["approvals"] = (tampered, *classification.approvals[1:])
    tampered_snapshot = classification.__class__(**snapshot_payload, content_digest=canonical_digest(snapshot_payload))
    result = BddCompiler().compile_all(scenarios, vocabulary, tampered_snapshot)
    assert any(BddBlockerCode.CLASSIFICATION_OBSERVATION_DIGEST_MISMATCH in item.blockers for item in result.compilation_results)


def test_semantic_digest_tampering_blocks_scenario_spec_compilation() -> None:
    parsed, semantic, _, _, _ = _workflow()
    tampered = semantic.model_copy(update={"content_digest": "sha256:" + "0" * 64})
    batch = ScenarioSpecCompiler().compile_all(parsed, tampered)
    assert not batch.scenario_specs
    assert all(item.compilation_status == ScenarioCompilationStatus.BLOCKED for item in batch.compilation_results)
    assert all(ScenarioBlockerCode.SEMANTIC_RESULT_DIGEST_INVALID in item.blockers for item in batch.compilation_results)


def test_candidate_emission_is_atomic_when_rendering_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, scenarios, vocabulary, classification = _workflow()
    compiler = BddCompiler()

    def fail_render(**_: object):
        raise ValueError("traceability construction failed")

    monkeypatch.setattr(compiler, "_render", fail_render)
    result = compiler.compile_all(scenarios, vocabulary, classification)
    assert not result.gherkin_artifacts
    assert not result.traceability_manifests
    assert not result.candidate_bdds
    assert all(item.compilation_status == BddCompilationStatus.FAILED for item in result.compilation_results)
    assert all(BddBlockerCode.TRACEABILITY_MANIFEST_FAILED in item.blockers for item in result.compilation_results)
