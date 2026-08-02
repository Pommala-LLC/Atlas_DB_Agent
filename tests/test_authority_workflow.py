from __future__ import annotations

from pathlib import Path

from jsonschema import validate

from ojas_reconciler.db2_behavior.authority import AuthorityRequirementsExporter, AuthoritySnapshotValidator
from ojas_reconciler.db2_behavior.authority_models import AuthorityValidationIssueCode, AuthorityValidationStatus
from ojas_reconciler.db2_behavior.bdd_explain import BddExplanationBuilder
from ojas_reconciler.db2_behavior.bdd_models import BddBlockerCode, BddCompilationStatus, VocabularySnapshot
from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _workflow(name: str = "settle_customer_claims.sql"):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    vocabulary, classification = FixtureAuthorityBuilder().build(scenarios)
    return scenarios, vocabulary, classification


def test_authority_requirements_export_is_complete_and_digest_stable() -> None:
    scenarios, _, _ = _workflow()
    manifest = AuthorityRequirementsExporter().export(scenarios)
    assert manifest.required_authority_scope == "PLATFORM"
    # Every spec requires feature, scenario, action, plus its rendered preconditions/effects.
    assert len(manifest.vocabulary_requirements) == sum(
        3 + len(spec.preconditions) + len(spec.expected_effects)
        for spec in scenarios.scenario_specs
    )
    assert all(item.normalized_technical_pattern_ref for item in manifest.vocabulary_requirements)
    assert all(item.structural_context_digest.startswith("sha256:") for item in manifest.vocabulary_requirements)
    expected_classifications = len({
        precondition.classification_observation_ref
        for spec in scenarios.scenario_specs
        for precondition in spec.preconditions
        if precondition.classification_observation_ref is not None
    })
    assert len(manifest.classification_requirements) == expected_classifications
    assert all(item.classification_observation_digest.startswith("sha256:") for item in manifest.classification_requirements)
    payload = manifest.model_dump(mode="python", exclude={"content_digest"})
    assert canonical_digest(payload) == manifest.content_digest


def test_fixture_authority_snapshots_validate() -> None:
    _, vocabulary, classification = _workflow()
    result = AuthoritySnapshotValidator().validate(vocabulary, classification)
    assert result.validation_status == AuthorityValidationStatus.VALID
    assert not result.issues


def test_duplicate_active_mapping_binding_is_invalid_before_compilation() -> None:
    _, vocabulary, classification = _workflow("process_claim_batch.sql")
    first = vocabulary.mappings[0]
    duplicate_payload = first.model_dump(mode="python", exclude={"mapping_id", "content_digest"})
    duplicate_payload["mapping_id"] = first.mapping_id + "-duplicate"
    duplicate = first.__class__(**duplicate_payload, content_digest=canonical_digest(duplicate_payload))
    snapshot_payload = vocabulary.model_dump(mode="python", exclude={"mappings", "content_digest"})
    snapshot_payload["mappings"] = (*vocabulary.mappings, duplicate)
    duplicated = VocabularySnapshot(**snapshot_payload, content_digest=canonical_digest(snapshot_payload))
    result = AuthoritySnapshotValidator().validate(duplicated, classification)
    assert result.validation_status == AuthorityValidationStatus.INVALID
    assert any(issue.code == AuthorityValidationIssueCode.DUPLICATE_ACTIVE_MAPPING_BINDING for issue in result.issues)


def test_explanation_lists_missing_vocabulary_and_withholds_all_bdd_outputs() -> None:
    scenarios, vocabulary, classification = _workflow()
    shortened_payload = vocabulary.model_dump(mode="python", exclude={"mappings", "content_digest"})
    shortened_payload["mappings"] = vocabulary.mappings[1:]
    shortened = VocabularySnapshot(**shortened_payload, content_digest=canonical_digest(shortened_payload))
    bdd = BddCompiler().compile_all(scenarios, shortened, classification)
    explanation = BddExplanationBuilder().build(scenarios, bdd, shortened, classification)
    blocked = [item for item in explanation.explanations if item.result == "BLOCKED"]
    assert blocked
    assert any(item.missing_vocabulary_slots for item in blocked)
    assert all(item.withheld_outputs == ("GHERKIN_ARTIFACT", "TRACEABILITY_MANIFEST", "CANDIDATE_BDD") for item in blocked)
    assert any(BddBlockerCode.NO_APPROVED_BUSINESS_TERM in item.blocker_codes for item in blocked)


def test_explanation_surfaces_platform_dependency_gate_for_affected_specs() -> None:
    from ojas_reconciler.db2_behavior.bdd_models import AuthorityScope
    from ojas_reconciler.db2_behavior.scenario_models import ResolutionStatus

    scenarios, _, _ = _workflow("process_claim_batch.sql")
    vocabulary, classification = FixtureAuthorityBuilder().build(
        scenarios,
        authority_scope=AuthorityScope.PLATFORM,
    )
    first = scenarios.resolution_vectors[0]
    resolution_payload = first.model_dump(
        mode="python",
        exclude={"trigger_resolution", "content_digest"},
    )
    resolution_payload["trigger_resolution"] = ResolutionStatus.NOT_ASSESSED
    unresolved = first.__class__(
        **resolution_payload,
        content_digest=canonical_digest(resolution_payload),
    )
    batch_payload = scenarios.model_dump(
        mode="python",
        exclude={"resolution_vectors", "content_digest"},
    )
    batch_payload["resolution_vectors"] = (unresolved, *scenarios.resolution_vectors[1:])
    unresolved_batch = scenarios.__class__(
        **batch_payload,
        content_digest=canonical_digest(batch_payload),
    )
    bdd = BddCompiler().compile_all(unresolved_batch, vocabulary, classification)
    blocked = [item for item in bdd.compilation_results if item.compilation_status == BddCompilationStatus.BLOCKED]
    assert blocked
    assert any(BddBlockerCode.DEPENDENCY_RESOLUTION_INCOMPLETE in item.blockers for item in blocked)
    explanation = BddExplanationBuilder().build(unresolved_batch, bdd, vocabulary, classification)
    affected = [item for item in explanation.explanations if BddBlockerCode.DEPENDENCY_RESOLUTION_INCOMPLETE in item.blocker_codes]
    assert affected
    assert any(value.value == "NOT_ASSESSED" for item in affected for value in item.dependency_resolution.values())


def test_authority_artifacts_validate_against_versioned_schemas() -> None:
    import json

    scenarios, vocabulary, classification = _workflow()
    requirements = AuthorityRequirementsExporter().export(scenarios)
    validation = AuthoritySnapshotValidator().validate(vocabulary, classification)
    bdd = BddCompiler().compile_all(scenarios, vocabulary, classification)
    explanations = BddExplanationBuilder().build(scenarios, bdd, vocabulary, classification)
    root = Path(__file__).parents[1]
    cases = (
        (requirements, "authority-requirements-1.1.schema.json"),
        (validation, "authority-validation-1.1.schema.json"),
        (explanations, "bdd-explanation-batch-1.1.schema.json"),
    )
    for artifact, schema_name in cases:
        schema = json.loads((root / "contracts" / schema_name).read_text(encoding="utf-8"))
        validate(instance=artifact.model_dump(mode="json"), schema=schema)
