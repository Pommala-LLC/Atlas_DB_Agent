from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from jsonschema import validate

from ojas_reconciler.db2_behavior.authority import AuthorityRequirementsExporter
from ojas_reconciler.db2_behavior.bdd_models import (
    AuthorityScope,
    BddBlockerCode,
    BddCompilationStatus,
    ClassificationSnapshot,
    MappingKind,
    VocabularyMapping,
    VocabularySnapshot,
)
from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _compile(name: str, *, scope: AuthorityScope = AuthorityScope.TEST_FIXTURE_ONLY):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    scenarios = ScenarioSpecCompiler().compile_all(parsed, semantic)
    vocabulary, classification = FixtureAuthorityBuilder().build(scenarios, authority_scope=scope)
    bdd = BddCompiler().compile_all(scenarios, vocabulary, classification)
    return scenarios, vocabulary, classification, bdd


def test_fixture_authority_compiles_every_admitted_scenario_as_test_only() -> None:
    scenarios, _, _, bdd = _compile("settle_customer_claims.sql")
    assert len(bdd.candidate_bdds) == len(scenarios.scenario_specs) == 6
    assert all(value.authority_scope == AuthorityScope.TEST_FIXTURE_ONLY for value in bdd.candidate_bdds)
    assert all(value.compilation_status == BddCompilationStatus.SUCCEEDED for value in bdd.compilation_results)


def test_process_batch_fixture_authority_compiles_admitted_scenarios() -> None:
    scenarios, _, _, bdd = _compile("process_claim_batch.sql")
    assert len(scenarios.scenario_specs) >= 3
    assert len(bdd.candidate_bdds) == len(scenarios.scenario_specs)
    assert len(bdd.gherkin_artifacts) == len(scenarios.scenario_specs)
    assert len(bdd.traceability_manifests) == len(scenarios.scenario_specs)


def test_missing_vocabulary_mapping_blocks_and_emits_no_partial_gherkin() -> None:
    scenarios, vocabulary, classification, _ = _compile("settle_customer_claims.sql")
    shortened_payload = vocabulary.model_dump(mode="python", exclude={"mappings", "content_digest"})
    shortened_payload["mappings"] = vocabulary.mappings[1:]
    shortened = VocabularySnapshot(**shortened_payload, content_digest=canonical_digest(shortened_payload))
    result = BddCompiler().compile_all(scenarios, shortened, classification)
    blocked = [value for value in result.compilation_results if value.compilation_status == BddCompilationStatus.BLOCKED]
    assert blocked
    assert any(BddBlockerCode.NO_APPROVED_BUSINESS_TERM in value.blockers for value in blocked)
    assert len(result.candidate_bdds) < len(scenarios.scenario_specs)


def test_missing_classification_approval_blocks_precondition_scenario() -> None:
    scenarios, vocabulary, classification, _ = _compile("settle_customer_claims.sql")
    empty_payload = {
        "schema_version": "classification-snapshot-1.1",
        "snapshot_id": classification.snapshot_id + "-empty",
        "registry_version": classification.registry_version,
        "effective_timestamp": classification.effective_timestamp,
        "authority_scope": classification.authority_scope,
        "approvals": (),
    }
    empty = ClassificationSnapshot(**empty_payload, content_digest=canonical_digest(empty_payload))
    result = BddCompiler().compile_all(scenarios, vocabulary, empty)
    assert any(BddBlockerCode.MISSING_CLASSIFICATION_APPROVAL in value.blockers for value in result.compilation_results)


def test_ambiguous_mapping_binding_blocks() -> None:
    scenarios, vocabulary, classification, _ = _compile("process_claim_batch.sql")
    first = vocabulary.mappings[0]
    duplicate_payload = first.model_dump(mode="python", exclude={"mapping_id", "content_digest"})
    duplicate_payload["mapping_id"] = first.mapping_id + "-duplicate"
    duplicate = first.__class__(**duplicate_payload, content_digest=canonical_digest(duplicate_payload))
    snapshot_payload = vocabulary.model_dump(mode="python", exclude={"mappings", "content_digest"})
    snapshot_payload["mappings"] = (*vocabulary.mappings, duplicate)
    ambiguous = VocabularySnapshot(**snapshot_payload, content_digest=canonical_digest(snapshot_payload))
    result = BddCompiler().compile_all(scenarios, ambiguous, classification)
    assert any(BddBlockerCode.AMBIGUOUS_APPROVED_BUSINESS_TERM in value.blockers for value in result.compilation_results)


def test_candidate_bdd_requires_complete_traceability_for_every_rendered_element() -> None:
    scenarios, vocabulary, classification, bdd = _compile("settle_customer_claims.sql")
    spec_by_id = {value.scenario_spec_id: value for value in scenarios.scenario_specs}
    artifact_by_id = {value.artifact_id: value for value in bdd.gherkin_artifacts}
    manifest_by_id = {value.manifest_id: value for value in bdd.traceability_manifests}
    requirements = AuthorityRequirementsExporter().export(scenarios)
    requirement_ids = {value.requirement_id for value in requirements.vocabulary_requirements}
    for candidate in bdd.candidate_bdds:
        spec = spec_by_id[candidate.scenario_spec_ref]
        artifact = artifact_by_id[candidate.gherkin_artifact_ref]
        manifest = manifest_by_id[candidate.traceability_manifest_ref]
        expected = 3 + len(spec.preconditions) + len(spec.expected_effects)
        assert len(manifest.element_bindings) == expected
        assert all(value.authority_requirement_ref in requirement_ids for value in manifest.element_bindings)
        assert artifact.text.endswith("\n")
        assert "\r" not in artifact.text
        assert manifest.scenario_spec_ref == spec.scenario_spec_id
        assert candidate.authority_requirements_digest == requirements.content_digest
        assert candidate.vocabulary_snapshot_digest == vocabulary.content_digest
        assert candidate.classification_snapshot_digest == classification.content_digest


def test_fixture_gherkin_is_technical_and_not_platform_governed() -> None:
    _, _, _, bdd = _compile("process_claim_batch.sql")
    for artifact in bdd.gherkin_artifacts:
        assert "Technical behavior" in artifact.text
        assert "technical effect" in artifact.text
    assert all(value.platform_governance_ref is None for value in bdd.candidate_bdds)


def test_bdd_batch_is_stable_across_process_environment() -> None:
    root = Path(__file__).parents[1]
    fixture = root / "tests" / "fixtures" / "settle_customer_claims.sql"
    script = (
        "from pathlib import Path;"
        "from ojas_reconciler.db2_behavior.canonical_json import canonical_json_bytes;"
        "from ojas_reconciler.db2_behavior.compiler import BddCompiler,ScenarioSpecCompiler;"
        "from ojas_reconciler.db2_behavior.fixture_authority import FixtureAuthorityBuilder;"
        "from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer;"
        "from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser;"
        f"p=LarkSqlPlSpikeParser().parse_file(Path({str(fixture)!r}));"
        "s=Phase1SemanticAnalyzer().analyze(p);"
        "x=ScenarioSpecCompiler().compile_all(p,s);"
        "v,c=FixtureAuthorityBuilder().build(x);"
        "b=BddCompiler().compile_all(x,v,c);"
        "import sys;sys.stdout.buffer.write(canonical_json_bytes(b))"
    )
    outputs = []
    for seed, timezone in (("31", "UTC"), ("1013", "America/Chicago")):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["PYTHONHASHSEED"] = seed
        env["TZ"] = timezone
        completed = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, env=env, cwd=root)
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]


def test_tampered_snapshot_digest_blocks_all_candidates() -> None:
    scenarios, vocabulary, classification, _ = _compile("settle_customer_claims.sql")
    tampered = vocabulary.model_copy(update={"content_digest": "sha256:" + "0" * 64})
    result = BddCompiler().compile_all(scenarios, tampered, classification)
    assert not result.candidate_bdds
    assert all(BddBlockerCode.VOCABULARY_SNAPSHOT_DIGEST_INVALID in value.blockers for value in result.compilation_results)


def test_tampered_scenario_nested_digest_blocks_all_candidates() -> None:
    scenarios, vocabulary, classification, _ = _compile("settle_customer_claims.sql")
    first = scenarios.effect_closures[0].model_copy(update={"content_digest": "sha256:" + "0" * 64})
    payload = scenarios.model_dump(mode="python", exclude={"effect_closures", "content_digest"})
    payload["effect_closures"] = (first, *scenarios.effect_closures[1:])
    tampered = scenarios.__class__(**payload, content_digest=canonical_digest(payload))
    result = BddCompiler().compile_all(tampered, vocabulary, classification)
    assert not result.candidate_bdds
    assert all(BddBlockerCode.SCENARIO_NESTED_ARTIFACT_DIGEST_INVALID in value.blockers for value in result.compilation_results)


def test_expired_mapping_blocks_compilation() -> None:
    scenarios, vocabulary, classification, _ = _compile("constraint_contradiction.sql")
    first = vocabulary.mappings[0]
    payload = first.model_dump(mode="python", exclude={"valid_from", "valid_to", "content_digest"})
    payload["valid_from"] = "2024-01-01T00:00:00.000000Z"
    payload["valid_to"] = "2025-01-01T00:00:00.000000Z"
    expired = first.__class__(**payload, content_digest=canonical_digest(payload))
    snapshot_payload = vocabulary.model_dump(mode="python", exclude={"mappings", "content_digest"})
    snapshot_payload["mappings"] = (expired, *vocabulary.mappings[1:])
    expired_snapshot = VocabularySnapshot(**snapshot_payload, content_digest=canonical_digest(snapshot_payload))
    result = BddCompiler().compile_all(scenarios, expired_snapshot, classification)
    assert any(BddBlockerCode.MAPPING_NOT_EFFECTIVE in value.blockers for value in result.compilation_results)


def test_platform_scope_can_compile_fully_resolved_direct_behavior() -> None:
    scenarios, vocabulary, classification, bdd = _compile(
        "constraint_contradiction.sql",
        scope=AuthorityScope.PLATFORM,
    )
    assert scenarios.scenario_specs
    assert bdd.candidate_bdds
    assert all(value.authority_scope == AuthorityScope.PLATFORM for value in bdd.candidate_bdds)


def test_bdd_batch_validates_against_versioned_json_schema() -> None:
    import json

    _, _, _, bdd = _compile("settle_customer_claims.sql")
    schema = json.loads((Path(__file__).parents[1] / "contracts" / "bdd-compilation-batch-1.1.schema.json").read_text())
    validate(instance=bdd.model_dump(mode="json"), schema=schema)
