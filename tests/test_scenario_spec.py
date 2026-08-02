from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.scenario_models import (
    ScenarioBlockerCode,
    ScenarioCompilationStatus,
)
from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser

FIXTURES = Path(__file__).parent / "fixtures"


def _compile(name: str):
    parsed = LarkSqlPlSpikeParser().parse_file(FIXTURES / name)
    assert parsed.ast is not None
    semantic = Phase1SemanticAnalyzer().analyze(parsed)
    return parsed, semantic, ScenarioSpecCompiler().compile_all(parsed, semantic)


def test_settle_compiles_only_complete_technical_behaviors() -> None:
    _, semantic, batch = _compile("settle_customer_claims.sql")
    succeeded = [
        value for value in batch.compilation_results
        if value.compilation_status == ScenarioCompilationStatus.SUCCEEDED
    ]
    blocked = [
        value for value in batch.compilation_results
        if value.compilation_status == ScenarioCompilationStatus.BLOCKED
    ]
    assert len(batch.compilation_results) == len(semantic.behavior_bundles)
    assert len(succeeded) == 6
    assert len(blocked) == 4
    assert len(batch.scenario_specs) == 6


def test_process_batch_compiles_three_and_blocks_unresolved_boundaries() -> None:
    _, _, batch = _compile("process_claim_batch.sql")
    succeeded = [
        value for value in batch.compilation_results
        if value.compilation_status == ScenarioCompilationStatus.SUCCEEDED
    ]
    blocked = [
        value for value in batch.compilation_results
        if value.compilation_status == ScenarioCompilationStatus.BLOCKED
    ]
    assert len(succeeded) == 3
    assert len(blocked) == 6
    assert any(
        ScenarioBlockerCode.UNKNOWN_EFFECT_MODALITY in value.blockers
        or ScenarioBlockerCode.BEHAVIOR_BUNDLE_PARTIAL in value.blockers
        for value in blocked
    )


def test_contradictory_behavior_is_blocked_and_possible_branch_compiles() -> None:
    _, _, batch = _compile("constraint_contradiction.sql")
    assert len(batch.scenario_specs) == 1
    blocked = next(
        value for value in batch.compilation_results
        if value.compilation_status == ScenarioCompilationStatus.BLOCKED
    )
    assert ScenarioBlockerCode.OBVIOUS_PREDICATE_CONTRADICTION in blocked.blockers


def test_scenario_spec_restores_three_identity_spine_and_has_no_render_state() -> None:
    _, _, batch = _compile("settle_customer_claims.sql")
    spec = batch.scenario_specs[0]
    assert spec.behavior_id.startswith("behavior-")
    assert spec.source_symbol_id == batch.source_symbol_id
    assert spec.symbol_lineage_id == batch.symbol_lineage_id
    assert spec.action.procedure_identity_ref == spec.procedure_identity_ref
    dumped = spec.model_dump(mode="python")
    assert "rendering_eligibility" not in dumped
    assert "rendering_blockers" not in dumped
    assert "governance_status" not in dumped
    assert "trust_label" not in dumped


def test_scenario_spec_digest_is_reproducible_from_digest_free_projection() -> None:
    _, _, batch = _compile("process_claim_batch.sql")
    spec = batch.scenario_specs[0]
    payload = spec.model_dump(mode="python", exclude={"content_digest"})
    assert canonical_digest(payload) == spec.content_digest


def test_successful_specs_have_no_unknown_effects_and_blocked_results_emit_no_spec() -> None:
    _, _, batch = _compile("settle_customer_claims.sql")
    spec_by_id = {value.scenario_spec_id: value for value in batch.scenario_specs}
    for result in batch.compilation_results:
        if result.compilation_status == ScenarioCompilationStatus.SUCCEEDED:
            assert result.scenario_spec_ref in spec_by_id
            spec = spec_by_id[result.scenario_spec_ref]
            assert all(value.modality.value != "UNKNOWN" for value in spec.expected_effects)
            assert result.output_digest == spec.content_digest
        else:
            assert result.scenario_spec_ref is None
            assert result.output_digest is None


def test_scenario_spec_batch_is_stable_across_process_environment() -> None:
    import os
    import subprocess
    import sys

    root = Path(__file__).parents[1]
    fixture = root / "tests" / "fixtures" / "settle_customer_claims.sql"
    script = (
        "from pathlib import Path;"
        "from ojas_reconciler.db2_behavior.canonical_json import canonical_json_bytes;"
        "from ojas_reconciler.db2_behavior.compiler import ScenarioSpecCompiler;"
        "from ojas_reconciler.db2_behavior.semantic import Phase1SemanticAnalyzer;"
        "from ojas_reconciler.db2_behavior.spikes.lark_sqlpl.parser import LarkSqlPlSpikeParser;"
        f"p=LarkSqlPlSpikeParser().parse_file(Path({str(fixture)!r}));"
        "s=Phase1SemanticAnalyzer().analyze(p);"
        "b=ScenarioSpecCompiler().compile_all(p,s);"
        "import sys;sys.stdout.buffer.write(canonical_json_bytes(b))"
    )
    outputs = []
    for seed, timezone in (("23", "UTC"), ("991", "America/Chicago")):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["PYTHONHASHSEED"] = seed
        env["TZ"] = timezone
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            env=env,
            cwd=root,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
