from __future__ import annotations

import json
from pathlib import Path

from ojas_reconciler.db2_behavior.doctor import build_doctor_report
from ojas_reconciler.db2_behavior.pipeline import EndToEndPipeline
from ojas_reconciler.db2_behavior.release_models import AuthorityMode, DoctorCheckStatus, PipelineStageStatus


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def test_end_to_end_local_pipeline_with_fixture_authority(tmp_path: Path) -> None:
    output = tmp_path / "run"
    db = output / "governance.sqlite3"
    manifest = EndToEndPipeline().run(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
        governance_db=db,
    )
    assert manifest.content_digest.startswith("sha256:")
    assert db.exists()
    stages = {stage.stage: stage for stage in manifest.stage_records}
    assert stages["GATE_0_INVENTORY"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_1_PARSE_EVIDENCE"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_2_3_4_SEMANTIC"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_5A_SCENARIO_SPEC"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_5B_BDD_COMPILER"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION"].status == PipelineStageStatus.SKIPPED
    assert "DEFERRED_CAPABILITY_DISABLED" in stages["PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION"].blocker_codes
    assert stages["PHASE_7_LOCAL_EVIDENCE_CACHE"].status == PipelineStageStatus.SUCCEEDED
    assert (output / "run-manifest.json").exists()
    assert list((output / "gherkin").glob("*.feature"))


def test_end_to_end_without_authority_stops_only_bdd(tmp_path: Path) -> None:
    output = tmp_path / "run"
    manifest = EndToEndPipeline().run(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.NONE,
    )
    stages = {stage.stage: stage for stage in manifest.stage_records}
    assert stages["PHASE_5A_SCENARIO_SPEC"].status == PipelineStageStatus.SUCCEEDED
    assert stages["PHASE_5B_BDD_COMPILER"].status == PipelineStageStatus.BLOCKED
    assert "AUTHORITY_SNAPSHOT_NOT_SUPPLIED" in stages["PHASE_5B_BDD_COMPILER"].blocker_codes
    assert stages["PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION"].status == PipelineStageStatus.SKIPPED
    assert stages["PHASE_7_LOCAL_EVIDENCE_CACHE"].status == PipelineStageStatus.SKIPPED


def test_doctor_validates_local_project(tmp_path: Path) -> None:
    report = build_doctor_report(ROOT)
    assert report.overall_status in {DoctorCheckStatus.PASS, DoctorCheckStatus.WARN}
    assert all(check.status != DoctorCheckStatus.FAIL for check in report.checks)


def test_manifest_is_valid_json(tmp_path: Path) -> None:
    output = tmp_path / "run"
    EndToEndPipeline().run(
        source=FIXTURES / "eligible_claim.sql",
        output_dir=output,
        authority_mode=AuthorityMode.NONE,
    )
    payload = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "db2-e2e-run-1.0"
    assert payload["input_dependent_checks"]


def test_release_artifacts_validate_against_json_schema(tmp_path: Path) -> None:
    from jsonschema import Draft202012Validator

    output = tmp_path / "run"
    EndToEndPipeline().run(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    run_schema = json.loads((ROOT / "contracts" / "end-to-end-run-1.0.schema.json").read_text())
    doctor_schema = json.loads((ROOT / "contracts" / "doctor-report-1.0.schema.json").read_text())
    run_payload = json.loads((output / "run-manifest.json").read_text())
    doctor_payload = json.loads(build_doctor_report(ROOT).model_dump_json())
    Draft202012Validator(run_schema).validate(run_payload)
    Draft202012Validator(doctor_schema).validate(doctor_payload)


def test_experimental_runtime_stage_requires_explicit_pipeline_opt_in(tmp_path: Path) -> None:
    output = tmp_path / "run"
    manifest = EndToEndPipeline().run(
        source=FIXTURES / "constraint_contradiction.sql",
        output_dir=output,
        authority_mode=AuthorityMode.NONE,
        enable_experimental_runtime=True,
    )
    stages = {stage.stage: stage for stage in manifest.stage_records}
    stage = stages["PHASE_6_EXPERIMENTAL_RUNTIME_VERIFICATION"]
    assert stage.status == PipelineStageStatus.SUCCEEDED
    assert "DEFERRED_CAPABILITY_NOT_PRODUCT_BASELINE" in stage.blocker_codes
