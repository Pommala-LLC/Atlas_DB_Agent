from __future__ import annotations

import importlib
import sys
from datetime import datetime, timezone

import pytest

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.runtime_evidence_properties import (
    Db2RuntimeEvidenceProperties,
    RuntimeEvidenceAvailability,
    RuntimeEvidencePlatform,
    RuntimeEvidenceSource,
    RuntimeEvidenceUnavailable,
    load_runtime_evidence_backend,
    runtime_evidence_status,
)
from ojas_reconciler.db2_behavior.runtime_models import (
    RuntimeInvocation,
    RuntimeInvocationParameter,
    RuntimePlanStatus,
    RuntimeValue,
    RuntimeValueKind,
    RuntimeVerificationPlan,
)


def test_disabled_property_does_not_import_any_runtime_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    imported: list[str] = []
    monkeypatch.setattr(importlib, "import_module", lambda name: imported.append(name))
    properties = Db2RuntimeEvidenceProperties(enabled=False)
    assert load_runtime_evidence_backend(properties) is None
    assert imported == []


def test_luw_property_refuses_when_driver_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    properties = Db2RuntimeEvidenceProperties(
        enabled=True,
        platform=RuntimeEvidencePlatform.DB2_LUW,
        source=RuntimeEvidenceSource.LIVE_PROBE,
        availability_attestation_ref="sandbox-attestation-001",
        connection_ref="env:OJAS_DB2_CONNECTION_STRING",
    )
    status, reasons = runtime_evidence_status(properties)
    assert status is RuntimeEvidenceAvailability.UNAVAILABLE
    assert any("ibm_db" in reason for reason in reasons)
    with pytest.raises(RuntimeEvidenceUnavailable, match="ibm_db"):
        load_runtime_evidence_backend(properties)


def test_zos_property_loads_only_offline_ifcid_backend() -> None:
    sentinel = object()
    ibm_db_before = sys.modules.get("ibm_db", sentinel)
    properties = Db2RuntimeEvidenceProperties(
        enabled=True,
        platform=RuntimeEvidencePlatform.DB2_ZOS,
        source=RuntimeEvidenceSource.IFCID_EXTRACT,
        availability_attestation_ref="ifcid-extract-attestation-001",
        ifcid_adapter_ref="site-adapter-v1",
    )
    backend = load_runtime_evidence_backend(properties)
    assert backend is not None
    assert backend.module_name.endswith("runtime.adapters.db2_zos_ifcid")
    assert backend.implementation_name == "IfcidObservationDeriver"
    # Preserve the test's real invariant: loading the offline z/OS backend must
    # not import or replace the LUW driver. It may already exist because another
    # test or plugin imported it earlier in the process.
    assert sys.modules.get("ibm_db", sentinel) is ibm_db_before


def test_property_shapes_are_platform_specific() -> None:
    with pytest.raises(ValueError, match="LIVE_PROBE"):
        Db2RuntimeEvidenceProperties(
            enabled=True,
            platform=RuntimeEvidencePlatform.DB2_LUW,
            source=RuntimeEvidenceSource.IFCID_EXTRACT,
            availability_attestation_ref="attestation",
            connection_ref="connection",
        )
    properties = Db2RuntimeEvidenceProperties(
        enabled=True,
        platform=RuntimeEvidencePlatform.DB2_ZOS,
        source=RuntimeEvidenceSource.IFCID_EXTRACT,
        availability_attestation_ref="attestation",
        ifcid_adapter_ref="   ",
    )
    status, reasons = runtime_evidence_status(properties)
    assert status is RuntimeEvidenceAvailability.SKIPPED
    assert reasons == ("IFCID_ADAPTER_REF_NOT_PROVIDED",)
    assert load_runtime_evidence_backend(properties) is None




def test_blank_optional_runtime_references_are_ignored() -> None:
    properties = Db2RuntimeEvidenceProperties(
        enabled=True,
        platform=RuntimeEvidencePlatform.DB2_LUW,
        source=RuntimeEvidenceSource.LIVE_PROBE,
        availability_attestation_ref="attestation",
        connection_ref="  ",
        ifcid_adapter_ref="",
    )
    assert properties.connection_ref is None
    assert properties.ifcid_adapter_ref is None
    status, reasons = runtime_evidence_status(properties)
    assert status is RuntimeEvidenceAvailability.SKIPPED
    assert reasons == ("CONNECTION_REF_NOT_PROVIDED",)

def _invocation() -> RuntimeInvocation:
    payload = {
        "invocation_id": "invocation-runtime-probe",
        "procedure_schema": "CLAIMS",
        "procedure_name": "P",
        "parameters": (
            RuntimeInvocationParameter(
                parameter_name="P_IN",
                parameter_mode="IN",
                type_text="INTEGER",
                value=RuntimeValue(value_kind=RuntimeValueKind.INTEGER, canonical_value="1"),
            ),
            RuntimeInvocationParameter(
                parameter_name="P_OUT",
                parameter_mode="OUT",
                type_text="VARCHAR(20)",
                value=RuntimeValue(value_kind=RuntimeValueKind.NULL),
            ),
        ),
    }
    return RuntimeInvocation(**payload, content_digest=canonical_digest(payload))


def _plan() -> RuntimeVerificationPlan:
    payload = {
        "plan_id": "plan-runtime-probe",
        "behavior_id": "behavior-runtime-probe",
        "source_symbol_id": "symbol-runtime-probe",
        "symbol_lineage_id": "lineage-runtime-probe",
        "artifact_revision_id": "revision-runtime-probe",
        "scenario_spec_ref": "scenario-runtime-probe",
        "scenario_spec_digest": "sha256:scenario",
        "procedure_identity_ref": "procedure-runtime-probe",
        "procedure_schema": "CLAIMS",
        "procedure_name": "P",
        "input_requirements": (),
        "expected_observations": (),
        "safety_assessment_ref": "safety-runtime-probe",
        "plan_status": RuntimePlanStatus.READY_DB2_SANDBOX,
        "blockers": (),
        "evidence_refs": (),
    }
    return RuntimeVerificationPlan(**payload, content_digest=canonical_digest(payload))


def test_corrected_luw_callproc_returns_out_values() -> None:
    from ojas_reconciler.db2_behavior.runtime_probe import Db2LuwProbe

    class FakeIbmDb:
        @staticmethod
        def callproc(conn: object, qualified: str, inputs: tuple[str | None, ...]):
            assert qualified == "CLAIMS.P"
            return (object(), "1", "APPROVED")

        @staticmethod
        def stmt_error(*args: object) -> str:
            return ""

        @staticmethod
        def conn_error(*args: object) -> str:
            return ""

    probe = Db2LuwProbe()
    probe._ibm_db = FakeIbmDb()  # type: ignore[attr-defined]
    probe._conn = object()  # type: ignore[attr-defined]
    outputs, sqlstate = probe.call_procedure(_invocation())
    assert outputs == {"P_OUT": "APPROVED"}
    assert sqlstate is None


def test_package_cache_diff_preserves_uncertain_counts() -> None:
    from ojas_reconciler.db2_behavior.runtime_probe import diff_package_cache

    statements, gaps = diff_package_cache(
        {"A": (5, "DYNAMIC"), "DISAPPEARED": (2, "STATIC")},
        {"A": (2, "DYNAMIC"), "B": (0, "STATIC")},
    )
    by_text = {statement.statement_text: statement for statement in statements}
    assert by_text["A"].executions is None
    assert by_text["A"].capture_qualifier == "POSSIBLE_CACHE_EVICTION_UNDERCOUNT"
    assert by_text["B"].executions is None
    assert by_text["B"].capture_qualifier == "POSSIBLE_METRICS_UNAVAILABLE"
    assert "PACKAGE_CACHE_ENTRY_DISAPPEARED" in gaps


def test_incomplete_capture_cannot_emit_exhaustiveness_contradiction() -> None:
    from ojas_reconciler.db2_behavior.runtime_probe import (
        ObservedStatement,
        ProbePlatform,
        RuntimeObservationRecord,
        TextResolution,
        falsify,
    )

    payload = {
        "schema_version": "runtime-observation-record-1.0",
        "authority_scope": "RUNTIME_EVIDENCE_ONLY",
        "platform_governance_ref": None,
        "observation_id": "observation-incomplete",
        "plan_ref": _plan().plan_id,
        "plan_digest": _plan().content_digest,
        "invocation_ref": _invocation().invocation_id,
        "platform": ProbePlatform.DB2_ZOS,
        "observed_at": "2026-07-29T00:00:00.000000Z",
        "sqlstate": None,
        "output_parameters": (),
        "dynamic_statements": (
            ObservedStatement(statement_text=None, executions=1, text_resolution=TextResolution.CATALOG_LOOKUP_REQUIRED),
            ObservedStatement(statement_text="UPDATE X SET Y = 1", executions=1),
        ),
        "table_deltas": (),
        "rolled_back": False,
        "capture_complete": False,
        "capture_gaps": ("TRACE_WINDOW_PARTIAL_COVERAGE",),
        "probe_name": "test",
        "probe_version": "1",
    }
    observation = RuntimeObservationRecord(**payload, content_digest=canonical_digest(payload))
    report = falsify(
        plan=_plan(),
        observation=observation,
        enumerated_dynamic_variants=("SELECT 1",),
    )
    assert report.contradictions == ()


def test_static_cli_import_does_not_load_runtime_adapters() -> None:
    import subprocess

    script = (
        "import sys; "
        "import ojas_reconciler.db2_behavior.cli; "
        "assert 'ojas_reconciler.db2_behavior.runtime_probe' not in sys.modules; "
        "assert 'ojas_reconciler.db2_behavior.zos_ifcid_consumer' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_runtime_evidence_status_cli_defaults_disabled(capsys: pytest.CaptureFixture[str]) -> None:
    from ojas_reconciler.db2_behavior.cli import main

    assert main(["runtime-evidence-status"]) == 0
    output = capsys.readouterr().out
    assert '"availability":"DISABLED"' in output
    assert '"enabled":false' in output


def test_runtime_evidence_property_schema_validates_examples() -> None:
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    root = Path(__file__).parent.parent
    schema = json.loads((root / "contracts/runtime-evidence-properties-1.0.schema.json").read_text())
    validator = Draft202012Validator(schema)
    for name in ("disabled.json", "db2-luw.json", "db2-zos-ifcid.json", "db2-luw-skipped-empty-connection.json"):
        payload = json.loads((root / "examples/runtime-evidence" / name).read_text())
        assert not list(validator.iter_errors(payload)), name
