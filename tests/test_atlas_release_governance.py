from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import jsonschema

from atlas.compatibility import (
    CANONICAL_NAMESPACE,
    LEGACY_NAMESPACE,
    identity_candidates,
    round_trip_legacy_record,
    verify_preserved_content_digest,
)
from atlas.core.canonical import canonical_digest
from atlas.product import load_capability_manifest
from atlas.release_evidence import release_evidence_exit_code
from atlas.release_environment import build_environment_report

ROOT = Path(__file__).resolve().parents[1]


def _validate(name: str, payload: dict[str, object]) -> None:
    schema = json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_release_extra_pins_every_assurance_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    release = project["project"]["optional-dependencies"]["release"]
    assert all("==" in item for item in release)
    names = {item.split("==", 1)[0] for item in release}
    assert {"pytest", "httpx", "PyJWT[crypto]", "cryptography", "gherkin-official", "ruff", "mypy"} <= names
    assert not any(item.lower().startswith("httpx2") for item in release)
    constraint_lines = {
        line.strip()
        for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    # pip 26.2 rejects extras in constraints. Extras remain on the requirement
    # in pyproject.toml; the constraint pins the underlying distribution.
    assert all("[" not in line and "]" not in line for line in constraint_lines)
    for item in release:
        base_requirement = re.sub(r"\[[^]]+\]", "", item)
        assert base_requirement in constraint_lines


def test_release_environment_reports_missing_or_mismatched_dependencies_explicitly() -> None:
    report = build_environment_report(ROOT)
    assert report["status"] in {"PASS", "INCOMPLETE"}
    assert {item["distribution"] for item in report["test_dependencies"]} >= {
        "pytest", "httpx", "PyJWT", "cryptography", "gherkin-official"
    }
    assert {item["distribution"] for item in report["quality_dependencies"]} == {"ruff", "mypy"}
    assert all(item["status"] in {"PASS", "MISSING", "VERSION_MISMATCH"} for item in report["test_dependencies"])


def test_conditional_release_evidence_returns_nonzero() -> None:
    payload: dict[str, object] = {
        "collection_launchers": {
            "python_module": {"exit_code": 0, "collection_consistent": True},
            "console_entry_point": {"exit_code": 0, "collection_consistent": True},
        },
        "launcher_inventory_match": True,
        "launcher_digest_match": True,
        "pytest_exit_code": 0,
        "status": "CONDITIONAL",
    }
    assert release_evidence_exit_code(payload) == 2


def test_naming_compatibility_policy_is_digest_bound_and_schema_valid() -> None:
    policy = json.loads((ROOT / "ATLAS_NAMING_COMPATIBILITY_POLICY.json").read_text(encoding="utf-8"))
    _validate("atlas-naming-compatibility-policy-1.0.schema.json", policy)
    digest = policy.pop("content_digest")
    assert digest == canonical_digest(policy)
    assert policy["legacy_compatibility"]["role"] == "COMPATIBILITY_FACADE"
    assert policy["artifact_policy"]["existing_content_digests"] == "NEVER_REWRITTEN"
    assert policy["serialization_policy"]["round_trip"] == "PRESERVE_LEGACY_IDENTITY_FOR_EXISTING_ARTIFACTS"


def test_historical_governance_record_resolves_without_rewrite_or_rehash() -> None:
    historical = {
        "schema_version": "governance-artifact-record-1.0",
        "artifact_id": "artifact:legacy:001",
        "producer_identity": "ojas_reconciler.db2_behavior.governance",
        "artifact_ref": "ojas_reconciler.db2_behavior:artifact:legacy:001",
        "payload_digest": "sha256:" + "1" * 64,
    }
    historical["content_digest"] = canonical_digest(historical)
    original = json.loads(json.dumps(historical))
    assert verify_preserved_content_digest(historical)
    assert identity_candidates(historical["producer_identity"]) == (
        historical["producer_identity"],
        "atlas.governance",
    )
    assert round_trip_legacy_record(historical) == original
    assert historical == original


def test_only_atlas_is_canonical_while_legacy_identity_remains_resolvable() -> None:
    assert CANONICAL_NAMESPACE == "atlas"
    assert LEGACY_NAMESPACE == "ojas_reconciler.db2_behavior"
    assert identity_candidates(CANONICAL_NAMESPACE) == (CANONICAL_NAMESPACE,)


def test_dialect_capability_manifest_blocks_commercial_availability_claims() -> None:
    manifest = load_capability_manifest()
    _validate("atlas-capability-manifest-1.0.schema.json", manifest)
    payload = dict(manifest)
    digest = payload.pop("content_digest")
    assert digest == canonical_digest(payload)
    assert manifest["overall_commercialization_state"] == "ORGANIC_VALIDATION_REQUIRED"
    assert sum(item["synthetic_fixture_count"] for item in manifest["dialects"]) == 13
    assert all(item["implementation_state"] == "IMPLEMENTED" for item in manifest["dialects"])
    assert all(item["validation_state"] == "SYNTHETICALLY_VALIDATED" for item in manifest["dialects"])
    db2 = next(item for item in manifest["dialects"] if item["dialect"] == "DB2_SQL_PL")
    assert db2["organic_validation_state"] == "REVALIDATION_REQUIRED_AFTER_REMEDIATION"
    assert db2["public_repository_file_count"] == 5
    assert db2["public_repository_routine_count"] == 15
    assert "PINNED_IBM_DB2_SAMPLES_POST_FIX_REVALIDATION_NOT_EXECUTED" in db2["commercialization_blockers"]
    assert all(item["organic_validation_state"] == "NOT_ATTEMPTED" for item in manifest["dialects"] if item is not db2)
    assert all(item["commercialization_state"] == "ORGANIC_VALIDATION_REQUIRED" for item in manifest["dialects"])
    assert all(item["organic_estate_count"] == 0 for item in manifest["dialects"])
    assert all(item["organic_routine_count"] == 0 for item in manifest["dialects"])


def test_cli_exposes_detailed_naming_and_capability_policies(capsys) -> None:
    from atlas.cli import main

    assert main(["naming"]) == 0
    naming = json.loads(capsys.readouterr().out)
    assert naming["status"] == "FROZEN_WITH_COMPATIBILITY_POLICY"
    assert naming["governance_resolution"]["legacy_records_resolvable"] is True

    assert main(["capabilities"]) == 0
    capabilities = json.loads(capsys.readouterr().out)
    assert capabilities["overall_commercialization_state"] == "ORGANIC_VALIDATION_REQUIRED"
    assert len(capabilities["dialects"]) == 5


def test_release_manifest_status_is_gate_derived_and_commercially_bounded() -> None:
    from atlas.release_manifest import build_release_manifest, derive_release_status

    assert derive_release_status({"tests": "PASS", "quality": "NOT_EXECUTED"}) == "CONDITIONAL"
    manifest = build_release_manifest(
        release="2.0.0rc5",
        gate_summary={"tests": "PASS", "quality": "NOT_EXECUTED"},
        blocking_conditions=["QUALITY_NOT_EXECUTED"],
        test_execution={
            "collected": 1,
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "required_assurance_complete": False,
            "evidence_ref": "acceptance/pytest-report.json",
        },
        artifacts={},
    )
    _validate("atlas-release-manifest-2.1.schema.json", manifest)
    assert manifest["status"] == "CONDITIONAL"
    assert manifest["commercialization_claim"] == "NOT_COMMERCIALLY_AVAILABLE"
    assert manifest["capability_governance"]["organic_estate_count"] == 0
    assert manifest["capability_governance"]["public_repository_file_count"] == 5
    assert manifest["capability_governance"]["public_repository_routine_count"] == 15
    assert manifest["capability_governance"]["db2_organic_validation_state"] == "REVALIDATION_REQUIRED_AFTER_REMEDIATION"
