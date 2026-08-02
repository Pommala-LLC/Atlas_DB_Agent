from __future__ import annotations

from pathlib import Path
from typing import Mapping

from atlas.compatibility import naming_compatibility_policy
from atlas.product import load_capability_manifest

IMPLEMENTATION_SCOPE = (
    "atlas.dialects.db2",
    "atlas.dialects.oracle",
    "atlas.dialects.sqlserver",
    "atlas.dialects.postgresql",
    "atlas.dialects.mysql",
)


def derive_release_status(gates: Mapping[str, str]) -> str:
    values = tuple(gates.values())
    if any(value == "FAIL" for value in values):
        return "FAIL"
    if all(value in {"PASS", "NOT_APPLICABLE"} for value in values):
        return "PASS"
    return "CONDITIONAL"


def build_release_manifest(
    *,
    release: str,
    gate_summary: Mapping[str, str],
    blocking_conditions: list[str],
    test_execution: Mapping[str, object],
    artifacts: Mapping[str, Mapping[str, object]],
    environment_notes: list[str] | None = None,
) -> dict[str, object]:
    naming = naming_compatibility_policy()
    capabilities = load_capability_manifest()
    dialects = list(capabilities["dialects"])
    status = derive_release_status(gate_summary)
    overall_state = str(capabilities["overall_commercialization_state"])
    commercial_claim = (
        "COMMERCIALLY_AVAILABLE"
        if overall_state == "COMMERCIALLY_AVAILABLE"
        else "COMMERCIALIZATION_CANDIDATE"
        if overall_state == "COMMERCIALIZATION_CANDIDATE"
        else "NOT_COMMERCIALLY_AVAILABLE"
    )
    return {
        "schema_version": "atlas-release-manifest-2.1",
        "product": "Atlas Procedure Intelligence",
        "release": release,
        "status": status,
        "implementation_scope": list(IMPLEMENTATION_SCOPE),
        "gate_summary": dict(gate_summary),
        "blocking_conditions": list(blocking_conditions),
        "test_execution": dict(test_execution),
        "naming_governance": {
            "status": naming["status"],
            "policy_ref": "ATLAS_NAMING_COMPATIBILITY_POLICY.json",
            "canonical_namespace": naming["canonical"]["python_namespace"],
            "legacy_namespace": naming["legacy_compatibility"]["python_namespace"],
            "legacy_role": naming["legacy_compatibility"]["role"],
            "historical_digests_rewritten": False,
        },
        "capability_governance": {
            "manifest_ref": "ATLAS_CAPABILITY_MANIFEST.json",
            "overall_state": overall_state,
            "synthetic_fixture_count": sum(int(item["synthetic_fixture_count"]) for item in dialects),
            "organic_estate_count": sum(int(item["organic_estate_count"]) for item in dialects),
            "organic_routine_count": sum(int(item["organic_routine_count"]) for item in dialects),
            "public_repository_file_count": sum(int(item["public_repository_file_count"]) for item in dialects),
            "public_repository_routine_count": sum(int(item["public_repository_routine_count"]) for item in dialects),
            "db2_organic_validation_state": next(
                str(item["organic_validation_state"]) for item in dialects if item["dialect"] == "DB2_SQL_PL"
            ),
        },
        "commercialization_claim": commercial_claim,
        "environment_notes": list(environment_notes or []),
        "artifacts": {name: dict(value) for name, value in artifacts.items()},
    }
