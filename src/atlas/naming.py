from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AtlasNamingPolicy:
    product_name: str = "Atlas"
    distribution_name: str = "atlas-procedure-intelligence"
    canonical_namespace: str = "atlas"
    canonical_cli: str = "atlas"
    legacy_distribution: str = "db2-behavior-extraction-framework"
    legacy_namespace: str = "ojas_reconciler.db2_behavior"
    compatibility_until: str = "3.0.0"
    artifact_schema_policy: str = "PRESERVE_EXISTING_SCHEMA_IDS_AND_DIGESTS"
    governance_record_policy: str = "NO_REWRITE; RECORD_CANONICAL_AND_LEGACY_PRODUCER_ALIASES"


POLICY = AtlasNamingPolicy()
