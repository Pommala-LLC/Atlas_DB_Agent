from __future__ import annotations

import json
from importlib.resources import files
from typing import Mapping

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest

CANONICAL_NAMESPACE = "atlas"
LEGACY_NAMESPACE = "ojas_reconciler.db2_behavior"
CANONICAL_DISTRIBUTION = "atlas-procedure-intelligence"
LEGACY_DISTRIBUTION = "db2-behavior-extraction-framework"


def naming_compatibility_policy() -> dict[str, object]:
    resource = files("atlas").joinpath("ATLAS_NAMING_COMPATIBILITY_POLICY.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def identity_candidates(identity: str) -> tuple[str, ...]:
    """Return lookup candidates without mutating the supplied historical identity."""
    if identity.startswith(LEGACY_NAMESPACE):
        suffix = identity[len(LEGACY_NAMESPACE):]
        return identity, CANONICAL_NAMESPACE + suffix
    if identity == LEGACY_DISTRIBUTION:
        return identity, CANONICAL_DISTRIBUTION
    return (identity,)


def verify_preserved_content_digest(record: Mapping[str, object]) -> bool:
    """Verify a self-digest against the record's original serialized identity fields."""
    expected = record.get("content_digest")
    if not isinstance(expected, str):
        return False
    payload = dict(record)
    payload.pop("content_digest", None)
    return canonical_digest(payload) == expected


def round_trip_legacy_record(record: Mapping[str, object]) -> dict[str, object]:
    """Return an exact field-preserving copy; migration by rewriting is prohibited."""
    return dict(record)
