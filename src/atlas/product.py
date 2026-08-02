from __future__ import annotations

import json
from importlib.resources import files

from atlas.core.models import AtlasSemanticCoverageManifest


def load_semantic_coverage_manifest() -> AtlasSemanticCoverageManifest:
    resource = files("atlas").joinpath("ATLAS_DIALECT_COVERAGE.json")
    return AtlasSemanticCoverageManifest.model_validate_json(resource.read_text(encoding="utf-8"))


def load_capability_manifest() -> dict[str, object]:
    resource = files("atlas").joinpath("ATLAS_CAPABILITY_MANIFEST.json")
    return json.loads(resource.read_text(encoding="utf-8"))
