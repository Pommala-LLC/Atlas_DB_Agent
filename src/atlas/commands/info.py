from __future__ import annotations

import json
from pathlib import Path

from atlas import __version__
from atlas.application import AtlasSemanticService
from atlas.core.canonical import canonical_json_bytes
from atlas.product import load_capability_manifest, load_semantic_coverage_manifest


def handle(args) -> int | None:
    if args.command == "dialects":
        values = [item.value for item in AtlasSemanticService(__version__).registry.dialects()]
        print(json.dumps(values) if args.json else "\n".join(values))
        return 0
    if args.command == "coverage":
        print(canonical_json_bytes(load_semantic_coverage_manifest()).decode("utf-8"))
        return 0
    if args.command == "capabilities":
        print(canonical_json_bytes(load_capability_manifest()).decode("utf-8"))
        return 0
    if args.command == "naming":
        path = Path(__file__).resolve().parents[1] / "ATLAS_NAMING_COMPATIBILITY_POLICY.json"
        print(canonical_json_bytes(json.loads(path.read_text(encoding="utf-8"))).decode("utf-8"))
        return 0
    return None
