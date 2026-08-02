from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.analysis.models import QuerySemanticsCatalog


def load_query_semantics_catalog(path: Path | None) -> QuerySemanticsCatalog | None:
    if path is None:
        return None
    catalog = QuerySemanticsCatalog.model_validate_json(path.read_text(encoding="utf-8"))
    payload = catalog.model_dump(mode="python", exclude={"content_digest"})
    expected = canonical_digest(payload)
    if expected != catalog.content_digest:
        raise ValueError(
            f"Invalid query semantics catalog digest: expected {expected}, got {catalog.content_digest}"
        )
    return catalog
