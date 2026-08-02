from __future__ import annotations

from atlas.core.models import SemanticFinding, SemanticNode


def merge_attributes(node: SemanticNode, **attributes: object) -> SemanticNode:
    merged = dict(node.attributes)
    merged.update(attributes)
    return node.model_copy(update={"attributes": merged})


def finding(
    code: str,
    message: str,
    consequence: str,
    node: SemanticNode,
    severity: str = "ERROR",
) -> SemanticFinding:
    return SemanticFinding(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        source_span=node.source_span,
        consequence=consequence,
    )
