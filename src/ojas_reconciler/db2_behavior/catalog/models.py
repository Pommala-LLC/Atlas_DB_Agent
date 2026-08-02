from __future__ import annotations

from enum import StrEnum
from pydantic import Field, model_validator

from ..core.models import CanonicalModel
from ..type_system.models import RelationDefinition


class RelationKind(StrEnum):
    TABLE = "TABLE"
    VIEW = "VIEW"
    MATERIALIZED_QUERY_TABLE = "MATERIALIZED_QUERY_TABLE"
    SYNONYM = "SYNONYM"
    NICKNAME = "NICKNAME"
    TABLE_FUNCTION = "TABLE_FUNCTION"
    TEMPORARY_TABLE = "TEMPORARY_TABLE"
    UNKNOWN = "UNKNOWN"


class CatalogSourceKind(StrEnum):
    DB2_LUW_CATALOG = "DB2_LUW_CATALOG"
    DB2_ZOS_CATALOG = "DB2_ZOS_CATALOG"
    DDL_FILES = "DDL_FILES"
    JSON_SNAPSHOT = "JSON_SNAPSHOT"
    APPROVED_OVERRIDE = "APPROVED_OVERRIDE"


class CatalogRelation(CanonicalModel):
    relation_ref: str
    relation_kind: RelationKind
    definition: RelationDefinition
    view_definition_text: str | None = None
    synonym_target_ref: str | None = None
    remote_source_ref: str | None = None
    resolution_status: str = "RESOLVED_METADATA"
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_kind_payload(self) -> "CatalogRelation":
        if self.relation_kind in {RelationKind.VIEW, RelationKind.MATERIALIZED_QUERY_TABLE} and not self.view_definition_text:
            if self.resolution_status == "RESOLVED_METADATA":
                raise ValueError("Resolved views and MQTs require view_definition_text.")
        if self.relation_kind is RelationKind.SYNONYM and not self.synonym_target_ref:
            raise ValueError("SYNONYM requires synonym_target_ref.")
        return self


class CatalogSnapshot(CanonicalModel):
    schema_version: str = "catalog-snapshot-1.0"
    snapshot_id: str
    platform: str
    provider_ref: str
    source_kind: CatalogSourceKind
    captured_at: str
    schema_refs: tuple[str, ...]
    relations: tuple[CatalogRelation, ...]
    unresolved_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    content_digest: str

    @model_validator(mode="after")
    def validate_unique_relations(self) -> "CatalogSnapshot":
        refs = [item.relation_ref.upper() for item in self.relations]
        if len(refs) != len(set(refs)):
            raise ValueError("Catalog relation refs must be unique.")
        return self


class LineageNode(CanonicalModel):
    node_id: str
    relation_ref: str
    relation_kind: RelationKind
    status: str
    depth: int = Field(ge=0)
    attributes: dict[str, object] = {}


class LineageEdge(CanonicalModel):
    edge_id: str
    source_ref: str
    target_ref: str
    edge_kind: str
    evidence_refs: tuple[str, ...] = ()


class RelationLineageReport(CanonicalModel):
    schema_version: str = "relation-lineage-report-1.0"
    report_id: str
    root_relation_refs: tuple[str, ...]
    nodes: tuple[LineageNode, ...]
    edges: tuple[LineageEdge, ...]
    base_relation_refs: tuple[str, ...]
    unresolved_boundaries: tuple[str, ...]
    cycles: tuple[tuple[str, ...], ...] = ()
    max_depth_reached: bool = False
    content_digest: str
