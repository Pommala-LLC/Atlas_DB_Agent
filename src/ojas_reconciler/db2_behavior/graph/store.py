from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ..commercial.models import ProcedureKnowledgeGraph
from ..core.canonical_json import canonical_digest, canonical_json_bytes


class GraphStoreError(RuntimeError):
    pass


class PersistentKnowledgeGraphStore:
    """SQLite-backed technical evidence graph.

    Nodes and edges retain source graph digests and authority/status metadata.
    The store never promotes runtime or inferred evidence to authority.
    """

    def __init__(self, path: Path, *, tenant_ref: str) -> None:
        self.path = path.resolve()
        self.tenant_ref = tenant_ref
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS graph_documents (
                    tenant_ref TEXT NOT NULL,
                    graph_id TEXT NOT NULL,
                    graph_digest TEXT NOT NULL,
                    procedure_ref TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_ref, graph_id, graph_digest)
                );
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    tenant_ref TEXT NOT NULL,
                    graph_id TEXT NOT NULL,
                    graph_digest TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    authority TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_ref, graph_id, graph_digest, node_id)
                );
                CREATE TABLE IF NOT EXISTS graph_edges (
                    tenant_ref TEXT NOT NULL,
                    graph_id TEXT NOT NULL,
                    graph_digest TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_ref, graph_id, graph_digest, edge_id)
                );
                CREATE INDEX IF NOT EXISTS graph_nodes_label_idx ON graph_nodes(tenant_ref, label);
                CREATE INDEX IF NOT EXISTS graph_edges_source_idx ON graph_edges(tenant_ref, source_node);
                CREATE INDEX IF NOT EXISTS graph_edges_target_idx ON graph_edges(tenant_ref, target_node);
                """
            )

    def ingest(self, graph: ProcedureKnowledgeGraph) -> dict[str, object]:
        if canonical_digest(graph.model_dump(exclude={"content_digest"})) != graph.content_digest:
            raise GraphStoreError("Procedure knowledge graph digest is invalid.")
        payload_text = canonical_json_bytes(graph).decode("utf-8")
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO graph_documents VALUES (?,?,?,?,?)",
                (self.tenant_ref, graph.graph_id, graph.content_digest, graph.procedure_ref, payload_text),
            )
            for node in graph.nodes:
                conn.execute(
                    "INSERT OR IGNORE INTO graph_nodes VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        self.tenant_ref,
                        graph.graph_id,
                        graph.content_digest,
                        node.node_id,
                        node.node_type,
                        node.label,
                        node.authority,
                        node.status,
                        canonical_json_bytes(node.attributes).decode("utf-8"),
                    ),
                )
            for edge in graph.edges:
                conn.execute(
                    "INSERT OR IGNORE INTO graph_edges VALUES (?,?,?,?,?,?,?,?)",
                    (
                        self.tenant_ref,
                        graph.graph_id,
                        graph.content_digest,
                        edge.edge_id,
                        edge.source,
                        edge.target,
                        edge.edge_type,
                        canonical_json_bytes(edge.attributes).decode("utf-8"),
                    ),
                )
        return {
            "graph_id": graph.graph_id,
            "graph_digest": graph.content_digest,
            "nodes_ingested": len(graph.nodes),
            "edges_ingested": len(graph.edges),
        }

    def search_nodes(self, query: str, *, limit: int = 100) -> list[dict[str, Any]]:
        value = f"%{query.strip()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT graph_id,graph_digest,node_id,node_type,label,authority,status,attributes_json
                FROM graph_nodes
                WHERE tenant_ref=? AND (label LIKE ? OR node_id LIKE ? OR node_type LIKE ?)
                ORDER BY label,node_id LIMIT ?
                """,
                (self.tenant_ref, value, value, value, limit),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": json.loads(row["attributes_json"]),
            }
            for row in rows
        ]

    def neighborhood(self, node_id: str, *, depth: int = 1, limit: int = 500) -> dict[str, object]:
        if depth < 0 or depth > 8:
            raise GraphStoreError("Graph neighborhood depth must be between 0 and 8.")
        frontier = {node_id}
        visited = {node_id}
        edges: list[dict[str, Any]] = []
        with self._connect() as conn:
            for _ in range(depth):
                if not frontier or len(edges) >= limit:
                    break
                placeholders = ",".join("?" for _ in frontier)
                params = [self.tenant_ref, *sorted(frontier), *sorted(frontier), limit - len(edges)]
                rows = conn.execute(
                    f"""
                    SELECT graph_id,graph_digest,edge_id,source_node,target_node,edge_type,attributes_json
                    FROM graph_edges
                    WHERE tenant_ref=? AND (source_node IN ({placeholders}) OR target_node IN ({placeholders}))
                    LIMIT ?
                    """,
                    params,
                ).fetchall()
                next_frontier: set[str] = set()
                for row in rows:
                    record = {
                        **{key: row[key] for key in row.keys() if key != "attributes_json"},
                        "attributes": json.loads(row["attributes_json"]),
                    }
                    if record not in edges:
                        edges.append(record)
                    for candidate in (row["source_node"], row["target_node"]):
                        if candidate not in visited:
                            visited.add(candidate)
                            next_frontier.add(candidate)
                frontier = next_frontier
            if visited:
                placeholders = ",".join("?" for _ in visited)
                rows = conn.execute(
                    f"""
                    SELECT graph_id,graph_digest,node_id,node_type,label,authority,status,attributes_json
                    FROM graph_nodes WHERE tenant_ref=? AND node_id IN ({placeholders})
                    """,
                    [self.tenant_ref, *sorted(visited)],
                ).fetchall()
            else:
                rows = []
        nodes = [
            {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": json.loads(row["attributes_json"]),
            }
            for row in rows
        ]
        without = {"node_id": node_id, "depth": depth, "nodes": nodes, "edges": edges}
        return {**without, "content_digest": canonical_digest(without)}

    def list_graphs(self) -> list[dict[str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT graph_id,graph_digest,procedure_ref FROM graph_documents WHERE tenant_ref=? ORDER BY procedure_ref,graph_id",
                (self.tenant_ref,),
            ).fetchall()
        return [dict(row) for row in rows]
