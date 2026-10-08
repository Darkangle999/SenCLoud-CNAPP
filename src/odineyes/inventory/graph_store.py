"""Optional Neo4j write-through for the security graph (dual-store).

Postgres/sqlite stays the source of truth; Neo4j is a queryable projection of
the same AssetGraph the issue engine traverses. Strictly opt-in: the store
activates only when ``ODINEYES_NEO4J_URI`` is set, and every failure is
logged and swallowed — graph export must never sink a scan or an evaluation.

Node shape:   (:Asset {id, kind, name, account})
Edge shapes:  EXPOSED_TO | CAN_ASSUME | CAN_ACCESS | USES_SECURITY_GROUP
Stale nodes for the account (absent from the current graph) are detached.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from odineyes.inventory.graph import AssetGraph

logger = logging.getLogger(__name__)

# Relationship types are interpolated into Cypher (parameters can't bind rel
# types), so only whitelisted values ever reach the query string.
_EDGE_TYPES = {"EXPOSED_TO", "CAN_ASSUME", "CAN_ACCESS", "USES_SECURITY_GROUP"}

ENV_URI = "ODINEYES_NEO4J_URI"
ENV_USER = "ODINEYES_NEO4J_USER"
ENV_PASSWORD = "ODINEYES_NEO4J_PASSWORD"


class Neo4jGraphStore:
    def __init__(self, driver: Any):
        self._driver = driver

    @classmethod
    def from_env(cls) -> Optional["Neo4jGraphStore"]:
        """Build a store from the environment, or None when not configured /
        driver missing / server unreachable. Callers treat None as 'feature off'."""
        uri = os.environ.get(ENV_URI)
        if not uri:
            return None
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.warning("%s set but neo4j driver not installed", ENV_URI)
            return None
        try:
            driver = GraphDatabase.driver(
                uri,
                auth=(os.environ.get(ENV_USER, "neo4j"), os.environ.get(ENV_PASSWORD, "neo4j")),
            )
            driver.verify_connectivity()
            return cls(driver)
        except Exception as exc:  # noqa: BLE001 — any connect failure = feature off
            logger.warning("Neo4j unreachable at %s: %s", uri, exc)
            return None

    def sync_account(self, account_identifier: str, graph: AssetGraph) -> dict[str, int]:
        """Project the in-process graph into Neo4j. Idempotent (MERGE-based);
        nodes that left the graph are detach-deleted for this account."""
        nodes = [
            {"id": n.id, "kind": n.kind, "name": n.name}
            for n in graph.nodes.values()
        ]
        edges: list[dict[str, str]] = []
        for node_id in graph.nodes:
            for e in graph.out_edges(node_id):
                if e.edge_type in _EDGE_TYPES:
                    edges.append({"src": e.src, "dst": e.dst, "type": e.edge_type})

        with self._driver.session() as session:
            session.run(
                "UNWIND $nodes AS n "
                "MERGE (a:Asset {id: n.id, account: $account}) "
                "SET a.kind = n.kind, a.name = n.name",
                nodes=nodes, account=account_identifier,
            )
            for edge_type in _EDGE_TYPES:
                batch = [e for e in edges if e["type"] == edge_type]
                if not batch:
                    continue
                session.run(
                    "UNWIND $edges AS e "
                    "MATCH (s:Asset {id: e.src, account: $account}) "
                    "MATCH (d:Asset {id: e.dst, account: $account}) "
                    f"MERGE (s)-[:{edge_type}]->(d)",
                    edges=batch, account=account_identifier,
                )
            session.run(
                "MATCH (a:Asset {account: $account}) "
                "WHERE NOT a.id IN $ids DETACH DELETE a",
                account=account_identifier, ids=[n["id"] for n in nodes],
            )
        return {"nodes": len(nodes), "edges": len(edges)}

    def close(self) -> None:
        try:
            self._driver.close()
        except Exception:  # noqa: BLE001
            pass
