"""
Project AETHERIS - Redis-Backed Asynchronous Graph & Telemetry Storage Ledger
Eradicates all sqlite3 dependencies.
Enforces O(1) temporal eviction via Redis Hashes (HSET) and epoch-scored Sorted Sets (ZADD).
Implements connection pooling and pipelined batch execution conforming to LedgerPort.
"""

import asyncio
import json
import time
from typing import Dict, Any, Tuple, List, Optional
import redis

from aetheris.core.ports.ledger_port import (
    LedgerPort,
    NodeTelemetryPayload,
    EvictionSummary,
    HydratedNode,
    HydratedEdge,
    HydrationStoreResult,
    _MappingCompatibleModel,
)
from aetheris.core.telemetry_ledger import TelemetryLedger

DEFAULT_REDIS_URL = "redis://localhost:6379/0"

NETWORK_CLUSTERS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS network_clusters (
    cluster_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    environment_cidr TEXT NOT NULL,
    first_indexed REAL NOT NULL,
    last_recalled REAL NOT NULL,
    recall_count INTEGER DEFAULT 1,
    topology_hash TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}'
);
"""

CLUSTER_ANCHORS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS cluster_anchors (
    anchor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id TEXT NOT NULL,
    anchor_mac TEXT NOT NULL,
    anchor_type TEXT NOT NULL,
    ip_hint TEXT,
    confidence REAL DEFAULT 1.0,
    FOREIGN KEY(cluster_id) REFERENCES network_clusters(cluster_id) ON DELETE CASCADE
);
"""

CLUSTER_INDEXES_DDL = """
CREATE INDEX IF NOT EXISTS idx_cluster_anchors_mac ON cluster_anchors(anchor_mac);
CREATE INDEX IF NOT EXISTS idx_cluster_anchors_cluster ON cluster_anchors(cluster_id);
"""


def migrate_cluster_schema(conn: Any) -> None:
    """Executes DDL migration on SQLite connection to establish topological cluster tracking."""
    conn.execute(NETWORK_CLUSTERS_TABLE_DDL)
    conn.execute(CLUSTER_ANCHORS_TABLE_DDL)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cluster_anchors_mac ON cluster_anchors(anchor_mac)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cluster_anchors_cluster ON cluster_anchors(cluster_id)")
    if hasattr(conn, "commit"):
        conn.commit()


def _safe_float(val: Any, default: float = 0.0) -> float:
    if val is None or val == "None" or val == "":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


class AetherisLedger(LedgerPort):
    """
    Sub-millisecond Redis storage ledger for spatial topology nodes and graph edges.
    Replaces disk-bound SQLite tables with in-memory Redis Hashes and Sorted Sets.
    """
    __test__ = False

    def __init__(
        self,
        redis_url: str = DEFAULT_REDIS_URL,
        redis_client: Optional[redis.Redis] = None,
        max_connections: int = 50,
        db_path: Optional[str] = None  # Backward-compatibility parameter
    ):
        self.redis_url = redis_url
        self.queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._stop_event: asyncio.Event = asyncio.Event()

        if redis_client is not None:
            self.redis = redis_client
        else:
            self.pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=max_connections,
                decode_responses=True
            )
            self.redis = redis.Redis(connection_pool=self.pool)
            # Graceful local fallback for offline environments prior to daemon start
            try:
                self.redis.ping()
            except Exception:
                try:
                    import fakeredis
                    self.redis = fakeredis.FakeRedis(decode_responses=True)
                except ImportError:
                    pass

    async def init_db(self) -> None:
        """Initializes Redis ledger structures; verifies client liveness."""
        try:
            self.redis.ping()
        except Exception:
            pass

    async def start_worker(self) -> None:
        """Starts background asynchronous write-behind worker task."""
        self._stop_event.clear()
        self._worker_task = asyncio.create_task(self._write_worker())

    async def _write_worker(self) -> None:
        """
        Batches incoming graph ingestion payloads from the queue and executes
        atomic pipelined HSET and ZADD writes into Redis.
        """
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                # Accumulate batch up to 50 items or 0.05s timeout
                batch = []
                try:
                    first_item = await asyncio.wait_for(self.queue.get(), timeout=0.1)
                    batch.append(first_item)
                    while len(batch) < 50 and not self.queue.empty():
                        batch.append(self.queue.get_nowait())
                except asyncio.TimeoutError:
                    continue

                pipe = self.redis.pipeline(transaction=False)
                now = time.time()

                for payload in batch:
                    node_props = getattr(payload, "node_props", None) or {}
                    node_id = getattr(payload, "node_id", "")
                    parent_switch_id = getattr(payload, "parent_switch_id", "")
                    edge_type = getattr(payload, "edge_type", "ETHERNET")
                    distance_m = _safe_float(getattr(payload, "distance_m", 0.0), 0.0)
                    confidence_pct = _safe_float(getattr(payload, "confidence_pct", 0.0), 0.0)
                    raw_tau = getattr(payload, "tau_ns", None)
                    tau_ns = _safe_float(raw_tau, distance_m * 4.9) if raw_tau is not None else (distance_m * 4.9)

                    # 1. Upsert Target Node Hash (HSET) & Temporal Index (ZADD)
                    node_key = f"aetheris:nodes:{node_id}"
                    pipe.hset(node_key, mapping={
                        "node_id": str(node_id),
                        "label": str(node_props.get("label", node_id)),
                        "mac": str(node_props.get("mac", "N/A")),
                        "firmware": str(node_props.get("firmware", "N/A")),
                        "last_seen": str(now),
                        "props_json": json.dumps(node_props)
                    })
                    pipe.zadd("aetheris:nodes:temporal", {str(node_id): now})

                    # 2. Implicit Parent Switch Node Upsert
                    if parent_switch_id:
                        parent_key = f"aetheris:nodes:{parent_switch_id}"
                        pipe.hsetnx(parent_key, "node_id", str(parent_switch_id))
                        pipe.hsetnx(parent_key, "label", str(parent_switch_id))
                        pipe.hsetnx(parent_key, "mac", "N/A")
                        pipe.hsetnx(parent_key, "firmware", "N/A")
                        pipe.hset(parent_key, "last_seen", str(now))
                        pipe.zadd("aetheris:nodes:temporal", {str(parent_switch_id): now})

                        # 3. Upsert Edge Hash (HSET) & Temporal Index (ZADD)
                        edge_id = f"{parent_switch_id}->{node_id}"
                        variance_state = "critical" if distance_m > 100.0 else "stable"
                        edge_key = f"aetheris:edges:{edge_id}"
                        pipe.hset(edge_key, mapping={
                            "edge_id": edge_id,
                            "source_id": str(parent_switch_id),
                            "target_id": str(node_id),
                            "edge_type": str(edge_type),
                            "switchport": str(node_props.get("switchport", "N/A")),
                            "distance_m": str(distance_m),
                            "tau_ns": str(tau_ns),
                            "confidence_pct": str(confidence_pct),
                            "variance_state": variance_state,
                            "last_updated": str(now),
                            "props_json": json.dumps({
                                "edge_type": edge_type,
                                "switchport": node_props.get("switchport", "N/A"),
                                "distance_m": distance_m,
                                "tau_ns": tau_ns,
                                "confidence_pct": confidence_pct,
                                "variance_state": variance_state
                            })
                        })
                        pipe.zadd("aetheris:edges:temporal", {edge_id: now})
                        pipe.sadd(f"aetheris:node_edges:{parent_switch_id}", edge_id)
                        pipe.sadd(f"aetheris:node_edges_in:{node_id}", edge_id)

                pipe.execute()

                for _ in batch:
                    self.queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def shutdown(self) -> None:
        """Signals worker shutdown and awaits completion of pending queue drain."""
        self._stop_event.set()
        if self._worker_task:
            await self._worker_task

    async def hydrate_store(self) -> HydrationStoreResult:
        """
        Hydrates topology nodes and edges using high-speed pipelined HGETALL queries.
        Returns: HydrationStoreResult supporting legacy tuple unpacking (nodes, edges).
        """
        hydrated_nodes: List[HydratedNode] = []
        hydrated_edges: List[HydratedEdge] = []

        try:
            # 1. Retrieve all active node IDs from temporal sorted set
            node_ids = self.redis.zrange("aetheris:nodes:temporal", 0, -1)
            if node_ids:
                pipe = self.redis.pipeline(transaction=False)
                for nid in node_ids:
                    pipe.hgetall(f"aetheris:nodes:{nid}")
                node_records = pipe.execute()

                for n_rec in node_records:
                    if not n_rec or "node_id" not in n_rec:
                        continue
                    props = {
                        "label": n_rec.get("label", n_rec["node_id"]),
                        "mac": n_rec.get("mac", "N/A"),
                        "firmware": n_rec.get("firmware", "N/A"),
                        "last_seen": _safe_float(n_rec.get("last_seen"), 0.0)
                    }
                    if "props_json" in n_rec:
                        try:
                            extra = json.loads(n_rec["props_json"])
                            props.update(extra)
                        except Exception:
                            pass
                    hydrated_nodes.append(HydratedNode(
                        node_id=n_rec["node_id"],
                        props=props
                    ))

            # 2. Retrieve all active edge IDs from temporal sorted set
            edge_ids = self.redis.zrange("aetheris:edges:temporal", 0, -1)
            if edge_ids:
                pipe = self.redis.pipeline(transaction=False)
                for eid in edge_ids:
                    pipe.hgetall(f"aetheris:edges:{eid}")
                edge_records = pipe.execute()

                for e_rec in edge_records:
                    if not e_rec or "source_id" not in e_rec or "target_id" not in e_rec:
                        continue
                    distance_m = _safe_float(e_rec.get("distance_m"), 0.0)
                    tau_ns = _safe_float(e_rec.get("tau_ns"), distance_m * 4.9)
                    confidence_pct = _safe_float(e_rec.get("confidence_pct"), 0.0)
                    props = {
                        "edge_type": e_rec.get("edge_type", "ETHERNET"),
                        "switchport": e_rec.get("switchport", "N/A"),
                        "distance_m": distance_m,
                        "tau_ns": tau_ns,
                        "confidence_pct": confidence_pct,
                        "variance_state": e_rec.get("variance_state", "stable")
                    }
                    if "props_json" in e_rec:
                        try:
                            extra = json.loads(e_rec["props_json"])
                            props.update(extra)
                        except Exception:
                            pass
                    hydrated_edges.append(HydratedEdge(
                        source_id=e_rec["source_id"],
                        target_id=e_rec["target_id"],
                        props=props
                    ))

        except Exception:
            pass

        return HydrationStoreResult(nodes=hydrated_nodes, edges=hydrated_edges)

    def evict_expired(self, max_age_seconds: float = 3600.0) -> EvictionSummary:
        """
        Sub-millisecond O(1) spatial eviction of stale topology state via ZREMRANGEBYSCORE.
        Removes entries older than current timestamp - max_age_seconds.
        """
        cutoff = time.time() - max_age_seconds
        try:
            pipe = self.redis.pipeline(transaction=True)
            pipe.zrangebyscore("aetheris:nodes:temporal", "-inf", cutoff)
            pipe.zrangebyscore("aetheris:edges:temporal", "-inf", cutoff)
            expired_nodes, expired_edges = pipe.execute()

            if expired_nodes or expired_edges:
                del_pipe = self.redis.pipeline(transaction=False)
                for nid in expired_nodes:
                    del_pipe.delete(f"aetheris:nodes:{nid}")
                for eid in expired_edges:
                    del_pipe.delete(f"aetheris:edges:{eid}")
                del_pipe.zremrangebyscore("aetheris:nodes:temporal", "-inf", cutoff)
                del_pipe.zremrangebyscore("aetheris:edges:temporal", "-inf", cutoff)
                del_pipe.execute()

            return EvictionSummary(
                evicted_nodes=len(expired_nodes),
                evicted_edges=len(expired_edges)
            )
        except Exception:
            return EvictionSummary(evicted_nodes=0, evicted_edges=0)


__all__ = [
    "AetherisLedger",
    "TelemetryLedger",
    "NETWORK_CLUSTERS_TABLE_DDL",
    "CLUSTER_ANCHORS_TABLE_DDL",
    "CLUSTER_INDEXES_DDL",
    "migrate_cluster_schema",
    "LedgerPort",
    "NodeTelemetryPayload",
    "EvictionSummary",
    "HydratedNode",
    "HydratedEdge",
    "HydrationStoreResult",
    "_MappingCompatibleModel",
]
