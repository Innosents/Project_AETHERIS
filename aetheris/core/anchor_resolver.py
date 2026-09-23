"""
aetheris/core/anchor_resolver.py
Autonomous topological environment recognition via Anchor Subgraph Hashing (ASH).
"""
import hashlib
import json
import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from aetheris.storage.ledger import TelemetryLedger

logger = logging.getLogger("aetheris.core.anchor_resolver")


class AnchorSubgraphResolver:
    """
    Evaluates discovered structural Layer-2/Layer-3 backbone nodes against
    episodic network graph clusters. Enforces strict >= 3 anchor match threshold.
    """

    MATCH_THRESHOLD: int = 3

    def __init__(self, ledger: TelemetryLedger):
        self.ledger = ledger

    def compute_anchor_fingerprint(self, anchor_macs: List[str]) -> str:
        """Produces a deterministic SHA-256 hash over canonically ordered MAC identifiers."""
        normalized = sorted({mac.upper().strip() for mac in anchor_macs if mac})
        seed = ":".join(normalized).encode("utf-8")
        return hashlib.sha256(seed).hexdigest()[:16]

    def evaluate_environment(
        self,
        candidate_anchors: List[Dict[str, str]],
        cidr_hint: str = "0.0.0.0/0"
    ) -> Tuple[Optional[str], float, List[str]]:
        """
        Interrogates candidate anchors against episodic ledger records.
        
        Returns:
            Tuple[Optional[cluster_id], match_confidence, matched_macs]
        """
        mac_to_meta = {
            a["mac"].upper().strip(): a 
            for a in candidate_anchors 
            if a.get("mac")
        }
        candidate_macs = list(mac_to_meta.keys())
        if not candidate_macs:
            return None, 0.0, []

        placeholders = ",".join("?" for _ in candidate_macs)
        query = f"""
            SELECT cluster_id, anchor_mac, anchor_type 
            FROM cluster_anchors 
            WHERE anchor_mac IN ({placeholders})
        """
        
        matches_by_cluster: Dict[str, Set[str]] = {}
        with self.ledger._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, candidate_macs)
            for cid, mac, _ in cursor.fetchall():
                matches_by_cluster.setdefault(cid, set()).add(mac)

        if not matches_by_cluster:
            return None, 0.0, []

        best_cluster_id = max(matches_by_cluster, key=lambda k: len(matches_by_cluster[k]))
        matched_macs = sorted(list(matches_by_cluster[best_cluster_id]))
        match_count = len(matched_macs)

        if match_count >= self.MATCH_THRESHOLD:
            confidence = min(1.0, 0.60 + (match_count * 0.10))
            self._touch_cluster_recall(best_cluster_id)
            return best_cluster_id, confidence, matched_macs

        return None, (match_count / self.MATCH_THRESHOLD) * 0.50, matched_macs

    def register_new_cluster(
        self,
        label: str,
        environment_cidr: str,
        anchors: List[Dict[str, str]],
        metadata: Optional[Dict] = None
    ) -> str:
        """Persists a novel topological cluster and registers initial structural anchor nodes."""
        anchor_macs = [a["mac"] for a in anchors if a.get("mac")]
        cluster_id = f"NET-{self.compute_anchor_fingerprint(anchor_macs)}"
        now = time.time()

        with self.ledger._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO network_clusters (
                    cluster_id, label, environment_cidr, first_indexed,
                    last_recalled, recall_count, topology_hash, metadata_json
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(cluster_id) DO UPDATE SET
                    last_recalled = excluded.last_recalled,
                    recall_count = network_clusters.recall_count + 1
                """,
                (
                    cluster_id,
                    label,
                    environment_cidr,
                    now,
                    now,
                    self.compute_anchor_fingerprint(anchor_macs),
                    json.dumps(metadata or {})
                )
            )

            for a in anchors:
                cursor.execute(
                    """
                    INSERT INTO cluster_anchors (
                        cluster_id, anchor_mac, anchor_type, ip_hint, confidence
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        cluster_id,
                        a["mac"].upper().strip(),
                        a.get("type", "GATEWAY"),
                        a.get("ip", ""),
                        float(a.get("confidence", 1.0))
                    )
                )
            conn.commit()

        logger.info(f"[*] Registered novel topological cluster: {cluster_id} with {len(anchors)} anchors")
        return cluster_id

    def _touch_cluster_recall(self, cluster_id: str) -> None:
        with self.ledger._get_connection() as conn:
            conn.execute(
                """
                UPDATE network_clusters
                SET last_recalled = ?, recall_count = recall_count + 1
                WHERE cluster_id = ?
                """,
                (time.time(), cluster_id)
            )
            conn.commit()


__all__ = [
    "AnchorSubgraphResolver",
]

