"""
GraphPath Topology Graph Store
Thread-safe, transactional in-memory NetworkX graph store supporting Cytoscape export,
device-to-switch edge reconciliation, and batch context management.
"""

import threading
from contextlib import contextmanager
from typing import Dict, Any, List, Optional
import networkx as nx


class GraphStore:
    _instances: List["GraphStore"] = []
    _global_lock = threading.RLock()

    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.lock = threading.RLock()
        self._in_transaction = False
        with self._global_lock:
            self._instances.append(self)

    @classmethod
    def close_all(cls):
        """Clean shutdown handler invoked by signal/lifecycle handlers."""
        with cls._global_lock:
            cls._instances.clear()

    @property
    def nodes(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            return dict(self.graph.nodes(data=True))

    @property
    def edges(self) -> List[tuple]:
        with self.lock:
            return list(self.graph.edges(data=True))

    @contextmanager
    def batch_transaction(self):
        """Atomic batch mutation context."""
        with self.lock:
            self._in_transaction = True
            try:
                yield self
            finally:
                self._in_transaction = False

    def add_node(self, node_id: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Upserts a node, preserving and merging previous telemetry attributes."""
        if not node_id:
            return
        node_key = str(node_id).strip()
        attrs = dict(attributes or {})
        attrs.setdefault("id", node_key)
        attrs.setdefault("label", attrs.get("hostname") or attrs.get("model") or node_key)

        with self.lock:
            if self.graph.has_node(node_key):
                # Update existing attributes without overwriting with empty values
                existing = self.graph.nodes[node_key]
                for k, v in attrs.items():
                    if v is not None and v != "":
                        existing[k] = v
            else:
                self.graph.add_node(node_key, **attrs)

    def add_edge(self, source: str, target: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Adds a directional edge between two topology nodes."""
        if not source or not target or source == target:
            return
        src_key = str(source).strip()
        tgt_key = str(target).strip()
        attrs = dict(attributes or {})

        with self.lock:
            if not self.graph.has_node(src_key):
                self.add_node(src_key, {"type": "inferred_node"})
            if not self.graph.has_node(tgt_key):
                self.add_node(tgt_key, {"type": "inferred_node"})

            # Prevent duplicate identical edges
            existing_edges = self.graph.get_edge_data(src_key, tgt_key, default={})
            for _, edge_data in existing_edges.items():
                if edge_data.get("layer") == attrs.get("layer") and edge_data.get("port") == attrs.get("port"):
                    edge_data.update(attrs)
                    return

            self.graph.add_edge(src_key, tgt_key, **attrs)

    def reconcile_topology(self) -> None:
        """
        Reconciles layer-2 and layer-3 edges.
        If a device has an explicit switch port link (layer 2), removes generic
        subnet-level edges (layer 3) to prevent redundant clutter on the visual graph.
        """
        with self.lock:
            nodes_to_check = list(self.graph.nodes())
            for node_id in nodes_to_check:
                in_edges = list(self.graph.in_edges(node_id, data=True, keys=True))
                has_l2_switch_link = any(
                    data.get("layer") in (1, 2) or data.get("method") in ("bridge_fdb_cam_table", "snmp_bridge_fdb")
                    for _, _, _, data in in_edges
                )
                if has_l2_switch_link:
                    # Drop pure layer-3 broadcast sweep edges to this node
                    for u, v, k, data in in_edges:
                        if data.get("layer") == 3 and data.get("method") == "tier4_sweep":
                            self.graph.remove_edge(u, v, key=k)

    def export_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Exports graph elements into standard Cytoscape JSON schema."""
        elements = []
        with self.lock:
            for node_id, data in self.graph.nodes(data=True):
                elements.append({
                    "group": "nodes",
                    "data": {
                        "id": node_id,
                        **data
                    }
                })

            for u, v, data in self.graph.edges(data=True):
                elements.append({
                    "group": "edges",
                    "data": {
                        "source": u,
                        "target": v,
                        **data
                    }
                })
        return elements