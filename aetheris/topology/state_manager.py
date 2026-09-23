"""
Project AETHERIS - State Manager
Maintains a memory-bounded dual-ledger topology matrix that segregates persistent infrastructure nodes from LRU-evicted ephemeral telemetry streams. Computes discrete O(1) additive and destructive 
delta frames to stream bandwidth-optimized graph mutations over asynchronous WebSockets.
"""

import asyncio
import json
import logging
import time
from typing import Dict, Any, Set, List
from collections import OrderedDict

from aetheris.core.ports.state_manager_port import (
    TopologyStateManagerPort,
    DeltaPayloadRecord,
    StateManagerMetrics,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AETHERIS_WS_DELTA] - %(message)s')

class TopologyStateManager(TopologyStateManagerPort):
    """
    Project AETHERIS v2.5 - Memory-Bounded Delta Matrix
    Segregates state tracking from network transmission to guarantee O(1) DOM updates.
    """
    def __init__(self, max_ephemeral_nodes: int = 50000, ttl_seconds: float = 300.0):
        self.static_nodes: Dict[str, Dict[str, Any]] = {}
        self.ephemeral_nodes = OrderedDict()
        self.MAX_EPHEMERAL = max_ephemeral_nodes
        self.TTL_SECONDS = ttl_seconds
        
        # The O(1) Mutator Ledger
        self._delta_adds: Dict[str, Dict[str, Any]] = {}
        self._delta_removes: Set[str] = set()

    def _track_addition(self, node_id: str, payload: Dict[str, Any]):
        """Registers an entity for frontend injection."""
        self._delta_adds[node_id] = payload
        self._delta_removes.discard(node_id)

    def _track_removal(self, node_id: str):
        """Registers an entity for frontend destruction."""
        self._delta_removes.add(node_id)
        self._delta_adds.pop(node_id, None)

    def upsert_ephemeral_telemetry(self, node_id: str, payload: Dict[str, Any]):
        """Executes O(1) injection and LRU eviction, instantly writing to the Delta Ledger."""
        current_time = time.monotonic()
        payload["last_seen"] = current_time

        if node_id in self.ephemeral_nodes:
            self.ephemeral_nodes.move_to_end(node_id)
        else:
            if len(self.ephemeral_nodes) >= self.MAX_EPHEMERAL:
                evicted_key, _ = self.ephemeral_nodes.popitem(last=False)
                self._track_removal(evicted_key)
                logging.warning(f"OOM DEFENSE: LRU Evicted {evicted_key}")

        self.ephemeral_nodes[node_id] = payload
        self._track_addition(node_id, payload)

    async def async_ttl_garbage_collector(self):
        """Executes O(K) temporal pruning and queues DOM destruction instructions."""
        while True:
            await asyncio.sleep(1)
            current_time = time.monotonic()
            stale_threshold = current_time - self.TTL_SECONDS
            
            while self.ephemeral_nodes:
                oldest_key, oldest_payload = next(iter(self.ephemeral_nodes.items()))
                if oldest_payload["last_seen"] < stale_threshold:
                    self.ephemeral_nodes.popitem(last=False)
                    self._track_removal(oldest_key)
                else:
                    break 

    def extract_and_flush_deltas(self) -> str:
        """Atomically extracts the delta and resets the ledger. Yields Cytoscape-ready JSON."""
        delta_payload = {
            "adds": list(self._delta_adds.values()),
            "removes": list(self._delta_removes)
        }
        self._delta_adds.clear()
        self._delta_removes.clear()
        return json.dumps(delta_payload)

    def get_metrics(self) -> StateManagerMetrics:
        """Returns dual-ledger state metrics."""
        return StateManagerMetrics(
            static_node_count=len(self.static_nodes),
            ephemeral_node_count=len(self.ephemeral_nodes),
            max_ephemeral=self.MAX_EPHEMERAL,
            ttl_seconds=self.TTL_SECONDS
        )


async def cytoscape_delta_streamer(websocket, path, state_manager: TopologyStateManager):
    """
    WebSocket Daemon: Broadcasts JSON delta frames at 1Hz.
    Lazy-loads websockets exceptions.
    """
    try:
        import websockets
        closed_exc = websockets.exceptions.ConnectionClosed
    except ImportError:
        closed_exc = Exception

    logging.info(f"Terra Digital DOM Socket Connected: {getattr(websocket, 'remote_address', 'Unknown')}")
    
    baseline = {"adds": list(state_manager.static_nodes.values()), "removes": []}
    await websocket.send(json.dumps(baseline))
    
    try:
        while True:
            await asyncio.sleep(1.0)
            delta_json = state_manager.extract_and_flush_deltas()
            parsed = json.loads(delta_json)
            if len(parsed["adds"]) > 0 or len(parsed["removes"]) > 0:
                await websocket.send(delta_json)
    except closed_exc:
        logging.info("Frontend DOM Disconnected. Suspending broadcast.")
