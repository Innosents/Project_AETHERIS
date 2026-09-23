"""Backward-compatible shim redirecting to canonical state manager."""
from aetheris.topology.state_manager import TopologyStateManager, cytoscape_delta_streamer

__all__ = ["TopologyStateManager", "cytoscape_delta_streamer"]
