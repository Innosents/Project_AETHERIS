"""
Project AETHERIS - Web UI REST API Routes and Graph Blueprint.
"""

from flask import Blueprint, jsonify, render_template_string, request
from graphpath.topology.graph_store import GraphStore
from graphpath.core.traffic_matrix import TrafficMatrixTracker
from graphpath.config import ConfigurationManager
from graphpath.core.discovery_engine import DiscoveryEngine
from graphpath.core.state_machine import DiscoveryStateMachine
from graphpath.discovery.dns_discovery import DnsDiscoveryEngine

graph_store = GraphStore()
traffic_matrix_instance = TrafficMatrixTracker()

graph = graph_store  # Backward compatibility alias for DiscoveryEngine

ui_bp = Blueprint("ui", __name__)

@ui_bp.route("/api/v1/topology", methods=["GET"])
def api_get_topology():
    """Returns full Cytoscape-compatible topology graph elements."""
    elements = graph_store.export_cytoscape_elements()
    return jsonify({
        "status": "success",
        "elements": elements,
        "summary": {
            "total_nodes": len(graph_store.nodes),
            "total_edges": len(graph_store.edges)
        }
    })

@ui_bp.route("/api/v1/traffic/summary", methods=["GET"])
def api_traffic_summary():
    """Returns traffic matrix conversation flow statistics."""
    return jsonify({
        "status": "success",
        "traffic": traffic_matrix_instance.get_summary(),
        "top_talkers": traffic_matrix_instance.get_top_talkers(limit=10)
    })

@ui_bp.route("/api/v1/dip", methods=["GET"])
def api_get_dip():
    """Returns all dynamically cached Device Identity Profiles."""
    from graphpath.core.dip_manager import DeviceIdentityProfileManager
    dip_mgr = DeviceIdentityProfileManager()
    return jsonify({
        "status": "success",
        "total_profiles": len(dip_mgr.profiles),
        "profiles": dip_mgr.get_all_profiles()
    })

@ui_bp.route("/api/v1/dip/lock", methods=["POST"])
def api_lock_dip():
    """Pins a custom user-defined identity for a device profile."""
    from graphpath.core.dip_manager import DeviceIdentityProfileManager
    dip_mgr = DeviceIdentityProfileManager()
    
    data = request.get_json(silent=True) or {}
    profile_id = data.get("profile_id")
    custom_type = data.get("type")
    custom_vendor = data.get("vendor", "custom")
    custom_model = data.get("model", "User Defined Device")
    uplink_ip = data.get("uplink_ip")

    if not profile_id or not custom_type:
        return jsonify({"status": "error", "message": "Missing profile_id or type"}), 400

    success = dip_mgr.lock_profile(profile_id, custom_type, custom_vendor, custom_model, uplink_ip=uplink_ip)
    
    try:
        graph_store.reconcile_topology()
    except Exception:
        pass

    return jsonify({"status": "success" if success else "failed", "locked": success})

@ui_bp.route("/", methods=["GET"])
def index_dashboard():
    """Renders lightweight embedded operational status dashboard."""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>GraphPath Dashboard</title>
        <style>
            body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
            h1 { color: #fff; border-bottom: 1px solid #333; padding-bottom: 10px; }
            .card { background: #1e1e1e; border: 1px solid #333; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>GraphPath: Autonomous Network Topology Discovery</h1>
        <div class="card">
            <h3>Status: ONLINE</h3>
            <p>Target Graph Engine Active. Nodes: <span id="node-count">...</span> | Edges: <span id="edge-count">...</span></p>
        </div>
        <div class="card">
            <h3>API Endpoints</h3>
            <ul>
                <li><a href="/api/v1/topology" style="color: #00bcd4;">/api/v1/topology</a></li>
                <li><a href="/api/v1/traffic/summary" style="color: #00bcd4;">/api/v1/traffic/summary</a></li>
                <li><a href="/api/v1/dip" style="color: #00bcd4;">/api/v1/dip</a></li>
            </ul>
        </div>
        <script>
            fetch('/api/v1/topology')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('node-count').innerText = data.summary.total_nodes;
                    document.getElementById('edge-count').innerText = data.summary.total_edges;
                });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)