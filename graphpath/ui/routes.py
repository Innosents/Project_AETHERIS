"""
GraphPath Web UI REST API Routes and Graph Blueprint.
"""

from flask import Blueprint, jsonify, render_template_string, request
from graphpath.topology.graph_store import GraphStore
from graphpath.core.traffic_matrix import TrafficMatrixTracker

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