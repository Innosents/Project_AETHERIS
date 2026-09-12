"""
GraphPath Web Visualizer Server
Serves the Cytoscape WebGL spatial canvas and exports live GraphStore topology.
"""

from typing import Optional
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from graphpath.topology.graph_store import GraphStore

app = FastAPI(title="Project AETHERIS - L1 Physical Topology Engine")

# Active topology singleton instance
active_store: Optional[GraphStore] = None


def set_active_graph_store(store: GraphStore) -> None:
    global active_store
    active_store = store


@app.get("/api/topology", tags=["Telemetry"])
def get_topology():
    """Returns serialized Cytoscape elements directly from the active GraphStore."""
    if active_store:
        return active_store.get_cytoscape_elements()
    return []


@app.get("/", response_class=HTMLResponse, tags=["Visualizer"])
def render_visualizer():
    """Serves the Cytoscape WebGL HTML/JS UI."""
    with open("graphpath/web/static/topology.html", "r", encoding="utf-8") as f:
        return f.read()


def run_server(port: int = 8080, host: str = "127.0.0.1") -> None:
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_server()