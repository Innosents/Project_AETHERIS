"""
Project AETHERIS - Web Visualizer Server
Serves the Cytoscape WebGL spatial canvas, accepts remote CLI telemetry,
and broadcasts real-time Kalman updates over WebSockets.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

from graphpath.topology.graph_store import GraphStore

app = FastAPI(title="Project AETHERIS - L1 Physical Topology Engine")

STATIC_DIR = Path(__file__).resolve().parent / "static"
HTML_FILE = STATIC_DIR / "topology.html"

# Global persistent GraphStore instance
active_store = GraphStore()


class TelemetryPayload(BaseModel):
    node_id: str
    node_props: Optional[Dict[str, Any]] = None
    parent_switch_id: str
    distance_m: float
    variance_m2: float
    confidence_pct: float
    is_anchor: bool = False
    edge_type: str = "ETHERNET_LINK"
    net_flight_time_ns: Optional[float] = None


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


@app.get("/api/topology", tags=["Telemetry"])
def get_topology():
    """Returns serialized Cytoscape elements directly from the active GraphStore."""
    return active_store.get_cytoscape_elements()


@app.post("/api/telemetry/ingest", tags=["Telemetry"])
async def ingest_telemetry(payload: TelemetryPayload):
    """
    Ingests live discovery payloads from SubnetSweeper, updates GraphStore,
    and broadcasts the update to all connected Cytoscape canvases.
    """
    # Format deterministic edge label
    if payload.edge_type == "WIRELESS_AIRLINK":
        label_str = f"~{payload.distance_m:.1f}m ({payload.confidence_pct:.0f}%)" if payload.distance_m > 0 else "AirLink"
    else:
        label_str = f"{payload.distance_m:.1f}m ({payload.confidence_pct:.0f}%)"

    # 1. Update GraphStore
    active_store.upsert_node(payload.node_id, payload.node_props or {})
    active_store.add_edge(
        source=payload.parent_switch_id,
        target=payload.node_id,
        edge_type=payload.edge_type,
        distance_m=payload.distance_m,
        variance_m2=payload.variance_m2,
        confidence_pct=payload.confidence_pct,
        is_anchor=payload.is_anchor,
        net_flight_time_ns=payload.net_flight_time_ns,
        label=label_str
    )

    # 2. Prepare Cytoscape element update payload
    delta = {
        "node": {
            "data": {
                "id": payload.node_id,
                "label": payload.node_id,
                **(payload.node_props or {})
            }
        },
        "edge": {
            "data": {
                "id": f"{payload.parent_switch_id}->{payload.node_id}",
                "source": payload.parent_switch_id,
                "target": payload.node_id,
                "edge_type": payload.edge_type,
                "distance_m": payload.distance_m,
                "variance_m2": payload.variance_m2,
                "confidence_pct": payload.confidence_pct,
                "is_anchor": payload.is_anchor,
                "net_flight_time_ns": payload.net_flight_time_ns,
                "label": label_str
            }
        }
    }

    # 3. Broadcast to all active browsers
    await manager.broadcast({"type": "TELEMETRY_UPDATE", "payload": delta})
    return {"status": "ok", "node_id": payload.node_id}


@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """Subscribes web clients to real-time discovery and Kalman shrinkage events."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive loop; client messages discarded
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/", response_class=HTMLResponse, tags=["Visualizer"])
def render_visualizer():
    """Serves the Cytoscape WebGL HTML/JS UI."""
    if not HTML_FILE.exists():
        return HTMLResponse(content=f"<h3>Error: {HTML_FILE} not found.</h3>", status_code=404)
    return HTML_FILE.read_text(encoding="utf-8")


def run_server(port: int = 8080, host: str = "127.0.0.1") -> None:
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_server()