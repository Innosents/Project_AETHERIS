"""
Project AETHERIS - Web Visualizer Server & Dash Cytoscape Event Loop
Serves the Cytoscape WebGL spatial canvas, binds the Dash event loop to the
active Redis O(1) ledger, and broadcasts real-time physical telemetry updates.
"""

from pathlib import Path
import sys
import os
import re
import json
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from a2wsgi import WSGIMiddleware
import dash
import dash_cytoscape as cyto
from dash import html, dcc
from dash.dependencies import Input, Output, State
from pydantic import BaseModel
import uvicorn
import numpy as np

# Inject relative path to access storage and core modules
sys.path.append(str(Path(__file__).parent.parent.parent))
from aetheris.storage.ledger import AetherisLedger
from aetheris.core.telemetry_ledger import TelemetryLedger
from aetheris.core.spatial_normalizer import SpatialNormalizationEngine
from aetheris.core.anchor_guard import AnchorGuard

active_ledger = AetherisLedger()
telemetry_ledger = TelemetryLedger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- COLD BOOT HYDRATION ---
    await active_ledger.init_db()
    nodes, edges = await active_ledger.hydrate_store()
    for node in nodes:
        active_store.upsert_node(node["node_id"], node["props"])
    for edge in edges:
        active_store.add_edge(
            source=edge["source_id"],
            target=edge["target_id"],
            edge_type=edge["props"].get("edge_type", "ETHERNET"),
            distance_m=edge["props"].get("distance_m", 0.0),
            props=edge["props"]
        )
    # --- START WRITE-BEHIND WORKER ---
    await active_ledger.start_worker()

    yield

    # --- GRACEFUL TEARDOWN ---
    await active_ledger.shutdown()


app = FastAPI(title="AETHERIS Visualizer", lifespan=lifespan)
HTML_FILE = Path(__file__).parent / "static" / "topology.html"


# --- Telemetry Store & WebSocket Manager ---
class ActiveGraphStore:
    def __init__(self):
        self.nodes: Dict[str, dict] = {}
        self.edges: Dict[str, dict] = {}

    @property
    def _graph(self):
        return self

    def clear(self):
        self.nodes.clear()
        self.edges.clear()

    def upsert_node(self, node_id: str, props: dict):
        self.nodes[node_id] = props

    def add_edge(self, source: str, target: str, edge_type: str, distance_m: float, props: dict = None):
        edge_id = f"{source}->{target}"
        self.edges[edge_id] = {
            "source": source,
            "target": target,
            "edge_type": edge_type,
            "distance_m": distance_m,
            **(props or {})
        }

    def get_cytoscape_elements(self) -> List[dict]:
        elements = []
        for nid, props in self.nodes.items():
            elements.append({"data": {"id": nid, "label": props.get("label", nid), **props}})
        for eid, props in self.edges.items():
            elements.append({"data": {"id": eid, **props}})
        return elements


active_store = ActiveGraphStore()


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


# --- Telemetry Extraction from Redis O(1) Ledger ---
def extract_live_node_telemetry(node_id: str, tap_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Directly queries the active Redis O(1) ledger Hashes and Sorted Sets.
    Extracts calibrated tau_flight, OS profile, dynamic line impedance (Z_0),
    and wire-level dissections (Modbus FC, Mercury FW, BACnet state).
    Enforces strict '[PENDING L2 SWEEP]' for unobserved metrics.
    """
    tap_data = tap_data or {}
    node_props = active_ledger.get_node(node_id) or {}

    # Merge tap_data as fallback
    merged: Dict[str, Any] = {**tap_data, **node_props}

    label = merged.get("label") or node_id
    dev_type = (merged.get("type") or merged.get("device_type") or "generic").upper()

    # 1. Network Layer Addressing
    raw_ip = merged.get("ip") or merged.get("ipv4")
    if not raw_ip:
        # Check if node_id itself is an IP address
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", node_id):
            raw_ip = node_id
        elif node_id.startswith("host_"):
            candidate = node_id.replace("host_", "").replace("_", ".")
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
                raw_ip = candidate

    raw_mac = merged.get("mac") or merged.get("mac_address")
    raw_vlan = merged.get("vlan")
    raw_switchport = merged.get("switchport") or merged.get("port")

    # 2. Nanosecond Spatial Vectors & Dynamic Transmission Line Impedance (Z0)
    tau_flight_ns: Optional[float] = None
    z0_ohms: Optional[float] = None
    cable_distance_m: Optional[float] = None
    jitter_ns: float = 0.0

    if raw_ip:
        try:
            flight_times = telemetry_ledger.get_raw_nanosecond_flight_times(raw_ip)
            if flight_times:
                valid_samples = [float(t) for t in flight_times if float(t) > 0]
                if valid_samples:
                    tau_flight_ns = round(float(np.percentile(valid_samples, 10)), 2)
                    jitter_ns = round(float(np.ptp(valid_samples)), 2) if len(valid_samples) > 1 else 0.0

                    nvp = float(merged.get("nvp", 0.69))
                    z0_calc = SpatialNormalizationEngine.calculate_dynamic_line_impedance(
                        tau_flight_ns=tau_flight_ns,
                        jitter_ns=jitter_ns,
                        nvp=nvp
                    )
                    z0_ohms = z0_calc["z0_ohms"]
                    cable_distance_m = z0_calc["distance_m"]
        except Exception as e:
            logger.debug(f"[Visualizer] Error extracting Redis telemetry for {raw_ip}: {e}")

    # If distance was explicitly set on node or edge, preserve if not yet calibrated
    if cable_distance_m is None and merged.get("distance_m") is not None:
        try:
            cable_distance_m = float(merged["distance_m"])
        except (ValueError, TypeError):
            pass

    # 3. Live Wire Dissector Telemetry (Phase 1 Scapy dissector outputs)
    raw_telemetry = merged.get("telemetry") or {}
    if isinstance(raw_telemetry, str):
        try:
            raw_telemetry = json.loads(raw_telemetry)
        except Exception:
            raw_telemetry = {}

    modbus_fc = (
        raw_telemetry.get("function_code")
        or merged.get("modbus_function_code")
        or merged.get("modbus_fc")
    )
    mercury_fw = (
        raw_telemetry.get("firmware")
        or merged.get("mercury_firmware")
        or (merged.get("firmware") if "mercury" in str(merged.get("vendor", "")).lower() or "mercury" in str(merged.get("model", "")).lower() else None)
    )
    bacnet_status = (
        raw_telemetry.get("apdu_service")
        or merged.get("bacnet_status")
        or (raw_telemetry.get("protocol") if raw_telemetry.get("protocol") == "BACNET_IP" else None)
    )

    # 4. OS Profiling & AnchorGuard Status
    os_profile = merged.get("os") or merged.get("os_family") or merged.get("os_version")

    anchor_eval = AnchorGuard.evaluate_anchor_candidate({
        "ip": raw_ip,
        "mac": raw_mac,
        "medium": merged.get("medium", "COPPER"),
        "switchport": raw_switchport,
        "archetype": merged.get("archetype", "GENERIC_HOST"),
        "is_anchor": bool(merged.get("is_anchor", False)),
        "jitter_ns": jitter_ns,
    })
    anchor_trust_state = anchor_eval.get("anchor_trust_state", "UNQUALIFIED_ENDPOINT")

    # Helper function to enforce [PENDING L2 SWEEP]
    def _display_val(val, suffix=""):
        if val is None or str(val).strip() in ("", "N/A", "None", "unknown"):
            return "[PENDING L2 SWEEP]"
        return f"{val}{suffix}"

    display_ip = _display_val(raw_ip)
    display_mac = _display_val(raw_mac)
    display_vlan = _display_val(raw_vlan)
    display_switchport = _display_val(raw_switchport)
    display_distance = _display_val(f"{cable_distance_m:.2f}" if cable_distance_m is not None else None, "m")
    display_tau = _display_val(f"{tau_flight_ns:.1f}" if tau_flight_ns is not None else None, " ns")
    display_z0 = _display_val(f"{z0_ohms:.1f}" if z0_ohms is not None else None, " \u03a9")
    display_modbus = _display_val(modbus_fc)
    display_mercury = _display_val(mercury_fw)
    display_bacnet = _display_val(bacnet_status)
    display_os = _display_val(os_profile)
    display_anchor = _display_val(anchor_trust_state)

    # Generate Unified HTML Telemetry Frame strictly from live metrics
    html_frame = f"""
    <div class="space-y-4 text-sm font-mono text-gray-300 p-2 h-full overflow-y-auto">
        <div class="border-b border-gray-700 pb-2">
            <span class="text-white font-bold text-xl block">{label}</span>
            <span class="text-xs text-blue-400 mt-1 block">ID: {node_id} | TYPE: {dev_type}</span>
        </div>
        <div>
            <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">Network Layer</h4>
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-gray-500">IPv4:</span> <span class="{'text-white' if display_ip != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_ip}</span></div>
                <div><span class="text-gray-500">MAC:</span> <span class="{'text-white' if display_mac != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_mac}</span></div>
                <div><span class="text-gray-500">VLAN:</span> <span class="{'text-white' if display_vlan != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_vlan}</span></div>
                <div><span class="text-gray-500">Switchport:</span> <span class="{'text-white' if display_switchport != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_switchport}</span></div>
            </div>
        </div>
        <div>
            <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">TDR & Spatial Vectors</h4>
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-gray-500">Distance:</span> <span class="{'text-yellow-400 font-bold' if display_distance != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_distance}</span></div>
                <div><span class="text-gray-500">&tau; Flight:</span> <span class="{'text-white' if display_tau != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_tau}</span></div>
                <div><span class="text-gray-500">Impedance Z0:</span> <span class="{'text-white' if display_z0 != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_z0}</span></div>
                <div><span class="text-gray-500">Jitter (&Delta;&tau;):</span> <span class="{'text-white' if jitter_ns > 0 else 'text-slate-500'}">{f"{jitter_ns:.1f} ns" if jitter_ns > 0 else "[PENDING L2 SWEEP]"}</span></div>
            </div>
        </div>
        <div>
            <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">OT / SCADA Wire Dissectors</h4>
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-gray-500">Modbus FC:</span> <span class="{'text-cyan-400' if display_modbus != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_modbus}</span></div>
                <div><span class="text-gray-500">Mercury FW:</span> <span class="{'text-purple-400' if display_mercury != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_mercury}</span></div>
                <div class="col-span-2"><span class="text-gray-500">BACnet State:</span> <span class="{'text-emerald-400' if display_bacnet != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_bacnet}</span></div>
            </div>
        </div>
        <div>
            <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">Passive Classification</h4>
            <div class="flex flex-col gap-1 text-xs">
                <div><span class="text-gray-500">OS Profile:</span> <span class="{'text-white' if display_os != '[PENDING L2 SWEEP]' else 'text-amber-500/80 italic'}">{display_os}</span></div>
                <div><span class="text-gray-500">AnchorGuard:</span> <span class="{'text-green-400 font-semibold' if 'TRUSTED' in display_anchor else 'text-slate-400'}">{display_anchor}</span></div>
            </div>
        </div>
    </div>
    """

    return {
        "node_id": node_id,
        "label": label,
        "type": dev_type,
        "ipv4": display_ip,
        "mac": display_mac,
        "vlan": display_vlan,
        "switchport": display_switchport,
        "distance": display_distance,
        "tau_flight": display_tau,
        "impedance_z0": display_z0,
        "modbus_fc": display_modbus,
        "mercury_fw": display_mercury,
        "bacnet_status": display_bacnet,
        "os_profile": display_os,
        "anchor_status": display_anchor,
        "html_frame": html_frame.strip(),
    }


# --- API Routes ---
@app.get("/api/graph", tags=["Graph"])
@app.get("/api/topology", tags=["Topology"])
async def get_graph_state():
    return active_store.get_cytoscape_elements()


@app.get("/api/node/{node_id}/telemetry", tags=["Telemetry"])
async def get_node_telemetry_endpoint(node_id: str):
    """Returns live physical telemetry from the Redis O(1) ledger for a node."""
    return extract_live_node_telemetry(node_id)


class TelemetryPayload(BaseModel):
    node_id: str
    node_props: Optional[Dict[str, Any]] = None
    parent_switch_id: str
    distance_m: float
    confidence_pct: float
    edge_type: str = "ETHERNET"


@app.post("/api/telemetry/ingest", tags=["Telemetry"])
async def ingest_telemetry(payload: TelemetryPayload):
    """
    Ingests sub-microsecond physical spatial telemetry.
    Re-renders the physics layout if the geometry delta exceeds the threshold.
    """
    active_store.upsert_node(payload.node_id, payload.node_props or {})
    if payload.edge_type == "WIRELESS_AIRLINK":
        label_str = f"~{payload.distance_m:.1f}m ({payload.confidence_pct:.0f}%)" if payload.distance_m > 0 else "AirLink"
    else:
        label_str = f"{payload.distance_m:.1f}m ({payload.confidence_pct:.0f}%)"

    active_store.add_edge(
        source=payload.parent_switch_id,
        target=payload.node_id,
        edge_type=payload.edge_type,
        distance_m=payload.distance_m,
        props={"label": label_str}
    )

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
                "label": label_str
            }
        }
    }

    await manager.broadcast({"type": "TELEMETRY_UPDATE", "payload": delta})
    active_ledger.queue.put_nowait(payload)
    return {"status": "ok", "node_id": payload.node_id}


@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """Subscribes web clients to real-time discovery and Kalman shrinkage events."""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/", tags=["Visualizer"])
def render_visualizer(request: Request):
    """Redirects to the Dash Cytoscape visualizer."""
    mode = request.query_params.get("mode")
    suffix = "?mode=demo" if mode == "demo" else ""
    return RedirectResponse(f"/dash/{suffix}")


# --- Dash Cytoscape Instantiation & Callback Hydration ---
dash_app = dash.Dash(__name__, requests_pathname_prefix='/dash/')

with open(Path(__file__).parent / "static" / "topology.html", "r", encoding="utf-8") as f:
    raw_html = f.read()
    raw_html = raw_html.replace("</title>", "</title>\n  {%metas%}\n  {%favicon%}\n  {%css%}")
    raw_html = raw_html.replace('<div id="cy" class="w-full h-full spatial-grid bg-obsidian-950"></div>', '<div id="cy-dash-wrapper" class="w-full h-full spatial-grid bg-obsidian-950">{%app_entry%}</div>')
    raw_html = raw_html.replace("</body>", "  {%config%}\n  {%scripts%}\n  {%renderer%}\n</body>")

    raw_html = re.sub(r'setInterval\(\(\) => \{\s*loadTopology\(\);\s*\}, 1000\);', '// Dash now handles live polling', raw_html)
    raw_html = re.sub(r'loadTopology\(\);', '// loadTopology bypassed for Dash', raw_html)

    dash_app.index_string = raw_html

cyto.load_extra_layouts()

dash_app.layout = html.Div(style={'backgroundColor': 'transparent', 'width': '100%', 'height': '100%'}, children=[
    dcc.Location(id='url', refresh=False),
    dcc.Interval(id='telemetry-interval', interval=3000, n_intervals=0),
    dcc.Store(id='inspector-store'),
    html.Div(id='dummy-inspector-output', style={'display': 'none'}),
    cyto.Cytoscape(
        id='cytoscape-canvas',
        layout={
            'name': 'cose',
            'idealEdgeLength': 150,
            'nodeRepulsion': 400000,
            'componentSpacing': 150,
            'padding': 50,
            'animate': False
        },
        style={'width': '100%', 'height': '100%', 'position': 'absolute'},
        elements=[],
        stylesheet=[
            {
                'selector': 'node',
                'style': {
                    'shape': 'ellipse',
                    'width': '50px',
                    'height': '50px',
                    'label': 'data(label)',
                    'color': '#ffffff',
                    'text-valign': 'bottom',
                    'text-margin-y': '8px',
                    'font-family': 'monospace',
                    'font-size': '11px',
                    'border-width': '2px',
                    'border-color': '#334155',
                    'background-color': '#1e293b'
                }
            },
            {
                'selector': '[vlan = 10], [vlan = "10"]',
                'style': { 'background-color': '#d97706', 'border-color': '#fcd34d' }
            },
            {
                'selector': '[vlan = 20], [vlan = "20"]',
                'style': { 'background-color': '#0284c7', 'border-color': '#7dd3fc' }
            },
            {
                'selector': '[vlan = 30], [vlan = "30"]',
                'style': { 'background-color': '#475569', 'border-color': '#94a3b8' }
            },
            {
                'selector': 'edge',
                'style': { 'width': 2, 'line-color': '#334155', 'curve-style': 'bezier' }
            }
        ]
    )
])

# 1. Synchronize native HTML HUD via Clientside Callback
dash_app.clientside_callback(
    """
    function(elements) {
        if (!elements) return window.dash_clientside.no_update;
        let nodes = 0; let edges = 0; let criticals = 0;
        elements.forEach(e => {
            if (e.data.source) { edges++; } else { nodes++; }
            if (e.classes && e.classes.includes('critical')) { criticals++; }
        });
        const nEl = document.getElementById('hud-node-count');
        const eEl = document.getElementById('hud-edge-count');
        const aEl = document.getElementById('hud-anomaly-count');
        if (nEl) nEl.innerText = nodes;
        if (eEl) eEl.innerText = edges;
        if (aEl) aEl.innerText = criticals;
        return window.dash_clientside.no_update;
    }
    """,
    Output('cytoscape-canvas', 'className'),
    [Input('cytoscape-canvas', 'elements')]
)

# 2. Server-side Dash Event Loop: Query Active Redis O(1) Ledger on tapNodeData
@dash_app.callback(
    Output('inspector-store', 'data'),
    [Input('cytoscape-canvas', 'tapNodeData')]
)
def handle_node_click_redis_lookup(tap_data):
    """
    Triggered when a Cytoscape node is clicked.
    Instantly queries Redis O(1) Hashes for calibrated tau_flight, Z0, OS profile,
    and wire dissector telemetry, pushing the JSON delta to the frontend.
    """
    if not tap_data or not tap_data.get("id"):
        return None
    node_id = str(tap_data.get("id"))
    return extract_live_node_telemetry(node_id, tap_data)


# 3. Clientside Telemetry Frame Renderer (Consumes Live Redis JSON Delta - No pseudoRand)
dash_app.clientside_callback(
    """
    function(delta) {
        if (!delta) return window.dash_clientside.no_update;

        const inspector = document.getElementById('inspector-content') 
                       || document.querySelector('.sidebar-container')
                       || document.getElementById('sidebar')
                       || document.querySelector('aside');

        if (!inspector) return window.dash_clientside.no_update;

        // Render live metrics delta pushed from backend Redis subscription
        if (delta.html_frame) {
            inspector.innerHTML = delta.html_frame;
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output('dummy-inspector-output', 'children'),
    [Input('inspector-store', 'data')]
)


@dash_app.callback(
    Output('cytoscape-canvas', 'elements'),
    [Input('url', 'search'), Input('telemetry-interval', 'n_intervals')]
)
def hydrate_topology(search, n_intervals):
    if search and '?mode=demo' in search:
        is_anomaly = n_intervals is not None and n_intervals > 0 and (n_intervals % 3 == 0)
        edge_state = "critical" if is_anomaly else "stable"
        from aetheris.topology.demo_payload import get_demo_msp_elements
        elements = get_demo_msp_elements()
        elements.append({
            "data": {
                "id": "edge1",
                "source": "sw_mercury",
                "target": "sw_tiandy",
                "variance_state": edge_state,
                "switchport": "Gi1/0/24",
                "distance_m": 15.2,
                "confidence_pct": 99.1,
                "edge_id": "edge1",
                "edge_type": "HARDLINED"
            },
            "classes": edge_state
        })
        return elements
    global active_store
    return active_store.get_cytoscape_elements()


app.mount("/dash", WSGIMiddleware(dash_app.server))


def run_server(port: int = 8080, host: str = "127.0.0.1") -> None:
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_server()
