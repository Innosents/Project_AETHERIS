"""
Project AETHERIS - Unified Spatial Intelligence Server & Cytoscape Telemetry Bridge
Integrates FastMCP spatial reasoning tools with a high-fidelity Cytoscape L1/L2 visualizer.

Provides:
  - POST /api/telemetry/ingest: Normalizes node/edge spatial evidence (physical length d ± σ, CAM switchports, OT profiles).
  - GET /api/graph: Generates Cytoscape elements with specialized styling (.anchor, .switch, .industrial_ot, .copper, .wlan).
  - GET /api/telemetry/stream: Real-time Server-Sent Events (SSE) push pipeline.
  - GET /: Interactive Cytoscape HTML dashboard with compound hierarchical layout and live visualizer bridge.
  - MCP Tools: query_device_prior, get_device_history, get_ledger_stats, list_unique_endpoints.
"""

import sys
import os
import time
import math
import json
import asyncio
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.fastmcp import FastMCP

from graphpath.topology.graph_store import GraphStore
from graphpath.core.telemetry_ledger import TelemetryLedger
from graphpath.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# ---------------------------------------------------------------------------
# Core Server Setup: FastMCP and FastAPI Bridge
# ---------------------------------------------------------------------------

mcp = FastMCP("AETHERIS-Spatial-Intelligence")
ledger = TelemetryLedger()
active_store = GraphStore()

app = FastAPI(title="AETHERIS Spatial Server & Cytoscape Telemetry Bridge")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory caches for UI polling and SSE streaming
latest_telemetry: Dict[str, Any] = {
    "nodes": [],
    "summary": {"total_nodes": 0, "avg_confidence": 0.0}
}
sse_subscribers: List[asyncio.Queue] = []


class TelemetryIngestPayload(BaseModel):
    node_id: Optional[str] = None
    target: Optional[str] = None
    source: Optional[str] = None
    parent_switch_id: Optional[str] = "Gateway-Core"
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    archetype: Optional[str] = None
    os_profile: Optional[str] = None
    confidence: Optional[float] = None
    confidence_pct: Optional[float] = None
    is_anchor: Optional[bool] = False
    edge_type: Optional[str] = "ETHERNET_LINK"
    port: Optional[str] = None
    switchport: Optional[str] = None
    medium: Optional[str] = None
    distance_m: float = 0.0
    variance_m2: float = 0.0
    jitter_ns: Optional[float] = 0.0
    t_kernel_us: Optional[float] = 0.0
    net_flight_time_ns: Optional[float] = None
    mcmc_kernel_turnaround_us: Optional[float] = None
    node_props: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# HTML Dashboard with Cytoscape.js, Compound Layout, and Live SSE Bridge
# ---------------------------------------------------------------------------

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AETHERIS Physical L1/L2 Spatial Graph & Telemetry Bridge</title>
    <!-- Cytoscape Core & Layout Extensions -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/layout-base/layout-base.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cose-base/cose-base.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-fcose/cytoscape-fcose.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
        h1 { color: #58a6ff; font-size: 20px; margin-bottom: 5px; }
        .subtitle { color: #8b949e; font-size: 12px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; text-transform: uppercase; font-size: 11px; }
        .tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .tag-win { background: #1f6feb33; color: #58a6ff; }
        .tag-linux { background: #23863633; color: #3fb950; }
        .tag-ot { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
        .tag-anchor { background: #e3b34133; color: #e3b341; border: 1px solid #e3b341; }
        .badge-conf { font-weight: bold; }
        .conf-high { color: #3fb950; }
        .conf-med { color: #d29922; }
        .conf-low { color: #f85149; }
        #canvas-container { width: 100%; height: 580px; position: relative; background: #0b0e14; border-radius: 6px; border: 1px solid #30363d; overflow: hidden; }
        #cy { width: 100%; height: 100%; position: absolute; top: 0; left: 0; }
        .hud-bar {
            position: absolute;
            top: 12px;
            left: 12px;
            display: flex;
            gap: 6px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid #1e293b;
            backdrop-filter: blur(8px);
            padding: 6px 10px;
            border-radius: 6px;
            z-index: 10;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
        }
        .hud-btn {
            background: #1e293b;
            color: #cbd5e1;
            border: 1px solid #334155;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .hud-btn:hover {
            background: #334155;
            color: #f8fafc;
            border-color: #64748b;
        }
        .hud-btn:active {
            background: #0f172a;
        }
        .legend-overlay {
            position: absolute;
            top: 12px;
            right: 12px;
            background: rgba(15, 23, 42, 0.92);
            border: 1px solid #1e293b;
            backdrop-filter: blur(8px);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 11px;
            color: #94a3b8;
            z-index: 10;
            pointer-events: none;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
        }
        .legend-title { font-weight: bold; color: #f8fafc; margin-bottom: 6px; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; }
        .legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
        .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .legend-line { width: 18px; display: inline-block; }
        .legend-sep { height: 1px; background: #1e293b; margin: 6px 0; }
    </style>
</head>
<body>
    <h1>AETHERIS Physical L1/L2 Spatial Sweep Engine</h1>
    <div class="subtitle">Live Hardware Identification & Physical Propagation Telemetry (Cytoscape Bridge)</div>

    <div class="grid">
        <div class="card">
            <div id="canvas-container">
                <div id="cy"></div>
                <div class="hud-bar">
                    <button class="hud-btn" onclick="centerAndFit()" title="Fit View to Elements">⛶ Fit View</button>
                    <button class="hud-btn" onclick="applyTreeLayout()" title="Compact Tree Hierarchy">🌲 Compact Tree</button>
                    <button class="hud-btn" onclick="zoomIn()" title="Zoom In">+</button>
                    <button class="hud-btn" onclick="zoomOut()" title="Zoom Out">−</button>
                    <button class="hud-btn" onclick="resetZoom()" title="Reset Zoom">↺</button>
                </div>
                <div class="legend-overlay">
                    <div class="legend-title">Topology Key</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#3b82f6;border-radius:2px;"></span> Switch / Gateway Chassis</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#eab308;box-shadow:0 0 6px #eab308;"></span> Physical Anchor Node</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#ef4444;border:1px solid #fca5a5;"></span> Industrial OT / PLC Asset</div>
                    <div class="legend-item"><span class="legend-dot" style="background:#10b981;"></span> Standard Endpoint</div>
                    <div class="legend-sep"></div>
                    <div class="legend-item"><span class="legend-line" style="border-top:2px solid #10b981;"></span> Copper Cat5e/Cat6 (d ± σ)</div>
                    <div class="legend-item"><span class="legend-line" style="border-top:2px dashed #a855f7;"></span> WLAN 802.11 AirLink</div>
                    <div class="legend-item"><span class="legend-line" style="border-top:3px solid #eab308;"></span> Calibrated Ground Truth</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2 style="font-size: 14px; margin-top: 0; color: #8b949e; text-transform: uppercase;">Discovered Nodes & Cable Runs</h2>
            <div id="summary-bar" style="margin-bottom: 12px; font-size: 12px; color: #8b949e;">Connecting to live stream...</div>
            <div style="overflow-y: auto; max-height: 480px;">
                <table>
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>Port / Medium</th>
                            <th>Distance ± σ</th>
                            <th>Conf</th>
                        </tr>
                    </thead>
                    <tbody id="nodes-table"></tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let cy = null;
        let initialFitDone = false;

        function getCompactLayoutOptions() {
            const hasFcose = typeof cytoscape('core', 'fcose') === 'function';
            if (hasFcose) {
                return {
                    name: 'fcose',
                    animate: true,
                    animationDuration: 400,
                    quality: 'default',
                    randomize: false,
                    fit: false,
                    nodeDimensionsIncludeLabels: true,
                    nodeRepulsion: function(node) { return node.isParent() ? 6000 : 1800; },
                    idealEdgeLength: function(edge) {
                        const d = edge.data('distance_m') || 10;
                        return Math.min(130, Math.max(50, d * 3.2));
                    },
                    edgeElasticity: 0.45,
                    nestingFactor: 0.08,
                    gravity: 0.35,
                    numIter: 1000,
                    tile: true,
                    tilingPaddingVertical: 16,
                    tilingPaddingHorizontal: 16
                };
            }
            return {
                name: 'cose',
                animate: true,
                animationDuration: 400,
                fit: false,
                nodeDimensionsIncludeLabels: true,
                nodeRepulsion: function(node) { return node.isParent() ? 6000 : 1800; },
                idealEdgeLength: function(edge) {
                    const d = edge.data('distance_m') || 10;
                    return Math.min(130, Math.max(50, d * 3.2));
                },
                edgeElasticity: function(edge) { return 100; },
                nestingFactor: 0.08,
                gravity: 0.35,
                numIter: 1000
            };
        }

        function initCytoscape(elements) {
            cy = cytoscape({
                container: document.getElementById('cy'),
                elements: elements,
                minZoom: 0.2,
                maxZoom: 3.0,
                wheelSensitivity: 0.18,
                boxSelectionEnabled: false,
                autounselectify: false,
                style: [
                    {
                        selector: 'node',
                        style: {
                            'background-color': '#1f2937',
                            'label': 'data(label)',
                            'color': '#f3f4f6',
                            'font-size': '10px',
                            'text-valign': 'bottom',
                            'text-margin-y': 4,
                            'border-width': 1.5,
                            'border-color': '#4b5563',
                            'width': 34,
                            'height': 34
                        }
                    },
                    {
                        selector: ':parent',
                        style: {
                            'background-opacity': 0.12,
                            'background-color': '#334155',
                            'border-width': 1.5,
                            'border-color': '#64748b',
                            'border-style': 'dashed',
                            'padding': 16,
                            'font-size': '11px',
                            'color': '#94a3b8',
                            'text-valign': 'top',
                            'text-halign': 'center'
                        }
                    },
                    {
                        selector: 'node.switch',
                        style: {
                            'background-color': '#1d4ed8',
                            'border-color': '#38bdf8',
                            'border-width': 2,
                            'shape': 'round-rectangle',
                            'width': 44,
                            'height': 44,
                            'font-weight': 'bold'
                        }
                    },
                    {
                        selector: 'node.anchor',
                        style: {
                            'background-color': '#854d0e',
                            'border-color': '#eab308',
                            'border-width': 3,
                            'shadow-blur': 12,
                            'shadow-color': '#eab308',
                            'shadow-opacity': 0.8
                        }
                    },
                    {
                        selector: 'node.industrial_ot',
                        style: {
                            'background-color': '#7f1d1d',
                            'border-color': '#ef4444',
                            'border-width': 2.5,
                            'shape': 'octagon',
                            'font-weight': 'bold'
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': '#4b5563',
                            'curve-style': 'bezier',
                            'label': 'data(label)',
                            'font-size': '9px',
                            'color': '#cbd5e1',
                            'text-background-color': '#0f172a',
                            'text-background-opacity': 0.85,
                            'text-background-padding': 2,
                            'text-background-shape': 'roundrectangle'
                        }
                    },
                    {
                        selector: 'edge.copper',
                        style: {
                            'line-color': '#10b981',
                            'width': 2.5
                        }
                    },
                    {
                        selector: 'edge.wlan',
                        style: {
                            'line-color': '#a855f7',
                            'line-style': 'dashed',
                            'line-dash-pattern': [3, 3]
                        }
                    },
                    {
                        selector: 'edge.anchor',
                        style: {
                            'line-color': '#eab308',
                            'width': 3.5
                        }
                    }
                ],
                layout: getCompactLayoutOptions()
            });
        }

        function centerAndFit() {
            if (!cy || cy.elements().length === 0) return;
            cy.stop();
            cy.fit(cy.elements(), 35);
        }

        function applyTreeLayout() {
            if (!cy || cy.elements().length === 0) return;
            cy.stop();
            cy.layout({
                name: 'breadthfirst',
                directed: true,
                animate: true,
                animationDuration: 400,
                fit: true,
                padding: 35,
                spacingFactor: 1.15
            }).run();
        }

        function zoomIn() {
            if (!cy) return;
            cy.zoom({
                level: Math.min(cy.maxZoom(), cy.zoom() * 1.25),
                renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
            });
        }

        function zoomOut() {
            if (!cy) return;
            cy.zoom({
                level: Math.max(cy.minZoom(), cy.zoom() * 0.8),
                renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
            });
        }

        function resetZoom() {
            if (!cy) return;
            cy.zoom(1.0);
            cy.center();
        }

        async function fetchGraph() {
            try {
                const res = await fetch('/api/graph');
                const elements = await res.json();
                if (!cy) {
                    initCytoscape(elements);
                    if (elements && elements.length > 0) {
                        centerAndFit();
                        initialFitDone = true;
                    }
                } else {
                    const previousCount = cy.elements().length;
                    cy.json({ elements: elements });
                    if (elements.length !== previousCount || !initialFitDone) {
                        cy.layout(getCompactLayoutOptions()).run();
                        centerAndFit();
                        initialFitDone = true;
                    }
                }
                updateTableFromElements(elements);
            } catch (err) {
                console.warn('Graph polling failed:', err);
            }
        }

        function updateTableFromElements(elements) {
            const nodes = elements.filter(el => el.data && !el.data.source && el.data.ip);
            const tableBody = document.getElementById('nodes-table');
            tableBody.innerHTML = '';

            nodes.forEach(n => {
                const d = n.data;
                const row = document.createElement('tr');
                const confClass = d.confidence >= 90 ? 'conf-high' : (d.confidence >= 70 ? 'conf-med' : 'conf-low');
                const otBadge = (n.classes || '').includes('industrial_ot') ? '<span class="tag tag-ot">OT</span> ' : '';
                const anchorBadge = (n.classes || '').includes('anchor') ? '<span class="tag tag-anchor">Anchor</span> ' : '';

                row.innerHTML = `
                    <td>${anchorBadge}${otBadge}<strong>${d.ip}</strong><br><span style="font-size:10px;color:#8b949e;">${d.mac || ''}</span></td>
                    <td>${d.switchport || 'Unknown'}</td>
                    <td>${d.distance_m ? d.distance_m.toFixed(1) + 'm' : '--'}</td>
                    <td class="badge-conf ${confClass}">${d.confidence ? d.confidence.toFixed(0) + '%' : '--'}</td>
                `;
                tableBody.appendChild(row);
            });

            document.getElementById('summary-bar').innerText = `Total mapped endpoints: ${nodes.length}`;
        }

        // Live Server-Sent Events (SSE) Stream
        function setupEventSource() {
            try {
                const evtSource = new EventSource('/api/telemetry/stream');
                evtSource.onmessage = function(e) {
                    try {
                        const payload = JSON.parse(e.data);
                        fetchGraph();
                    } catch (err) {}
                };
                evtSource.onerror = function() {
                    evtSource.close();
                    setTimeout(setupEventSource, 3000);
                };
            } catch (e) {
                setInterval(fetchGraph, 2000);
            }
        }

        fetchGraph();
        setupEventSource();
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Visualizer HTTP Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the interactive Cytoscape dashboard."""
    return HTMLResponse(content=HTML_DASHBOARD)


@app.get("/api/telemetry/nodes")
async def get_telemetry_nodes():
    """Returns cached list of ingested nodes and summary metrics."""
    return JSONResponse(content=latest_telemetry)


@app.get("/api/topology")
async def get_topology():
    """Returns serialized Cytoscape elements directly from GraphStore."""
    return JSONResponse(content=active_store.get_cytoscape_elements())


@app.get("/api/graph")
async def get_graph():
    """
    Returns Cytoscape-formatted JSON elements (nodes and edges) enriched with
    styling classes:
      - .anchor: Gold border, glowing halo.
      - .switch: Core gateway chassis icon.
      - .industrial_ot: High-contrast industrial badge.
      - .copper: Solid thick edge labeled with length d ± σ.
      - .wlan: Dashed edge indicating wireless hop.
    """
    elements: List[Dict[str, Any]] = []
    seen_nodes = set()

    # 1. Base Gateway & Core Switch Nodes
    core_switch_id = getattr(active_store, "switch_id", "Gateway-Core") or "Gateway-Core"
    elements.append({
        "data": {
            "id": core_switch_id,
            "label": f"{core_switch_id} [Core]",
            "device_type": "switch",
            "archetype": "SWITCH",
            "is_anchor": False
        },
        "classes": "switch"
    })
    seen_nodes.add(core_switch_id)

    # 2. Add Discovered Nodes from Cache / GraphStore
    for n in latest_telemetry["nodes"]:
        node_id = n.get("node_id") or f"host_{n.get('ip', '').replace('.', '_')}"
        seen_nodes.add(node_id)

        ip = n.get("ip", "")
        mac = n.get("mac", "")
        hostname = n.get("hostname") or n.get("identity_label") or ip
        dev_type = (n.get("device_type") or "").lower()
        archetype = (n.get("archetype") or "").upper()
        os_profile = (n.get("os_profile") or "").upper()
        is_anchor = bool(n.get("is_anchor", False))
        conf = float(n.get("confidence_pct", n.get("confidence", 95.0)))
        port = n.get("switchport") or n.get("port") or "Unknown"

        # Determine styling classes
        classes = []
        if is_anchor:
            classes.append("anchor")

        # Industrial OT classification heuristic
        is_ot = (
            "plc" in dev_type
            or "industrial" in dev_type
            or "rtu" in dev_type
            or "allen_bradley" in archetype.lower()
            or "siemens" in archetype.lower()
            or "mercury" in archetype.lower()
            or any(k in f"{n.get('vendor', '')} {n.get('model', '')} {hostname}".lower() for k in ("1769-l33er", "s7-1200", "s7-300", "bilian", "modbus", "bacnet", "cip"))
        )
        if is_ot:
            classes.append("industrial_ot")

        elements.append({
            "data": {
                "id": node_id,
                "label": hostname or ip,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "device_type": dev_type,
                "archetype": archetype,
                "os_profile": os_profile,
                "confidence": conf,
                "is_anchor": is_anchor,
                "switchport": port,
                "distance_m": n.get("distance_m", 0.0),
                "variance_m2": n.get("variance_m2", 0.0),
                "parent": n.get("parent_switch_id", core_switch_id)
            },
            "classes": " ".join(classes)
        })

    # 3. Add Edges with Length d ± σ and Medium Styling
    for n in latest_telemetry["nodes"]:
        node_id = n.get("node_id") or f"host_{n.get('ip', '').replace('.', '_')}"
        parent = n.get("parent_switch_id", core_switch_id)
        if parent not in seen_nodes:
            elements.append({
                "data": {"id": parent, "label": parent, "archetype": "SWITCH"},
                "classes": "switch"
            })
            seen_nodes.add(parent)

        dist = float(n.get("distance_m", 0.0))
        var = float(n.get("variance_m2", 0.0))
        sigma = math.sqrt(max(0.0, var))
        edge_type = n.get("edge_type", "ETHERNET_LINK")
        medium = (n.get("medium") or "").lower()
        is_wireless = edge_type == "WIRELESS_AIRLINK" or "wlan" in medium or "airlink" in medium
        is_anchor = bool(n.get("is_anchor", False))

        # Format label with distance ± σ
        if dist > 0:
            edge_label = f"{dist:.1f}m ± {sigma:.2f}m" if sigma > 0.001 else f"{dist:.1f}m"
        else:
            edge_label = "AirLink" if is_wireless else f"{dist:.1f}m"

        edge_classes = []
        if is_wireless:
            edge_classes.append("wlan")
        else:
            edge_classes.append("copper")
        if is_anchor:
            edge_classes.append("anchor")

        elements.append({
            "data": {
                "id": f"edge_{parent}_{node_id}",
                "source": parent,
                "target": node_id,
                "port": n.get("switchport") or n.get("port") or "Unknown",
                "medium": "WLAN (802.11 AirLink)" if is_wireless else "Copper (Cat5e/Cat6 Drop)",
                "distance_m": dist,
                "variance_m2": var,
                "sigma_m": round(sigma, 4),
                "label": edge_label,
                "jitter_ns": float(n.get("jitter_ns", 0.0)),
                "t_kernel_us": float(n.get("t_kernel_us", n.get("mcmc_kernel_us", 0.0))),
                "weight": max(1.0, dist)
            },
            "classes": " ".join(edge_classes)
        })

    return JSONResponse(content=sanitize_prober_payload(elements))


@app.get("/api/telemetry/stream")
async def stream_telemetry_events(request: Request, poll: bool = False, max_events: int = 0):
    """
    Real-time Server-Sent Events (SSE) push pipeline.
    Broadcasts ingested spatial telemetry directly to connected browser clients.
    """
    if poll:
        # Fallback polling response
        return JSONResponse(content=latest_telemetry)

    async def event_generator():
        q: asyncio.Queue = asyncio.Queue()
        sse_subscribers.append(q)
        events_yielded = 0
        try:
            # Yield initial snapshot
            initial_data = json.dumps({"type": "snapshot", "summary": latest_telemetry["summary"]})
            yield f"data: {initial_data}\n\n"
            events_yielded += 1

            while not await request.is_disconnected():
                if max_events > 0 and events_yielded >= max_events:
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=0.5)
                    yield f"data: {json.dumps(data)}\n\n"
                    events_yielded += 1
                except asyncio.TimeoutError:
                    if max_events > 0 and events_yielded >= max_events:
                        break
                    yield ": keepalive\n\n"
                except (asyncio.CancelledError, GeneratorExit):
                    break
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            if q in sse_subscribers:
                sse_subscribers.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/telemetry/ingest")
async def ingest_telemetry_endpoint(request: Request):
    """
    Ingests live discovery payloads from SubnetSweeper or external probers.
    Parses and normalizes:
      - Node: ip, mac, hostname, device_type, archetype, os_profile, confidence, is_anchor.
      - Edge: source, target, port, medium, distance_m, variance_m2, jitter_ns, t_kernel_us.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid JSON"})

    # Extract target identifier
    node_id_candidate = data.get("node_id") or data.get("target") or data.get("ip")
    if node_id_candidate is None or not str(node_id_candidate).strip():
        return JSONResponse(
            status_code=422,
            content={"status": "error", "message": "Missing or empty node_id"}
        )
    node_id = str(node_id_candidate).strip()

    # Nested props normalization
    node_props = data.get("node_props", {})
    ip = data.get("ip") or node_props.get("ip") or (node_id.replace("host_", "").replace("_", ".") if "host_" in node_id else node_id)
    mac = data.get("mac") or node_props.get("mac", "")
    hostname = (
        data.get("hostname")
        or node_props.get("hostname")
        or node_props.get("canonical_name")
        or node_props.get("identity_label")
        or ip
    )
    device_type = data.get("device_type") or node_props.get("device_type") or node_props.get("type", "endpoint")
    archetype = data.get("archetype") or node_props.get("archetype", "GENERIC_HOST")
    os_profile = data.get("os_profile") or node_props.get("os_profile", "GENERIC_HOST")
    confidence_pct = float(data.get("confidence") or data.get("confidence_pct") or node_props.get("confidence_pct", 95.0))
    is_anchor = bool(data.get("is_anchor", False) or node_props.get("is_anchor", False))

    parent_switch_id = data.get("source") or data.get("parent_switch_id", "Gateway-Core")
    port = data.get("port") or data.get("switchport") or node_props.get("switchport") or "Unknown"
    medium = data.get("medium") or node_props.get("medium") or ("WLAN (802.11 AirLink)" if data.get("edge_type") == "WIRELESS_AIRLINK" else "Copper (Cat5e/Cat6 Drop)")
    distance_m = float(data.get("distance_m", 0.0))
    variance_m2 = float(data.get("variance_m2", 0.0))
    jitter_ns = float(data.get("jitter_ns") or node_props.get("jitter_ns", 0.0))
    t_kernel_us = float(data.get("t_kernel_us") or data.get("mcmc_kernel_turnaround_us", 0.0))
    edge_type = data.get("edge_type", "ETHERNET_ANCHOR" if is_anchor else ("WIRELESS_AIRLINK" if "wlan" in medium.lower() else "ETHERNET_LINK"))

    # Compute deterministic edge label (d ± σ)
    sigma = math.sqrt(max(0.0, variance_m2))
    if edge_type == "WIRELESS_AIRLINK":
        label_str = f"~{distance_m:.1f}m ({confidence_pct:.0f}%)" if distance_m > 0 else "AirLink"
    else:
        label_str = f"{distance_m:.1f}m ({confidence_pct:.0f}%)"

    # Update GraphStore
    active_store.upsert_node(node_id, {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "canonical_name": hostname,
        "device_type": device_type,
        "archetype": archetype,
        "os_profile": os_profile,
        "confidence_pct": confidence_pct,
        "is_anchor": is_anchor,
        "switchport": port,
        "medium": medium,
        **node_props
    })
    active_store.add_edge(
        source=parent_switch_id,
        target=node_id,
        edge_type=edge_type,
        distance_m=distance_m,
        variance_m2=variance_m2,
        confidence_pct=confidence_pct,
        is_anchor=is_anchor,
        net_flight_time_ns=data.get("net_flight_time_ns"),
        label=label_str
    )

    # Cache Record
    node_record = {
        "node_id": node_id,
        "parent_switch_id": parent_switch_id,
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "identity_label": hostname,
        "device_type": device_type,
        "archetype": archetype,
        "os_profile": os_profile,
        "vendor": node_props.get("vendor", ""),
        "model": node_props.get("model", ""),
        "distance_m": distance_m,
        "variance_m2": variance_m2,
        "confidence_pct": confidence_pct,
        "is_anchor": is_anchor,
        "edge_type": edge_type,
        "edge_label": label_str,
        "port": port,
        "switchport": port,
        "medium": medium,
        "jitter_ns": jitter_ns,
        "t_kernel_us": t_kernel_us,
        "mcmc_kernel_us": t_kernel_us
    }

    # Upsert in cache
    existing_idx = None
    for i, n in enumerate(latest_telemetry["nodes"]):
        if n.get("node_id") == node_id or (ip and n.get("ip") == ip):
            existing_idx = i
            break

    if existing_idx is not None:
        latest_telemetry["nodes"][existing_idx] = node_record
    else:
        latest_telemetry["nodes"].append(node_record)

    total = len(latest_telemetry["nodes"])
    avg_conf = sum(n["confidence_pct"] for n in latest_telemetry["nodes"]) / max(1, total)
    latest_telemetry["summary"] = {
        "total_nodes": total,
        "avg_confidence": round(avg_conf, 2)
    }

    # Broadcast to SSE subscribers
    broadcast_payload = {"type": "node_update", "node": node_record}
    for q in list(sse_subscribers):
        try:
            q.put_nowait(broadcast_payload)
        except Exception:
            pass

    return JSONResponse(content={"status": "success", "node_id": node_id, "cached_nodes": total})


def run_visualizer_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Runs the FastAPI visualizer bridge service."""
    uvicorn.run(app, host=host, port=port, log_level="info")


# ---------------------------------------------------------------------------
# FastMCP Tools (AETHERIS Spatial Reasoning)
# ---------------------------------------------------------------------------

@mcp.tool()
def query_device_prior(oui: str, archetype: str) -> Dict[str, Any]:
    """
    Queries learned empirical kernel latency prior distributions for a hardware OUI and archetype.
    Used to initialize MCMC walker balls with empirically verified bounds.
    """
    clean_oui = oui.replace(":", "").replace("-", "").upper()[:6]
    prior = ledger.get_empirical_kernel_prior(clean_oui, archetype)
    
    if prior is None:
        return {
            "status": "unlearned",
            "message": f"Fewer than 3 convergence cycles recorded for OUI={clean_oui}, Archetype={archetype}.",
            "default_priors": {
                "WINDOWS_HOST": {"mu_us": 1000.0, "sigma_us": 500.0},
                "LINUX_SERVER": {"mu_us": 1100.0, "sigma_us": 600.0},
                "CCTV_VIDEO":   {"mu_us": 2000.0, "sigma_us": 800.0}
            }
        }

    mu_log, sigma_log = prior
    median_us = float(np.exp(mu_log) * 1e6)
    
    return {
        "status": "converged",
        "oui": clean_oui,
        "archetype": archetype,
        "mu_log_sec": round(mu_log, 4),
        "sigma_log_sec": round(sigma_log, 4),
        "median_kernel_turnaround_us": round(median_us, 2)
    }


@mcp.tool()
def get_device_history(identifier: str) -> List[Dict[str, Any]]:
    """
    Fetches past convergence records, jitter profiles, and estimated cable lengths
    for an endpoint by its MAC or IP address.
    """
    clean_id = identifier.upper().replace("-", ":")
    with ledger._get_connection() as conn:
        cursor = conn.execute("""
            SELECT timestamp, mac, oui, ip, archetype, min_rtt_us, jitter_us,
                   converged_distance_m, converged_kernel_us, variance_m2, confidence_pct
            FROM convergence_ledger
            WHERE mac = ? OR ip = ?
            ORDER BY timestamp DESC LIMIT 25
        """, (clean_id, identifier))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "timestamp": r[0],
            "mac": r[1],
            "oui": r[2],
            "ip": r[3],
            "archetype": r[4],
            "min_rtt_us": r[5],
            "jitter_us": r[6],
            "converged_distance_m": r[7],
            "converged_kernel_us": r[8],
            "variance_m2": r[9],
            "confidence_pct": r[10]
        })
    return results


@mcp.tool()
def get_ledger_stats() -> Dict[str, Any]:
    """Returns global empirical store statistics across all mapped network infrastructure."""
    return ledger.get_ledger_summary()


@mcp.tool()
def list_unique_endpoints() -> List[Dict[str, Any]]:
    """Lists all distinct hardware devices currently registered in the empirical experience ledger."""
    with ledger._get_connection() as conn:
        cursor = conn.execute("""
            SELECT mac, oui, ip, archetype, 
                   AVG(converged_distance_m) as avg_dist, 
                   AVG(confidence_pct) as avg_conf,
                   COUNT(*) as sweep_count
            FROM convergence_ledger
            GROUP BY mac
            ORDER BY avg_conf DESC
        """)
        rows = cursor.fetchall()

    return [
        {
            "mac": r[0],
            "oui": r[1],
            "ip": r[2],
            "archetype": r[3],
            "mean_distance_m": round(r[4], 2),
            "mean_confidence_pct": round(r[5], 1),
            "total_sweeps": r[6]
        }
        for r in rows
    ]


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--web":
        run_visualizer_server()
    else:
        mcp.run(transport="stdio")
