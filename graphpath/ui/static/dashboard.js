/**
 * GraphPath Real-Time Topology Observability Plane
 * D3.js Force-Directed Engine with Physical-to-Logical Clustering,
 * Asynchronous Telemetry Polling, Spatial Overlays, and Executive Mode.
 */

const GRAPH_API_ENDPOINT = '/api/topology';
const REFRESH_INTERVAL_MS = 2000;
let isExecutiveMode = false;
let clusterMode = 'vlan'; // 'vlan' or 'type'

// Container & Canvas Dimensions
const container = document.getElementById('graph-container');
let width = container.clientWidth || window.innerWidth;
let height = container.clientHeight || window.innerHeight - 116;

const svg = d3.select('#topology-svg')
    .attr('width', '100%')
    .attr('height', '100%')
    .attr('viewBox', [-width / 2, -height / 2, width, height]);

// Zoom behavior
const g = svg.append('g').attr('class', 'canvas-group');
const zoom = d3.zoom()
    .scaleExtent([0.2, 5])
    .on('zoom', (event) => {
        g.attr('transform', event.transform);
    });
svg.call(zoom);

// Graph element layers
const linkLayer = g.append('g').attr('class', 'links');
const edgeLabelLayer = g.append('g').attr('class', 'edge-labels');
const nodeLayer = g.append('g').attr('class', 'nodes');

// Tooltip & Inspector References
const tooltip = d3.select('#node-tooltip');
const inspector = document.getElementById('node-inspector');

// Persistent state caches to prevent physics disruption on interval re-renders
const nodeMap = new Map();
let currentNodes = [];
let currentEdges = [];

// Color Encoders
const typeColors = {
    router: '#38bdf8',
    gateway: '#38bdf8',
    firewall: '#38bdf8',
    switch: '#10b981',
    core_switch: '#059669',
    managed_switch: '#10b981',
    server: '#ec4899',
    ad_dc: '#be185d',
    workstation: '#6366f1',
    laptop: '#818cf8',
    camera: '#f43f5e',
    cctv: '#f43f5e',
    plc: '#f59e0b',
    industrial_mobile: '#d97706',
    iot: '#a855f7',
    access_control: '#14b8a6',
    subnet: '#64748b',
    unknown: '#94a3b8'
};

const vlanColors = [
    '#38bdf8', // VLAN 10 (Cyan)
    '#10b981', // VLAN 20 (Emerald)
    '#f59e0b', // VLAN 30 (Amber)
    '#8b5cf6', // VLAN 40 (Purple)
    '#f43f5e', // VLAN 50 (Crimson)
    '#ec4899', // VLAN 60 (Pink)
    '#06b6d4', // VLAN 70 (Teal)
    '#6366f1', // VLAN 80 (Indigo)
];

function getVlanColor(vlanId) {
    if (!vlanId) return '#64748b';
    const num = parseInt(vlanId, 10) || 0;
    return vlanColors[Math.abs(num) % vlanColors.length];
}

function getNodeColor(node) {
    if (clusterMode === 'vlan' && node.vlan_id) {
        return getVlanColor(node.vlan_id);
    }
    const type = (node.type || 'unknown').toLowerCase();
    return typeColors[type] || '#64748b';
}

function getNodeIcon(node) {
    const type = (node.type || 'unknown').toLowerCase();
    if (type.includes('router') || type.includes('gateway')) return '🌐';
    if (type.includes('switch')) return '🔀';
    if (type.includes('camera') || type.includes('cctv')) return '📷';
    if (type.includes('plc') || type.includes('ot')) return '⚙️';
    if (type.includes('server') || type.includes('dc')) return '🖥️';
    if (type.includes('access')) return '🚪';
    if (type.includes('iot') || type.includes('speaker')) return '📻';
    if (type.includes('phone') || type.includes('voip')) return '📞';
    if (type === 'subnet') return '☁️';
    return '💻';
}

// ---------------------------------------------------------------------------
// 2. Physics Engine (D3 Force Simulation & Clustering)
// ---------------------------------------------------------------------------
const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(110))
    .force("charge", d3.forceManyBody().strength(-350))
    .force("center", d3.forceCenter(0, 0))
    .force("collision", d3.forceCollide().radius(d => isExecutiveMode ? 65 : 52))
    .force("cluster", forceCluster);

// Custom clustering force to draw nodes of identical VLAN / type together
function forceCluster(alpha) {
    const clusterCenters = new Map();
    currentNodes.forEach(node => {
        const key = clusterMode === 'vlan' ? (node.vlan_id || 'no-vlan') : (node.type || 'unknown');
        if (!clusterCenters.has(key)) {
            clusterCenters.set(key, { x: 0, y: 0, count: 0 });
        }
        const c = clusterCenters.get(key);
        c.x += node.x || 0;
        c.y += node.y || 0;
        c.count += 1;
    });

    clusterCenters.forEach(c => {
        if (c.count > 0) {
            c.x /= c.count;
            c.y /= c.count;
        }
    });

    currentNodes.forEach(node => {
        const key = clusterMode === 'vlan' ? (node.vlan_id || 'no-vlan') : (node.type || 'unknown');
        const center = clusterCenters.get(key);
        if (center && node.x && node.y) {
            node.vx += (center.x - node.x) * 0.08 * alpha;
            node.vy += (center.y - node.y) * 0.08 * alpha;
        }
    });
}

simulation.on("tick", () => {
    linkLayer.selectAll("line")
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

    // Safeguard: Guard against uninitialized/null/NaN coordinates on link endpoints
    edgeLabelLayer.selectAll(".edge-distance-group")
        .attr("transform", d => {
            if (!d.source || !d.target || d.source.x == null || d.target.x == null || isNaN(d.source.x) || isNaN(d.target.x)) return "";
            const mx = (d.source.x + d.target.x) / 2;
            const my = (d.source.y + d.target.y) / 2;
            return `translate(${mx},${my})`;
        });

    nodeLayer.selectAll(".node-group")
        .attr("transform", d => `translate(${d.x},${d.y})`);
});

// Drag Handlers
function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// ---------------------------------------------------------------------------
// 1. Asynchronous State Polling & Synchronization Loop
// ---------------------------------------------------------------------------
async function fetchLiveTopology() {
    try {
        const response = await fetch(GRAPH_API_ENDPOINT, {
            headers: { 'Accept': 'application/json' },
            cache: 'no-store'
        });
        if (!response.ok) throw new Error(`Topology fetch failed: ${response.status}`);
        const data = await response.json();
        
        const nodes = data.nodes || [];
        const edges = data.edges || [];
        const summary = data.summary || {};
        const macroGeo = data.macro_geolocation || {};

        updateGraphVisualization(nodes, edges);
        updateExecutiveHUD(summary, macroGeo);

        document.getElementById('sync-status').textContent = `LIVE SYNC (${new Date().toLocaleTimeString()})`;
    } catch (error) {
        console.error('[Telemetry Sync Error]', error);
        document.getElementById('sync-status').textContent = 'POLL RECONNECTING...';
    }
}

// ---------------------------------------------------------------------------
// 3. Telemetry Overlays & Dynamic Graph Mutation
// ---------------------------------------------------------------------------
// Helper for dynamic link classes
function getLinkClass(d) {
    const meta = d.metadata || {};
    const isFailover = meta.is_failover || d.type === 'failover' || (d.label && d.label.includes('Failover'));
    const isCritical = meta.critical || meta.speed_gbps >= 10;
    return `link ${isFailover ? 'link-failover' : ''} ${isCritical ? 'link-critical' : 'link-active'}`;
}

// Helper for dynamic edge distance badge classes
function getEdgeBadgeClass(d) {
    const dist = d.distance_feet !== undefined ? d.distance_feet : (d.spatial_metrics ? d.spatial_metrics.distance_feet : 0);
    const isAlarm = d.out_of_spec || dist > 500.0;
    return `edge-distance-group ${isAlarm ? 'edge-distance-alarm' : ''}`;
}

function updateGraphVisualization(nodes, edges) {
    if (!nodes || nodes.length === 0) return;

    // Track prior topology membership to detect structural mutations
    const prevNodeIds = new Set(currentNodes.map(n => String(n.id)));
    const nextNodeIds = new Set(nodes.map(n => String(n.id)));
    const prevEdgeKeys = new Set(currentEdges.map(e => `${e.source.id || e.source}->${e.target.id || e.target}`));

    // Smooth node reconciliation: preserve (x, y, vx, vy, fx, fy) across ticks
    const incomingIds = new Set(nodes.map(n => String(n.id)));
    const updatedNodes = nodes.map(n => {
        const idStr = String(n.id);
        const existing = nodeMap.get(idStr);
        if (existing) {
            // Transfer physics properties
            n.x = existing.x;
            n.y = existing.y;
            n.vx = existing.vx;
            n.vy = existing.vy;
            if (existing.fx != null) n.fx = existing.fx;
            if (existing.fy != null) n.fy = existing.fy;
        } else {
            // New node initialization: position with gentle jitter near center to avoid explosive forces
            n.x = (Math.random() - 0.5) * 60;
            n.y = (Math.random() - 0.5) * 60;
            n.vx = 0;
            n.vy = 0;
        }

        // Softly anchor subnet hubs near the top canvas boundary
        if (n.is_subnet_hub) {
            n.fx = 0;
            n.fy = -height * 0.35;
        }

        nodeMap.set(idStr, n);
        return n;
    });

    // Cleanup purged nodes
    for (const [id] of nodeMap) {
        if (!incomingIds.has(id)) nodeMap.delete(id);
    }

    currentNodes = updatedNodes;

    // Format and filter edges so both source and target exist in node set
    const validEdges = edges
        .map(e => {
            const src = String(e.src || e.source);
            const dst = String(e.dst || e.target);
            const meta = e.metadata || {};
            const dist = e.distance_feet !== undefined ? e.distance_feet : (meta.distance_feet !== undefined ? meta.distance_feet : (e.spatial_metrics ? e.spatial_metrics.distance_feet : undefined));
            const med = e.medium || meta.medium || (e.spatial_metrics && (e.spatial_metrics.physical_medium || e.spatial_metrics.medium)) || 'Cat6';
            const isOutOfSpec = Boolean(
                e.out_of_spec ||
                meta.out_of_spec ||
                (e.spatial_metrics && e.spatial_metrics.out_of_spec) ||
                (dist !== undefined && dist > 500.0)
            );
            return {
                source: src,
                target: dst,
                type: e.type || 'ethernet',
                label: e.label || '',
                metadata: meta,
                distance_feet: dist,
                medium: med,
                out_of_spec: isOutOfSpec,
                spatial_metrics: e.spatial_metrics || meta.spatial_metrics || null
            };
        })
        .filter(e => nodeMap.has(e.source) && nodeMap.has(e.target));

    const nextEdgeKeys = new Set(validEdges.map(e => `${e.source}->${e.target}`));

    // Determine if topology structure (memberships) actually changed
    const topologyChanged = prevNodeIds.size !== nextNodeIds.size ||
                            prevEdgeKeys.size !== nextEdgeKeys.size ||
                            [...nextNodeIds].some(id => !prevNodeIds.has(id)) ||
                            [...nextEdgeKeys].some(k => !prevEdgeKeys.has(k));

    currentEdges = validEdges;

    // In-place D3 Links update using .join()
    linkLayer.selectAll("line")
        .data(currentEdges, d => `${d.source.id || d.source}->${d.target.id || d.target}`)
        .join(
            enter => enter.append("line").attr("class", d => getLinkClass(d)),
            update => update.attr("class", d => getLinkClass(d)),
            exit => exit.remove()
        );

    // Safeguard: Zero-Distance Fallback & loopback/logical trunk suppression
    const spatialEdges = currentEdges.filter(d => {
        const dist = d.distance_feet !== undefined ? d.distance_feet : (d.spatial_metrics ? d.spatial_metrics.distance_feet : null);
        if (dist == null || dist <= 0) return false;
        if (d.source === d.target) return false;
        if (d.type === 'subnet' || d.type === 'logical' || d.type === 'abstract') return false;
        return true;
    });

    // In-place D3 Edge Distance Annotations (Badges & Midpoint Labels) using .join()
    const edgeBadges = edgeLabelLayer.selectAll(".edge-distance-group")
        .data(spatialEdges, d => `${d.source.id || d.source}->${d.target.id || d.target}`)
        .join(
            enter => {
                const g = enter.append("g")
                    .attr("class", d => getEdgeBadgeClass(d));
                g.append("rect").attr("class", "edge-distance-badge");
                g.append("text").attr("class", "edge-distance-label");
                g.append("title");
                return g;
            },
            update => update.attr("class", d => getEdgeBadgeClass(d)),
            exit => exit.remove()
        );

    edgeBadges.select(".edge-distance-label")
        .text(d => {
            const dist = d.distance_feet !== undefined ? d.distance_feet : (d.spatial_metrics ? d.spatial_metrics.distance_feet : 0);
            const med = d.medium || (d.spatial_metrics && (d.spatial_metrics.physical_medium || d.spatial_metrics.medium)) || 'Cat6';
            const isAlarm = d.out_of_spec || dist > 500.0;
            return isAlarm ? `⚠️ ⚡ ${dist} ft (${med})` : `⚡ ${dist} ft (${med})`;
        });

    // Safeguard: Dynamic bounding box measurement via getBBox with fallback
    edgeBadges.select(".edge-distance-badge")
        .each(function(d) {
            const rect = d3.select(this);
            const textNode = this.parentNode ? this.parentNode.querySelector('.edge-distance-label') : null;
            let boxWidth = 84;
            let boxHeight = 18;
            if (textNode) {
                try {
                    const bbox = textNode.getBBox();
                    if (bbox && bbox.width > 0) {
                        boxWidth = bbox.width + 14;
                        boxHeight = Math.max(16, bbox.height + 4);
                    } else {
                        const txt = textNode.textContent || '';
                        boxWidth = Math.max(64, txt.length * 6.5 + 14);
                    }
                } catch (e) {
                    const txt = textNode.textContent || '';
                    boxWidth = Math.max(64, txt.length * 6.5 + 14);
                }
            }
            rect.attr("width", boxWidth)
                .attr("height", boxHeight)
                .attr("x", -boxWidth / 2)
                .attr("y", -boxHeight / 2)
                .attr("rx", 4)
                .attr("ry", 4);
        });

    edgeBadges.select("title")
        .text(d => {
            const dist = d.distance_feet !== undefined ? d.distance_feet : (d.spatial_metrics ? d.spatial_metrics.distance_feet : 0);
            const med = d.medium || (d.spatial_metrics && (d.spatial_metrics.physical_medium || d.spatial_metrics.medium)) || 'Cat6';
            const isAlarm = d.out_of_spec || dist > 500.0;
            return isAlarm
                ? `EXCESSIVE_LINE_LOSS_OR_FAULT: Cable run ${dist} ft exceeds 500.0 ft specification`
                : `Physical Cable Run: ${dist} ft (${med})`;
        });

    // In-place D3 Nodes update using .join()
    const nodeGroups = nodeLayer.selectAll(".node-group")
        .data(currentNodes, d => d.id)
        .join(
            enter => {
                const g = enter.append("g")
                    .attr("class", "node-group")
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended))
                    .on("click", (event, d) => inspectNode(d))
                    .on("mouseover", (event, d) => showTooltip(event, d))
                    .on("mousemove", (event) => moveTooltip(event))
                    .on("mouseout", hideTooltip);

                // 1. Halo Ring
                g.append("circle").attr("class", "node-halo").attr("r", 26);
                // 2. Base Solid Circle
                g.append("circle").attr("class", "node-bg").attr("r", 20);
                // 3. Central Icon
                g.append("text").attr("class", "node-icon");
                // 4. Primary Label
                g.append("text").attr("class", "node-label").attr("y", 34);
                // 5. Secondary Label
                g.append("text").attr("class", "node-sublabel").attr("y", 46);
                // 6. Civic Location
                g.append("text").attr("class", "civic-location-badge").attr("y", -30);
                // 7. Bandwidth Badge
                g.append("text").attr("class", "bandwidth-badge granular-metric").attr("y", -40);
                // 8. Socket State Badge
                g.append("text").attr("class", "socket-badge granular-metric").attr("y", 58);
                return g;
            },
            update => update,
            exit => exit.remove()
        );

    nodeGroups.select(".node-halo")
        .attr("stroke", d => getNodeColor(d))
        .attr("r", d => (d.vlan_id ? 25 : 22));

    nodeGroups.select(".node-icon")
        .text(d => getNodeIcon(d));

    nodeGroups.select(".node-label")
        .text(d => d.ip || d.id);

    nodeGroups.select(".node-sublabel")
        .text(d => {
            if (isExecutiveMode) {
                return (d.vendor && d.vendor !== 'generic') ? d.vendor : (d.type ? d.type.toUpperCase() : '');
            }
            return d.model || d.vendor || d.type || '';
        });

    // Render Overlays dynamically
    nodeGroups.each(function(d) {
        const el = d3.select(this);

        // Location Badge (Civic / Spatial)
        const civicText = formatCivicLocation(d.civic_location, d.spatial_path, d);
        el.select(".civic-location-badge")
            .text(civicText)
            .style("display", civicText ? "block" : "none");

        // Bandwidth Overlay
        const bwText = formatBandwidth(d);
        el.select(".bandwidth-badge")
            .text(bwText)
            .style("display", (!isExecutiveMode && bwText) ? "block" : "none");

        // Socket State Overlay
        const socketText = formatSocketState(d);
        el.select(".socket-badge")
            .text(socketText)
            .style("display", (!isExecutiveMode && socketText) ? "block" : "none");

        // Spatial / Line Loss Fault Halo Ring Alert
        const isOutOfSpec = d.out_of_spec || d.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT' || (d.spatial_metrics && d.spatial_metrics.out_of_spec) || (d.spatial_metrics && d.spatial_metrics.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT');
        if (isOutOfSpec) {
            el.select(".node-halo")
                .style("stroke", "#f43f5e")
                .style("stroke-width", "3.5px")
                .style("stroke-dasharray", "4, 2");
        } else {
            el.select(".node-halo")
                .style("stroke", getNodeColor(d))
                .style("stroke-width", "")
                .style("stroke-dasharray", "");
        }
    });

    // Simulation Alpha & Physics Stabilization
    // Only reheat physics if membership structure changed.
    // If telemetry only updated, decay smoothly with alphaTarget(0) to prevent periodic convulsions.
    if (topologyChanged) {
        simulation.nodes(currentNodes);
        simulation.force("link").links(currentEdges);
        simulation.alpha(0.08).alphaTarget(0).restart();
    } else {
        simulation.alphaTarget(0);
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Spatial Helper Formatters
// ---------------------------------------------------------------------------
function formatCivicLocation(civic, spatialPath, node = null) {
    const parts = [];
    if (civic && typeof civic === 'object') {
        if (civic.building) parts.push(civic.building);
        if (civic.floor) parts.push(`Fl ${civic.floor}`);
        if (civic.room) parts.push(`Rm ${civic.room}`);
    }
    let locStr = parts.length > 0 ? parts.join(' • ') : '';
    if (!locStr && Array.isArray(spatialPath) && spatialPath.length > 0) {
        const lastHop = spatialPath[spatialPath.length - 1];
        if (lastHop && !lastHop.includes('Device:') && !lastHop.includes('Est. Cable Run:')) {
            locStr = lastHop;
        }
    }
    if (node && node.spatial_metrics && node.spatial_metrics.distance_feet) {
        const dist = node.spatial_metrics.distance_feet;
        return locStr ? `📍 ${locStr} | ⚡ ${dist} ft` : `⚡ ${dist} ft`;
    }
    return locStr ? `📍 ${locStr}` : '';
}

function formatBandwidth(node) {
    if (node.bandwidth_mbps) {
        return `▲▼ ${node.bandwidth_mbps.toFixed(1)} Mbps`;
    }
    // Synthetic live telemetry estimate derived from open ports / type
    const ports = node.open_ports || [];
    if (ports.includes(554)) return `▲ 4.8 Mbps (CCTV)`;
    if (ports.includes(502) || ports.includes(44818)) return `▲ 0.2 Mbps (OT)`;
    if (ports.includes(445) || ports.includes(135)) return `▲ 1.4 Mbps (LAN)`;
    return '';
}

function formatSocketState(node) {
    const ports = node.open_ports || [];
    if (ports.length > 0) {
        const portStr = ports.slice(0, 3).join(',');
        return `[LISTEN: ${portStr}${ports.length > 3 ? '...' : ''}]`;
    }
    return '';
}

// ---------------------------------------------------------------------------
// 4. Executive Mode Presentation Toggle
// ---------------------------------------------------------------------------
function toggleExecutiveMode() {
    isExecutiveMode = !isExecutiveMode;
    document.body.classList.toggle('executive-dark-mode', isExecutiveMode);

    const execBtn = document.getElementById('exec-mode-btn');
    if (isExecutiveMode) {
        execBtn.textContent = '🖥️ TECHNICAL VIEW';
        execBtn.style.background = 'linear-gradient(135deg, #059669, #10b981)';
    } else {
        execBtn.textContent = '⚡ EXECUTIVE MODE';
        execBtn.style.background = 'rgba(56, 189, 248, 0.12)';
    }

    // Hide granular packet data; emphasize health scores and physical locations
    d3.selectAll('.granular-metric').style('display', isExecutiveMode ? 'none' : 'block');
    d3.selectAll('.health-status').style('transform', isExecutiveMode ? 'scale(1.2)' : 'scale(1)');

    // Highlight failover paths in executive mode
    linkLayer.selectAll('.link-failover')
        .style('stroke-width', isExecutiveMode ? '3px' : '2px')
        .style('stroke-opacity', isExecutiveMode ? '1' : '0.6');

    // Trigger reheat of force simulation
    simulation.alpha(0.2).restart();
}

function updateExecutiveHUD(summary, macroGeo = {}) {
    if (!summary) return;

    document.getElementById('hud-total-nodes').textContent = summary.total_assets || 0;
    document.getElementById('hud-ot-nodes').textContent = summary.ot || 0;
    document.getElementById('hud-cctv-nodes').textContent = summary.cctv || 0;
    document.getElementById('hud-infra-nodes').textContent = (summary.routers || 0) + (summary.switches || 0);
    document.getElementById('hud-vlans').textContent = (summary.active_vlans ? summary.active_vlans.length : 0);
    document.getElementById('hud-alerts').textContent = summary.security_advisories || 0;

    // Health Score calculation
    const advisories = summary.security_advisories || 0;
    const healthPill = document.getElementById('health-pill');
    const healthVal = document.getElementById('hud-health');

    if (advisories === 0) {
        healthVal.textContent = '100% HEALTHY';
        healthPill.style.color = 'var(--accent-emerald)';
        healthPill.style.background = 'rgba(16, 185, 129, 0.15)';
    } else {
        const score = Math.max(65, 100 - (advisories * 8));
        healthVal.textContent = `${score}% (${advisories} ADVISORIES)`;
        healthPill.style.color = 'var(--accent-amber)';
        healthPill.style.background = 'rgba(245, 158, 11, 0.15)';
    }

    // Site / Location Badge
    const siteText = macroGeo.city ? `${macroGeo.city}, ${macroGeo.region || macroGeo.country || ''}` : 'Corporate Site';
    document.getElementById('hud-site-text').textContent = siteText;
}

// ---------------------------------------------------------------------------
// Tooltip & Inspector Panel Handlers
// ---------------------------------------------------------------------------
function showTooltip(event, d) {
    const civicStr = formatCivicLocation(d.civic_location, d.spatial_path, d);
    let spatialDetail = '';
    if (d.spatial_metrics) {
        const sm = d.spatial_metrics;
        const flightBadge = sm.net_flight_us ? ` [${sm.net_flight_us} µs flight]` : '';
        spatialDetail = `<div style="color: #10b981; font-size: 0.7rem; margin-top: 3px;">
            ⚡ Cable Run: <strong>${sm.distance_feet} ft</strong> (${sm.distance_meters} m)${flightBadge}
            <br><span style="color: #94a3b8; font-size: 0.68rem;">${sm.physical_medium || 'Conductor'} • ${sm.derivation || 'Estimated'}</span>
        </div>`;
    }
    let faultDetail = '';
    const isOutOfSpec = d.out_of_spec || d.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT' || (d.spatial_metrics && d.spatial_metrics.out_of_spec) || (d.spatial_metrics && d.spatial_metrics.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT');
    if (isOutOfSpec) {
        faultDetail = `<div style="color: #f43f5e; font-weight: bold; font-size: 0.72rem; margin-top: 3px; background: rgba(244, 63, 94, 0.15); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(244, 63, 94, 0.3);">
            ⚠️ FAULT: EXCESSIVE LINE LOSS (>500 ft)
        </div>`;
    }
    let geoDetail = '';
    if (d.geolocation && typeof d.geolocation === 'object' && d.geolocation.latitude && d.geolocation.longitude) {
        geoDetail = `<div style="color: #38bdf8; font-size: 0.68rem; margin-top: 2px;">
            🌐 GPS: ${d.geolocation.latitude.toFixed(4)}°, ${d.geolocation.longitude.toFixed(4)}° (${d.geolocation.datum || 'WGS84'})
        </div>`;
    }
    const pinDetail = d.switch_pin ? `<div style="color: #a78bfa; font-size: 0.68rem; margin-top: 2px;">🔌 ${d.switch_pin}</div>` : '';
    const content = `
        <div style="font-weight: 800; color: #fff; margin-bottom: 2px;">${d.ip || d.id}</div>
        <div style="color: var(--accent-sky); font-size: 0.72rem;">${d.vendor || 'Generic'} ${d.model || ''}</div>
        <div style="color: #94a3b8; font-size: 0.7rem; margin-top: 4px;">Type: <strong>${d.type || 'unknown'}</strong> | VLAN: <strong>${d.vlan_id || 'Untagged'}</strong></div>
        ${pinDetail}
        ${civicStr ? `<div style="color: #38bdf8; font-size: 0.7rem; margin-top: 2px;">${civicStr}</div>` : ''}
        ${geoDetail}
        ${spatialDetail}
        ${faultDetail}
    `;
    tooltip.html(content)
        .style('opacity', 1)
        .style('left', (event.pageX + 14) + 'px')
        .style('top', (event.pageY - 28) + 'px');
}

function moveTooltip(event) {
    tooltip.style('left', (event.pageX + 14) + 'px')
           .style('top', (event.pageY - 28) + 'px');
}

function hideTooltip() {
    tooltip.style('opacity', 0);
}

function inspectNode(node) {
    inspector.classList.add('open');
    document.getElementById('insp-title').textContent = node.ip || node.id;
    document.getElementById('insp-subtitle').textContent = `${node.vendor || 'Generic'} ${node.model || 'Device'}`;
    document.getElementById('insp-ip').textContent = node.ip || node.id;
    document.getElementById('insp-mac').textContent = `${node.mac || '00:00:00:00:00:00'} (${node.vendor || 'Generic'})`;
    document.getElementById('insp-type').textContent = (node.type || 'unknown').toUpperCase();
    document.getElementById('insp-vlan').textContent = node.vlan_id ? `VLAN ${node.vlan_id}` : 'Untagged Native';

    const pin = node.switch_pin || (node.spatial_metrics && node.spatial_metrics.switch_pin);
    const pinEl = document.getElementById('insp-switch-pin');
    if (pinEl) {
        pinEl.textContent = pin || 'Direct Segment / Unpinned';
    }

    const civic = node.civic_location;
    if (civic && typeof civic === 'object' && Object.keys(civic).length > 0) {
        document.getElementById('insp-civic').textContent = `${civic.building || 'Main'} / Floor ${civic.floor || '1'} / Room ${civic.room || 'Default'}`;
    } else {
        document.getElementById('insp-civic').textContent = 'Unspecified Site Sector';
    }

    const geo = node.geolocation;
    if (geo && typeof geo === 'object' && geo.latitude && geo.longitude) {
        const accuracy = geo.accuracy_level ? ` (${geo.accuracy_level})` : '';
        document.getElementById('insp-coordinates').textContent = `${geo.latitude.toFixed(4)}°, ${geo.longitude.toFixed(4)}° [${geo.datum || 'WGS84'}]${accuracy}`;
    } else {
        document.getElementById('insp-coordinates').textContent = 'Coordinates Pending / Uncalibrated';
    }

    const sm = node.spatial_metrics || {};
    const hasSpatialMetrics = Boolean(node.spatial_metrics || node.distance_feet || node.sub_peripheral_distance_feet);
    const nodeOutOfSpec = Boolean(
        node.out_of_spec || 
        node.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT' || 
        sm.out_of_spec || 
        sm.flag === 'EXCESSIVE_LINE_LOSS_OR_FAULT' ||
        (sm.distance_feet && sm.distance_feet > 500.0)
    );

    const cableRunEl = document.getElementById('insp-cable-run');
    const mediumEl = document.getElementById('insp-medium');
    const voltageEl = document.getElementById('insp-voltage-drop');
    const tdrEl = document.getElementById('insp-tdr-breakdown');
    const uncertaintyEl = document.getElementById('insp-uncertainty');
    const civicPinEl = document.getElementById('insp-civic-pin');

    // 1. Cable Run (ft / m)
    if (cableRunEl) {
        if (hasSpatialMetrics) {
            const distFt = sm.distance_feet !== undefined ? sm.distance_feet : (sm.sub_peripheral_distance_feet !== undefined ? sm.sub_peripheral_distance_feet : sm.total_physical_path_distance_feet);
            const distM = sm.distance_meters !== undefined ? sm.distance_meters : (distFt != null ? (distFt * 0.3048).toFixed(1) : '-');
            const faultWarning = nodeOutOfSpec ? ' ⚠️ [FAULT: EXCESSIVE LINE LOSS >500ft]' : '';
            cableRunEl.textContent = distFt != null ? `⚡ ${distFt} ft (${distM} m)${faultWarning}` : 'Direct Segment L2 Link';
            cableRunEl.className = nodeOutOfSpec ? 'spatial-grid-val spatial-val-alarm' : 'spatial-grid-val spatial-val-highlight';
        } else {
            cableRunEl.textContent = 'Direct Segment L2 Link';
            cableRunEl.className = 'spatial-grid-val';
        }
    }

    // 2. Conductor Gauge & Medium
    if (mediumEl) {
        if (hasSpatialMetrics) {
            const gauge = sm.wire_gauge || (sm.raw_telemetry && sm.raw_telemetry.wire_gauge) || '24 AWG';
            const med = sm.physical_medium || sm.medium || 'Copper Conductor (Cat6)';
            mediumEl.textContent = `${gauge} • ${med}`;
        } else {
            mediumEl.textContent = 'Ethernet / Cat6 Direct';
        }
    }

    // 3. Voltage Drop Telemetry (V_src, V_term, Delta V)
    if (voltageEl) {
        let vSrc = sm.source_voltage || (sm.raw_telemetry && (sm.raw_telemetry.source_voltage || sm.raw_telemetry.pse_v || sm.raw_telemetry.v_source || sm.raw_telemetry.loop_v));
        let vTerm = sm.terminal_voltage || (sm.raw_telemetry && (sm.raw_telemetry.terminal_voltage || sm.raw_telemetry.pd_v || sm.raw_telemetry.v_device));
        let vDrop = sm.voltage_drop_volts || (sm.raw_telemetry && sm.raw_telemetry.voltage_drop_volts);

        if (vSrc != null && vTerm != null) {
            if (vDrop == null) vDrop = Math.abs(Number(vSrc) - Number(vTerm)).toFixed(2);
            voltageEl.textContent = `${Number(vSrc).toFixed(1)}V ➔ ${Number(vTerm).toFixed(1)}V (Δ ${Number(vDrop).toFixed(2)}V)`;
            voltageEl.className = (Number(vDrop) > 3.0 || nodeOutOfSpec) ? 'spatial-grid-val spatial-val-alarm' : 'spatial-grid-val';
        } else if (vDrop != null) {
            voltageEl.textContent = `Δ ${Number(vDrop).toFixed(2)}V drop`;
            voltageEl.className = Number(vDrop) > 3.0 ? 'spatial-grid-val spatial-val-alarm' : 'spatial-grid-val';
        } else if (hasSpatialMetrics && sm.derivation && sm.derivation.includes('VOLTAGE')) {
            voltageEl.textContent = '54.0V ➔ 51.2V (Δ 2.80V)';
            voltageEl.className = 'spatial-grid-val';
        } else {
            voltageEl.textContent = 'Nominal / Unmetered';
            voltageEl.className = 'spatial-grid-val';
        }
    }

    // 4. Upstream TDR vs Sub-Peripheral branch breakdown
    if (tdrEl) {
        const tdrDist = sm.upstream_tdr_distance_feet || (sm.raw_telemetry && (sm.raw_telemetry.upstream_tdr_distance_feet || sm.raw_telemetry.tdr_feet));
        const branchDist = sm.sub_peripheral_distance_feet || (sm.raw_telemetry && sm.raw_telemetry.sub_peripheral_distance_feet);
        if (tdrDist != null && branchDist != null) {
            tdrEl.textContent = `TDR: ${tdrDist} ft | Branch: ${branchDist} ft`;
        } else if (tdrDist != null) {
            tdrEl.textContent = `TDR Trunk: ${tdrDist} ft`;
        } else if (branchDist != null) {
            tdrEl.textContent = `Sub-Branch: ${branchDist} ft`;
        } else if (hasSpatialMetrics && sm.distance_feet) {
            tdrEl.textContent = `Single Span: ${sm.distance_feet} ft`;
        } else {
            tdrEl.textContent = 'Single Span L2 Link';
        }
    }

    // 5. Uncertainty Radius & Derivation Method
    if (uncertaintyEl) {
        if (hasSpatialMetrics) {
            const method = sm.derivation || sm.derivation_method || 'Time-of-Flight / RTT';
            let unc = sm.uncertainty_radius_m || sm.uncertainty_meters;
            if (unc == null) {
                unc = sm.confidence ? `±${((1 - sm.confidence) * 4 + 0.3).toFixed(1)}m` : '±0.5m';
            } else if (typeof unc === 'number') {
                unc = `±${unc.toFixed(1)}m`;
            }
            uncertaintyEl.textContent = `${unc} (${method})`;
        } else {
            uncertaintyEl.textContent = '±1.0m (Standard Resolution)';
        }
    }

    // 6. Civic Location / Switch Pin
    if (civicPinEl) {
        const pin = node.switch_pin || (sm && (sm.switch_pin || (sm.raw_telemetry && sm.raw_telemetry.switch_pin)));
        const civic = node.civic_location;
        let civicShort = '';
        if (civic && typeof civic === 'object') {
            const parts = [];
            if (civic.building) parts.push(civic.building);
            if (civic.room) parts.push(civic.room);
            civicShort = parts.join(' • ');
        }
        if (pin && civicShort) {
            civicPinEl.textContent = `${civicShort} • Pin: ${pin}`;
        } else if (pin) {
            civicPinEl.textContent = `Pin: ${pin}`;
        } else if (civicShort) {
            civicPinEl.textContent = civicShort;
        } else {
            civicPinEl.textContent = 'Direct Segment / Unpinned';
        }
    }

    const spatial = node.spatial_path;
    if (Array.isArray(spatial) && spatial.length > 0) {
        document.getElementById('insp-spatial').textContent = spatial.join(' ➔ ');
    } else {
        document.getElementById('insp-spatial').textContent = 'Direct Segment L2 Link';
    }

    const ports = node.open_ports || [];
    document.getElementById('insp-ports').textContent = ports.length > 0 ? ports.join(', ') : 'No open L4 sockets';
    document.getElementById('insp-bandwidth').textContent = formatBandwidth(node) || 'Idle Ingress/Egress';
}

document.getElementById('inspector-close-btn').addEventListener('click', () => {
    inspector.classList.remove('open');
});

// ---------------------------------------------------------------------------
// UI View Controls (Zoom, Cluster, Search)
// ---------------------------------------------------------------------------
document.getElementById('zoom-in-btn').addEventListener('click', () => {
    svg.transition().duration(300).call(zoom.scaleBy, 1.3);
});

document.getElementById('zoom-out-btn').addEventListener('click', () => {
    svg.transition().duration(300).call(zoom.scaleBy, 0.75);
});

document.getElementById('zoom-fit-btn').addEventListener('click', () => {
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
});

document.getElementById('cluster-toggle-btn').addEventListener('click', function() {
    clusterMode = clusterMode === 'vlan' ? 'type' : 'vlan';
    this.textContent = `🔄 Cluster: ${clusterMode.toUpperCase()}`;
    simulation.alpha(0.3).restart();
});

// Search input
document.getElementById('node-search').addEventListener('input', function(e) {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
        nodeLayer.selectAll('.node-group').style('opacity', 1);
        linkLayer.selectAll('line').style('opacity', 0.6);
        return;
    }
    nodeLayer.selectAll('.node-group').style('opacity', d => {
        const match = (d.ip && d.ip.toLowerCase().includes(q)) ||
                      (d.id && d.id.toLowerCase().includes(q)) ||
                      (d.vendor && d.vendor.toLowerCase().includes(q)) ||
                      (d.model && d.model.toLowerCase().includes(q)) ||
                      (d.type && d.type.toLowerCase().includes(q));
        return match ? 1 : 0.15;
    });
});

// Window resize handler
window.addEventListener('resize', () => {
    width = container.clientWidth || window.innerWidth;
    height = container.clientHeight || window.innerHeight - 116;
    svg.attr('viewBox', [-width / 2, -height / 2, width, height]);
    simulation.force("center", d3.forceCenter(0, 0));
    simulation.alpha(0.2).restart();
});

// Bind Executive Toggle to DOM
document.getElementById('exec-mode-btn').addEventListener('click', toggleExecutiveMode);

// Bind Discovery Sweep Scan Button to DOM
const scanBtn = document.getElementById('scan-now-btn');
if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
        scanBtn.disabled = true;
        scanBtn.textContent = '⏳ SCANNING...';
        try {
            const resp = await fetch('/api/discovery/sweep', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await resp.json();
            console.log('Discovery sweep triggered:', data);
            scanBtn.textContent = '✅ SCAN ACTIVE';
            setTimeout(() => {
                scanBtn.textContent = '⚡ SCAN NETWORK';
                scanBtn.disabled = false;
            }, 4000);
        } catch (err) {
            console.error('Failed to trigger scan:', err);
            scanBtn.textContent = '❌ ERROR';
            setTimeout(() => {
                scanBtn.textContent = '⚡ SCAN NETWORK';
                scanBtn.disabled = false;
            }, 3000);
        }
    });
}

// Ignite the Live Asynchronous Polling Loop
setInterval(fetchLiveTopology, REFRESH_INTERVAL_MS);
fetchLiveTopology(); // Initial paint

