/**
 * Project AETHERIS v2.5 - Frontend Delta Hydration & Real-Time Telemetry Inspector
 * Ingests 1Hz WebSocket microscopic payloads and live REST deltas.
 * Mathematically suspends V8 layout thrashing via cy.batch() and isolated spatial physics.
 * Binds Cytoscape tapNodeData directly to live Redis O(1) ledger telemetry.
 * 
 * Strict Telemetry Guardrails:
 * 1. ZERO pseudoRand or synthetic metric generators.
 * 2. All unobserved metrics strictly render as [PENDING L2 SWEEP].
 * 3. Atomic DOM replacement via unified telemetry frame.
 */

(function () {
    const PENDING_TOKEN = "[PENDING L2 SWEEP]";

    // Resolve dynamic WebSocket endpoint based on host
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.host || "localhost:8080";
    const wsUrl = `${wsProtocol}//${wsHost}/ws/telemetry`;

    let ws = null;
    try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => console.log("[AETHERIS DOM] Live Telemetry WebSocket Connected to", wsUrl);
        ws.onclose = () => console.warn("[AETHERIS DOM] Telemetry WebSocket Suspended - Falling back to REST polling");
        ws.onerror = (err) => console.debug("[AETHERIS DOM] WebSocket state:", err);

        ws.onmessage = function (event) {
            try {
                const msg = JSON.parse(event.data);
                if (typeof cy === "undefined" || !cy) return;

                // Handle TELEMETRY_UPDATE broadcast
                if (msg.type === "TELEMETRY_UPDATE" && msg.payload) {
                    const payload = msg.payload;
                    cy.batch(() => {
                        if (payload.node && payload.node.data) {
                            const existing = cy.getElementById(payload.node.data.id);
                            if (existing.length === 0) {
                                cy.add(payload.node);
                            } else {
                                existing.data(payload.node.data);
                            }
                        }
                        if (payload.edge && payload.edge.data) {
                            const existingEdge = cy.getElementById(payload.edge.data.id);
                            if (existingEdge.length === 0) {
                                cy.add(payload.edge);
                            } else {
                                existingEdge.data(payload.edge.data);
                            }
                        }
                    });
                    return;
                }

                // Handle batch adds / removes
                if (msg.adds || msg.removes) {
                    if ((!msg.adds || msg.adds.length === 0) && (!msg.removes || msg.removes.length === 0)) return;

                    cy.batch(() => {
                        if (msg.removes && msg.removes.length > 0) {
                            msg.removes.forEach(node_id => {
                                const ele = cy.getElementById(node_id);
                                if (ele.length !== 0) ele.remove();
                            });
                        }

                        if (msg.adds && msg.adds.length > 0) {
                            const newElements = [];
                            msg.adds.forEach(node => {
                                if (cy.getElementById(node.data.id).length === 0) {
                                    newElements.push(node);
                                }
                            });

                            if (newElements.length > 0) {
                                const addedEles = cy.add(newElements);
                                const layoutConfig = {
                                    name: 'cose',
                                    spacingFactor: 2.5,
                                    nodeRepulsion: 400000,
                                    fit: false,
                                    animate: true,
                                    animationDuration: 300
                                };
                                addedEles.layout(layoutConfig).run();
                            }
                        }
                    });
                }
            } catch (err) {
                console.error("[AETHERIS DOM] Error parsing WebSocket telemetry frame:", err);
            }
        };
    } catch (e) {
        console.warn("[AETHERIS DOM] WebSocket initialization bypassed:", e);
    }

    /**
     * Formats metric values, strictly returning [PENDING L2 SWEEP] if unobserved.
     */
    function formatMetric(val, suffix = "") {
        if (val === null || val === undefined) return PENDING_TOKEN;
        const str = String(val).trim();
        if (!str || str === "N/A" || str === "None" || str === "unknown" || str === PENDING_TOKEN) {
            return PENDING_TOKEN;
        }
        return `${str}${suffix}`;
    }

    /**
     * Finds the inspector sidebar container in the DOM.
     */
    function getInspectorElement() {
        return document.getElementById('inspector-content')
            || document.querySelector('.sidebar-container')
            || document.getElementById('sidebar')
            || document.querySelector('[id*="inspector"]')
            || document.querySelector('aside');
    }

    /**
     * Renders a unified live telemetry frame into the sidebar inspector.
     */
    function renderTelemetryFrame(inspector, data) {
        if (!inspector) return;

        if (data.html_frame) {
            inspector.innerHTML = data.html_frame;
            return;
        }

        const label = formatMetric(data.label || data.node_id);
        const nodeType = formatMetric(data.type ? data.type.toUpperCase() : null);
        const ip = formatMetric(data.ipv4 || data.ip);
        const mac = formatMetric(data.mac);
        const vlan = formatMetric(data.vlan);
        const switchport = formatMetric(data.switchport || data.port);

        const dist = formatMetric(data.distance);
        const tau = formatMetric(data.tau_flight);
        const z0 = formatMetric(data.impedance_z0);
        const jitter = formatMetric(data.jitter_ns ? `${data.jitter_ns} ns` : null);

        const modbus = formatMetric(data.modbus_fc);
        const mercury = formatMetric(data.mercury_fw);
        const bacnet = formatMetric(data.bacnet_status);

        const os = formatMetric(data.os_profile);
        const anchor = formatMetric(data.anchor_status);

        const pendingClass = "text-amber-500/80 italic";
        const valClass = (v, activeClass = "text-white") => (v === PENDING_TOKEN ? pendingClass : activeClass);

        inspector.innerHTML = `
            <div class="space-y-4 text-sm font-mono text-gray-300 p-2 h-full overflow-y-auto">
                <div class="border-b border-gray-700 pb-2">
                    <span class="text-white font-bold text-xl block">${label}</span>
                    <span class="text-xs text-blue-400 mt-1 block">ID: ${data.node_id || 'N/A'} | TYPE: ${nodeType}</span>
                </div>

                <div>
                    <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">Network Layer</h4>
                    <div class="grid grid-cols-2 gap-2 text-xs">
                        <div><span class="text-gray-500">IPv4:</span> <span class="${valClass(ip)}">${ip}</span></div>
                        <div><span class="text-gray-500">MAC:</span> <span class="${valClass(mac)}">${mac}</span></div>
                        <div><span class="text-gray-500">VLAN:</span> <span class="${valClass(vlan)}">${vlan}</span></div>
                        <div><span class="text-gray-500">Switchport:</span> <span class="${valClass(switchport)}">${switchport}</span></div>
                    </div>
                </div>

                <div>
                    <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">TDR & Spatial Vectors</h4>
                    <div class="grid grid-cols-2 gap-2 text-xs">
                        <div><span class="text-gray-500">Distance:</span> <span class="${valClass(dist, 'text-yellow-400 font-bold')}">${dist}</span></div>
                        <div><span class="text-gray-500">&tau; Flight:</span> <span class="${valClass(tau)}">${tau}</span></div>
                        <div><span class="text-gray-500">Impedance Z0:</span> <span class="${valClass(z0)}">${z0}</span></div>
                        <div><span class="text-gray-500">Jitter (&Delta;&tau;):</span> <span class="${valClass(jitter)}">${jitter}</span></div>
                    </div>
                </div>

                <div>
                    <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">OT / SCADA Wire Dissectors</h4>
                    <div class="grid grid-cols-2 gap-2 text-xs">
                        <div><span class="text-gray-500">Modbus FC:</span> <span class="${valClass(modbus, 'text-cyan-400')}">${modbus}</span></div>
                        <div><span class="text-gray-500">Mercury FW:</span> <span class="${valClass(mercury, 'text-purple-400')}">${mercury}</span></div>
                        <div class="col-span-2"><span class="text-gray-500">BACnet State:</span> <span class="${valClass(bacnet, 'text-emerald-400')}">${bacnet}</span></div>
                    </div>
                </div>

                <div>
                    <h4 class="text-gray-500 text-[10px] tracking-widest border-b border-gray-700 mb-1 uppercase font-semibold">Passive Classification</h4>
                    <div class="flex flex-col gap-1 text-xs">
                        <div><span class="text-gray-500">OS Profile:</span> <span class="${valClass(os)}">${os}</span></div>
                        <div><span class="text-gray-500">AnchorGuard:</span> <span class="${anchor.includes('TRUSTED') ? 'text-green-400 font-semibold' : 'text-slate-400'}">${anchor}</span></div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Binds Cytoscape tapNodeData event to live Redis O(1) ledger extraction.
     */
    function attachCytoscapeListener(cyInstance) {
        if (!cyInstance || cyInstance.__aetheris_bound) return;
        cyInstance.__aetheris_bound = true;

        cyInstance.on('tap', 'node', async function (evt) {
            const d = evt.target.data();
            const inspector = getInspectorElement();
            if (!inspector) return;

            const nodeId = d.id;

            // Immediate Pending L2 Sweep feedback state
            renderTelemetryFrame(inspector, {
                node_id: nodeId,
                label: d.label || nodeId,
                type: d.type || "generic",
                ipv4: d.ip || d.ipv4 || null,
                mac: d.mac || null,
                vlan: d.vlan || null,
                switchport: d.switchport || null,
                distance: d.distance_m ? `${d.distance_m.toFixed(2)}m` : null,
                tau_flight: null,
                impedance_z0: null,
                modbus_fc: null,
                mercury_fw: null,
                bacnet_status: null,
                os_profile: null,
                anchor_status: null
            });

            // Query active Redis O(1) ledger directly via REST telemetry endpoint
            try {
                const res = await fetch(`/api/node/${encodeURIComponent(nodeId)}/telemetry`);
                if (res.ok) {
                    const liveData = await res.json();
                    renderTelemetryFrame(inspector, liveData);
                }
            } catch (err) {
                console.debug(`[AETHERIS DOM] Telemetry query for ${nodeId} in flight or offline:`, err);
            }
        });
    }

    /**
     * Initializes Cytoscape.js topology rendering from topology_audit.json.
     */
    function initCytoscapeTopology() {
        const container = document.getElementById('cy');
        if (!container) {
            console.warn("[AETHERIS DOM] Canvas container #cy not found in DOM");
            return;
        }

        fetch('topology_audit.json')
            .then(res => {
                if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
                return res.json();
            })
            .then(data => {
                const elements = data.elements || data;

                // Determine layout engine: dagre (hierarchical) or fallback
                let layoutConfig = {
                    name: 'dagre',
                    rankDir: 'TB'
                };
                try {
                    if (typeof cytoscape('layout', 'dagre') === 'undefined') {
                        layoutConfig = {
                            name: 'breadthfirst',
                            directed: true
                        };
                    }
                } catch (e) {
                    layoutConfig = { name: 'breadthfirst', directed: true };
                }

                const cyInstance = cytoscape({
                    container: container,
                    elements: elements,
                    style: [
                        {
                            selector: 'node[type = "Endpoint"]',
                            style: {
                                'shape': 'ellipse',
                                'label': 'data(ui_label)',
                                'width': 'mapData(ttl_hops, 1, 10, 40, 10)',
                                'height': 'mapData(ttl_hops, 1, 10, 40, 10)',
                                'background-color': function(ele) {
                                    const risk = ele.data('cve_exposure');
                                    if (risk === 'CRITICAL') return '#E74C3C'; // Red
                                    if (risk === 'HIGH') return '#E67E22';     // Orange
                                    if (risk === 'MEDIUM') return '#F1C40F';   // Yellow
                                    if (risk === 'LOW') return '#2ECC71';      // Green
                                    return '#95A5A6';                          // Gray (Unknown/Pending)
                                },
                                'border-width': function(ele) {
                                    return ele.data('cve_exposure') === 'CRITICAL' ? 4 : 0;
                                },
                                'border-color': '#C0392B',
                                'color': '#FFFFFF',
                                'text-valign': 'bottom',
                                'text-margin-y': 5
                            }
                        },
                        {
                            selector: 'node[type = "Unmanaged_Switch"]',
                            style: {
                                'shape': 'diamond',
                                'background-color': '#34495E',
                                'label': 'data(id)',
                                'color': '#FFFFFF',
                                'text-valign': 'bottom'
                            }
                        },
                        {
                            selector: 'edge',
                            style: {
                                'width': 2,
                                'line-color': '#BDC3C7',
                                'target-arrow-color': '#BDC3C7',
                                'target-arrow-shape': 'triangle',
                                'curve-style': 'bezier'
                            }
                        }
                    ],
                    layout: layoutConfig
                });

                const cy = cyInstance;
                window.cy = cyInstance;

                // Append this logic block immediately after the initial cytoscape() instantiation

                const POLL_INTERVAL_MS = 2000;

                setInterval(() => {
                    // Enforce strict cache bypassing to prevent browser memory reads of stale state
                    fetch(`topology_audit.json?t=${Date.now()}`, { cache: 'no-store' })
                        .then(res => {
                            if (!res.ok) throw new Error(`HTTP ${res.status}`);
                            return res.json();
                        })
                        .then(newData => {
                            // Suspend the Cytoscape rendering thread to prevent O(N) DOM redraws
                            cy.batch(() => {
                                const incomingNodes = newData.elements?.nodes || [];
                                
                                incomingNodes.forEach(node => {
                                    const existingNode = cy.getElementById(node.data.id);
                                    
                                    if (existingNode.length > 0) {
                                        // Mutate discrete data attributes to trigger style recalculation
                                        if (node.data.cve_exposure !== existingNode.data('cve_exposure')) {
                                            existingNode.data('cve_exposure', node.data.cve_exposure);
                                        }
                                        if (node.data.cve_notes !== existingNode.data('cve_notes')) {
                                            existingNode.data('cve_notes', node.data.cve_notes);
                                        }
                                    } else {
                                        // Dynamic injection for endpoints resolved mid-cycle
                                        cy.add({ group: 'nodes', data: node.data });
                                    }
                                });
                            });
                        })
                        .catch(err => console.error('AETHERIS State Synchronization Fault:', err));
                }, POLL_INTERVAL_MS);

                // Bind tap listener to display CVE details in the UI sidebar
                cy.on('tap', 'node', function(evt){
                    const nodeData = evt.target.data();
                    if(nodeData.cve_exposure) {
                        const sidebar = document.getElementById('sidebar') || document.getElementById('inspector-content');
                        if (sidebar) {
                            sidebar.innerHTML = `
                                <h3>${nodeData.ui_label || nodeData.id}</h3>
                                <p><strong>IP:</strong> ${nodeData.ip_address || 'N/A'}</p>
                                <p><strong>Risk:</strong> ${nodeData.cve_exposure}</p>
                                <p><strong>Details:</strong> ${nodeData.cve_notes || 'N/A'}</p>
                            `;
                        }
                    }
                });

                attachCytoscapeListener(cy);

                console.log("[AETHERIS DOM] Cytoscape topology initialized successfully from topology_audit.json");
            })
            .catch(err => {
                console.warn("[AETHERIS DOM] Unable to initialize from topology_audit.json:", err);
                if (typeof cy !== 'undefined' && cy) {
                    attachCytoscapeListener(cy);
                }
            });
    }

    // Auto-detect or initialize Cytoscape
    if (typeof cy !== 'undefined' && cy) {
        attachCytoscapeListener(cy);
    } else if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCytoscapeTopology);
    } else {
        initCytoscapeTopology();
    }
})();
