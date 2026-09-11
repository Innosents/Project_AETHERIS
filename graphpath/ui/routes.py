import threading
from flask import Blueprint, jsonify, request

from config import ConfigurationManager
from core.discovery_engine import DiscoveryEngine
from core.state_machine import DiscoveryStateMachine
from discovery.dns_discovery import DnsDiscoveryEngine
from discovery.vlan_scan import IndustrialVlanOrchestrator
from discovery.edge_broadcast_discovery import EdgeBroadcastEngine

from topology.graph_store import GraphStore
from ui.auth_middleware import require_auth

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Centralized graph engine instance exposed for orchestration layer integration
graph = GraphStore()

@api_bp.route("/topology", methods=["GET"])
@require_auth
def api_topology():
    """
    Exposes a read-only snapshot payload of the active topology mapping canvas.
    Secured via persistent session token verification cookies.
    """
    return jsonify(graph.export_topology_snapshot())

@api_bp.route("/dip", methods=["GET"])
@require_auth
def api_get_dip():
    """Returns all dynamically cached Device Identity Profiles."""
    from core.dip_manager import DeviceIdentityProfileManager
    dip_mgr = DeviceIdentityProfileManager()
    return jsonify({
        "status": "success",
        "total_profiles": len(dip_mgr.profiles),
        "profiles": dip_mgr.get_all_profiles()
    })

@api_bp.route("/dip/lock", methods=["POST"])
@require_auth
def api_lock_dip():
    """Pins a custom user-defined identity for a device profile."""
    from core.dip_manager import DeviceIdentityProfileManager
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
    
    # Reconcile topology immediately
    try:
        graph.reconcile_topology()
    except Exception:
        pass

    return jsonify({"status": "success" if success else "failed", "locked": success})



@api_bp.route("/discovery/expand", methods=["POST"])
@require_auth
def api_discovery_expand():
    """
    Ingests network parameters discovered post-login from device web/SSH interfaces
    (e.g., DNS server, PBX server, Voice VLAN, new subnets) and initiates further discovery.
    """
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip", "")
    discovered_dns = data.get("dns_server", "").strip()
    discovered_pbx = data.get("pbx_server", "").strip()
    discovered_subnets = data.get("subnets", [])
    if isinstance(discovered_subnets, str):
        discovered_subnets = [s.strip() for s in discovered_subnets.split(",") if s.strip()]
    
    actions_taken = []
    subnets_to_sweep = list(discovered_subnets)

    # 1. If DNS Server provided: register node, derive containing subnet, and query PTR + SRV records
    if discovered_dns:
        try:
            import ipaddress
            dns_obj = ipaddress.ip_address(discovered_dns)
            dns_ip_str = str(dns_obj)

            # Auto-register DNS Server Node
            if not graph._G.has_node(dns_ip_str):
                graph.add_node(dns_ip_str, {
                    "type": "server",
                    "ip": dns_ip_str,
                    "vendor": "Domain Infrastructure Core",
                    "model": "Primary DNS & Domain Controller",
                    "open_ports": [53]
                })

            # If private IP, auto-derive /24 subnet and queue for sweep
            if dns_obj.is_private:
                derived_net = ipaddress.ip_network(f"{dns_ip_str}/24", strict=False)
                derived_cidr = str(derived_net)
                if derived_cidr not in subnets_to_sweep:
                    subnets_to_sweep.append(derived_cidr)
                    actions_taken.append(f"Auto-expanded subnet boundary to {derived_cidr} from DNS server {dns_ip_str}")

            # Execute targeted PTR sweep against this DNS server
            dns_eng = DnsDiscoveryEngine(dns_server=dns_ip_str, timeout=0.8)
            cfg = ConfigurationManager()
            resolved_domains = set()
            for cidr in list(set(cfg.target_subnets + subnets_to_sweep)):
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    hosts = [str(h) for h in net.hosts()]
                    ptr_map = dns_eng.sweep_ptr_records(hosts)
                    for h_ip, h_name in ptr_map.items():
                        if graph._G.has_node(h_ip):
                            graph._G.nodes[h_ip]["hostname"] = h_name
                            banners = graph._G.nodes[h_ip].setdefault("banners", {})
                            banners["dns_hostname"] = h_name
                        if "." in h_name:
                            domain_part = ".".join(h_name.split(".")[1:])
                            if domain_part:
                                resolved_domains.add(domain_part)
                except Exception:
                    pass

            # Query SRV records for telephony and infrastructure
            for dom in resolved_domains:
                try:
                    srv_records = dns_eng.discover_srv_records(dom)
                    for srv in srv_records:
                        srv_ip = srv.get("target_ip") or srv.get("target_host")
                        if srv_ip:
                            dev_type = "voip_pbx" if "sip" in srv.get("service_name", "").lower() else "server"
                            if not graph._G.has_node(srv_ip):
                                graph.add_node(srv_ip, {
                                    "type": dev_type,
                                    "ip": srv_ip,
                                    "vendor": srv.get("service_label", "Discovered Service"),
                                    "model": f"SRV Target ({srv.get('service_name')})",
                                    "open_ports": [srv.get("port", 5060)]
                                })
                            actions_taken.append(f"Discovered {srv.get('service_label')} at {srv_ip}:{srv.get('port')}")
                except Exception:
                    pass

            actions_taken.append(f"Reverse DNS PTR sweep executed via DNS server {dns_ip_str}")
        except Exception as e:
            actions_taken.append(f"DNS resolution warning: {e}")

    # 2. If PBX Server provided: register or promote PBX and link telephony uplink
    if discovered_pbx:
        try:
            import ipaddress
            pbx_obj = ipaddress.ip_address(discovered_pbx)
            pbx_ip_str = str(pbx_obj)

            if not graph._G.has_node(pbx_ip_str):
                graph.add_node(pbx_ip_str, {
                    "type": "voip_pbx",
                    "ip": pbx_ip_str,
                    "vendor": "VoIP PBX Telephony Core",
                    "model": "Discovered PBX Controller",
                    "open_ports": [5060, 80, 443]
                })
            else:
                graph._G.nodes[pbx_ip_str]["type"] = "voip_pbx"
            
            if source_ip and graph._G.has_node(source_ip):
                graph.add_edge(pbx_ip_str, source_ip, {
                    "layer": 2,
                    "type": "ethernet",
                    "label": "📞 VoIP PBX Telephony Uplink",
                    "method": "post_login_discovery"
                })

            if pbx_obj.is_private:
                derived_net = ipaddress.ip_network(f"{pbx_ip_str}/24", strict=False)
                derived_cidr = str(derived_net)
                if derived_cidr not in subnets_to_sweep:
                    subnets_to_sweep.append(derived_cidr)
                    actions_taken.append(f"Auto-expanded subnet boundary to {derived_cidr} from PBX {pbx_ip_str}")

            actions_taken.append(f"Registered PBX telephony server {pbx_ip_str}")
        except Exception as e:
            actions_taken.append(f"PBX registration error: {e}")

    # 3. If new Subnets provided / derived: add to target subnets and trigger background sweep
    if not subnets_to_sweep and not discovered_dns and not discovered_pbx:
        cfg = ConfigurationManager()
        subnets_to_sweep = list(cfg.target_subnets)

    if subnets_to_sweep:
        cfg = ConfigurationManager()
        for sub in subnets_to_sweep:
            if sub not in cfg.target_subnets:
                cfg.target_subnets.append(sub)

        def _async_sweep_expansion(subnets):
            eng = DiscoveryEngine(graph=graph)
            sm = DiscoveryStateMachine(eng)
            for s in subnets:
                try:
                    sm.execute(s)
                except Exception as e:
                    print(f"[Discovery Expansion Error] Sweep failed on {s}: {e}")
            try:
                graph.reconcile_topology()
            except Exception:
                pass

        threading.Thread(target=_async_sweep_expansion, args=(subnets_to_sweep,), daemon=True).start()
        actions_taken.append(f"Background discovery sweep initiated across: {subnets_to_sweep}")

    try:
        graph.reconcile_topology()
    except Exception:
        pass

    return jsonify({
        "status": "success",
        "message": "Discovery expansion initiated successfully.",
        "actions": actions_taken,
        "source_ip": source_ip,
        "subnets": subnets_to_sweep
    })

@api_bp.route("/discovery/sweep", methods=["POST"])
@require_auth
def api_discovery_sweep():
    """Triggers background discovery sweep across specified or all configured subnets."""
    data = request.get_json(silent=True, force=True) or {}
    subnets = data.get("subnets", None)

    cfg = ConfigurationManager()
    if not subnets:
        subnets = list(cfg.target_subnets) if cfg.target_subnets else ["10.10.7.0/24", "10.10.4.0/24"]

    def _sweep():
        eng = DiscoveryEngine(graph=graph)
        sm = DiscoveryStateMachine(eng)
        for s in subnets:
            try:
                sm.execute(s)
            except Exception as e:
                print(f"[Sweep Error] {s}: {e}")
        try:
            graph.reconcile_topology()
        except Exception:
            pass

    threading.Thread(target=_sweep, daemon=True).start()
    return jsonify({
        "status": "success",
        "message": f"Discovery sweep initiated for subnets: {subnets}",
        "subnets": subnets
    })

@api_bp.route("/discovery/vlan_sweep", methods=["POST"])
@require_auth
def api_discovery_vlan_sweep():
    """Triggers concurrent 802.1Q multi-VLAN sweep across specified or auto-discovered VLANs."""
    data = request.get_json(silent=True, force=True) or {}
    target_vlans = data.get("vlans", None)

    if not target_vlans:
        cfg = ConfigurationManager()
        target_vlans = cfg.vlans_to_scan or {
            10: "172.28.10.0/24",
            20: "172.28.20.0/24",
            30: "172.28.30.0/24",
            40: "172.28.40.0/24"
        }

    def _async_vlan_sweep(vlans):
        orchestrator = IndustrialVlanOrchestrator(graph, timeout=1.2)
        orchestrator.sweep_all_vlans_concurrent(vlans, max_workers=8)
        try:
            graph.reconcile_topology()
        except Exception:
            pass

    threading.Thread(target=_async_vlan_sweep, args=(target_vlans,), daemon=True).start()

    return jsonify({
        "status": "success",
        "message": f"Multi-VLAN concurrent discovery sweep initiated across {len(target_vlans)} boundaries.",
        "vlans": target_vlans
    })

@api_bp.route("/discovery/broadcast_edge", methods=["POST"])
@require_auth
def api_discovery_broadcast_edge():
    """
    Fires targeted protocol broadcasts (SIP PnP, WS-Discovery/ONVIF, SSDP, BACnet, UBNT)
    based on the selected device type/vendor to discover additional edge nodes.
    """
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip", "")
    dev_type = data.get("type", "generic")
    dev_vendor = data.get("vendor", "generic")
    
    cfg = ConfigurationManager()
    target_subnet = cfg.target_subnets[0] if cfg.target_subnets else "10.10.4.0/24"
    
    bcast_engine = EdgeBroadcastEngine(timeout=1.2)
    discovered_nodes = bcast_engine.broadcast_targeted_cluster_probe(
        device_type=dev_type, 
        vendor=dev_vendor, 
        target_subnet=target_subnet
    )
    
    newly_added = []
    for node in discovered_nodes:
        node_ip = node.get("ip")
        if node_ip and node_ip != "0.0.0.0":
            if not graph._G.has_node(node_ip):
                graph.add_node(node_ip, {
                    "type": node.get("type", "unknown"),
                    "ip": node_ip,
                    "vendor": node.get("vendor", "Edge Discovered"),
                    "model": node.get("model", "Network Endpoint"),
                    "open_ports": node.get("open_ports", []),
                    "discovery_method": "protocol_cluster_broadcast"
                })
                newly_added.append(node_ip)
            else:
                if node.get("vendor") and graph._G.nodes[node_ip].get("vendor") in ("generic", "unknown", ""):
                    graph._G.nodes[node_ip]["vendor"] = node["vendor"]
                if node.get("model") and graph._G.nodes[node_ip].get("model") in ("Discovered Asset", "Standard Device", ""):
                    graph._G.nodes[node_ip]["model"] = node["model"]

    try:
        graph.reconcile_topology()
    except Exception:
        pass

    return jsonify({
        "status": "success",
        "message": f"Broadcast discovery probe executed across {target_subnet}.",
        "source_ip": source_ip,
        "discovered_count": len(discovered_nodes),
        "newly_registered": newly_added,
        "nodes": discovered_nodes
    })

# =========================================================================
# Port Mirroring (SPAN/ERSPAN) & Traffic Matrix API Endpoints
# =========================================================================
from core.traffic_matrix import TrafficMatrixTracker, TrafficRoleClassifier
traffic_matrix_instance = TrafficMatrixTracker()

# Global SpanCaptureEngine instance for live Port Mirror capture
from discovery.mirror_engine import SpanCaptureEngine
global_span_engine = SpanCaptureEngine()

@api_bp.route("/traffic/matrix", methods=["GET"])
@require_auth
def api_traffic_matrix():
    """Returns active traffic conversation edges and top communicating talkers."""
    limit = int(request.args.get("limit", 15))
    return jsonify({
        "status": "success",
        "summary": traffic_matrix_instance.get_summary(),
        "top_talkers": traffic_matrix_instance.get_top_talkers(limit=limit),
        "conversation_edges": traffic_matrix_instance.get_conversation_edges(),
        "capture_active": global_span_engine._running,
        "capture_interface": global_span_engine.interface or "Auto / Default"
    })

@api_bp.route("/traffic/stats", methods=["GET"])
@require_auth
def api_traffic_stats():
    """Returns live packet and bandwidth metrics from mirrored SPAN streams."""
    return jsonify({
        "status": "success",
        "stats": traffic_matrix_instance.get_summary(),
        "capture_active": global_span_engine._running,
        "capture_interface": global_span_engine.interface or "Auto / Default"
    })

@api_bp.route("/traffic/interfaces", methods=["GET"])
@require_auth
def api_traffic_interfaces():
    """Returns available physical and virtual network interfaces for Port Mirroring."""
    interfaces = []

    # 1. Scapy Interface Discovery
    try:
        from scapy.config import conf
        for iface_key, iface_obj in conf.ifaces.items():
            name = getattr(iface_obj, "name", str(iface_key))
            ip = getattr(iface_obj, "ip", "")
            desc = getattr(iface_obj, "description", name)
            ips = [ip] if ip and ip != "0.0.0.0" else []
            display = f"{desc} ({ip})" if ip and ip != "0.0.0.0" else desc
            interfaces.append({
                "name": name,
                "display_name": display,
                "ips": ips,
                "is_up": True
            })
    except Exception:
        pass

    # 2. Optional psutil Discovery (if installed)
    if not interfaces:
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, addr_list in addrs.items():
                ipv4_list = [a.address for a in addr_list if getattr(a, "family", None) and getattr(a.family, "name", "") == "AF_INET"]
                is_up = stats[iface_name].isup if iface_name in stats else True
                interfaces.append({
                    "name": iface_name,
                    "display_name": f"{iface_name} ({', '.join(ipv4_list)})" if ipv4_list else iface_name,
                    "ips": ipv4_list,
                    "is_up": is_up
                })
        except Exception:
            pass

    # 3. Standard Library Socket Fallback
    if not interfaces:
        try:
            import socket
            host_name = socket.gethostname()
            _, _, ip_list = socket.gethostbyname_ex(host_name)
            for i, ip in enumerate(ip_list):
                interfaces.append({
                    "name": f"Interface_{i+1}",
                    "display_name": f"Adapter ({ip})",
                    "ips": [ip],
                    "is_up": True
                })
        except Exception:
            pass

    if not interfaces:
        interfaces = [{"name": "Default Interface", "display_name": "Default Network Interface (10.10.7.22)", "ips": ["10.10.7.22"], "is_up": True}]

    return jsonify({
        "status": "success",
        "interfaces": interfaces,
        "active_capture": global_span_engine._running,
        "current_interface": global_span_engine.interface or ""
    })

@api_bp.route("/traffic/capture/start", methods=["POST"])
@require_auth
def api_traffic_capture_start():
    """Starts live SPAN packet capture on the specified or active interface."""
    data = request.get_json(silent=True) or {}
    iface_name = data.get("interface", None)

    global_span_engine.start_capture(interface=iface_name)
    return jsonify({
        "status": "success",
        "message": f"Port Mirror (SPAN) capture started on {iface_name or 'Default Interface'}.",
        "capture_active": True,
        "interface": iface_name or "Default Interface"
    })

@api_bp.route("/traffic/capture/stop", methods=["POST"])
@require_auth
def api_traffic_capture_stop():
    """Stops live SPAN packet capture."""
    global_span_engine.stop_capture()
    return jsonify({
        "status": "success",
        "message": "Port Mirror (SPAN) capture stopped.",
        "capture_active": False
    })

@api_bp.route("/traffic/infer_role/<ip>", methods=["GET"])
@require_auth
def api_traffic_infer_role(ip):
    """Infers client/server role of a host based on traffic flow analysis."""
    role_info = TrafficRoleClassifier.infer_role(ip, traffic_matrix_instance)
    return jsonify({
        "status": "success",
        "ip": ip,
        **role_info
    })

@api_bp.route("/geolocation", methods=["GET"])
@require_auth
def api_geolocation_overview():
    """Returns macro WAN GPS coordinates, civic locations, and spatial path trails for all assets."""
    from discovery.geolocation_engine import PublicGeoIpResolver

    macro_geo = PublicGeoIpResolver.resolve()
    graph_data = graph.export_topology_snapshot()

    device_locations = []
    for node in graph_data.get("nodes", []):
        if not node.get("is_subnet_hub"):
            device_locations.append({
                "id": node.get("id"),
                "ip": node.get("ip"),
                "hostname": node.get("hostname", ""),
                "vendor": node.get("vendor", ""),
                "model": node.get("model", ""),
                "type": node.get("type", "unknown"),
                "geolocation": node.get("geolocation", {}),
                "civic_location": node.get("civic_location", {}),
                "spatial_path": node.get("spatial_path", [])
            })

    return jsonify({
        "status": "success",
        "macro_geolocation": macro_geo,
        "total_located_devices": len(device_locations),
        "devices": device_locations
    })

@api_bp.route("/geolocation/protocols", methods=["GET"])
@require_auth
def api_geolocation_protocols():
    """Returns the queryable catalog of all 11 network geolocation and physical tracking protocols."""
    from discovery.geolocation_engine import GeolocationProtocolsLibrary
    return jsonify({
        "status": "success",
        "total_protocols": len(GeolocationProtocolsLibrary.get_all_protocols()),
        "protocols": GeolocationProtocolsLibrary.get_all_protocols()
    })

@api_bp.route("/geolocation/refresh", methods=["POST"])
@require_auth
def api_geolocation_refresh():
    """Forces a refresh of the public WAN GeoIP lookup."""
    from discovery.geolocation_engine import PublicGeoIpResolver
    geo_data = PublicGeoIpResolver.resolve(force_refresh=True)
    return jsonify({
        "status": "success",
        "message": "Public GeoIP coordinates refreshed successfully.",
        "macro_geolocation": geo_data
    })

@api_bp.route("/report/inventory", methods=["GET"])
@require_auth
def api_report_inventory():
    """
    Generates a structured, comprehensive asset inventory & audit report payload.
    Organizes devices by type, count, IP, MAC, hostname, vendor, model, ports, location, and advisories.
    """
    import datetime
    from discovery.geolocation_engine import PublicGeoIpResolver
    
    macro_geo = PublicGeoIpResolver.resolve()
    graph_data = graph.export_topology_snapshot()
    
    nodes = graph_data.get("nodes", [])
    raw_devices = [n for n in nodes if not n.get("is_subnet_hub")]
    
    # Category counts
    category_counts = {}
    formatted_devices = []
    
    for idx, node in enumerate(raw_devices, start=1):
        dev_type = node.get("type", "unknown").lower()
        category_counts[dev_type] = category_counts.get(dev_type, 0) + 1
        
        ports = node.get("ports", [])
        if isinstance(ports, list):
            ports_str = ", ".join(str(p) for p in ports) if ports else "None detected"
        else:
            ports_str = str(ports)
            
        civic = node.get("civic_location", {})
        loc_parts = []
        if civic.get("building"): loc_parts.append(civic["building"])
        if civic.get("floor"): loc_parts.append(civic["floor"])
        if civic.get("room"): loc_parts.append(civic["room"])
        if civic.get("wall_jack"): loc_parts.append(f"Jack: {civic['wall_jack']}")
        location_str = ", ".join(loc_parts) if loc_parts else "Unspecified"
        
        advisories = node.get("security_advisories", [])
        risk_level = node.get("risk_level", "NOT_ASSESSED")
        is_assessed = node.get("security_assessed", risk_level in ("LOW", "MEDIUM", "HIGH", "NONE"))
        
        if isinstance(advisories, list):
            finding_titles = [
                item.get("title", str(item)) if isinstance(item, dict) else str(item)
                for item in advisories
            ]
            advisory_count = len(finding_titles)
            if finding_titles:
                advisories_str = "; ".join(finding_titles)
                has_advisory = True
                security_status = "Advisory"
            elif is_assessed and risk_level == "NONE":
                advisories_str = "None (Clean)"
                has_advisory = False
                security_status = "Clean"
            else:
                advisories_str = "Not Assessed (No Sockets/OIDs)"
                has_advisory = False
                security_status = "Not Assessed"
        else:
            has_advisory = bool(advisories)
            advisories_str = str(advisories) if advisories else "Not Assessed"
            security_status = "Advisory" if has_advisory else "Not Assessed"
            advisory_count = 1 if has_advisory else 0
            
        formatted_devices.append({
            "index": idx,
            "id": node.get("id"),
            "ip": node.get("ip", ""),
            "mac": node.get("mac") or "Unresolved",
            "hostname": node.get("hostname", "") or node.get("label", ""),
            "type": dev_type,
            "vendor": node.get("vendor", "Generic/Unknown"),
            "model": node.get("model", "") or node.get("hardware", ""),
            "os": node.get("os", "") or node.get("fingerprint", ""),
            "ports": ports,
            "ports_str": ports_str,
            "services": node.get("services", []),
            "location": location_str,
            "civic_location": civic,
            "geolocation": node.get("geolocation", {}),
            "spatial_path": node.get("spatial_path", []),
            "advisories": advisories,
            "advisories_str": advisories_str,
            "advisory_count": advisory_count,
            "has_advisory": has_advisory,
            "security_status": security_status,
            "risk_level": risk_level,
            "last_seen": node.get("last_seen", ""),
            "discovery_method": node.get("discovery_method", "hybrid_sweep")
        })
        
    return jsonify({
        "status": "success",
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_assets": len(formatted_devices),
        "category_counts": category_counts,
        "macro_geolocation": macro_geo,
        "summary": graph_data.get("summary", {}),
        "devices": formatted_devices
    })