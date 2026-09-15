import json
import sys
from pathlib import Path
import requests

JSON_PATH = Path("topology_audit.json")
API_URL = "http://127.0.0.1:8080/api/telemetry/ingest"

def transmit_audit_nodes():
    if not JSON_PATH.exists():
        print(f"[-] Error: {JSON_PATH} not found. Run scripts/export_topology_audit.py first.", file=sys.stderr)
        sys.exit(1)

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        audit = json.load(f)

    # 1. Build MAC-to-Switchport & Interface Map
    mac_to_port = {}
    for port_id, interfaces in audit.get("switch_fabric_interfaces", {}).items():
        for iface in interfaces:
            mac = (iface.get("mac_address") or "").upper()
            if mac:
                mac_to_port[mac] = {
                    "port_id": port_id,
                    "hostname": iface.get("hostname"),
                    "link_speed_mbps": iface.get("link_speed_mbps"),
                    "connection_type": iface.get("connection_type")
                }

    # 2. Build Ground Truth Pinning Map
    gt_pins = {
        gt["mac_address"].upper(): gt 
        for gt in audit.get("ground_truth_accuracy_audit", [])
    }

    # 3. Stream Converged Endpoints to Cytoscape Visualizer
    endpoints = audit.get("converged_endpoints", [])
    print(f"[*] Streaming {len(endpoints)} verified nodes to {API_URL}...")
    
    success_count = 0
    for ep in endpoints:
        mac_clean = ep["mac"].upper()
        port_meta = mac_to_port.get(mac_clean, {})
        gt_meta = gt_pins.get(mac_clean)

        is_anchor = (ep.get("ip") == "192.168.1.86" or gt_meta is not None)
        port_name = port_meta.get("port_id", "WLAN")

        # Determine logical parent for Cytoscape topology
        if port_name == "Port 1" and mac_clean != "10:78:5B:3D:08:80":
            parent_switch = "Actiontec-Q6000"
        else:
            parent_switch = "Gateway-Core"

        payload = {
            "node_id": f"host_{ep['ip'].replace('.', '_')}",
            "parent_switch_id": parent_switch,
            "distance_m": ep["converged_distance_m"],
            "variance_m2": ep["variance_m2"],
            "confidence_pct": ep["confidence_pct"],
            "is_anchor": is_anchor,
            "edge_type": "ETHERNET_ANCHOR" if is_anchor else ("ETHERNET_LINK" if "Copper" in ep.get("medium", "") else "WIRELESS_AIRLINK"),
            "node_props": {
                "ip": ep["ip"],
                "mac": ep["mac"],
                "canonical_name": gt_meta.get("canonical_name") if gt_meta else port_meta.get("hostname", ep["ip"]),
                "switchport": port_name,
                "medium": ep.get("medium", "Unknown"),
                "ground_truth_m": gt_meta.get("ground_truth_m") if gt_meta else None
            }
        }

        try:
            res = requests.post(API_URL, json=payload, timeout=2.0)
            res.raise_for_status()
            success_count += 1
        except Exception as e:
            print(f"[-] Failed to ingest {ep['ip']} ({ep['mac']}): {e}", file=sys.stderr)

    print(f"[+] Ingestion complete: {success_count}/{len(endpoints)} nodes rendered into GraphStore.")

if __name__ == "__main__":
    transmit_audit_nodes()