import json
import sys
from pathlib import Path
import requests
import time

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

JSON_PATH = root_dir / "topology_audit.json" if (root_dir / "topology_audit.json").exists() else Path("topology_audit.json")
API_URL = "http://127.0.0.1:8080/api/telemetry/ingest"

def transmit_audit_nodes(stream_delay: float = 0.0):
    if not JSON_PATH.exists():
        print(f"[-] Error: {JSON_PATH} not found. Run scripts/reseed_definitive_topology.py first.", file=sys.stderr)
        sys.exit(1)

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        audit = json.load(f)
    
    # Check if it's the new OT array payload
    if isinstance(audit, list):
        nodes = [item["data"] for item in audit if "id" in item.get("data", {})]
        edges = [item["data"] for item in audit if "source" in item.get("data", {})]
        
        # Build map of target -> source for parent relationship
        edge_map = {e["target"]: e for e in edges}
        
        print(f"[*] Streaming {len(nodes)} OT verified nodes to {API_URL}...")
        success_count = 0
        for node in nodes:
            node_id = node["id"]
            edge = edge_map.get(node_id, {})
            parent_id = edge.get("source", "RTR-ISR4331") # default to core if no incoming edge
            dist = edge.get("distance", 0.0)
            conf = edge.get("confidence", node.get("confidence", 0.9))
            med = edge.get("medium", "copper").upper()
            
            payload = {
                "node_id": node_id,
                "parent_switch_id": parent_id,
                "distance_m": float(dist),
                "confidence_pct": float(conf) * 100,
                "edge_type": med,
                "node_props": {
                    "label": node.get("label", node_id),
                    "type": node.get("type", "endpoint"),
                    "vlan": node.get("vlan", 1),
                    "confidence": float(conf),
                    "mac": "00:00:00:00:00:00"
                }
            }
            
            try:
                res = requests.post(API_URL, json=payload, timeout=2.0)
                res.raise_for_status()
                success_count += 1
                if stream_delay > 0:
                    time.sleep(stream_delay)
            except Exception as e:
                print(f"[-] Failed to ingest {node_id}: {e}", file=sys.stderr)
                
        print(f"[+] OT Ingestion complete: {success_count}/{len(nodes)} nodes rendered into GraphStore.")
        return

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AETHERIS Telemetry Ingest Streamer")
    parser.add_argument("--stream-delay", type=float, default=0.0, help="Delay in seconds between posting endpoints")
    args = parser.parse_args()
    
    for _ in range(10):
        try:
            requests.get("http://127.0.0.1:8080/", timeout=1.0)
            break
        except Exception:
            time.sleep(0.5)
            
    transmit_audit_nodes(stream_delay=args.stream_delay)