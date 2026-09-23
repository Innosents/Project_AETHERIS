import json
from pathlib import Path
import sqlite3
import os

def generate_terra_digital_matrix():
    """Generates a strict Purdue Model industrial topology."""
    nodes = [
        # --- INJECT INTO NODES ARRAY ---
        # VLAN 30: IT / Admin & Logistics
        {"data": {"id": "RTR-ISR4331", "label": "Cisco ISR 4331", "type": "router", "vlan": 30, "confidence": 0.99}},
        {"data": {"id": "SRV-DHCP", "label": "DHCP Server", "type": "server", "vlan": 30, "confidence": 1.0}},
        {"data": {"id": "PC-JUMP", "label": "JumpHost", "type": "workstation", "vlan": 30, "confidence": 0.95}},
        {"data": {"id": "PC-ENG", "label": "Engineering WS", "type": "workstation", "vlan": 30, "confidence": 0.98}},
        {"data": {"id": "HMI-01", "label": "Primary HMI", "type": "hmi", "vlan": 30, "confidence": 0.99}},

        # VLAN 20: Physical Security (CCTV & ACM)
        {"data": {"id": "NVR-AVG-PRI", "label": "Avigilon Unity (Pri)", "type": "nvr", "vlan": 20, "confidence": 1.0}},
        {"data": {"id": "NVR-AVG-SEC", "label": "Avigilon Unity (Sec)", "type": "nvr", "vlan": 20, "confidence": 1.0}},
        {"data": {"id": "ACM-MP1502", "label": "Mercury MP1502", "type": "controller", "vlan": 20, "confidence": 1.0}},
        {"data": {"id": "PER-RDR-01", "label": "OSDP Card Reader", "type": "peripheral", "vlan": 20, "confidence": 0.90}},
        {"data": {"id": "PER-STR-01", "label": "Door Strike", "type": "peripheral", "vlan": 20, "confidence": 0.85}},
        {"data": {"id": "PER-REX-01", "label": "REX Sensor", "type": "peripheral", "vlan": 20, "confidence": 0.85}},
        {"data": {"id": "PER-CON-01", "label": "Door Contact", "type": "peripheral", "vlan": 20, "confidence": 0.85}},
        {"data": {"id": "CAM-AXS-THM", "label": "Axis Thermal", "type": "camera", "vlan": 20, "confidence": 0.95}},
        {"data": {"id": "CAM-AXS-PTZ", "label": "Axis PTZ", "type": "camera", "vlan": 20, "confidence": 0.95}},
        {"data": {"id": "CAM-AXS-DOM", "label": "Axis Dome", "type": "camera", "vlan": 20, "confidence": 0.95}},
        {"data": {"id": "CAM-AXS-PAN", "label": "Axis Panoramic", "type": "camera", "vlan": 20, "confidence": 0.95}},

        # VLAN 10: OT / Control Layer (Purdue Level 0-1)
        {"data": {"id": "SW-3650", "label": "Cisco 3650-24RS", "type": "switch", "vlan": 10, "confidence": 1.0}},
        {"data": {"id": "SRV-HIST", "label": "Data Historian", "type": "server", "vlan": 10, "confidence": 0.99}},
        {"data": {"id": "SRV-PATCH", "label": "Patch Server", "type": "server", "vlan": 10, "confidence": 0.98}},
        {"data": {"id": "RELAY-01", "label": "Safety Relay", "type": "relay", "vlan": 10, "confidence": 0.99}},
        {"data": {"id": "PLC-MB-01", "label": "Modbus PLC", "type": "plc", "vlan": 10, "confidence": 1.0}},
        {"data": {"id": "SENS-TEMP", "label": "Temp Sensor", "type": "sensor", "vlan": 10, "confidence": 0.88}},
        {"data": {"id": "ACT-VALVE", "label": "Flow Actuator", "type": "actuator", "vlan": 10, "confidence": 0.88}}
    ]

    edges = [
        # --- INJECT INTO EDGES ARRAY ---
        # Core Routing & IT Links
        {"data": {"source": "RTR-ISR4331", "target": "SW-3650", "distance": 1, "confidence": 1.0, "medium": "fiber"}},
        {"data": {"source": "RTR-ISR4331", "target": "SRV-DHCP", "distance": 2, "confidence": 0.98, "medium": "copper"}},
        {"data": {"source": "RTR-ISR4331", "target": "PC-JUMP", "distance": 3, "confidence": 0.95, "medium": "copper"}},
        {"data": {"source": "RTR-ISR4331", "target": "PC-ENG", "distance": 3, "confidence": 0.95, "medium": "copper"}},
        {"data": {"source": "RTR-ISR4331", "target": "HMI-01", "distance": 2, "confidence": 0.99, "medium": "copper"}},

        # CCTV & ACM Downstream
        {"data": {"source": "SW-3650", "target": "NVR-AVG-PRI", "distance": 1, "confidence": 1.0, "medium": "copper"}},
        {"data": {"source": "NVR-AVG-PRI", "target": "NVR-AVG-SEC", "distance": 1, "confidence": 1.0, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "ACM-MP1502", "distance": 2, "confidence": 1.0, "medium": "copper"}},
        {"data": {"source": "NVR-AVG-PRI", "target": "CAM-AXS-PTZ", "distance": 50, "confidence": 0.95, "medium": "copper"}},
        {"data": {"source": "ACM-MP1502", "target": "PER-RDR-01", "distance": 15, "confidence": 0.90, "medium": "rs485"}},
        {"data": {"source": "ACM-MP1502", "target": "PER-STR-01", "distance": 15, "confidence": 0.85, "medium": "copper"}},
        {"data": {"source": "ACM-MP1502", "target": "PER-REX-01", "distance": 15, "confidence": 0.85, "medium": "copper"}},
        {"data": {"source": "ACM-MP1502", "target": "PER-CON-01", "distance": 15, "confidence": 0.85, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "CAM-AXS-THM", "distance": 45, "confidence": 0.95, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "CAM-AXS-DOM", "distance": 30, "confidence": 0.95, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "CAM-AXS-PAN", "distance": 35, "confidence": 0.95, "medium": "copper"}},

        # OT / Industrial Downstream
        {"data": {"source": "SW-3650", "target": "SRV-HIST", "distance": 2, "confidence": 0.99, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "SRV-PATCH", "distance": 2, "confidence": 0.98, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "RELAY-01", "distance": 5, "confidence": 0.99, "medium": "copper"}},
        {"data": {"source": "SW-3650", "target": "PLC-MB-01", "distance": 10, "confidence": 1.0, "medium": "copper"}},
        {"data": {"source": "PLC-MB-01", "target": "SENS-TEMP", "distance": 20, "confidence": 0.88, "medium": "serial"}},
        {"data": {"source": "PLC-MB-01", "target": "ACT-VALVE", "distance": 25, "confidence": 0.88, "medium": "serial"}}
    ]
    
    # Execute injection into the AETHERIS state ledger
    out_dir = Path(__file__).resolve().parent.parent / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "raw_device_table.txt"
    out_file.write_text(json.dumps({"nodes": nodes, "edges": edges}))
    print(f"[+] Matrix Reseeded: {len(nodes)} Nodes, {len(edges)} Conductors over 3 VLANs.")
    
    # Also overwrite topology_audit.json so that standard endpoints can use it
    audit_file = out_dir.parent / "topology_audit.json"
    audit_file.write_text(json.dumps(nodes + edges))

if __name__ == "__main__":
    generate_terra_digital_matrix()
