"""
Project AETHERIS - Demo Payload
Synthesizes verified Cytoscape graph payloads representing compound subnet clusters, access controllers, and downstream physical security peripherals for demonstration sandboxes. Models composite 
multi-conductor cabling types and edge associations to validate graph visualization layouts without live hardware connections.
"""

import json

def get_demo_msp_elements():
    """
    Mock MSP payload simulation that generates the REX and Strike nodes based on 
    simulated R_count and S_count variables to prove the sub-peripheral extraction.
    """
    # Base Mercury MP1502 and Tiandy NVR
    base_elements = [
        {"data": {"id": "sw_mercury", "label": "Mercury MP1502", "parent": "compound_mercury", "mac_address": "00:1F:F3:4A:2B:9C", "firmware": "1.29.1", "device_class": "Access Controller", "confidence": 95}},
        {"data": {"id": "sw_tiandy", "label": "Tiandy NVR", "parent": "compound_tiandy", "mac_address": "B4:A3:82:11:00:FF", "firmware": "V5.1.0", "device_class": "NVR", "confidence": 80}},
        {"data": {"id": "compound_mercury", "label": "Mercury Subnet"}},
        {"data": {"id": "compound_tiandy", "label": "Tiandy Subnet"}}
    ]

    # MSP Extracted Downstream Inventory (Dark Inventory)
    # Simulated R_count = 2, S_count = 2, X_count = 2, D_count = 2
    r_count = 2
    s_count = 2

    extracted_nodes = []
    extracted_edges = []

    for i in range(1, r_count + 1):
        reader_id = f"reader_{i}"
        extracted_nodes.append({"data": {"id": reader_id, "label": f"HID Signo Reader {i}", "parent": "compound_mercury", "device_class": "Card Reader", "confidence": 100}})
        extracted_edges.append({"data": {"id": f"link_mercury_reader_{i}", "source": "sw_mercury", "target": reader_id, "edge_type": "composite_22_6", "edge_label": "RS-485 (22/6)"}, "classes": "hardlined"})

    for i in range(1, s_count + 1):
        strike_id = f"strike_{i}"
        extracted_nodes.append({"data": {"id": strike_id, "label": f"HES Door Strike {i}", "parent": "compound_mercury", "device_class": "Door Strike", "confidence": 100}})
        extracted_edges.append({"data": {"id": f"link_mercury_strike_{i}", "source": "sw_mercury", "target": strike_id, "edge_type": "composite_18_2", "edge_label": "18/2 Power"}, "classes": "hardlined"})

    return base_elements + extracted_nodes + extracted_edges

