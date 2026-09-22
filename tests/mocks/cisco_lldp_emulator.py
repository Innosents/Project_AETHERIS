import struct
import time
import logging
from scapy.all import Ether, sendp, conf, get_if_list

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AETHERIS_L2_DAEMON] - %(message)s')

def compile_lldp_med_frame() -> Ether:
    """
    Constructs a bit-perfect IEEE 802.1AB LLDP packet featuring the 
    TIA TR-41 OUI (00:12:BB) and Extended Power-via-MDI TLV.
    """
    # L2 Boundary: LLDP Multicast MAC (01:80:c2:00:00:0e) & EtherType (0x88cc)
    eth = Ether(dst="01:80:c2:00:00:0e", src="00:1A:2B:3C:4D:5E", type=0x88cc)
    
    # TLV 1: Chassis ID (Type 1, Len 7) -> MAC Address
    chassis_tlv = b'\x02\x07\x04\x00\x1a\x2b\x3c\x4d\x5e'
    
    # TLV 2: Port ID (Type 2, Len 7) -> MAC Address
    port_tlv = b'\x04\x07\x03\x00\x1a\x2b\x3c\x4d\x5f'
    
    # TLV 3: Time To Live (Type 3, Len 2) -> 120 seconds (0x0078)
    ttl_tlv = b'\x06\x02\x00\x78'
    
    # TLV 127: Organizationally Specific (Type 127, Len 7)
    # Binary Header: 1111111 (Type 127) + 000000111 (Len 7) = 0xFE 0x07
    # OUI: 00:12:BB (TIA) | Subtype: 02 (Extended Power-via-MDI)
    # Power Flag: 01 (PSE) | Power Value: 3C 28 (15400 / 15.4W)
    med_power_tlv = b'\xfe\x07\x00\x12\xbb\x02\x01\x3c\x28'
    
    # TLV 0: End of LLDPDU (Type 0, Len 0)
    end_tlv = b'\x00\x00'
    
    return eth / chassis_tlv / port_tlv / ttl_tlv / med_power_tlv / end_tlv

def main():
    # Npcap strict Windows loopback identifier
    npcap_loopback = r"\Device\NPF_Loopback"
    
    # Dynamic interface fallback routing
    available_interfaces = get_if_list()
    if npcap_loopback in available_interfaces:
        conf.iface = npcap_loopback
        logging.info(f"Npcap Loopback Adapter identified. Binding to {conf.iface}")
    else:
        logging.warning("Explicit Npcap Loopback not found. Defaulting to generic OS loopback.")
        conf.iface = conf.loopback_name

    logging.info("Compiling LLDP-MED Extended Power-via-MDI struct matrix...")
    frame = compile_lldp_med_frame()
    
    logging.info("Initiating 15.4W (0x3C28) L2 thermodynamic beacon broadcast.")
    
    try:
        while True:
            sendp(frame, verbose=False)
            logging.info("L2 Frame injected. Thermodynamic TLV emitted. Cycle: 30s.")
            time.sleep(30)
    except KeyboardInterrupt:
        logging.info("SIGINT received. Tearing down L2 Npcap binding.")

if __name__ == "__main__":
    main()