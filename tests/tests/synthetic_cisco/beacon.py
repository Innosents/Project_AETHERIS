import time
import threading
from scapy.all import sendp, conf
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgSoftwareVersion, CDPMsgPortID
from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUEndOfLLDPDU

# Cisco Industrial Ethernet 3400 Series Profile
SYS_NAME = b"IE-3400-DIST-01"
PLATFORM = b"cisco IE-3400-8P2S"
IOS_VERSION = b"Cisco IOS Software [Dublin], IE3000 Software (IE3k-UNIVERSALK9-M), Version 17.12.1a"
MAC_ADDR = "00:1A:8C:F0:44:22"
IFACE = "eth0"

def broadcast_cdp():
    """Transmits the exact CDPv2 TLV structure every 60 seconds."""
    # CDP Multicast Destination
    eth_cdp = type("Ether", (object,), {}) # Scapy Ether layer placeholder to avoid missing import
    from scapy.all import Ether
    eth = Ether(src=MAC_ADDR, dst="01:00:0c:cc:cc:cc")
    
    cdp_frame = eth / CDPv2_HDR() / \
                CDPMsgDeviceID(val=SYS_NAME) / \
                CDPMsgPortID(iface=b"GigabitEthernet1/1") / \
                CDPMsgPlatform(val=PLATFORM) / \
                CDPMsgSoftwareVersion(val=IOS_VERSION)

    while True:
        sendp(cdp_frame, iface=IFACE, verbose=False)
        time.sleep(60)

def broadcast_lldp():
    """Transmits the exact LLDP TLV structure every 30 seconds."""
    from scapy.all import Ether
    # LLDP Multicast Destination
    eth = Ether(src=MAC_ADDR, dst="01:80:c2:00:00:0e", type=0x88CC)
    
    lldp_frame = eth / LLDPDU() / \
                 LLDPDUChassisID(subtype=4, id=bytes.fromhex(MAC_ADDR.replace(':', ''))) / \
                 LLDPDUPortID(subtype=7, id=b"Gi1/1") / \
                 LLDPDUTimeToLive(ttl=120) / \
                 LLDPDUSystemName(system_name=SYS_NAME) / \
                 LLDPDUSystemDescription(description=IOS_VERSION) / \
                 LLDPDUEndOfLLDPDU()

    while True:
        sendp(lldp_frame, iface=IFACE, verbose=False)
        time.sleep(30)

if __name__ == "__main__":
    print(f"[AETHERIS TEST HARNESS] Igniting Synthetic Cisco IE-3400 Beacon on {IFACE}...")
    threading.Thread(target=broadcast_cdp, daemon=True).start()
    threading.Thread(target=broadcast_lldp, daemon=True).start()
    
    # Keep main thread locked
    while True:
        time.sleep(1)