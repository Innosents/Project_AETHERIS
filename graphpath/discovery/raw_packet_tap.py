"""
GraphPath Low-Level Raw Packet Sniffer & Hardware Timestamp Tap
Utilizes Npcap / Scapy promiscuous capture to extract kernel-level microsecond RTTs
and stream incoming CDP/LLDP frames into DiscoveryEngine.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp, AsyncSniffer
from scapy.arch.windows import get_windows_if_list


class RawPacketTap:
    def __init__(
        self,
        interface: Optional[str] = None,
        on_packet_received: Optional[Callable[[Any], None]] = None
    ):
        self.interface = interface or self._detect_default_interface()
        self.on_packet_received = on_packet_received
        
        # Pending RTT probes: (dst_ip, dst_port, src_port) -> {"tx_time_s": float, "samples": List[float]}
        self._pending_probes: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None

    @staticmethod
    def _detect_default_interface() -> Optional[str]:
        """Discovers primary active physical Npcap interface name."""
        try:
            interfaces = get_windows_if_list()
            for iface in interfaces:
                # Prefer Ethernet connections with valid default gateway
                name = iface.get("name", "")
                desc = iface.get("description", "").lower()
                if ("ethernet" in desc or "realtek" in desc or "intel" in desc) and iface.get("ips"):
                    return name
            if interfaces:
                return interfaces[0].get("name")
        except Exception:
            pass
        return None

    def _packet_handler(self, packet: Any) -> None:
        """Processes captured packets from kernel filter buffer."""
        # 1. Forward raw frames to passive L2 CDP/LLDP listeners
        if self.on_packet_received:
            self.on_packet_received(packet)

        # 2. Extract TCP handshake response timestamps (SYN-ACK or RST)
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Inbound response: match src_ip, src_port (target port), and dst_port (prober port)
            probe_key = f"{ip_layer.src}:{tcp_layer.sport}:{tcp_layer.dport}"
            
            with self._lock:
                if probe_key in self._pending_probes:
                    rx_time_s = float(packet.time)
                    tx_time_s = self._pending_probes[probe_key]["tx_time_s"]
                    rtt_us = (rx_time_s - tx_time_s) * 1_000_000.0

                    if rtt_us > 0.0:
                        self._pending_probes[probe_key]["samples"].append(rtt_us)

    def start_listener(self, bpf_filter: str = "ether proto 0x88cc or ether host 01:00:0c:cc:cc:cc or tcp") -> None:
        """Launches Scapy AsyncSniffer on Npcap interface."""
        if self._sniffer and self._sniffer.running:
            return

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf_filter,
            prn=self._packet_handler,
            store=False
        )
        self._sniffer.start()

    def stop_listener(self) -> None:
        """Stops background packet capture."""
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            self._sniffer = None

    def execute_rtt_pulse_burst(
        self,
        target_ip: str,
        target_port: int,
        source_port: int = 49152,
        burst_count: int = 5,
        inter_packet_gap_s: float = 0.005,
        timeout_s: float = 0.5
    ) -> List[float]:
        """
        Transmits a burst of raw TCP SYN probes, capturing kernel arrival timestamps.
        Returns microsecond RTT readings.
        """
        probe_key = f"{target_ip}:{target_port}:{source_port}"
        
        with self._lock:
            self._pending_probes[probe_key] = {
                "tx_time_s": 0.0,
                "samples": []
            }

        # Build raw TCP SYN probe
        syn_packet = IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="S", seq=1000)

        for _ in range(burst_count):
            tx_monotonic = time.time()
            with self._lock:
                self._pending_probes[probe_key]["tx_time_s"] = tx_monotonic
            
            # Direct NDIS raw packet transmission
            try:
                sendp(Ether() / syn_packet, iface=self.interface, verbose=False)
            except Exception:
                pass

            time.sleep(inter_packet_gap_s)

        # Wait for responses to drain
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._lock:
                if len(self._pending_probes[probe_key]["samples"]) >= burst_count:
                    break
            time.sleep(0.005)

        with self._lock:
            samples = list(self._pending_probes[probe_key]["samples"])
            del self._pending_probes[probe_key]

        return samples