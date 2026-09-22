"""
Project AETHERIS - Low-Level Raw Packet Sniffer & Hardware Timestamp Tap
Incorporates automated driver-loop overhead calibration to eliminate
Windows kernel dispatch delay from cable flight-time measurements.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sendp, AsyncSniffer
try:
    from scapy.arch.windows import get_windows_if_list
except (ImportError, ModuleNotFoundError):
    get_windows_if_list = None


class RawPacketTap:

    def _resolve_interface(self, iface_str: str) -> str:
        # If it looks like an IP address, try to resolve to interface name
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', iface_str):
            if get_windows_if_list is not None:
                try:
                    for iface in get_windows_if_list():
                        if iface_str in iface.get("ips", []):
                            return iface.get("name") or iface_str
                except Exception:
                    pass
        return iface_str
    def __init__(
        self,
        interface: Optional[str] = None,
        on_packet_received: Optional[Callable[[Any], None]] = None
    ):
        self.interface = self._resolve_interface(interface or self._detect_default_interface())
        self.on_packet_received = on_packet_received
        
        self._pending_probes: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._sniffer: Optional[AsyncSniffer] = None
        self.driver_overhead_us: float = 0.0

    @staticmethod
    def _detect_default_interface() -> Optional[str]:
        if get_windows_if_list is not None:
            try:
                interfaces = get_windows_if_list()
                for iface in interfaces:
                    name = iface.get("name", "")
                    desc = iface.get("description", "").lower()
                    if ("ethernet" in desc or "realtek" in desc or "intel" in desc) and iface.get("ips"):
                        return name
                if interfaces:
                    return interfaces[0].get("name")
            except Exception:
                pass
        try:
            from scapy.config import conf
            if conf.iface:
                return getattr(conf.iface, "name", str(conf.iface))
            from scapy.interfaces import get_if_list
            ifaces = get_if_list()
            if ifaces:
                return ifaces[0]
        except Exception:
            pass
        return None

    def calibrate_driver_overhead(self, iterations: int = 5) -> float:
        """
        Measures baseline OS execution time for building and transmitting a raw frame
        to subtract dispatch latency from physical line measurements.
        """
        dummy_packet = Ether() / IP(dst="127.0.0.1") / TCP(dport=9)
        deltas = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            try:
                sendp(dummy_packet, iface=self.interface, verbose=False)
            except Exception:
                pass
            t1 = time.perf_counter_ns()
            deltas.append((t1 - t0) / 1000.0)

        # Baseline dispatch latency (lower quartile)
        deltas.sort()
        self.driver_overhead_us = deltas[len(deltas) // 4] if deltas else 0.0
        return self.driver_overhead_us

    def _packet_handler(self, packet: Any) -> None:
        rx_ns = time.perf_counter_ns()

        if self.on_packet_received:
            self.on_packet_received(packet)

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            probe_key = None
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                probe_key = f"{ip_layer.src}:{tcp_layer.sport}:{tcp_layer.dport}"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                probe_key = f"{ip_layer.src}:{udp_layer.sport}:{udp_layer.dport}"

            if probe_key:
                with self._lock:
                    if probe_key in self._pending_probes:
                        tx_ns = self._pending_probes[probe_key]["tx_ns"]
                        if tx_ns > 0:
                            raw_rtt_us = (rx_ns - tx_ns) / 1000.0
                            # Subtract driver dispatch latency
                            net_rtt_us = max(0.1, raw_rtt_us - self.driver_overhead_us)

                            if net_rtt_us < 50_000.0:
                                self._pending_probes[probe_key]["samples"].append(net_rtt_us)

    def start_listener(self, bpf_filter: str = "tcp or udp or icmp or ether proto 0x88cc or ether host 01:00:0c:cc:cc:cc") -> None:
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
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            self._sniffer = None

    def execute_rtt_pulse_burst(
        self,
        target_ip: str,
        target_port: int,
        target_mac: Optional[str] = None,
        source_port: int = 49152,
        burst_count: int = 5,
        inter_packet_gap_s: float = 0.005,
        timeout_s: float = 0.4
    ) -> List[float]:
        probe_key = f"{target_ip}:{target_port}:{source_port}"
        
        with self._lock:
            self._pending_probes[probe_key] = {
                "tx_ns": 0,
                "samples": []
            }

        # Build Ethernet frame directly with target MAC to prevent inline ARP delays
        eth_kwargs = {"dst": target_mac} if target_mac else {}
        syn_packet = Ether(**eth_kwargs) / IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="S", seq=1000)

        for _ in range(burst_count):
            with self._lock:
                self._pending_probes[probe_key]["tx_ns"] = time.perf_counter_ns()
            
            try:
                sendp(syn_packet, iface=self.interface, verbose=False)
            except Exception:
                pass

            time.sleep(inter_packet_gap_s)

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._lock:
                if len(self._pending_probes[probe_key]["samples"]) >= burst_count:
                    break
            time.sleep(0.005)

        with self._lock:
            samples = list(self._pending_probes[probe_key]["samples"])
            if probe_key in self._pending_probes:
                del self._pending_probes[probe_key]

        return samples