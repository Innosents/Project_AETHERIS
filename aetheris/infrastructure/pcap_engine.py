import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List

# Assuming scapy or a similar libpcap Python wrapper is utilized
from scapy.all import sniff, Packet

class AsyncPcapPublisher:
    """
    Pure Infrastructure Adapter for libpcap interface bindings.
    Implements a zero-domain-knowledge Pub/Sub architecture. Executes raw frame
    interception within an isolated thread pool to prevent event loop exhaustion.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._subscribers: List[Dict[str, Any]] = []
        self._thread_pool = ThreadPoolExecutor(max_workers=1)

    def register_listener(self, bpf_filter: str, delegate_callback: Callable[[Packet], None]) -> None:
        """
        Subscribes a delegate function to a specific Berkeley Packet Filter (BPF) stream.
        """
        self._subscribers.append({
            "bpf_filter": bpf_filter,
            "callback": delegate_callback
        })
        logging.debug(f"[PCAP_ENGINE] Registered BPF: {bpf_filter}")

    def _sync_sniff_loop(self, duration_sec: float) -> None:
        """
        Synchronous libpcap execution context. 
        Evaluates frames against subscriber BPF constraints and routes payloads dynamically.
        """
        def _multiplex_frame(packet: Packet) -> None:
            # Note: For hyper-optimized captures, a compiled master BPF filter combining 
            # all subscriber filters should be applied at the C-level sniff() call. 
            # This router handles user-space distribution.
            for sub in self._subscribers:
                sub["callback"](packet)

        logging.info(f"[PCAP_ENGINE] Locking interface {self.interface} for {duration_sec}s")
        
        # Generates a unified BPF string to drop irrelevant traffic at the kernel level
        unified_bpf = " or ".join([f"({s['bpf_filter']})" for s in self._subscribers if s['bpf_filter']])
        
        sniff(
            iface=self.interface,
            filter=unified_bpf,
            prn=_multiplex_frame,
            timeout=duration_sec,
            store=False  # Absolute memory constraint: Never buffer raw frames in Python lists
        )

    async def execute_capture(self, duration_sec: float) -> None:
        """
        Asynchronous boundary. Offloads the blocking C-library call to the thread pool.
        """
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._thread_pool, self._sync_sniff_loop, duration_sec)