"""
Project AETHERIS - Infrastructure Adapters Package.
Kernel-level packet capture, BPF filter offloading, Npcap NDIS LWF bindings, and zero-copy ctypes memory structures.
"""

from aetheris.infrastructure.adapters.pcap_capture_adapter import (
    EthernetHeader,
    VLANHeader,
    MBAPHeader,
    ProfinetIRTHeader,
    bpf_insn,
    bpf_program,
    inject_kernel_bpf,
    compile_bpf_filter,
    load_windows_capture_interface,
    dissect_frame_zero_copy,
    INDUSTRIAL_BPF_FILTER,
)

__all__ = [
    "EthernetHeader",
    "VLANHeader",
    "MBAPHeader",
    "ProfinetIRTHeader",
    "bpf_insn",
    "bpf_program",
    "inject_kernel_bpf",
    "compile_bpf_filter",
    "load_windows_capture_interface",
    "dissect_frame_zero_copy",
    "INDUSTRIAL_BPF_FILTER",
]

