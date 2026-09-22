"""
Project AETHERIS - Infrastructure Adapters: Kernel PCAP & BPF Offload Engine
Npcap NDIS Light-Weight Filter (LWF) driver interface and zero-copy ctypes memory overlays.
Hexagonal Infrastructure Layer: $O(1)$ feature extraction with exact memory alignment (_pack_ = 1).
"""

import ctypes
import ctypes.util
import os
import platform
import socket
from ctypes import (
    c_char_p,
    c_int,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint32,
    c_ushort,
    c_ubyte,
    POINTER,
    Structure,
)
from typing import Any, Dict, List, Optional, Tuple, Union

# Primary OT/ICS BPF matrix offloaded to kernel
INDUSTRIAL_BPF_FILTER: str = (
    "(ether proto 0x8892) or (vlan and ether proto 0x8892) or "
    "(tcp port 502) or (port 44818) or (udp port 2222)"
)

# Standard DLT linktype for Ethernet
DLT_EN10MB: int = 1
DEFAULT_SNAPLEN: int = 65535
DEFAULT_NETMASK: int = 0xFFFFFF00


# ============================================================================
# 1. REQUIRED C-TYPES SCHEMAS (Strict _pack_ = 1 Alignment)
# ============================================================================

class EthernetHeader(Structure):
    """
    Standard IEEE 802.3 Ethernet frame header (14 bytes).
    Maps destination MAC, source MAC, and EtherType in wire byte order.
    """
    _pack_ = 1
    _fields_ = [
        ("dest_mac", c_uint8 * 6),
        ("src_mac", c_uint8 * 6),
        ("ethertype", c_uint16),
    ]

    @property
    def ethertype_host(self) -> int:
        """Returns the EtherType in host byte order (Big-Endian to Little-Endian conversion)."""
        return socket.ntohs(self.ethertype)

    @property
    def formatted_dest_mac(self) -> str:
        """Returns colon-delimited uppercase MAC string."""
        return ":".join(f"{b:02X}" for b in self.dest_mac)

    @property
    def formatted_src_mac(self) -> str:
        """Returns colon-delimited uppercase MAC string."""
        return ":".join(f"{b:02X}" for b in self.src_mac)


class VLANHeader(Structure):
    """
    IEEE 802.1Q Customer VLAN Tagging Header (4 bytes).
    Maps Tag Control Information (Priority + DEI + VLAN ID) and encapsulated EtherType.
    """
    _pack_ = 1
    _fields_ = [
        ("tci", c_uint16),
        ("encap_proto", c_uint16),
    ]

    @property
    def vlan_id(self) -> int:
        """Extracts the 12-bit VLAN identifier in host byte order."""
        return socket.ntohs(self.tci) & 0x0FFF

    @property
    def pcp(self) -> int:
        """Extracts the 3-bit Priority Code Point (CoS)."""
        return (socket.ntohs(self.tci) >> 13) & 0x07

    @property
    def encap_proto_host(self) -> int:
        """Returns the encapsulated protocol EtherType in host byte order."""
        return socket.ntohs(self.encap_proto)


class MBAPHeader(Structure):
    """
    Modbus Application Protocol (MBAP) Header (7 bytes).
    Maps Modbus TCP transaction context directly onto raw TCP payload.
    """
    _pack_ = 1
    _fields_ = [
        ("transaction_id", c_uint16),
        ("protocol_id", c_uint16),
        ("length", c_uint16),
        ("unit_id", c_uint8),
    ]

    @property
    def transaction_id_host(self) -> int:
        return socket.ntohs(self.transaction_id)

    @property
    def protocol_id_host(self) -> int:
        return socket.ntohs(self.protocol_id)

    @property
    def length_host(self) -> int:
        return socket.ntohs(self.length)


class ProfinetIRTHeader(Structure):
    """
    PROFINET Real-Time / Isochronous Real-Time (IRT) Frame ID Header (2 bytes).
    Directly follows Ethernet or VLAN header on EtherType 0x8892.
    """
    _pack_ = 1
    _fields_ = [
        ("frame_id", c_uint16),
    ]

    @property
    def frame_id_host(self) -> int:
        return socket.ntohs(self.frame_id)


# ============================================================================
# 2. BPF C-TYPES MEMORY STRUCTURES
# ============================================================================

class bpf_insn(Structure):
    """
    Direct memory mapping of struct bpf_insn (<pcap/bpf.h>).
    Single Berkeley Packet Filter instruction executed inside the kernel VM (8 bytes).
    """
    _fields_ = [
        ("code", c_ushort),  # Opcode and addressing mode
        ("jt", c_ubyte),     # Jump relative offset if true
        ("jf", c_ubyte),     # Jump relative offset if false
        ("k", c_uint32),     # Generic operand (constant or address)
    ]


class bpf_program(Structure):
    """
    Direct memory mapping of struct bpf_program (<pcap/pcap.h>).
    Container for compiled BPF instruction array.
    """
    _fields_ = [
        ("bf_len", c_uint),                 # Number of instructions
        ("bf_insns", POINTER(bpf_insn)),    # Pointer to instruction array
    ]


class PcapAdapterError(RuntimeError):
    """Raised on PCAP or BPF compilation/attachment failure."""
    pass


_CACHED_PCAP_LIB: Optional[ctypes.CDLL] = None


# ============================================================================
# 3. WINDOWS NPCAP BINDING LOGIC
# ============================================================================

def load_windows_capture_interface(device_name: str) -> ctypes.c_void_p:
    """
    Bypasses the Windows networking stack and binds directly to the Npcap NDIS LWF driver
    ring buffer via wpcap.dll.

    Parameters:
        device_name: Npcap device path, e.g. '\\Device\\NPF_{GUID}'.

    Returns:
        ctypes.c_void_p: Pointer to the initialized pcap_t descriptor.
    """
    try:
        wpcap = ctypes.cdll.LoadLibrary("wpcap.dll")
    except OSError:
        raise RuntimeError("Npcap driver not found. Cannot execute L2 capture on Windows 11.")

    wpcap.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    wpcap.pcap_open_live.restype = ctypes.c_void_p

    errbuf = ctypes.create_string_buffer(256)

    pcap_handle = wpcap.pcap_open_live(
        device_name.encode("utf-8"),
        65536,  # Snaplen
        1,      # Promiscuous mode
        1,      # 1ms timeout
        errbuf,
    )

    if not pcap_handle:
        raise RuntimeError(f"Failed to bind to interface {device_name}: {errbuf.value.decode(errors='replace')}")

    return pcap_handle


def load_pcap_library() -> ctypes.CDLL:
    """
    Discovers and binds the host libpcap or wpcap dynamic shared library.
    Resolves wpcap.dll on Windows 11 NT Kernel and libpcap.so on Linux fallback nodes.
    """
    global _CACHED_PCAP_LIB
    if _CACHED_PCAP_LIB is not None:
        return _CACHED_PCAP_LIB

    system_name = platform.system().lower()
    candidates: List[str] = []

    if "windows" in system_name:
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        wpcap_sys32 = os.path.join(sys32, "wpcap.dll")
        if os.path.exists(wpcap_sys32):
            candidates.append(wpcap_sys32)
        candidates.extend(["wpcap.dll", "wpcap", "packet.dll"])
    else:
        candidates.extend([
            "libpcap.so.1",
            "libpcap.so",
            "libpcap.so.0.8",
            "pcap",
        ])

    lib = None
    find_name = "wpcap" if "windows" in system_name else "pcap"
    found_path = ctypes.util.find_library(find_name)
    if found_path:
        candidates.insert(0, found_path)

    for cand in candidates:
        try:
            lib = ctypes.cdll.LoadLibrary(cand)
            if hasattr(lib, "pcap_compile") and hasattr(lib, "pcap_setfilter"):
                break
        except (OSError, ImportError):
            continue

    if lib is None:
        raise PcapAdapterError(
            f"Unable to locate dynamic PCAP library (checked {candidates}). Ensure Npcap is installed on Windows 11."
        )

    # Declare rigid C-types signatures
    lib.pcap_compile.restype = c_int
    lib.pcap_compile.argtypes = [
        ctypes.c_void_p,
        POINTER(bpf_program),
        c_char_p,
        c_int,
        c_uint32,
    ]

    lib.pcap_setfilter.restype = c_int
    lib.pcap_setfilter.argtypes = [
        ctypes.c_void_p,
        POINTER(bpf_program),
    ]

    lib.pcap_geterr.restype = c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]

    if hasattr(lib, "pcap_freecode"):
        lib.pcap_freecode.restype = None
        lib.pcap_freecode.argtypes = [POINTER(bpf_program)]

    if hasattr(lib, "pcap_open_dead"):
        lib.pcap_open_dead.restype = ctypes.c_void_p
        lib.pcap_open_dead.argtypes = [c_int, c_int]

    if hasattr(lib, "pcap_close"):
        lib.pcap_close.restype = None
        lib.pcap_close.argtypes = [ctypes.c_void_p]

    _CACHED_PCAP_LIB = lib
    return lib


# ============================================================================
# 4. ZERO-COPY MEMORY OVERLAYS ($O(1)$ Feature Extraction)
# ============================================================================

def dissect_frame_zero_copy(
    raw_buffer: Union[bytes, bytearray, memoryview, ctypes.Array],
    length: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Executes zero-copy O(1) protocol dissection by casting ctypes.Structure
    memory pointers directly over raw packet buffer memory.

    Parameters:
        raw_buffer: Raw wire buffer (bytes, bytearray, or memoryview).
        length: Total wire frame length in bytes.

    Returns:
        Structured dictionary containing extracted L2/L3/L4 protocol attributes.
    """
    if isinstance(raw_buffer, bytes):
        # Convert immutable bytes to bytearray to support from_buffer memory sharing
        buf = bytearray(raw_buffer)
    elif isinstance(raw_buffer, (bytearray, memoryview)):
        buf = raw_buffer
    else:
        buf = bytearray(raw_buffer)

    buf_len = length if length is not None else len(buf)
    if buf_len < 14:
        raise ValueError(f"Packet buffer too small for Ethernet header: {buf_len} < 14 bytes")

    # 1. Overlay Ethernet Header (14 bytes)
    eth_hdr = EthernetHeader.from_buffer(buf, 0)
    ethertype = eth_hdr.ethertype_host

    result: Dict[str, Any] = {
        "dest_mac": eth_hdr.formatted_dest_mac,
        "src_mac": eth_hdr.formatted_src_mac,
        "ethertype": ethertype,
        "is_vlan": False,
        "vlan_id": None,
        "payload_offset": 14,
        "protocol": "GENERIC_ETHERNET",
        "ot_metadata": {},
    }

    offset = 14

    # 2. Check for IEEE 802.1Q VLAN Tag (EtherType 0x8100)
    if ethertype == 0x8100:
        if buf_len < offset + 4:
            return result
        vlan_hdr = VLANHeader.from_buffer(buf, offset)
        result["is_vlan"] = True
        result["vlan_id"] = vlan_hdr.vlan_id
        result["pcp"] = vlan_hdr.pcp
        result["encap_proto"] = vlan_hdr.encap_proto_host
        ethertype = vlan_hdr.encap_proto_host
        offset += 4
        result["payload_offset"] = offset

    # 3. Dissect OT/ICS L2 Payloads
    # PROFINET IRT / RT (EtherType 0x8892)
    if ethertype == 0x8892:
        result["protocol"] = "PROFINET_IRT"
        if buf_len >= offset + 2:
            profinet_hdr = ProfinetIRTHeader.from_buffer(buf, offset)
            frame_id = profinet_hdr.frame_id_host
            result["ot_metadata"] = {
                "frame_id": hex(frame_id),
                "frame_id_int": frame_id,
                "is_irt": 0x0100 <= frame_id <= 0x0FFF,
                "is_rt": 0x8000 <= frame_id <= 0xFCFF,
            }
        return result

    # 4. Dissect IPv4 / TCP (Modbus TCP)
    if ethertype == 0x0800:
        # Check minimum IPv4 header (20 bytes)
        if buf_len >= offset + 20:
            ip_ihl = (buf[offset] & 0x0F) * 4
            ip_proto = buf[offset + 9]
            tcp_offset = offset + ip_ihl

            # TCP Protocol = 6
            if ip_proto == 6 and buf_len >= tcp_offset + 20:
                dst_port = (buf[tcp_offset + 2] << 8) | buf[tcp_offset + 3]
                src_port = (buf[tcp_offset] << 8) | buf[tcp_offset + 1]
                tcp_data_offset = ((buf[tcp_offset + 12] >> 4) & 0x0F) * 4
                app_offset = tcp_offset + tcp_data_offset

                # Modbus TCP Port 502
                if (dst_port == 502 or src_port == 502) and buf_len >= app_offset + 7:
                    mbap_hdr = MBAPHeader.from_buffer(buf, app_offset)
                    result["protocol"] = "MODBUS_TCP"
                    result["ot_metadata"] = {
                        "transaction_id": mbap_hdr.transaction_id_host,
                        "protocol_id": mbap_hdr.protocol_id_host,
                        "length": mbap_hdr.length_host,
                        "unit_id": mbap_hdr.unit_id,
                    }

    return result


# ============================================================================
# 5. KERNEL BPF COMPILATION & INJECTION
# ============================================================================

def compile_bpf_filter(
    filter_exp: str = INDUSTRIAL_BPF_FILTER,
    netmask: int = DEFAULT_NETMASK,
    linktype: int = DLT_EN10MB,
    snaplen: int = DEFAULT_SNAPLEN,
    optimize: int = 1,
) -> Tuple[bpf_program, ctypes.c_void_p]:
    """
    Compiles an ASCII BPF filter string into raw kernel bytecode using a dead capture handle.
    """
    lib = load_pcap_library()
    dead_handle = lib.pcap_open_dead(linktype, snaplen)
    if not dead_handle:
        raise PcapAdapterError(f"Failed to allocate dead PCAP descriptor for linktype {linktype}")

    prog = bpf_program()
    encoded = filter_exp.encode("utf-8")
    ret = lib.pcap_compile(
        dead_handle,
        ctypes.byref(prog),
        encoded,
        optimize,
        c_uint32(netmask),
    )

    if ret != 0:
        err_msg = lib.pcap_geterr(dead_handle).decode("utf-8", errors="replace")
        lib.pcap_close(dead_handle)
        raise PcapAdapterError(f"BPF compilation failed for '{filter_exp}': {err_msg}")

    return prog, dead_handle


def inject_kernel_bpf(
    pcap_handle: ctypes.c_void_p,
    netmask: int = DEFAULT_NETMASK,
    filter_exp: str = INDUSTRIAL_BPF_FILTER,
    optimize: int = 1,
) -> bool:
    """
    Compiles and offloads the optimized Berkeley Packet Filter matrix directly to the kernel VM.
    """
    if not pcap_handle:
        raise ValueError("Invalid NULL pcap_handle provided to inject_kernel_bpf")

    lib = load_pcap_library()
    prog = bpf_program()
    encoded = filter_exp.encode("utf-8")

    compile_res = lib.pcap_compile(
        pcap_handle,
        ctypes.byref(prog),
        encoded,
        optimize,
        c_uint32(netmask),
    )

    if compile_res != 0:
        err_msg = lib.pcap_geterr(pcap_handle).decode("utf-8", errors="replace")
        raise PcapAdapterError(f"Kernel BPF compilation failure: {err_msg}")

    try:
        filter_res = lib.pcap_setfilter(pcap_handle, ctypes.byref(prog))
        if filter_res != 0:
            err_msg = lib.pcap_geterr(pcap_handle).decode("utf-8", errors="replace")
            raise PcapAdapterError(f"libpcap.pcap_setfilter kernel offload failed: {err_msg}")
        return True
    finally:
        if hasattr(lib, "pcap_freecode"):
            lib.pcap_freecode(ctypes.byref(prog))


def inspect_bpf_bytecode(prog: bpf_program) -> List[Dict[str, Any]]:
    """
    Disassembles the raw bpf_insn array into a structured diagnostic trace.
    """
    instructions: List[Dict[str, Any]] = []
    if not prog.bf_insns or prog.bf_len == 0:
        return instructions

    for idx in range(prog.bf_len):
        insn = prog.bf_insns[idx]
        instructions.append({
            "step": idx,
            "code": hex(insn.code),
            "jt": insn.jt,
            "jf": insn.jf,
            "k": hex(insn.k),
            "k_int": insn.k,
        })
    return instructions


def verify_8021q_vlan_offsets(filter_exp: str = INDUSTRIAL_BPF_FILTER) -> Dict[str, Any]:
    """
    Stress-tests the compiled BPF bytecode to ensure explicit handling of 802.1Q VLAN headers.
    """
    lib = load_pcap_library()
    prog, dead_handle = compile_bpf_filter(filter_exp)

    try:
        bytecode = inspect_bpf_bytecode(prog)

        has_vlan_check = any(insn["k_int"] == 0x8100 for insn in bytecode)
        has_profinet_check = any(insn["k_int"] == 0x8892 for insn in bytecode)
        has_modbus_check = any(insn["k_int"] == 502 for insn in bytecode)
        has_cip_check = any(insn["k_int"] == 44818 for insn in bytecode)
        has_enip_io_check = any(insn["k_int"] == 2222 for insn in bytecode)
        profinet_checks_count = sum(1 for insn in bytecode if insn["k_int"] == 0x8892)

        is_valid = (
            has_vlan_check and
            has_profinet_check and
            has_modbus_check and
            has_cip_check and
            has_enip_io_check and
            profinet_checks_count >= 2
        )

        return {
            "valid": is_valid,
            "total_instructions": prog.bf_len,
            "has_vlan_8021q_check": has_vlan_check,
            "has_profinet_check": has_profinet_check,
            "profinet_checks_count": profinet_checks_count,
            "has_modbus_check": has_modbus_check,
            "has_cip_check": has_cip_check,
            "has_enip_io_check": has_enip_io_check,
        }
    finally:
        if hasattr(lib, "pcap_freecode"):
            lib.pcap_freecode(ctypes.byref(prog))
        if hasattr(lib, "pcap_close"):
            lib.pcap_close(dead_handle)

