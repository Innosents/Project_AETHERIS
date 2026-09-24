"""
Project AETHERIS - Unit Tests for Infrastructure Adapters: PCAP & Kernel BPF Offload
Tests ctypes memory structures, Npcap NDIS LWF bindings, zero-copy O(1) frame dissection,
and dependency inversion across domain boundaries.
"""

import ctypes
import socket
import unittest

from aetheris.infrastructure.adapters.pcap_capture_adapter import (
    EthernetHeader,
    VLANHeader,
    MBAPHeader,
    ProfinetIRTHeader,
    bpf_insn,
    bpf_program,
    compile_bpf_filter,
    verify_8021q_vlan_offsets,
    load_windows_capture_interface,
    dissect_frame_zero_copy,
    INDUSTRIAL_BPF_FILTER,
    PcapAdapterError,
    inject_kernel_bpf,
)


class TestPcapCaptureAdapter(unittest.TestCase):
    """Verifies low-level ctypes BPF structures, Npcap NDIS bindings, and zero-copy dissectors."""

    def test_ethernet_header_memory_alignment(self):
        # 6 (dest_mac) + 6 (src_mac) + 2 (ethertype) = 14 bytes with _pack_ = 1
        self.assertEqual(ctypes.sizeof(EthernetHeader), 14)

        raw = (
            b"\x00\x11\x22\x33\x44\x55"  # Dest MAC
            b"\x66\x77\x88\x99\xAA\xBB"  # Src MAC
            b"\x88\x92"                  # EtherType: PROFINET (Big-Endian)
        )
        eth = EthernetHeader.from_buffer_copy(raw)
        self.assertEqual(eth.formatted_dest_mac, "00:11:22:33:44:55")
        self.assertEqual(eth.formatted_src_mac, "66:77:88:99:AA:BB")
        self.assertEqual(eth.ethertype_host, 0x8892)

    def test_vlan_header_memory_alignment(self):
        # 2 (tci) + 2 (encap_proto) = 4 bytes with _pack_ = 1
        self.assertEqual(ctypes.sizeof(VLANHeader), 4)

        # PCP = 5 (Voice/RT), DEI = 0, VID = 100 -> TCI = (5 << 13) | 100 = 0xA064
        # encap_proto = 0x8892 (PROFINET)
        tci_be = socket.htons(0xA064)
        proto_be = socket.htons(0x8892)
        raw = ctypes.string_at(ctypes.byref(ctypes.c_uint16(tci_be)), 2) + \
              ctypes.string_at(ctypes.byref(ctypes.c_uint16(proto_be)), 2)

        vlan = VLANHeader.from_buffer_copy(raw)
        self.assertEqual(vlan.vlan_id, 100)
        self.assertEqual(vlan.pcp, 5)
        self.assertEqual(vlan.encap_proto_host, 0x8892)

    def test_mbap_header_memory_alignment(self):
        # 2 (tx_id) + 2 (proto_id) + 2 (len) + 1 (unit_id) = 7 bytes with _pack_ = 1
        self.assertEqual(ctypes.sizeof(MBAPHeader), 7)

        raw = (
            b"\x00\x01"  # Transaction ID: 1
            b"\x00\x00"  # Protocol ID: 0 (Modbus)
            b"\x00\x06"  # Length: 6 bytes
            b"\x05"      # Unit ID: 5
        )
        mbap = MBAPHeader.from_buffer_copy(raw)
        self.assertEqual(mbap.transaction_id_host, 1)
        self.assertEqual(mbap.protocol_id_host, 0)
        self.assertEqual(mbap.length_host, 6)
        self.assertEqual(mbap.unit_id, 5)

    def test_profinet_irt_header_memory_alignment(self):
        # 2 (frame_id) = 2 bytes with _pack_ = 1
        self.assertEqual(ctypes.sizeof(ProfinetIRTHeader), 2)

        raw = b"\x01\x20"  # Frame ID: 0x0120 (IRT Frame ID)
        pnet = ProfinetIRTHeader.from_buffer_copy(raw)
        self.assertEqual(pnet.frame_id_host, 0x0120)

    def test_bpf_insn_ctypes_memory_alignment(self):
        # struct bpf_insn must be exactly 8 bytes (2 + 1 + 1 + 4)
        self.assertEqual(ctypes.sizeof(bpf_insn), 8)

        insn = bpf_insn(code=0x28, jt=0, jf=0, k=0x8892)
        self.assertEqual(insn.code, 0x28)
        self.assertEqual(insn.jt, 0)
        self.assertEqual(insn.jf, 0)
        self.assertEqual(insn.k, 0x8892)

    def test_bpf_program_ctypes_structure(self):
        prog = bpf_program()
        self.assertEqual(prog.bf_len, 0)
        self.assertFalse(bool(prog.bf_insns))

    def test_zero_copy_dissect_vlan_profinet_frame(self):
        # Construct synthetic VLAN-tagged PROFINET frame
        frame = bytearray()
        # Ethernet Header: Dest, Src, 802.1Q EtherType 0x8100
        frame.extend(b"\x01\x0E\xCF\x00\x00\x01\x00\x1B\x1B\x33\x44\x55\x81\x00")
        # VLAN Header: VID 20, Encap 0x8892
        tci_val = socket.htons(20)
        proto_val = socket.htons(0x8892)
        frame.extend(ctypes.string_at(ctypes.byref(ctypes.c_uint16(tci_val)), 2))
        frame.extend(ctypes.string_at(ctypes.byref(ctypes.c_uint16(proto_val)), 2))
        # PROFINET IRT Frame ID: 0x0200
        frame_id_val = socket.htons(0x0200)
        frame.extend(ctypes.string_at(ctypes.byref(ctypes.c_uint16(frame_id_val)), 2))

        result = dissect_frame_zero_copy(frame)
        self.assertTrue(result["is_vlan"])
        self.assertEqual(result["vlan_id"], 20)
        self.assertEqual(result["protocol"], "PROFINET_IRT")
        self.assertTrue(result["ot_metadata"]["is_irt"])
        self.assertEqual(result["ot_metadata"]["frame_id_int"], 0x0200)

    def test_zero_copy_dissect_modbus_tcp_frame(self):
        # Construct synthetic Ethernet -> IPv4 -> TCP (port 502) -> MBAP
        frame = bytearray()
        # Ethernet (14 bytes)
        frame.extend(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00")
        # IPv4 Header (20 bytes): IHL = 5, Proto = 6 (TCP)
        ip_hdr = bytearray(20)
        ip_hdr[0] = 0x45  # Version 4, IHL 5
        ip_hdr[9] = 6     # Protocol TCP
        frame.extend(ip_hdr)
        # TCP Header (20 bytes): src_port=502 (0x01F6), dst_port=49152 (0xC000), Data Offset = 5 (20 bytes)
        tcp_hdr = bytearray(20)
        tcp_hdr[0] = 0x01; tcp_hdr[1] = 0xF6  # src port 502
        tcp_hdr[2] = 0xC0; tcp_hdr[3] = 0x00  # dst port 49152
        tcp_hdr[12] = 0x50                    # Data offset 5
        frame.extend(tcp_hdr)
        # MBAP Header (7 bytes): Tx=42, Proto=0, Len=6, Unit=1
        frame.extend(b"\x00\x2A\x00\x00\x00\x06\x01")

        result = dissect_frame_zero_copy(frame)
        self.assertEqual(result["protocol"], "MODBUS_TCP")
        self.assertEqual(result["ot_metadata"]["transaction_id"], 42)
        self.assertEqual(result["ot_metadata"]["unit_id"], 1)

    def test_industrial_bpf_filter_compilation(self):
        prog, dead_handle = compile_bpf_filter(INDUSTRIAL_BPF_FILTER)
        try:
            self.assertGreater(prog.bf_len, 0)
            self.assertTrue(bool(prog.bf_insns))
        finally:
            from aetheris.infrastructure.adapters.pcap_capture_adapter import load_pcap_library
            lib = load_pcap_library()
            if hasattr(lib, "pcap_freecode"):
                lib.pcap_freecode(ctypes.byref(prog))
            if hasattr(lib, "pcap_close"):
                lib.pcap_close(dead_handle)

    def test_8021q_vlan_offsets_and_protocol_coverage(self):
        result = verify_8021q_vlan_offsets(INDUSTRIAL_BPF_FILTER)

        self.assertTrue(result["valid"])
        self.assertTrue(result["has_vlan_8021q_check"])
        self.assertTrue(result["has_profinet_check"])
        self.assertGreaterEqual(result["profinet_checks_count"], 2)
        self.assertTrue(result["has_modbus_check"])
        self.assertTrue(result["has_cip_check"])
        self.assertTrue(result["has_enip_io_check"])

    def test_load_windows_capture_interface_nonexistent_device(self):
        # Binding to an invalid device path must fail with a descriptive RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            load_windows_capture_interface(r"\Device\NPF_{NONEXISTENT_DEVICE_GUID_12345}")
        self.assertTrue(any(msg in str(ctx.exception) for msg in ["Failed to bind", "Npcap driver not found", "No such device", "Network is down", "pcap"]))

    def test_dependency_inversion_domain_purity(self):
        """
        Dependency Inversion Check:
        Asserts that aetheris.domain.models and aetheris.domain.math retain zero imports
        or references to wpcap, ctypes, socket, or infrastructure adapters.
        """
        from pathlib import Path
        import aetheris.domain.models.topology_states as top_mod
        import aetheris.domain.math.bayesian_anchors as math_mod

        for mod in (top_mod, math_mod):
            source = Path(mod.__file__).read_text(encoding="utf-8")
            for forbidden in ("wpcap", "pcap", "ctypes", "load_windows_capture_interface"):
                self.assertNotIn(
                    forbidden,
                    source,
                    f"Domain module {mod.__name__} violates dependency inversion by referencing {forbidden}",
                )


if __name__ == "__main__":
    unittest.main()
