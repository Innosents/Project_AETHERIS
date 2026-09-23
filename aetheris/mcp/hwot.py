"""
Project AETHERIS - Hardware OT (HWOT) Loopback Simulator Engine
Provides ephemeral mock loopback responders for industrial protocols
(EtherNet/IP CIP, Siemens S7Comm ISO-on-TCP) conforming to HwotSimulatorPort.
"""

import socket
import struct
import threading
from typing import Any, Dict, List, Optional
from aetheris.core.ports.hwot_port import (
    HwotSimulatorPort,
    HwotServerStatus,
    HwotTerminationResult,
    _MappingCompatibleModel,
)

ACTIVE_SERVERS: Dict[int, threading.Event] = {}


def _run_cip_server(port: int, stop_event: threading.Event):
    """Spawns an RFC/ODVA CIP ListIdentity mock responder."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue

        try:
            data = conn.recv(1024)
            if len(data) >= 24:
                cmd, length, session, status, ctx, opts = struct.unpack(
                    "<HHII8sI", data[:24]
                )
                if cmd == 0x0063:  # ListIdentity command
                    product_name = b"1769-L33ER/A LOGIX5333ER"
                    item_data = struct.pack(
                        "<HHIHHBB16sBB",
                        0x000C,
                        len(product_name) + 29,
                        1,
                        0x000E,
                        1,
                        1,
                        33,
                        1,
                        b"\x00" * 16,
                        len(product_name),
                    )
                    item_data += product_name + b"\x00"

                    resp_header = struct.pack(
                        "<HHII8sI",
                        0x0063,
                        len(item_data) + 2,
                        session,
                        0,
                        ctx,
                        0,
                    )
                    full_resp = resp_header + struct.pack("<H", 1) + item_data
                    conn.sendall(full_resp)
        except Exception:
            pass
        finally:
            conn.close()
    sock.close()


def _run_s7_server(port: int, stop_event: threading.Event):
    """Spawns an RFC 1006 / Siemens S7Comm mock responder."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue

        try:
            while not stop_event.is_set():
                data = conn.recv(1024)
                if not data:
                    break

                if len(data) >= 7 and data[5] == 0xE0:
                    cotp_cc = bytes([
                        0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01,
                        0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
                        0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
                    ])
                    conn.sendall(cotp_cc)
                elif len(data) >= 10 and data[7] == 0x32:
                    rosctr = data[8]
                    if rosctr == 0x01:
                        resp = (
                            bytes([
                                0x03, 0x00, 0x00, 0x38, 0x02, 0xF0, 0x80,
                                0x32, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
                                0x08, 0x00, 0x1C, 0x00, 0x00,
                            ])
                            + b"6ES7 214-1AG40-0XB0 "
                            + b"V04.05.01"
                        )
                        conn.sendall(resp)
        except Exception:
            pass
        finally:
            conn.close()
    sock.close()


class HwotSimulatorEngine(HwotSimulatorPort):
    """Simulator engine implementing HwotSimulatorPort."""

    def spawn_cip_plc(self, port: int = 44818) -> HwotServerStatus:
        """Launch an ephemeral EtherNet/IP CIP PLC mock on 127.0.0.1."""
        if port in ACTIVE_SERVERS:
            return HwotServerStatus(
                status="ALREADY_RUNNING",
                protocol="CIP",
                port=port,
                emulated_device="Allen-Bradley 1769-L33ER"
            )

        stop_event = threading.Event()
        thread = threading.Thread(
            target=_run_cip_server, args=(port, stop_event), daemon=True
        )
        thread.start()
        ACTIVE_SERVERS[port] = stop_event
        return HwotServerStatus(
            status="RUNNING",
            protocol="CIP",
            port=port,
            emulated_device="Allen-Bradley 1769-L33ER"
        )

    def spawn_s7_plc(self, port: int = 10102) -> HwotServerStatus:
        """Launch an ephemeral Siemens S7Comm ISO-on-TCP mock on 127.0.0.1."""
        if port in ACTIVE_SERVERS:
            return HwotServerStatus(
                status="ALREADY_RUNNING",
                protocol="S7Comm",
                port=port,
                emulated_device="Siemens S7-1200 CPU 1214C"
            )

        stop_event = threading.Event()
        thread = threading.Thread(
            target=_run_s7_server, args=(port, stop_event), daemon=True
        )
        thread.start()
        ACTIVE_SERVERS[port] = stop_event
        return HwotServerStatus(
            status="RUNNING",
            protocol="S7Comm",
            port=port,
            emulated_device="Siemens S7-1200 CPU 1214C"
        )

    def kill_all(self) -> HwotTerminationResult:
        """Terminate all active loopback hardware simulators."""
        terminated = []
        for port, stop_event in list(ACTIVE_SERVERS.items()):
            stop_event.set()
            terminated.append(port)
            del ACTIVE_SERVERS[port]
        return HwotTerminationResult(terminated_ports=terminated)


default_hwot_engine = HwotSimulatorEngine()


def hwot_spawn_cip_plc(port: int = 44818) -> HwotServerStatus:
    return default_hwot_engine.spawn_cip_plc(port=port)


def hwot_spawn_s7_plc(port: int = 10102) -> HwotServerStatus:
    return default_hwot_engine.spawn_s7_plc(port=port)


def hwot_kill_all() -> HwotTerminationResult:
    return default_hwot_engine.kill_all()


__all__ = [
    "HwotSimulatorEngine",
    "HwotSimulatorPort",
    "HwotServerStatus",
    "HwotTerminationResult",
    "default_hwot_engine",
    "hwot_spawn_cip_plc",
    "hwot_spawn_s7_plc",
    "hwot_kill_all",
    "ACTIVE_SERVERS",
    "_MappingCompatibleModel",
]

