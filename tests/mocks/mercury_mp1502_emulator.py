"""
Project AETHERIS - Mercury MP1502 Hardware Emulator Mock
Accurately emulates an asynchronous Mercury Security MP1502 / LP1502 access control panel
operating on TCP Port 3001. Handles diagnostic edge-case payloads, binary inquiries,
STX/ETX tokenized status framing, and asynchronous hardware state transitions.
"""

import asyncio
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [MP1502_EMULATOR] - %(message)s')


class MercuryHardwareState:
    ONLINE_READY = "ONLINE_READY"
    ALARM_DOOR_FORCED = "ALARM_DOOR_FORCED"
    TAMPER_ENCLOSURE = "TAMPER_ENCLOSURE"
    LOCKDOWN_ACTIVE = "LOCKDOWN_ACTIVE"
    MAINTENANCE_MODE = "MAINTENANCE_MODE"


class MercuryMP1502Emulator:
    """
    Asynchronous hardware mock for Mercury Security MP1502 Access Controller.
    Supports live hardware state transitions, fragmented network delivery,
    and protocol responses for both ASCII MSP framing and binary status inquiries.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3001,
        readers: int = 2,
        rex: int = 2,
        strikes: int = 2,
        dps: int = 2,
        initial_state: str = MercuryHardwareState.ONLINE_READY,
    ):
        self.host = host
        self.port = port
        self.readers = readers
        self.rex = rex
        self.strikes = strikes
        self.dps = dps
        self.state = initial_state
        self.server: Optional[asyncio.Server] = None
        self._is_running = False

    def transition_state(self, new_state: str) -> None:
        """Asynchronously transitions controller operational status."""
        logging.info(f"[MP1502] State Transition: {self.state} -> {new_state}")
        self.state = new_state

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info('peername')
        logging.info(f"TCP connection accepted from {client_addr}")

        try:
            # Fragmented MSP payload injection simulating network congestion / MTU fragmentation
            # Matches dark-inventory discovery requirements (R2_X2_S2_D2)
            payload_chunk_1 = f"\x02MP1502_V129_{self.state}_R{self.readers}_".encode("utf-8")
            payload_chunk_2 = f"X{self.rex}_S{self.strikes}_D{self.dps}\x03\r\n".encode("utf-8")

            logging.info("Transmitting fragment 1 (STX bound)...")
            writer.write(payload_chunk_1)
            await writer.drain()

            # Micro-yield to force parser buffer accumulation across L2 fragments
            await asyncio.sleep(0.05)

            logging.info("Transmitting fragment 2 (ETX bound)...")
            writer.write(payload_chunk_2)
            await writer.drain()

            # Read client commands or acknowledgment
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                except asyncio.TimeoutError:
                    break

                if not data:
                    break

                # Case 1: AETHERIS Positive ACK sequence
                if data == b'\x02\x01\x04\x03':
                    logging.info("HANDSHAKE VERIFIED. Positive ACK sequence ingested.")
                    break

                # Case 2: Phase 3 Diagnostic Probe (b"\x02STATUS\x03")
                elif b"STATUS" in data:
                    diag_resp = (
                        f"\x02MP1502_V129_{self.state}_R{self.readers}_X{self.rex}_S{self.strikes}_D{self.dps}\x03\r\n"
                    ).encode("utf-8")
                    writer.write(diag_resp)
                    await writer.drain()
                    break

                # Case 3: Binary Status Inquiry (b"\x00\x10\x00\x01\x00\x00\x00\x00\xff\xff")
                elif len(data) >= 4 and data[:2] == b"\x00\x10":
                    # Respond with valid binary status framing containing model code 0x02 (LP1502/MP1502)
                    binary_resp = b"\x02\x02\x01\x29" + b"MP1502 V1.29.1" + b"\x00\x00\x03"
                    writer.write(binary_resp)
                    await writer.drain()
                    break

                # Case 4: Binary Envelope (0xFFFE framing)
                elif len(data) >= 2 and data[:2] == b"\xFF\xFE":
                    env_resp = b"\xFF\xFE\x00\x01\x00\x00\x02MP1502_ONLINE_READY\x03"
                    writer.write(env_resp)
                    await writer.drain()
                    break

        except Exception as e:
            logging.error(f"Error handling MP1502 client: {e}")
        finally:
            # Strict L4 teardown
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# Global singleton instance for module-level handle_client compatibility
_default_emulator = MercuryMP1502Emulator()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Module-level entrypoint for existing test suites."""
    await _default_emulator.handle_client(reader, writer)


async def main():
    host, port = '127.0.0.1', 3001
    server = await asyncio.start_server(handle_client, host, port)
    logging.info(f"MP1502 Daemon bound to {host}:{port}. Awaiting telemetry polling.")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("MP1502 Emulator gracefully terminated.")