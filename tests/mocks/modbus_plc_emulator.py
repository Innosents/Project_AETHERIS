import asyncio
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [MODBUS_PLC_EMULATOR] - %(message)s')

async def handle_modbus_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client_addr = writer.get_extra_info('peername')
    logging.info(f"ICS Connection established from {client_addr}")

    try:
        while True:
            # Modbus TCP Application Data Unit (ADU) standard length
            request = await reader.read(256)
            if not request:
                break
            
            # Extract Modbus Application Protocol (MBAP) Header
            transaction_id = request[0:2]
            protocol_id = request[2:4]
            unit_id = request[6:7]
            function_code = request[7]

            if function_code == 0x2B:  # FC 43: Read Device Identification
                logging.info("FC 0x2B intercepted. Returning Schneider Modicon M221 morphology.")
                # Mock encapsulated response: VendorName (Schneider), ProductCode (M221)
                response = transaction_id + protocol_id + b'\x00\x1a' + unit_id + b'\x2b\x0e\x01\x83\x00\x00\x02\x00\x09Schneider\x01\x04M221'
                writer.write(response)
                await writer.drain()

            elif function_code == 0x03:  # FC 03: Read Holding Registers
                logging.info("FC 0x03 intercepted. Returning 4-20mA sensor arrays.")
                # Mock register values for 4 downstream sensors (e.g., flow meters)
                response = transaction_id + protocol_id + b'\x00\x0b' + unit_id + b'\x03\x08\x01\xf4\x01\xf5\x01\xf6\x01\xf7'
                writer.write(response)
                await writer.drain()
            else:
                logging.warning(f"Unexpected Function Code: {hex(function_code)}")
    
    except Exception as e:
        logging.error(f"Emulator fault: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        logging.info("ICS Connection cleanly terminated.")

async def main():
    host, port = '127.0.0.1', 5020
    server = await asyncio.start_server(handle_modbus_client, host, port)
    logging.info(f"Modicon PLC Daemon bound to {host}:{port}. Awaiting read-only interrogation.")
    
    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        pass

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Modbus PLC Emulator gracefully terminated.")