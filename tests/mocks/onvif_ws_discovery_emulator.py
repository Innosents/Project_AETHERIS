import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ONVIF_WS_Discovery_Emulator")

def generate_probe_match(manufacturer, ip):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <env:Header>
    <wsdd:MessageID>uuid:12345678-1234-1234-1234-123456789012</wsdd:MessageID>
    <wsdd:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsdd:To>
    <wsdd:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsdd:Action>
  </env:Header>
  <env:Body>
    <wsdd:ProbeMatches>
      <wsdd:ProbeMatch>
        <wsdd:EndpointReference>
          <wsdd:Address>urn:uuid:mock-{manufacturer.lower()}-1</wsdd:Address>
        </wsdd:EndpointReference>
        <wsdd:Types>tds:Device</wsdd:Types>
        <wsdd:Scopes>onvif://www.onvif.org/name/SimulatedCamera onvif://www.onvif.org/hardware/V1 onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/Manufacturer/{manufacturer}</wsdd:Scopes>
        <wsdd:XAddrs>http://{ip}/onvif/device_service</wsdd:XAddrs>
        <wsdd:MetadataVersion>1</wsdd:MetadataVersion>
      </wsdd:ProbeMatch>
    </wsdd:ProbeMatches>
  </env:Body>
</env:Envelope>
""".encode('utf-8')


class WSDiscoveryProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"ONVIF WS-Discovery emulator listening on {transport.get_extra_info('sockname')}")

    def datagram_received(self, data, addr):
        msg = data.decode('utf-8', errors='ignore')
        logger.info(f"Received probe from {addr}")
        
        if "Probe" in msg:
            logger.info(f"Responding to WS-Discovery probe from {addr} with Axis/Avigilon payloads.")
            self.transport.sendto(generate_probe_match("Axis", "192.168.1.50"), addr)
            self.transport.sendto(generate_probe_match("Avigilon", "192.168.1.51"), addr)

async def start_onvif_server(host="127.0.0.1", port=33702):
    loop = asyncio.get_running_loop()
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: WSDiscoveryProtocol(),
        local_addr=(host, port)
    )
    
    try:
        # Run emulator for test phase (normally would serve_forever)
        await asyncio.sleep(5)
    finally:
        transport.close()
        logger.info("ONVIF Emulator shutdown.")

if __name__ == "__main__":
    try:
        asyncio.run(start_onvif_server())
    except KeyboardInterrupt:
        logger.info("ONVIF Emulator interrupted.")

