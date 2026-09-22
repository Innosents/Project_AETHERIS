import asyncio
import pytest
from aetheris.core.probers.mercury_msp_parser import MSPParser
from tests.mocks.mercury_mp1502_emulator import handle_client

@pytest.mark.asyncio
async def test_msp_parser_extraction():
    # Spin up the mercury_mp1502_emulator.py daemon logic
    server = await asyncio.start_server(handle_client, '127.0.0.1', 3001)
    
    # Let the server bind fully
    await asyncio.sleep(0.1)
    
    try:
        # Execute the production mercury_msp_parser.py against 127.0.0.1:3001
        parser = MSPParser(host='127.0.0.1', port=3001)
        result = await parser.extract_dark_inventory()
        
        # Assert that the resulting dictionary perfectly matches {'readers': 2, 'rex': 2, 'strikes': 2, 'dps': 2}
        assert result == {'readers': 2, 'rex': 2, 'strikes': 2, 'dps': 2}
        
    finally:
        # Teardown the emulator
        server.close()
        await server.wait_closed()

