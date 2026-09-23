import asyncio
import json
import sys
from aetheris.core.probers.base_probe import BaseAetherisProbe
# Adjust this import path if your directory structure differs
from aetheris.core.probers.l2_physical.chassis_intelligence_probe import ChassisIntelligenceProbe

async def execute_l2_ingestion():
    """Asynchronous execution matrix for the passive L2 chassis probe."""
    
    # 1. Define the telemetry context. 
    # Mutate "span_interface" to "eth0" if executing inside WSL natively, 
    # or "vEthernet (WSL)" if executing via Windows PowerShell.
    telemetry_context = {
        "span_interface": "eth0", 
        "capture_duration_sec": 65.0
    }
    
    print(f"[*] Initializing AETHERIS ChassisIntelligenceProbe on interface: {telemetry_context['span_interface']}...")
    print(f"[*] Awaiting multicast beacons for {telemetry_context['capture_duration_sec']} seconds...")
    
    # 2. Instantiate the probe 
    # (Target IP is 0.0.0.0 as passive multicast ingestion does not target a specific L3 address)
    probe = ChassisIntelligenceProbe("0.0.0.0", telemetry_context)
    
    # 3. Await the execution payload
    try:
        result_matrix = await probe.execute()
        
        # 4. Output the extracted TLV dictionary
        print("\n[+] L2 Telemetry Extraction Complete:")
        print(json.dumps(result_matrix, indent=4))
        
    except Exception as e:
        print(f"\n[-] Critical Exception during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Ensure Windows asyncio compatibility if running natively on Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(execute_l2_ingestion())