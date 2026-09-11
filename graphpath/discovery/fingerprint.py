import re

def fingerprint_device(ip: str, mac: str, open_ports: list, banners: dict, services: list) -> dict:
    """
    Analyzes port patterns and banner signatures to accurately classify hardware.
    Optimized to eliminate nested classification overrides.
    """
    vendor = "Unknown Vendor"
    device_type = "unknown"
    model = "Generic Device"

    # 0. Hardware MAC OUI Fast Match
    if mac and mac != "00:00:00:00:00:00":
        clean_mac = mac.replace(":", "").replace("-", "").upper()[:6]
        try:
            from core.device_classifier import DeviceClassifier
            if clean_mac in DeviceClassifier.OUI_DB:
                oui_info = DeviceClassifier.OUI_DB[clean_mac]
                vendor = oui_info.get("vendor", vendor)
                device_type = oui_info.get("type", device_type)
                model = oui_info.get("model", model)
        except Exception:
            pass

    # Compile a composite banner string for string matching lookups
    all_banners = " ".join([str(v) for v in banners.values()]).lower()

    # Rule 0.5: Enterprise VoIP, Telephony & PBX Signatures
    if 5060 in open_ports or 5061 in open_ports or "sip" in services or "asterisk" in all_banners or "freepbx" in all_banners or "3cx" in all_banners or "grandstream" in all_banners or "yealink" in all_banners:
        is_pbx = any(k in all_banners for k in ["asterisk", "freepbx", "3cx", "ucm", "pbx", "issabel", "elastix", "switchvox"])
        if is_pbx:
            device_type = "voip_pbx"
            if "asterisk" in all_banners:
                vendor = "Asterisk / Digium"
                model = "Asterisk IP PBX Core"
            elif "freepbx" in all_banners:
                vendor = "Sangoma"
                model = "FreePBX Telephony Server"
            elif "3cx" in all_banners:
                vendor = "3CX"
                model = "3CX Phone System"
            elif "grandstream" in all_banners or "ucm" in all_banners:
                vendor = "Grandstream Networks"
                model = "Grandstream UCM IP PBX"
            else:
                vendor = "IP PBX Core"
                model = "Enterprise VoIP PBX Server"
        else:
            device_type = "voip_phone"
            if "grandstream" in all_banners or "trackid" in all_banners:
                vendor = "Grandstream Networks"
                if "gxp2130" in all_banners: model = "Grandstream GXP2130 HD IP Phone"
                elif "gxp" in all_banners: model = "Grandstream GXP Enterprise Phone"
                elif "grp" in all_banners: model = "Grandstream GRP Carrier-Grade Phone"
                else: model = "Grandstream Enterprise IP Phone"
            elif "yealink" in all_banners:
                vendor = "Yealink"
                if "t46" in all_banners or "t48" in all_banners: model = "Yealink SIP-T46S / T48S IP Phone"
                elif "t54" in all_banners: model = "Yealink SIP-T54W Smart IP Phone"
                else: model = "Yealink Enterprise IP Phone"
            elif "cisco" in all_banners or "cp-" in all_banners:
                vendor = "Cisco Systems"
                if "7841" in all_banners: model = "Cisco IP Phone CP-7841"
                elif "8841" in all_banners or "8845" in all_banners: model = "Cisco IP Phone CP-8841/8845"
                else: model = "Cisco Unified IP Phone"
            elif "polycom" in all_banners or "poly" in all_banners:
                vendor = "Polycom / Poly"
                model = "Polycom VVX IP Phone"
            else:
                vendor = "Unknown Vendor"
                model = "Generic VoIP Endpoint"
    elif "fortigate" in all_banners or "fortinet" in all_banners:
        device_type = "firewall"
        vendor = "Fortinet"
        model = "FortiGate Security Gateway"

    # Rule 1: Infrastructure Router & Gateway Isolation Matrix
    if any(p in open_ports for p in [53, 1900]):
        if any(b in all_banners for b in ["dnsmasq", "ubiquiti", "mikrotik", "cisco"]):
            device_type = "router"
            model = "Gateway Router"
            
    # Corrected: Decoupled to correctly identify routers that expose only web management frameworks
    if device_type == "unknown" and (80 in open_ports or 443 in open_ports):
        if any(b in all_banners for b in ["linksys", "netgear", "tp-link", "asuswrt"]):
            device_type = "router"
            model = "SOHO Gateway"

    # Rule 2: Managed Core Switch & Cisco PoE Access Switches
    if (22 in open_ports and 161 in open_ports) or "catalyst" in all_banners or "cisco-ios" in all_banners:
        device_type = "switch"
        vendor = "Cisco Systems"
        if "9300" in all_banners:
            model = "Catalyst 9300-48P PoE+ Access Switch"
        elif "3850" in all_banners:
            model = "Catalyst 3850-24P PoE+ Access Switch"
        else:
            model = "Cisco Catalyst Managed Switch"

    # Rule 3: Smart Streaming Media, Print Servers & Edge Camera / NVR Interrogation
    if 38880 in open_ports or 38881 in open_ports or "avigilon" in all_banners:
        device_type = "nvr"
        vendor = "Avigilon"
        if "hd-nvr5" in all_banners or "nvr5" in all_banners:
            model = "ACC HD-NVR5-PRM 96TB"
        elif "hd-nvr4-prm" in all_banners:
            model = "ACC HD-NVR4-PRM 64TB"
        elif "hd-nvr4-std" in all_banners:
            model = "ACC HD-NVR4-STD 32TB"
        elif "enterprise" in all_banners:
            model = "ACC Enterprise Master Archive Server 128TB"
        elif "standby" in all_banners or "failover" in all_banners:
            model = "ACC NVR5-STD (Failover Standby)"
        else:
            model = "Avigilon Control Center (ACC) NVR"
    elif 37777 in open_ports or ("nvr" in all_banners and "tiandy" in all_banners):
        device_type = "nvr"
        vendor = "Tiandy Technologies"
        model = "Tiandy Super NVR"
    elif 554 in open_ports or "onvif" in services:
        device_type = "camera"
        if "axis" in all_banners:
            vendor = "Axis Communications"
            if "m3046" in all_banners: model = "AXIS M3046-V Mini Dome 4MP"
            elif "p3245-lve" in all_banners: model = "AXIS P3245-LVE Outdoor Dome"
            elif "p3245" in all_banners: model = "AXIS P3245-V Indoor Dome 1080p"
            elif "q3518" in all_banners: model = "AXIS Q3518-LVE High-Performance 4K Dome"
            elif "p1448" in all_banners: model = "AXIS P1448-LE Outdoor 4K Bullet"
            elif "p1455" in all_banners: model = "AXIS P1455-LE HD Bullet"
            elif "m1137" in all_banners: model = "AXIS M1137-E CS-Mount Box Camera"
            elif "q6075" in all_banners: model = "AXIS Q6075-E 30x Optical Zoom PTZ"
            elif "q6135" in all_banners: model = "AXIS Q6135-LE High-Speed IR PTZ"
            elif "m5075" in all_banners: model = "AXIS M5075-G Ceiling Mini PTZ"
            elif "p5655" in all_banners: model = "AXIS P5655-E Continuous 360° PTZ"
            elif "q1656" in all_banners: model = "AXIS Q1656-LE AI DLPU Analytics Box"
            elif "q1786" in all_banners: model = "AXIS Q1786-LE 32x Zoom 4MP Bullet"
            elif "p3719" in all_banners: model = "AXIS P3719-PLE Quad 15MP Panoramic"
            elif "m3057" in all_banners: model = "AXIS M3057-PLVE 6MP Fisheye Panoramic"
            elif "q8752" in all_banners: model = "AXIS Q8752-E Bi-Spectral Thermal PTZ"
            elif "q1942" in all_banners: model = "AXIS Q1942-E Thermal Perimeter Sensor"
            elif "fa54" in all_banners: model = "AXIS FA54 Modular Covert Unit"
            elif "p8815" in all_banners: model = "AXIS P8815-2 3D People Counting Sensor"
            elif "i8016" in all_banners: model = "AXIS I8016-LVE Video Intercom"
            else: model = "AXIS Network Camera"
        elif "tiandy" in all_banners:
            vendor = "Tiandy Technologies"
            model = "Tiandy IP Camera"
        else:
            vendor = "Generic Camera"
            model = "IP Security Camera"
    elif 9100 in open_ports or 515 in open_ports:
        device_type = "printer"
        model = "Network Office Printer"
    elif "linux" in all_banners and (8080 in open_ports or 9000 in open_ports):
        device_type = "iot"
        model = "Smart Embedded Appliance"

    # Rule 4: Access Control & Physical Security Panels
    if 3001 in open_ports or 23001 in open_ports or "mercury" in all_banners or "mp1502" in all_banners:
        device_type = "access_control"
        vendor = "Mercury Security"
        model = "Mercury MP1502 Controller"

    # Rule 5: Industrial Automation PLCs, PACs & HMIs
    if 102 in open_ports or "siemens" in all_banners or "s7-1200" in all_banners or "s7comm" in all_banners:
        device_type = "plc"
        vendor = "Siemens"
        model = "SIMATIC S7-1200 PLC (CPU 1214C)"
    elif 8088 in open_ports and (4840 in open_ports or 8043 in open_ports or "ignition" in all_banners):
        device_type = "server"
        vendor = "Inductive Automation"
        model = "Ignition SCADA Gateway v8.1"
    elif 44818 in open_ports or 8088 in open_ports or "panelview" in all_banners or "factorytalk" in all_banners:
        device_type = "hmi"
        vendor = "Rockwell Automation"
        model = "PanelView 5510 Industrial HMI"
    elif "moxa" in all_banners or 4800 in open_ports or "eds-510" in all_banners:
        device_type = "switch"
        vendor = "Moxa Technologies"
        model = "EDS-510E Industrial Managed Switch"
    elif 502 in open_ports or 10502 in open_ports or 20502 in open_ports or "modbus" in all_banners:
        device_type = "plc"
        if "schneider" in all_banners or "bmx" in all_banners or "factorycast" in all_banners:
            vendor = "Schneider Electric"
            model = "Modicon M340 PAC"
        elif "rockwell" in all_banners or "micro850" in all_banners or "allen-bradley" in all_banners:
            vendor = "Rockwell Automation"
            model = "Micro850 Modbus/TCP PLC"
        else:
            vendor = "Industrial Automation"
            model = "Modbus/TCP Programmable Logic Controller"

    # Rule 6: Dedicated Enterprise Server Detection & Workstations
    if 5985 in open_ports or 5986 in open_ports or (135 in open_ports and 445 in open_ports) or 3389 in open_ports or "microsoft" in all_banners or "wsman" in all_banners or "windows" in all_banners:
        device_type = "workstation"
        vendor = "Microsoft Corporation"
        if "lenovo" in all_banners or "thinkcentre" in all_banners:
            vendor = "Lenovo"
            model = "ThinkCentre M900 (Windows 11)"
        elif "dell" in all_banners or "optiplex" in all_banners:
            vendor = "Dell Technologies"
            model = "Dell OptiPlex Desktop"
        elif "hp" in all_banners or "prodesk" in all_banners:
            vendor = "HP Inc."
            model = "HP EliteDesk / ProDesk PC"
        else:
            model = "Windows Enterprise Workstation"

    if any(p in open_ports for p in [111, 2049, 3306, 5432, 27017, 8000]):
        device_type = "server"
        if "nginx" in all_banners:
            vendor = "Nginx Web Infrastructure"
        elif "apache" in all_banners:
            vendor = "Apache Software Foundation"
        model = "Enterprise Database/Web Server"

    # Rule 7: Mobile Devices, Tablets & Industrial Handhelds
    # Use strict boundary/token checks so NetBIOS, BIOS, Cisco IOS, or audio streams do not falsely match 'ios'
    is_windows_active = (135 in open_ports or 445 in open_ports or 5985 in open_ports or 3389 in open_ports or "windows" in all_banners)
    is_ios_match = (
        "iphone" in all_banners
        or "_apple-mobdev" in all_banners
        or (bool(re.search(r'\b(?:ios\s*(?:\d+|device|sdk)?|apple-mobdev)\b', all_banners)) and not any(k in all_banners for k in ["netbios", "cisco ios", "cisco-ios", "bios", "audiostream", "scenarios"]))
    )
    if is_ios_match and not is_windows_active:
        device_type = "mobile_ios"
        vendor = "Apple Inc."
        model = "Apple iPhone"
    elif "ipad" in all_banners and not is_windows_active:
        device_type = "tablet"
        vendor = "Apple Inc."
        model = "Apple iPad"
    elif ("android" in all_banners or "googlecast" in all_banners or "chromecast" in all_banners) and not is_windows_active:
        device_type = "mobile_android"
        vendor = "Google LLC"
        model = "Android Mobile/Smart Device"
    elif "zebra" in all_banners or "symbol" in all_banners:
        device_type = "industrial_mobile"
        vendor = "Zebra Technologies"
        model = "Zebra Industrial Mobile Scanner"
    elif "honeywell" in all_banners or "dolphin" in all_banners:
        device_type = "industrial_mobile"
        vendor = "Honeywell"
        model = "Honeywell Industrial Mobile Computer"

    # Rule 8: Portable Laptops
    if "macbook" in all_banners:
        device_type = "laptop"
        vendor = "Apple Inc."
        model = "Apple MacBook Pro/Air"
    elif "thinkpad" in all_banners:
        device_type = "laptop"
        vendor = "Lenovo"
        model = "Lenovo ThinkPad Laptop"
    elif "surface" in all_banners:
        device_type = "laptop"
        vendor = "Microsoft Corporation"
        model = "Microsoft Surface Laptop/Pro"
    elif "latitude" in all_banners or "xps" in all_banners or "inspiron" in all_banners:
        device_type = "laptop"
        vendor = "Dell Technologies"
        model = "Dell Latitude/XPS Laptop"
    elif "elitebook" in all_banners or "probook" in all_banners:
        device_type = "laptop"
        vendor = "HP Inc."
        model = "HP EliteBook/ProBook Laptop"
    elif "laptop" in all_banners:
        device_type = "laptop"
        model = "Portable Laptop"

    # Rule 9: Routers, Mesh Satellites & Wi-Fi Extenders
    if "extender" in all_banners or "repeater" in all_banners or "re200" in all_banners or "re450" in all_banners:
        device_type = "wifi_extender"
        vendor = "TP-Link" if "tp-link" in all_banners else "Wi-Fi Infrastructure"
        model = "Wi-Fi Range Extender / Booster"
    elif "orbi satellite" in all_banners or ("satellite" in all_banners and "orbi" in all_banners):
        device_type = "wifi_extender"
        vendor = "Netgear"
        model = "Netgear Orbi Mesh Satellite"
    elif "deco" in all_banners or ("tp-link" in all_banners and "mesh" in all_banners):
        device_type = "router"
        vendor = "TP-Link"
        model = "TP-Link Deco Mesh Unit"
    elif "nighthawk" in all_banners:
        device_type = "router"
        vendor = "Netgear"
        model = "Netgear Nighthawk Gateway"
    elif "eero" in all_banners:
        device_type = "router"
        vendor = "Amazon Eero"
        model = "Eero Mesh Node"
    elif "routeros" in all_banners or "mikrotik" in all_banners:
        device_type = "router"
        vendor = "MikroTik"
        model = "MikroTik RouterOS Gateway"
    elif "unifi" in all_banners:
        device_type = "wlan_ap"
        vendor = "Ubiquiti Networks"
        model = "Ubiquiti UniFi AP"

    # Rule 10: ISP TV Set-Top Boxes & Smart TVs
    if "arris" in all_banners or "vip56" in all_banners or "vip78" in all_banners or "vip22" in all_banners or "stb" in all_banners or "iptv" in all_banners:
        device_type = "stb"
        if "arris" in all_banners or "vip" in all_banners: vendor = "ARRIS / CommScope"
        elif "technicolor" in all_banners: vendor = "Technicolor"
        elif "sagemcom" in all_banners: vendor = "Sagemcom"
        elif "humax" in all_banners: vendor = "Humax"
        elif "tivo" in all_banners: vendor = "TiVo Inc."
        model = "ISP TV Set-Top Box / Receiver"
    elif "technicolor" in all_banners and "stb" in all_banners:
        device_type = "stb"
        vendor = "Technicolor"
        model = "Technicolor Set-Top Box"
    elif "smarttv" in all_banners or "webostv" in all_banners or "tizen" in all_banners or "bravia" in all_banners or "vizio" in all_banners or "smart-tv" in all_banners:
        device_type = "smart_tv"
        if "bravia" in all_banners: vendor = "Sony"
        elif "webos" in all_banners or "lg" in all_banners: vendor = "LG Electronics"
        elif "tizen" in all_banners or "samsung" in all_banners: vendor = "Samsung Electronics"
        elif "vizio" in all_banners: vendor = "Vizio"
        elif "tcl" in all_banners: vendor = "TCL"
        elif "hisense" in all_banners: vendor = "Hisense"
        model = "Smart TV"
    elif "roku" in all_banners:
        device_type = "media_device"
        vendor = "Roku Inc."
        model = "Roku Streaming Player"
    elif "firetv" in all_banners or "aft" in all_banners:
        device_type = "media_device"
        vendor = "Amazon"
        model = "Amazon Fire TV Device"

    result = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "type": device_type,
        "model": model,
        "open_ports": open_ports,
        "banners": banners,
        "services": services,
        "discovery_method": "heuristic_dna_fingerprint",
        "hw_vendor": vendor if mac and mac != "00:00:00:00:00:00" else None
    }
    return result