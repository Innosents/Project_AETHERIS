"""
Project AETHERIS - ONVIF Surveillance Camera Reactive Prober (Port 80/8000/8080 SOAP Device Service)
Sends SOAP GetDeviceInformation requests to /onvif/device_service,
measures microsecond response latency, and extracts camera manufacturer, model, and firmware.
"""

import time
import re
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional

from graphpath.core.probers.sanitization import sanitize_prober_payload

ONVIF_SOAP_GET_DEVICE_INFORMATION = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    '<soap:Body>'
    '<tds:GetDeviceInformation/>'
    '</soap:Body>'
    '</soap:Envelope>'
)


def parse_onvif_device_information_xml(xml_content: str) -> Dict[str, str]:
    """
    Parses ONVIF GetDeviceInformationResponse XML payload.
    Extracts Manufacturer, Model, FirmwareVersion, SerialNumber, and HardwareId.
    Uses ElementTree with local-name tag matching and regex fallback for maximum resilience.
    """
    info = {
        "manufacturer": "",
        "model": "",
        "firmware": "",
        "serial": "",
        "hardware_id": ""
    }

    if not xml_content or not xml_content.strip():
        return info

    try:
        root = ET.fromstring(xml_content)
        # Search for elements regardless of XML namespace prefixes
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            tag_lower = tag.lower()
            text_val = (elem.text or "").strip()
            if not text_val:
                continue

            if tag_lower == "manufacturer":
                info["manufacturer"] = text_val
            elif tag_lower == "model":
                info["model"] = text_val
            elif tag_lower in ("firmwareversion", "firmware"):
                info["firmware"] = text_val
            elif tag_lower in ("serialnumber", "serial"):
                info["serial"] = text_val
            elif tag_lower in ("hardwareid", "hardware_id"):
                info["hardware_id"] = text_val
    except Exception:
        pass

    # Regex fallback if ElementTree missed fields due to non-standard or malformed XML
    if not info["manufacturer"]:
        m = re.search(r'<[^>]*Manufacturer[^>]*>([^<]+)<', xml_content, re.IGNORECASE)
        if m:
            info["manufacturer"] = m.group(1).strip()

    if not info["model"]:
        m = re.search(r'<[^>]*Model[^>]*>([^<]+)<', xml_content, re.IGNORECASE)
        if m:
            info["model"] = m.group(1).strip()

    if not info["firmware"]:
        m = re.search(r'<[^>]*FirmwareVersion[^>]*>([^<]+)<', xml_content, re.IGNORECASE)
        if m:
            info["firmware"] = m.group(1).strip()

    if not info["serial"]:
        m = re.search(r'<[^>]*SerialNumber[^>]*>([^<]+)<', xml_content, re.IGNORECASE)
        if m:
            info["serial"] = m.group(1).strip()

    return info


def probe_onvif_camera(ip: str, port: int = 80, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Sends SOAP GetDeviceInformation inquiry to ONVIF camera device service.
    Measures kernel response turnaround time using time.perf_counter_ns().

    Returns:
        Dict containing vendor, model, firmware, archetype='CCTV_VIDEO', and latency metrics.
        Returns empty dict {} on error or non-ONVIF responses.
    """
    url = f"http://{ip}:{port}/onvif/device_service"
    req_body = ONVIF_SOAP_GET_DEVICE_INFORMATION.encode("utf-8")
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Content-Length": str(len(req_body)),
        "User-Agent": "AETHERIS-Spatial-Discovery/1.0",
        "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"'
    }

    req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")

    try:
        t_start = time.perf_counter_ns()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                resp_bytes = response.read()
        except urllib.error.HTTPError as http_err:
            # Some ONVIF cameras return 400/401/500 with a SOAP body containing device info or fault
            resp_bytes = http_err.read()
        t_end = time.perf_counter_ns()

        if not resp_bytes:
            return {}

        resp_text = resp_bytes.decode("utf-8", errors="ignore")
        if not ("GetDeviceInformation" in resp_text or "Envelope" in resp_text or "Manufacturer" in resp_text):
            return {}

        parsed = parse_onvif_device_information_xml(resp_text)
        if not (parsed["manufacturer"] or parsed["model"]):
            return {}

        turnaround_ns = max(1, t_end - t_start)
        kernel_turnaround_us = turnaround_ns / 1000.0
        latency_ms = turnaround_ns / 1e6

        vendor = parsed["manufacturer"] or "Generic ONVIF"
        model = parsed["model"] or "IP Surveillance Camera"

        payload = {
            "vendor": vendor,
            "model": model,
            "firmware": parsed["firmware"],
            "serial_number": parsed["serial"],
            "hardware_id": parsed["hardware_id"],
            "archetype": "CCTV_VIDEO",
            "type": "camera",
            "is_onvif": True,
            "port": port,
            "protocol": f"ONVIF Device Service (Port {port})",
            "kernel_turnaround_us": round(kernel_turnaround_us, 2),
            "latency_ms": round(latency_ms, 2),
            "turnaround_ns": turnaround_ns
        }
        return sanitize_prober_payload(payload)
    except Exception:
        return {}

