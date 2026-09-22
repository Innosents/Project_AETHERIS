"""
Unit Tests for SecurityAuditor
Validates passive security posture evaluations, cleartext protocol detection (Telnet, FTP),
industrial exposure (Modbus 502), default SNMP community auditing, and vendor hardening profiles.
"""

import pytest
from aetheris.core.security_auditor import SecurityAuditor


def test_security_auditor_telnet_risk():
    device_data = {
        "ip": "192.168.1.5",
        "open_ports": [23, 80],
        "port_scan_status": "completed"
    }
    audit = SecurityAuditor.audit_device(device_data)
    assert audit["risk_level"] == "MEDIUM"
    assert audit["risk_score"] == 55
    titles = [f["title"] for f in audit["findings"]]
    assert any("Telnet" in t for t in titles)
    assert any("HTTP" in t for t in titles)


def test_security_auditor_industrial_modbus_exposure():
    device_data = {
        "ip": "10.0.0.50",
        "open_ports": [502],
        "type": "plc",
        "port_scan_status": "completed"
    }
    audit = SecurityAuditor.audit_device(device_data)
    assert audit["risk_level"] in ("MEDIUM", "HIGH")
    titles = [f["title"] for f in audit["findings"]]
    assert any("Modbus/TCP" in t for t in titles)
    assert any("IEC 62443" in s for s in audit["hardening_checklist"])


def test_security_auditor_default_snmp_community_flagged():
    device_data = {
        "ip": "192.168.1.1",
        "open_ports": [161],
        "snmp_oids": [{"oid": "1.3.6.1.2.1.1.1.0", "value": "public community string active"}],
        "port_scan_status": "completed"
    }
    audit = SecurityAuditor.audit_device(device_data)
    titles = [f["title"] for f in audit["findings"]]
    assert any("Default SNMP Community" in t for t in titles)
    assert audit["risk_score"] >= 25


def test_security_auditor_vendor_profile_matching():
    device_data = {
        "ip": "192.168.1.120",
        "vendor": "Grandstream Networks",
        "model": "GXP2170",
        "open_ports": [80, 5060],
        "port_scan_status": "completed"
    }
    audit = SecurityAuditor.audit_device(device_data)
    assert audit["vendor_posture"] == "grandstream"
    titles = [f["title"] for f in audit["findings"]]
    assert any("Factory Default Configuration Risk (Grandstream Networks)" in t for t in titles)
    assert any("Voice VLAN" in s for s in audit["hardening_checklist"])


def test_security_auditor_unassessed_device():
    device_data = {
        "ip": "192.168.1.200",
        "open_ports": [],
        "port_scan_status": "not_run"
    }
    audit = SecurityAuditor.audit_device(device_data)
    assert audit["risk_level"] == "NOT_ASSESSED"
    assert audit["risk_score"] == 0
    assert audit["assessed"] is False


def test_security_auditor_score_capping_at_100():
    device_data = {
        "ip": "192.168.1.250",
        "open_ports": [21, 23, 80, 502, 5060],
        "vendor": "cisco",
        "snmp_oids": [{"oid": "1.3.6.1", "value": "public"}],
        "port_scan_status": "completed"
    }
    audit = SecurityAuditor.audit_device(device_data)
    assert audit["risk_score"] == 100
    assert audit["risk_level"] == "HIGH"
