"""
Unit Tests for NIST 800-82 Compliant EdgeSecurityAuditor.
Asserts semaphore concurrency throttling, read-only Modbus FC43 queries,
and targeted Axis VAPIX / Mercury MSP CVE correlation without intrusive fuzzing.
"""

import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
from aetheris.core.security_auditor import EdgeSecurityAuditor


class TestEdgeSecurityAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = EdgeSecurityAuditor(concurrency_limit=5)

    def _mock_msp_conn(self, payload: bytes):
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=payload)
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        sock = MagicMock()
        sock.shutdown = MagicMock()
        writer.get_extra_info = MagicMock(return_value=sock)
        return reader, writer

    def test_semaphore_concurrency_throttling(self):
        # Assert semaphore initialized with correct limit
        self.assertIsInstance(self.auditor.semaphore, asyncio.Semaphore)
        self.assertEqual(self.auditor.semaphore._value, 5)

    # --- Axis VAPIX Tests ---
    def test_axis_vapix_vulnerable_firmware(self):
        mock_response = MagicMock(status_code=200, text="Properties.Firmware.Version=9.80.1\n")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            res = asyncio.run(self.auditor._check_axis_cve("10.50.99.10"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "CRITICAL")
            self.assertEqual(res["cve_notes"], "VAPIX FW v9.80.1 vulnerable to CVE-2023-21406")

    def test_axis_vapix_authenticated_modern_firmware(self):
        mock_response = MagicMock(status_code=200, text="Properties.Firmware.Version=10.12.1\n")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            res = asyncio.run(self.auditor._check_axis_cve("10.50.99.10"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "LOW")
            self.assertEqual(res["cve_notes"], "VAPIX FW v10.12.1 authenticated")

    def test_axis_vapix_hardened_401_unauthorized(self):
        mock_response = MagicMock(status_code=401, text="Unauthorized")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            res = asyncio.run(self.auditor._check_axis_cve("10.50.99.10"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "LOW")
            self.assertEqual(res["cve_notes"], "VAPIX read requires authentication (Hardened)")

    def test_axis_vapix_timeout_exceeded(self):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ConnectTimeout("0.5s timeout")):
            res = asyncio.run(self.auditor._check_axis_cve("10.50.99.10"))
            self.assertEqual(res["audit_status"], "TIMEOUT")
            self.assertEqual(res["cve_exposure"], "UNKNOWN")
            self.assertEqual(res["cve_notes"], "0.5s VAPIX timeout exceeded")

    def test_axis_vapix_connection_refused(self):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ConnectError("Port 80 closed")):
            res = asyncio.run(self.auditor._check_axis_cve("10.50.99.10"))
            self.assertEqual(res["audit_status"], "FAILED")
            self.assertEqual(res["cve_exposure"], "UNKNOWN")
            self.assertEqual(res["cve_notes"], "VAPIX connection refused (Port 80 closed)")

    # --- Mercury MSP Tests ---
    def test_mercury_msp_vulnerable_firmware(self):
        reader, writer = self._mock_msp_conn(b"\x02\x0B\x00\x00LP1502_1.28.2\x03")
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "CRITICAL")
            self.assertEqual(res["cve_notes"], "MSP Plaintext Active, FW v1.28.2")

    def test_mercury_msp_patched_firmware(self):
        reader, writer = self._mock_msp_conn(b"\x02\x0B\x00\x00LP1502_1.30.1\x03")
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "MEDIUM")
            self.assertEqual(res["cve_notes"], "MSP Plaintext Active, FW v1.30.1")

    def test_mercury_msp_unverified_version(self):
        reader, writer = self._mock_msp_conn(b"\x02\x0B\x00\x00OTHER_DATA\x03")
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "HIGH")
            self.assertEqual(res["cve_notes"], "MSP port 3001 unencrypted, version unverified")

    def test_mercury_msp_zero_byte_read(self):
        reader, writer = self._mock_msp_conn(b"")
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "UNKNOWN")
            self.assertEqual(res["cve_notes"], "Connection established but zero-byte payload returned")

    def test_mercury_msp_timeout_exceeded(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=asyncio.TimeoutError()):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "TIMEOUT")
            self.assertEqual(res["cve_exposure"], "UNKNOWN")
            self.assertEqual(res["cve_notes"], "0.5s MSP timeout (Port 3001 filtered)")

    def test_mercury_msp_connection_refused_secured(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError()):
            res = asyncio.run(self.auditor._check_mercury_msp("10.50.99.20"))
            self.assertEqual(res["audit_status"], "SECURED")
            self.assertEqual(res["cve_exposure"], "LOW")
            self.assertEqual(res["cve_notes"], "Port 3001 closed (TLS/Secure Mode enforced)")

    # --- Modbus FC 43 (MEI Type 14) Tests ---
    def test_modbus_fc43_schneider_siemens_high_risk(self):
        # FC 43 MEI 14 response with Schneider Electric vendor object
        payload = b"\x00\x01\x00\x00\x00\x20\x01\x2B\x0E\x01\x00\x00\x02\x00\x00Schneider Electric\x00Modicon M340\x00"
        reader, writer = self._mock_msp_conn(payload)
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_modbus_fc43("10.50.99.30"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "HIGH")
            self.assertIn("Schneider Electric", res["cve_notes"])
            self.assertIn("Evaluate Default Credentials", res["cve_notes"])

    def test_modbus_fc43_generic_vendor_medium_risk(self):
        payload = b"\x00\x01\x00\x00\x00\x18\x01\x2B\x0E\x01\x00\x00\x01\x00\x00Generic PLC Corp\x00v1.0\x00"
        reader, writer = self._mock_msp_conn(payload)
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_modbus_fc43("10.50.99.30"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "MEDIUM")
            self.assertIn("Modbus FC43 Active", res["cve_notes"])
            self.assertIn("Generic PLC Corp", res["cve_notes"])

    def test_modbus_fc43_exception_rejected_low_risk(self):
        # Modbus Exception response (0xAB, Exception code 01 Illegal Function)
        payload = b"\x00\x01\x00\x00\x00\x03\x01\xAB\x01"
        reader, writer = self._mock_msp_conn(payload)
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
            res = asyncio.run(self.auditor._check_modbus_fc43("10.50.99.30"))
            self.assertEqual(res["audit_status"], "COMPLETED")
            self.assertEqual(res["cve_exposure"], "LOW")
            self.assertEqual(res["cve_notes"], "FC43 Rejected (Modbus Exception 1)")

    def test_modbus_fc43_timeout_exceeded(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=asyncio.TimeoutError()):
            res = asyncio.run(self.auditor._check_modbus_fc43("10.50.99.30"))
            self.assertEqual(res["audit_status"], "TIMEOUT")
            self.assertEqual(res["cve_exposure"], "UNKNOWN")
            self.assertEqual(res["cve_notes"], "0.5s Modbus timeout (Port 502 filtered/dropped)")

    def test_modbus_fc43_connection_refused_secured(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError()):
            res = asyncio.run(self.auditor._check_modbus_fc43("10.50.99.30"))
            self.assertEqual(res["audit_status"], "SECURED")
            self.assertEqual(res["cve_exposure"], "LOW")
            self.assertEqual(res["cve_notes"], "Port 502 closed")

    # --- Fleet Audit Integration ---
    def test_fleet_audit_execution(self):
        axis_mock_result = {
            "audit_status": "COMPLETED",
            "cve_exposure": "CRITICAL",
            "cve_notes": "VAPIX FW v9.80.1 vulnerable to CVE-2023-21406"
        }
        mercury_mock_result = {
            "audit_status": "COMPLETED",
            "cve_exposure": "MEDIUM",
            "cve_notes": "MSP Plaintext Active, FW v1.30.1"
        }
        with patch.object(self.auditor, "_check_axis_cve", new_callable=AsyncMock, return_value=axis_mock_result), \
             patch.object(self.auditor, "_check_mercury_msp", new_callable=AsyncMock, return_value=mercury_mock_result):
            res = asyncio.run(self.auditor.execute_fleet_audit())
            self.assertEqual(res["status"], "AUDIT_COMPLETE")
            self.assertEqual(res["nodes_processed"], 2)
            # Verify node data mutations in ledger
            self.assertIn("00:50:56:99:A1:01", self.auditor.audit_ledger)
            self.assertIn("00:50:56:99:A1:02", self.auditor.audit_ledger)
            self.assertEqual(self.auditor.audit_ledger["00:50:56:99:A1:01"]["cve_exposure"], "CRITICAL")
            self.assertEqual(self.auditor.audit_ledger["00:50:56:99:A1:02"]["cve_exposure"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
