"""
Unit tests for GraphPath Post-Sign-In Discovery Expansion API (/api/discovery/expand)
"""

import unittest
from unittest.mock import patch, MagicMock
from ui.server import app
from ui.routes import graph


class TestDiscoveryExpansionApi(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch("ui.auth_middleware.session_manager.verify_token")
    def test_discovery_expand_pbx(self, mock_verify):
        mock_verify.return_value = True

        payload = {
            "source_ip": "10.10.4.13",
            "pbx_server": "10.10.4.100",
            "dns_server": "",
            "subnets": []
        }

        # Ensure source node exists
        graph.add_node("10.10.4.13", {"type": "voip_phone", "ip": "10.10.4.13"})

        response = self.client.post("/api/discovery/expand", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(graph._G.has_node("10.10.4.100"))
        self.assertEqual(graph._G.nodes["10.10.4.100"]["type"], "voip_pbx")
        self.assertTrue(graph._G.has_edge("10.10.4.100", "10.10.4.13"))

    @patch("threading.Thread")
    @patch("ui.auth_middleware.session_manager.verify_token")
    def test_discovery_expand_subnet(self, mock_verify, mock_thread):
        mock_verify.return_value = True
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        payload = {
            "source_ip": "10.10.4.1",
            "subnets": ["10.10.99.0/24"]
        }

        response = self.client.post("/api/discovery/expand", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("10.10.99.0/24", data["subnets"])
        self.assertTrue(mock_thread_instance.start.called)

    @patch("threading.Thread")
    @patch("discovery.dns_discovery.DnsDiscoveryEngine.sweep_ptr_records")
    @patch("ui.auth_middleware.session_manager.verify_token")
    def test_discovery_expand_dns_server(self, mock_verify, mock_ptr, mock_thread):
        mock_verify.return_value = True
        mock_ptr.return_value = {"10.10.4.1": "gw-01.corp.local"}
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        payload = {
            "source_ip": "10.10.4.13",
            "dns_server": "192.168.2.8",
            "subnets": []
        }

        response = self.client.post("/api/discovery/expand", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(graph._G.has_node("192.168.2.8"))
        self.assertEqual(graph._G.nodes["192.168.2.8"]["type"], "server")
        # Ensure 192.168.2.0/24 was auto-derived
        self.assertIn("192.168.2.0/24", data["subnets"])
        self.assertTrue(mock_thread_instance.start.called)

    @patch("ui.auth_middleware.session_manager.verify_token")
    def test_report_inventory_endpoint(self, mock_verify):
        mock_verify.return_value = True
        
        # Add test nodes to graph
        graph.add_node("10.10.7.64", {
            "type": "laptop",
            "ip": "10.10.7.64",
            "hostname": "CJDellXPS15",
            "mac": "A0:59:50:57:38:CA",
            "vendor": "Dell Inc.",
            "ports": [135, 445],
            "civic_location": {"building": "HQ", "floor": "Floor 2", "room": "Office 204"}
        })

        response = self.client.get("/api/report/inventory")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("devices", data)
        self.assertIn("category_counts", data)
        self.assertIn("generated_at", data)
        
        # Verify node fields
        target = next((d for d in data["devices"] if d["ip"] == "10.10.7.64"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target["hostname"], "CJDellXPS15")
        self.assertEqual(target["vendor"], "Dell Inc.")
        self.assertIn("HQ", target["location"])


if __name__ == "__main__":
    unittest.main()
