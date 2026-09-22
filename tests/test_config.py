import unittest
from aetheris.config import ConfigurationManager

class TestConfigurationManager(unittest.TestCase):
    def test_profile_loading(self):
        cfg = ConfigurationManager(profile_name="industrial_vlan_lab")
        self.assertEqual(cfg.active_profile.get("name"), "Industrial Purdue Model Lab")
        self.assertIn("10.10.10.0/24", cfg.target_subnets)
        self.assertEqual(cfg.get_snmp_community(), "public")

if __name__ == "__main__":
    unittest.main()