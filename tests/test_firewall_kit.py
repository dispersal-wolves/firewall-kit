import unittest

from firewall_kit import PROFILES, parse_port, ports_for, render_nftables, render_ufw


class FirewallKitTests(unittest.TestCase):
    def test_port_validation(self):
        self.assertEqual(parse_port("TCP:443"), ("tcp", 443))
        with self.assertRaises(ValueError):
            parse_port("tcp:70000")

    def test_profiles_render_default_deny(self):
        ports = ports_for(PROFILES["web-server"], [])
        self.assertIn("policy drop", render_nftables("web-server", ports))
        self.assertIn("tcp dport 443", render_nftables("web-server", ports))
        self.assertIn("ufw default deny incoming", render_ufw("web-server", ports))


if __name__ == "__main__":
    unittest.main()
