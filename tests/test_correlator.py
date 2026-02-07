import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.correlator import Correlator
from web_ui.vuln_store import VulnStore

class TestCorrelator(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        self.store.targets = {}
        self.store.alias_index = {}
        self.correlator = Correlator(self.store)

    def test_link_subdomain_to_ip(self):
        # 1. Create target for domain
        domain = "dev.example.com"
        tid_domain = self.store.get_or_create_target(domain)
        self.store.update_osint_info(tid_domain, {"ips": ["1.2.3.4"]})
        
        # 2. Create target for IP
        ip = "1.2.3.4"
        tid_ip = self.store.get_or_create_target(ip)
        self.store.add_port(tid_ip, 80, "tcp", "http")
        
        # 3. Correlate
        self.correlator.correlate_all()
        
        # 4. Verify: domain profile should now know about the IP's ports
        profile_domain = self.store.get_target_profile(domain)
        self.assertIn(ip, profile_domain['aliases'])
        # The store should ideally merge these or link them.
        # For now, let's say it adds the IP as an alias to the domain profile.
        
    def test_identify_attack_surface_expansion(self):
        # If we find a new IP in OSINT, the correlator should automatically link it
        domain = "example.com"
        tid = self.store.get_or_create_target(domain)
        self.store.update_osint_info(tid, {"ips": ["8.8.8.8"], "subdomains": ["ns1.example.com"]})
        
        # Verify they became aliases automatically
        self.assertIn("8.8.8.8", self.store.alias_index)
        self.assertIn("ns1.example.com", self.store.alias_index)
        self.assertEqual(self.store.alias_index["8.8.8.8"], tid)

if __name__ == '__main__':
    unittest.main()
