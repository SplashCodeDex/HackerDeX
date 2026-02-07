import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import json

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.vuln_store import VulnStore
from web_ui.parsers.registry import registry
from web_ui.models import ScanResultModel

class TestE2ERobustScanner(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        # Fresh store for testing
        self.store.targets = {}
        self.store.alias_index = {}

    def test_multi_tool_flow_correlation_and_prioritization(self):
        """
        Simulate a flow: 
        1. theHarvester finds subdomains and IPs.
        2. Nmap scans an IP and finds an open port.
        3. Nikto finds a vulnerability on that port.
        4. Verify prioritization and correlation.
        """
        target_domain = "example.com"
        
        # --- 1. theHarvester Result ---
        harvester_output = "Emails found: admin@example.com\\nIPs found: 1.2.3.4\\nSubdomains: dev.example.com"
        tid = self.store.get_or_create_target(target_domain)
        parsed_osint = registry.parse_output(harvester_output, "theHarvester", target_domain)
        
        self.store.update_osint_info(tid, parsed_osint.osint_info)
        for v in parsed_osint.vulns:
            self.store.add_vulnerability(tid, v.title, v.severity, tool="theHarvester")
            
        # Verify OSINT correlation: IP 1.2.3.4 should now be an alias for example.com
        self.assertIn("1.2.3.4", self.store.alias_index)
        self.assertEqual(self.store.alias_index["1.2.3.4"], tid)

        # --- 2. Nmap Result for the discovered IP ---
        # Note: We use the same tid because of correlation
        nmap_output = "PORT 80/tcp open http"
        parsed_nmap = registry.parse_output(nmap_output, "Nmap", "1.2.3.4")
        
        for p in parsed_nmap.ports:
            self.store.add_port(tid, p.port, p.protocol, p.service)
            
        # --- 3. Nikto Result ---
        nikto_output = "+ /admin: Admin panel found."
        parsed_nikto = registry.parse_output(nikto_output, "Nikto", "1.2.3.4")
        
        for v in parsed_nikto.vulns:
            # Manually inject high advantage for test
            v.privilege_level = "admin"
            v.strategic_advantage = "credential_access"
            self.store.add_vulnerability(tid, v.title, v.severity, v.details, v.affected_url, "Nikto",
                                         privilege_level=v.privilege_level, 
                                         strategic_advantage=v.strategic_advantage)

        # --- 4. Verify Final State ---
        profile = self.store.get_target_profile(target_domain)
        
        # Risk score should be high due to 'admin' privilege and 'credential_access'
        # Base(medium=4) * Multiplier(admin=2) + Bonus(2) = 10.0
        # Plus OSINT vulns (2 vulns: 1 med, 1 low) = 4 + 2 = 6
        # Total approx 16.0
        self.assertGreaterEqual(profile['risk_score'], 10.0)
        self.assertEqual(profile['priority_level'], "high")
        
        # Verify correlation consistency
        self.assertEqual(len(profile['ports']), 1)
        self.assertIn("1.2.3.4", profile['aliases'])

if __name__ == '__main__':
    unittest.main()
