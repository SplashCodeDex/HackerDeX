import unittest
import sys
import os

# Adjust path to import from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.vuln_store import VulnStore

class TestVulnStoreV2(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        # Clean up store for testing
        self.store.targets = {}
        self.store.alias_index = {}

    def test_new_schema_fields(self):
        target = "example.com"
        tid = self.store.get_or_create_target(target)
        profile = self.store.get_target_profile(target)
        
        # Check for new top-level fields
        self.assertIn("dns_info", profile)
        self.assertIn("osint_info", profile)
        self.assertIn("risk_score", profile)
        self.assertIn("priority_level", profile)

    def test_enhanced_vulnerability_fields(self):
        target = "example.com"
        tid = self.store.get_or_create_target(target)
        
        # Add vulnerability with new fields
        self.store.add_vulnerability(
            tid, 
            title="SQL Injection", 
            severity="Critical", 
            details="Classic SQLi", 
            url="http://example.com/api", 
            tool="sqlmap",
            source_layer="web",
            privilege_level="admin",
            strategic_advantage="data_exfiltration",
            confidence=0.95
        )
        
        profile = self.store.get_target_profile(target)
        vuln = profile['vulnerabilities'][0]
        
        self.assertEqual(vuln.get("source_layer"), "web")
        self.assertEqual(vuln.get("privilege_level"), "admin")
        self.assertEqual(vuln.get("strategic_advantage"), "data_exfiltration")
        self.assertEqual(vuln.get("confidence"), 0.95)

    def test_dns_info_update(self):
        target = "example.com"
        tid = self.store.get_or_create_target(target)
        
        dns_data = {
            "a_records": ["93.184.216.34"],
            "mx_records": ["mail.example.com"]
        }
        self.store.update_dns_info(tid, dns_data)
        
        profile = self.store.get_target_profile(target)
        self.assertEqual(profile['dns_info']['a_records'], ["93.184.216.34"])

    def test_osint_info_update(self):
        target = "example.com"
        tid = self.store.get_or_create_target(target)
        
        osint_data = {
            "emails": ["admin@example.com"],
            "subdomains": ["dev.example.com"]
        }
        self.store.update_osint_info(tid, osint_data)
        
        profile = self.store.get_target_profile(target)
        self.assertEqual(profile['osint_info']['emails'], ["admin@example.com"])

    def test_automatic_risk_calculation(self):
        target = "risky-target.com"
        tid = self.store.get_or_create_target(target)
        
        self.store.add_vulnerability(
            tid, 
            title="RCE", 
            severity="Critical", 
            privilege_level="root",
            strategic_advantage="rce"
        )
        
        profile = self.store.get_target_profile(target)
        # (10 * 2) + 5 = 25
        self.assertEqual(profile['risk_score'], 25.0)
        self.assertEqual(profile['priority_level'], "critical")

if __name__ == '__main__':
    unittest.main()
