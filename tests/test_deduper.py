import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.deduper import Deduper
from web_ui.models import VulnerabilityModel

class TestDeduper(unittest.TestCase):

    def setUp(self):
        self.deduper = Deduper()

    def test_is_duplicate_by_cve(self):
        v1 = VulnerabilityModel(title="Vuln 1", severity="High", cve_id="CVE-2023-1234")
        v2 = VulnerabilityModel(title="Different Title", severity="High", cve_id="CVE-2023-1234")
        self.assertTrue(self.deduper.is_duplicate(v1, v2))

    def test_is_duplicate_by_url_and_type(self):
        v1 = VulnerabilityModel(title="SQL Injection", severity="High", affected_url="http://t.com/p?id=1")
        v2 = VulnerabilityModel(title="Blind SQLi", severity="High", affected_url="http://t.com/p?id=1")
        self.assertTrue(self.deduper.is_duplicate(v1, v2))

    def test_not_duplicate(self):
        v1 = VulnerabilityModel(title="XSS", severity="Medium", affected_url="http://t.com/p1")
        v2 = VulnerabilityModel(title="XSS", severity="Medium", affected_url="http://t.com/p2")
        self.assertFalse(self.deduper.is_duplicate(v1, v2))

if __name__ == '__main__':
    unittest.main()
