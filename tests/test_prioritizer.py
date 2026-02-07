import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.prioritizer import Prioritizer
from web_ui.models import VulnerabilityModel

class TestPrioritizer(unittest.TestCase):

    def setUp(self):
        self.prioritizer = Prioritizer()

    def test_calculate_vuln_score_rce(self):
        vuln = VulnerabilityModel(
            title="Remote Code Execution",
            severity="Critical",
            privilege_level="admin",
            strategic_advantage="rce",
            confidence=1.0
        )
        # (10 base * 2.0 admin) + 5 rce = 25
        score = self.prioritizer.calculate_vuln_score(vuln)
        self.assertEqual(score, 25.0)

    def test_calculate_vuln_score_low_confidence(self):
        vuln = VulnerabilityModel(
            title="Potential SQLi",
            severity="High",
            privilege_level="user",
            strategic_advantage="",
            confidence=0.5
        )
        # (7 base * 1.5 user) * 0.5 confidence = 10.5 * 0.5 = 5.25
        score = self.prioritizer.calculate_vuln_score(vuln)
        self.assertEqual(score, 5.25)

    def test_target_risk_score(self):
        vulns = [
            VulnerabilityModel(title="V1", severity="High", confidence=1.0),
            VulnerabilityModel(title="V2", severity="Medium", confidence=1.0)
        ]
        # (7 * 1.0) + (4 * 1.0) = 11.0
        target_score = self.prioritizer.calculate_target_risk(vulns)
        self.assertEqual(target_score, 11.0)

if __name__ == '__main__':
    unittest.main()
