import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.attack_pather import AttackPather
from web_ui.models import VulnerabilityModel

class TestAttackPather(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.store = MagicMock()
        self.pather = AttackPather(self.mock_client, self.store)

    def test_analyze_attack_path(self):
        self.store.get_all_targets_summary.return_value = [{"target": "t.com", "risk_score": 10}]
        
        # Mock Gemini
        mock_response = MagicMock()
        mock_response.text = "Attacker can leverage open port 80..."
        self.mock_client.models.generate_content.return_value = mock_response
        
        analysis = self.pather.analyze_attack_paths()
        
        self.assertIn("Attacker", analysis)
        self.mock_client.models.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
