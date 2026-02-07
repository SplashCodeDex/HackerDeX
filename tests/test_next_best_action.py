import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.next_best_action import NextBestActionEngine
from web_ui.models import VulnerabilityModel, PortModel

class TestNextBestAction(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.store = MagicMock()
        self.engine = NextBestActionEngine(self.mock_client, self.store)

    def test_suggest_next_action(self):
        # Mock target data
        mock_target = {
            "main_target": "test.com",
            "ports": [{"port": 80, "service": "http"}],
            "vulnerabilities": []
        }
        self.store.get_target_profile.return_value = mock_target
        
        # Mock Gemini
        mock_response = MagicMock()
        mock_response.text = '{"tool": "nikto", "reason": "Web server detected.", "command": "nikto -h test.com"}'
        self.mock_client.models.generate_content.return_value = mock_response
        
        suggestion = self.engine.suggest_next_action("test.com")
        
        self.assertIn("nikto", suggestion["tool"])
        self.mock_client.models.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
