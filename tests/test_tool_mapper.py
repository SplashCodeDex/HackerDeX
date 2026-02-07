import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.tool_mapper import ToolCapabilityMapper

class TestToolMapper(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.mapper = ToolCapabilityMapper(self.mock_client)

    def test_map_goal_to_command(self):
        goal = "Discover open ports and services"
        target = "127.0.0.1"
        tool_name = "nmap"
        
        # Mock Gemini response
        mock_response = MagicMock()
        mock_response.text = '{"command": "nmap -sV -sC 127.0.0.1", "rationale": "Standard service discovery scan"}'
        self.mock_client.models.generate_content.return_value = mock_response
        
        mapping = self.mapper.get_command(tool_name, goal, target)
        
        self.assertEqual(mapping["command"], "nmap -sV -sC 127.0.0.1")
        self.assertIn("rationale", mapping)
        self.mock_client.models.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
