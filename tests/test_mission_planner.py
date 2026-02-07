import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.mission_planner import MissionPlanner

class TestMissionPlanner(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.planner = MissionPlanner(self.mock_client)

    def test_decompose_goal(self):
        goal = "Compromise the internal database"
        target = "example.com"
        
        # Mock Gemini response for plan decomposition
        mock_response = MagicMock()
        mock_response.text = '{"phases": [{"name": "Recon", "tasks": ["nmap", "nikto"]}, {"name": "Exploit", "tasks": ["sqlmap"]}]}'
        self.mock_client.models.generate_content.return_value = mock_response
        
        mission_plan = self.planner.decompose_goal(goal, target)
        
        self.assertIn("phases", mission_plan)
        self.assertEqual(len(mission_plan["phases"]), 2)
        self.assertEqual(mission_plan["phases"][0]["name"], "Recon")
        self.mock_client.models.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
