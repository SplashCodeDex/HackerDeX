import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.mission_manager import MissionManager

class TestMissionManager(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.manager = MissionManager(self.mock_client)

    def test_exhaustive_exploration(self):
        # 1. Start mission
        goal = "Compromise segment A"
        target = "10.0.0.1"
        
        # Mock planner response with 2 parallel phases
        mock_plan = {
            "mission_name": "Test Mission",
            "phases": [
                {"name": "Web Recon", "goal": "Find web vulns", "tasks": ["nikto"], "parallel": True},
                {"name": "Net Recon", "goal": "Find net vulns", "tasks": ["nmap"], "parallel": True}
            ]
        }
        self.manager.planner.decompose_goal = MagicMock(return_value=mock_plan)
        
        self.manager.start_mission(goal, target)
        
        # Verify that both phases are tracked
        self.assertEqual(len(self.manager.active_phases), 2)
        
        # 2. Simulate one success
        self.manager.mark_task_complete("nikto", "success")
        
        # Verify that the mission is NOT finished (exhaustion)
        self.assertFalse(self.manager.is_mission_complete())
        self.assertIn("Net Recon", [p["name"] for p in self.manager.active_phases])

if __name__ == '__main__':
    unittest.main()
