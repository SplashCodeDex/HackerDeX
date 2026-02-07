import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.feedback_loop import FeedbackLoopController
from web_ui.mission_manager import MissionManager

class TestFeedbackLoop(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.mission_mgr = MagicMock()
        self.mission_mgr.current_mission = {"mission_name": "Test", "phases": []}
        self.mission_mgr.active_phases = []
        self.controller = FeedbackLoopController(self.mock_client, self.mission_mgr)

    def test_process_output_triggers_next_phase(self):
        # 1. Simulate output containing a new discovery
        output = "Found subdomain: secret.target.com"
        tool_name = "theHarvester"
        target = "target.com"
        
        # Mock Gemini reasoning about the output
        mock_response = MagicMock()
        mock_response.text = '{"new_tasks": ["nmap"], "intelligence": "Discovered new subdomain secret.target.com"}'
        self.mock_client.models.generate_content.return_value = mock_response
        
        self.controller.process_tool_output(tool_name, output, target)
        
        # Verify that mission manager was informed
        self.mission_mgr.mark_task_complete.assert_called_once_with(tool_name, "success")
        self.mock_client.models.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
