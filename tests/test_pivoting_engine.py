import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.pivoting_engine import PivotingEngine
from web_ui.vuln_store import VulnStore
from web_ui.mission_manager import MissionManager

class TestPivotingEngine(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        self.store.targets = {}
        self.store.alias_index = {}
        self.mission_mgr = MagicMock(spec=MissionManager)
        self.mission_mgr.current_mission = {"mission_name": "Test", "phases": []}
        self.mission_mgr.active_phases = []
        self.engine = PivotingEngine(self.store, self.mission_mgr)

    def test_foothold_detection_triggers_post_exploit(self):
        target = "compromised.com"
        tid = self.store.get_or_create_target(target)
        
        # 1. Add a high-privilege vulnerability (foothold)
        self.store.add_vulnerability(
            tid, 
            title="Remote Code Execution", 
            severity="Critical", 
            privilege_level="root",
            strategic_advantage="rce"
        )
        
        # 2. Check for footholds
        footholds = self.engine.detect_footholds()
        self.assertEqual(len(footholds), 1)
        self.assertEqual(footholds[0]['target'], target)
        
        # 3. Verify mission expansion
        self.engine.trigger_post_exploitation(footholds[0])
        self.assertEqual(len(self.mission_mgr.active_phases), 1)
        self.assertEqual(self.mission_mgr.active_phases[0]['name'], "Post-Exploitation & Pivoting")

if __name__ == '__main__':
    unittest.main()
