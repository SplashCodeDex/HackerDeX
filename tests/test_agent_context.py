import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.agent_context import AgentContext
from web_ui.vuln_store import VulnStore

class TestAgentContext(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        self.store.targets = {}
        self.store.alias_index = {}
        self.context_mgr = AgentContext(self.store)

    def test_get_mission_context(self):
        target = "target.com"
        tid = self.store.get_or_create_target(target)
        self.store.add_port(tid, 80, "tcp", "http")
        self.store.add_vulnerability(tid, "SQLi", "High")
        
        context = self.context_mgr.get_mission_context(target)
        
        self.assertIn("target.com", context)
        self.assertIn("SQLi", context)
        self.assertIn("80/tcp", context)

if __name__ == '__main__':
    unittest.main()
