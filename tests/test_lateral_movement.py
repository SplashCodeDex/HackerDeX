import unittest
from unittest.mock import MagicMock
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.lateral_movement import LateralMovementEngine
from web_ui.vuln_store import VulnStore

class TestLateralMovement(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        self.store.targets = {}
        self.store.alias_index = {}
        self.engine = LateralMovementEngine(self.store)

    def test_credential_correlation(self):
        # 1. Discover creds on target A
        tid1 = self.store.get_or_create_target("target-a.com")
        self.store.update_osint_info(tid1, {"emails": ["admin@corp.com"]})
        # Simulate finding a password in logs/config
        self.store.add_vulnerability(tid1, "Creds leaked", "Info", details="password: Password123")
        
        # 2. Know about target B
        tid2 = self.store.get_or_create_target("target-b.com")
        self.store.add_port(tid2, 22, "tcp", "ssh")
        
        # 3. Correlate
        movements = self.engine.correlate_credentials()
        self.assertGreaterEqual(len(movements), 1)
        self.assertEqual(movements[0]['target'], "target-b.com")
        self.assertIn("Password123", movements[0]['reasoning'])

if __name__ == '__main__':
    unittest.main()
