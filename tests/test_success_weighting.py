import unittest
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.tool_prioritizer import SuccessWeightingEngine

class TestSuccessWeighting(unittest.TestCase):

    def setUp(self):
        self.engine = SuccessWeightingEngine()

    def test_rank_tools_by_success(self):
        # 1. Record some successes
        self.engine.record_success("nmap", "port_discovery", score=10)
        self.engine.record_success("nikto", "web_vuln", score=5)
        
        # 2. Get ranked tools for a goal
        ranked = self.engine.rank_tools(["nmap", "nikto", "sqlmap"], "port_discovery")
        
        self.assertEqual(ranked[0], "nmap") # nmap should be first for port_discovery
        self.assertIn("sqlmap", ranked) # sqlmap should still be there but lower

if __name__ == '__main__':
    unittest.main()
