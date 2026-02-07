import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ToolExecutor
from web_ui.parsers.registry import registry
from web_ui.vuln_store import VulnStore

class TestDataFlow(unittest.TestCase):

    def setUp(self):
        self.store = VulnStore()
        # Clean up store for testing if needed, or use a separate data path
        self.store.targets = {}
        self.store.alias_index = {}

    @patch('core.ToolExecutor.run_blocking')
    def test_executor_to_parser_flow(self, mock_run_blocking):
        # 1. Simulate Tool Execution
        mock_run_blocking.return_value = {
            "stdout": "PORT     STATE SERVICE\n80/tcp   open  http\n443/tcp  open  https",
            "stderr": "",
            "returncode": 0
        }
        
        executor = ToolExecutor()
        result = executor.run_blocking("nmap 127.0.0.1")
        
        # 2. Simulate Parsing Logic (as done in app.py)
        target = "127.0.0.1"
        tool_name = "Nmap"
        
        parsed = registry.parse_output(result['stdout'], tool_name, target)
        
        # 3. Verify Parsing Results
        self.assertTrue(any(p['port'] == 80 for p in parsed.get('ports', [])))
        self.assertTrue(any(p['port'] == 443 for p in parsed.get('ports', [])))

    def test_parser_to_store_flow(self):
        target = "127.0.0.1"
        tid = self.store.get_or_create_target(target)
        
        # Sample parsed data
        parsed_data = {
            "ports": [{"port": 80, "protocol": "tcp", "service": "http", "version": ""}],
            "vulns": [{"title": "Test Vuln", "severity": "High", "details": "Desc", "url": ""}],
            "urls": ["http://127.0.0.1/admin"],
            "technologies": []
        }
        
        # Update Store (Simulating app.py logic)
        for p in parsed_data.get('ports', []):
            self.store.add_port(tid, p['port'], p['protocol'], p['service'], p['version'])
        for v in parsed_data.get('vulns', []):
            self.store.add_vulnerability(tid, v['title'], v['severity'], v['details'], v['url'], "TestTool")
        for url in parsed_data.get('urls', []):
            self.store.add_url(tid, url, tool="TestTool")
            
        # Verify Store content
        profile = self.store.get_target_profile(target)
        self.assertEqual(len(profile['ports']), 1)
        self.assertEqual(profile['ports'][0]['port'], 80)
        self.assertEqual(len(profile['vulnerabilities']), 1)
        self.assertEqual(profile['vulnerabilities'][0]['title'], "Test Vuln")
        self.assertIn("http://127.0.0.1/admin", profile['urls'])

if __name__ == '__main__':
    unittest.main()
