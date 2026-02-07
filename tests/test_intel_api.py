import unittest
from flask import Flask
from web_ui.blueprints.intel_routes import intel_bp
from web_ui.vuln_store import VulnStore

class TestIntelAPI(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(intel_bp)
        self.client = self.app.test_client()
        self.store = VulnStore()
        self.store.targets = {}
        self.store.alias_index = {}

    def test_list_targets_prioritized(self):
        tid1 = self.store.get_or_create_target("low.com")
        tid2 = self.store.get_or_create_target("high.com")
        
        self.store.add_vulnerability(tid2, title="RCE", severity="Critical", privilege_level="root")
        
        response = self.client.get('/api/targets')
        data = response.get_json()
        
        self.assertEqual(data[0]['target'], "high.com")
        self.assertEqual(data[1]['target'], "low.com")

    def test_prioritized_vulns_api(self):
        tid = self.store.get_or_create_target("target.com")
        self.store.add_vulnerability(tid, title="Low Vuln", severity="Low")
        self.store.add_vulnerability(tid, title="High Vuln", severity="High")
        
        response = self.client.get('/api/intel/prioritized-vulns')
        data = response.get_json()
        
        self.assertEqual(data[0]['title'], "High Vuln")
        self.assertEqual(data[1]['title'], "Low Vuln")

if __name__ == '__main__':
    unittest.main()
