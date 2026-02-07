import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from web_ui.models import PortModel, VulnerabilityModel, ScanResultModel
except ImportError:
    # This is expected to fail initially
    PortModel = None

class TestModels(unittest.TestCase):

    def test_port_model(self):
        if PortModel is None:
            self.fail("PortModel not imported")
        
        data = {"port": 80, "protocol": "tcp", "service": "http"}
        port = PortModel(**data)
        self.assertEqual(port.port, 80)
        self.assertEqual(port.protocol, "tcp")

    def test_vulnerability_model(self):
        data = {
            "title": "SQLi",
            "severity": "High",
            "source_layer": "web",
            "confidence": 0.9
        }
        vuln = VulnerabilityModel(**data)
        self.assertEqual(vuln.title, "SQLi")
        self.assertEqual(vuln.source_layer, "web")
        self.assertEqual(vuln.confidence, 0.9)

    def test_scan_result_model(self):
        data = {
            "target": "example.com",
            "tool_name": "nmap",
            "ports": [{"port": 22, "service": "ssh"}]
        }
        result = ScanResultModel(**data)
        self.assertEqual(result.target, "example.com")
        self.assertEqual(len(result.ports), 1)
        self.assertIsInstance(result.ports[0], PortModel)

if __name__ == '__main__':
    unittest.main()
