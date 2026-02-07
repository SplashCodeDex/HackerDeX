import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.parsers.registry import registry
from web_ui.models import ScanResultModel

class TestParserRegistryV2(unittest.TestCase):

    def test_parse_output_returns_model(self):
        # Even with empty/dummy output, it should return a ScanResultModel
        raw_output = "Nmap scan report for 127.0.0.1\nPORT 80/tcp open http"
        tool_name = "Nmap"
        target = "127.0.0.1"
        
        result = registry.parse_output(raw_output, tool_name, target)
        
        self.assertIsInstance(result, ScanResultModel)
        self.assertEqual(result.target, target)
        self.assertEqual(result.tool_name, tool_name)

    def test_dynamic_registration(self):
        # Test that we can add a new parser dynamically
        from web_ui.parsers.base_parser import BaseParser
        
        class MockParser(BaseParser):
            def can_parse(self, tool_name): return tool_name == "MockTool"
            def parse(self, raw, tool, target): return {"ports": [], "vulns": [], "urls": [], "technologies": []}
            
        registry.register_parser(MockParser())
        parser = registry.get_parser("MockTool")
        self.assertIsInstance(parser, MockParser)

if __name__ == '__main__':
    unittest.main()
