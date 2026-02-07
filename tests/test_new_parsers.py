import unittest
import json
import sys
import os

# Adjust path to include parent directory (hackingtool)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.parsers.amass_parser import AmassParser
from web_ui.parsers.ffuf_parser import FFUFParser
from web_ui.parsers.semgrep_parser import SemgrepParser
from web_ui.parsers.naabu_parser import NaabuParser
from web_ui.parsers.httpx_parser import HttpxParser

class TestNewParsers(unittest.TestCase):

    def test_amass_parser(self):
        parser = AmassParser()
        self.assertTrue(parser.can_parse("amass"))

        raw_output = json.dumps({"name": "sub.example.com", "domain": "example.com", "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 12345, "desc": "Test ASN"}]}) + "\n"
        raw_output += json.dumps({"name": "api.example.com", "domain": "example.com", "addresses": [{"ip": "5.6.7.8"}]})

        findings = parser.parse(raw_output, "amass", "example.com")

        self.assertIn("http://sub.example.com", findings['urls'])
        self.assertIn("https://api.example.com", findings['urls'])
        self.assertTrue(any("Test ASN" in t['version'] for t in findings['technologies']))

    def test_ffuf_parser(self):
        parser = FFUFParser()
        self.assertTrue(parser.can_parse("ffuf"))

        output_data = {
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "position": 1,
                    "status": 200,
                    "length": 123,
                    "words": 45,
                    "lines": 10,
                    "content-type": "text/html",
                    "redirectlocation": "",
                    "url": "http://example.com/admin"
                },
                {
                    "input": {"FUZZ": "config"},
                    "position": 2,
                    "status": 301,
                    "length": 0,
                    "words": 0,
                    "lines": 0,
                    "content-type": "text/html",
                    "redirectlocation": "http://example.com/config/",
                    "url": "http://example.com/config"
                }
            ]
        }

        findings = parser.parse(json.dumps(output_data), "ffuf", "example.com")

        self.assertTrue(any("admin" in v['url'] for v in findings['vulns']))
        self.assertTrue(any("high" == v['severity'] for v in findings['vulns']))
        self.assertTrue(any("-> http://example.com/config/" in u for u in findings['urls']))

    def test_semgrep_parser(self):
        parser = SemgrepParser()
        self.assertTrue(parser.can_parse("semgrep"))

        output_data = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec",
                    "path": "app.py",
                    "start": {"line": 10, "col": 5},
                    "extra": {
                        "message": "Exec detected",
                        "severity": "WARNING",
                        "metadata": {}
                    }
                }
            ]
        }

        findings = parser.parse(json.dumps(output_data), "semgrep", "example.com")

        self.assertEqual(len(findings['vulns']), 1)
        self.assertEqual(findings['vulns'][0]['severity'], "medium")
        self.assertIn("Exec detected", findings['vulns'][0]['details'])

    def test_naabu_parser(self):
        parser = NaabuParser()
        self.assertTrue(parser.can_parse("naabu"))

        raw_output = '{"ip": "127.0.0.1", "port": 80}\n{"ip": "127.0.0.1", "port": 443}'

        findings = parser.parse(raw_output, "naabu", "127.0.0.1")

        self.assertEqual(len(findings['ports']), 2)
        self.assertTrue(any(p['port'] == 80 for p in findings['ports']))
        self.assertIn("https://127.0.0.1:443", findings['urls']) # Fixed line

    def test_httpx_parser(self):
        parser = HttpxParser()
        self.assertTrue(parser.can_parse("httpx"))

        raw_output = json.dumps({
            "timestamp": "2023-01-01T12:00:00",
            "url": "https://example.com",
            "webserver": "nginx",
            "tech": ["React", "Express"],
            "status_code": 200,
            "title": "Example Domain"
        })

        findings = parser.parse(raw_output, "httpx", "example.com")

        self.assertTrue(any("nginx" in t['version'] for t in findings['technologies']))
        self.assertTrue(any("React" in t['name'] for t in findings['technologies']))
        self.assertTrue(any("Example Domain" in u for u in findings['urls']))

if __name__ == '__main__':
    unittest.main()
