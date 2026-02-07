import unittest
import sys
import os

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.parsers.nmap_parser import NmapParser
from web_ui.parsers.sqlmap_parser import SqlmapParser
from web_ui.parsers.nikto_parser import NiktoParser

class TestParsers(unittest.TestCase):

    def test_nmap_parser_text(self):
        sample_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-07 08:00
Nmap scan report for 127.0.0.1
Host is up (0.000050s latency).
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.49
443/tcp  open  https   OpenSSL 1.1.1
        """
        parser = NmapParser()
        findings = parser.parse(sample_output, "nmap", "127.0.0.1")
        
        self.assertEqual(len(findings['ports']), 2)
        self.assertEqual(findings['ports'][0]['port'], 80)
        self.assertEqual(findings['ports'][0]['service'], "http")
        self.assertEqual(findings['ports'][1]['port'], 443)

    def test_sqlmap_parser(self):
        sample_output = """
[08:00:00] [INFO] testing 'GET' parameter 'id'
[08:00:01] [INFO] parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N] 
[08:00:01] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL 5.7
web server operating system: Linux Ubuntu
web application technology: PHP 7.4.3, Apache 2.4.41
        """
        parser = SqlmapParser()
        findings = parser.parse(sample_output, "sqlmap", "http://example.com/id=1")
        
        self.assertEqual(len(findings['vulns']), 1)
        self.assertEqual(findings['vulns'][0]['title'], "SQL Injection (SQL Injection)")
        self.assertIn("MySQL", [t['name'] for t in findings['technologies']])

    def test_nikto_parser_text(self):
        sample_output = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ OSVDB-3092: /admin/: This might be interesting...
+ /config.php: Configuration file found.
        """
        parser = NiktoParser()
        findings = parser.parse(sample_output, "nikto", "http://127.0.0.1")
        
        self.assertTrue(len(findings['vulns']) >= 1)
        # Text fallback currently returns results from regex or base
        # Based on NiktoParser implementation, it might need better regex fallback

if __name__ == '__main__':
    unittest.main()
