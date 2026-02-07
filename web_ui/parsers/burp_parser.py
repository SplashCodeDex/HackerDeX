import re
import xml.etree.ElementTree as ET
from .base_parser import BaseParser

class BurpSuiteParser(BaseParser):
    """Parser for Burp Suite Scanner XML export."""
    
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['burp', 'burpsuite', 'burp-suite', 'burp-scanner']
    
    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }
        
        # Try to parse as XML first
        if raw_output.strip().startswith('<?xml') or raw_output.strip().startswith('<'):
            try:
                return self._parse_xml_output(raw_output, target)
            except Exception as e:
                # Fall back to text parsing
                pass
        
        # Text-based parsing for Burp output
        return self._parse_text_output(raw_output, target)
    
    def _parse_xml_output(self, xml_content: str, target: str) -> dict:
        """Parse Burp Suite XML export format."""
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }
        
        try:
            root = ET.fromstring(xml_content)
            
            # Burp XML structure: <issues><issue>...</issue></issues>
            for issue in root.findall('.//issue'):
                name = issue.find('name')
                severity = issue.find('severity')
                confidence = issue.find('confidence')
                host = issue.find('host')
                path = issue.find('path')
                location = issue.find('location')
                issue_detail = issue.find('issueDetail')
                issue_background = issue.find('issueBackground')
                
                vuln_title = name.text if name is not None else 'Unknown Vulnerability'
                vuln_severity = self._normalize_burp_severity(severity.text if severity is not None else 'Medium')
                vuln_confidence = confidence.text if confidence is not None else 'Tentative'
                
                # Build URL
                host_text = host.text if host is not None else target
                path_text = path.text if path is not None else '/'
                full_url = f"{host_text}{path_text}"
                
                # Get location (specific parameter or element)
                location_text = location.text if location is not None else ''
                
                # Get detailed information
                detail_text = issue_detail.text if issue_detail is not None else ''
                background_text = issue_background.text if issue_background is not None else ''
                
                vuln_entry = {
                    "title": vuln_title,
                    "severity": vuln_severity,
                    "confidence": vuln_confidence,
                    "url": full_url,
                    "location": location_text,
                    "details": detail_text[:500] if detail_text else vuln_title,
                    "background": background_text[:300] if background_text else '',
                    "source": "Burp Suite Scanner"
                }
                
                # Add exploit recommendation
                vuln_entry["exploit"] = self._get_exploit_recommendation(vuln_title)
                
                findings["vulns"].append(vuln_entry)
                
                if full_url not in findings["urls"]:
                    findings["urls"].append(full_url)
            
            # Summary
            if findings["vulns"]:
                findings["technologies"].append({
                    "name": "Burp Suite Scan Results",
                    "version": f"{len(findings['vulns'])} issues found"
                })
        
        except ET.ParseError as e:
            # XML parsing failed, return empty findings
            pass
        
        return findings
    
    def _parse_text_output(self, raw_output: str, target: str) -> dict:
        """Parse Burp Suite text output."""
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }
        
        # Common vulnerability patterns in Burp output
        vuln_patterns = {
            'SQL Injection': 'critical',
            'Cross-site scripting': 'high',
            'XSS': 'high',
            'OS command injection': 'critical',
            'Path traversal': 'high',
            'File path traversal': 'high',
            'XML external entity': 'critical',
            'XXE': 'critical',
            'Server-side request forgery': 'high',
            'SSRF': 'high',
            'Remote code execution': 'critical',
            'Arbitrary file upload': 'critical',
            'Insecure deserialization': 'critical',
            'LDAP injection': 'high',
            'Open redirect': 'medium',
            'Clickjacking': 'low',
            'Cross-domain script include': 'medium',
            'Directory listing': 'low',
            'Backup file': 'medium',
            'Password field with autocomplete': 'low',
            'SSL certificate': 'medium',
            'Cookie without HttpOnly': 'low',
            'Cookie without Secure': 'low',
            'Missing Content-Type': 'low',
            'Frameable response': 'low'
        }
        
        output_lower = raw_output.lower()
        
        for vuln_name, severity in vuln_patterns.items():
            if vuln_name.lower() in output_lower:
                # Try to extract URL context
                vuln_pattern = rf'({re.escape(vuln_name)}).*?(https?://[^\s]+)?'
                matches = re.finditer(vuln_pattern, raw_output, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    url = match.group(2) if match.group(2) else target
                    
                    findings["vulns"].append({
                        "title": vuln_name.title(),
                        "severity": severity,
                        "url": url,
                        "details": f"Burp Scanner detected {vuln_name}",
                        "source": "Burp Suite",
                        "exploit": self._get_exploit_recommendation(vuln_name)
                    })
                    
                    break  # Only add once per vulnerability type
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'}]+'
        urls = re.findall(url_pattern, raw_output)
        
        for url in set(urls):
            if url not in findings["urls"]:
                findings["urls"].append(url)
        
        # Technology detection
        tech_indicators = {
            'Apache': r'Apache[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'Nginx': r'nginx[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'IIS': r'IIS[/\s]+(\d+\.\d+)',
            'PHP': r'PHP[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'ASP.NET': r'ASP\.NET[/\s]+(\d+\.\d+)',
            'jQuery': r'jQuery[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'AngularJS': r'AngularJS[/\s]+(\d+\.\d+(?:\.\d+)?)'
        }
        
        for tech_name, pattern in tech_indicators.items():
            match = re.search(pattern, raw_output, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex >= 1 else 'detected'
                findings["technologies"].append({
                    "name": tech_name,
                    "version": version
                })
        
        return findings
    
    def _normalize_burp_severity(self, burp_severity: str) -> str:
        """Convert Burp severity levels to standard severity."""
        severity_map = {
            'High': 'critical',
            'Medium': 'high',
            'Low': 'medium',
            'Information': 'low'
        }
        
        return severity_map.get(burp_severity, 'medium')
    
    def _get_exploit_recommendation(self, vuln_name: str) -> str:
        """Get exploitation recommendation for vulnerability."""
        vuln_lower = vuln_name.lower()
        
        exploit_map = {
            'sql injection': 'Use SQLMap to exploit: sqlmap -u <URL> --batch --dbs',
            'xss': 'Inject JavaScript payload: <script>alert(document.cookie)</script>',
            'cross-site scripting': 'Inject JavaScript payload: <script>alert(document.cookie)</script>',
            'command injection': 'Execute system commands: ; id; whoami; uname -a',
            'path traversal': 'Read sensitive files: ../../../../etc/passwd',
            'file path traversal': 'Read sensitive files: ../../../../etc/passwd',
            'xxe': 'Read local files via XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            'ssrf': 'Access internal services: http://localhost:8080/admin',
            'file upload': 'Upload webshell (PHP/ASPX) for remote access',
            'deserialization': 'Use ysoserial to generate malicious payload',
            'ldap injection': 'Bypass authentication: *)(uid=*))(|(uid=*',
            'open redirect': 'Phishing vector: ?redirect=http://evil.com',
            'directory listing': 'Browse directory contents for sensitive files',
            'backup file': 'Download backup files and analyze contents'
        }
        
        for key, recommendation in exploit_map.items():
            if key in vuln_lower:
                return recommendation
        
        return 'Manually investigate and exploit the vulnerability'
