import re
from .base_parser import BaseParser

class NiktoParser(BaseParser):
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['nikto', 'nikto scan', 'web scanner']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Severity mapping logic
        def get_severity(text: str) -> str:
            text_lower = text.lower()
            if any(k in text_lower for k in ['rce', 'execution', 'admin', 'sql', 'injection']):
                return 'critical'
            if any(k in text_lower for k in ['xss', 'traversal', 'config', 'sensitive']):
                return 'high'
            if any(k in text_lower for k in ['phpinfo', 'listing', 'disclosure']):
                return 'medium'
            return 'low'

        try:
            # Check for XML signature
            if not raw_output.strip().startswith('<?xml') and not raw_output.strip().startswith('<niktoscan'):
                return self._parse_text_fallback(raw_output, findings, target)

            import xml.etree.ElementTree as ET
            # Fix potential multi-root issues if multiple scans concatenated (naive fix)
            if raw_output.count('<niktoscan>') > 1:
                raw_output = raw_output.split('</niktoscan>')[0] + '</niktoscan>'

            root = ET.fromstring(raw_output)

            # Additional header info
            scandetails = root.find('scandetails')
            if scandetails is not None:
                site_ip = scandetails.get('targetip')
                site_host = scandetails.get('targethostname')
                port = scandetails.get('targetport')
                banner = scandetails.get('sitebanner')

                if banner:
                    findings['technologies'].append({
                        "name": "Web Server",
                        "version": banner[:50]
                    })

                # Iterate findings
                for item in scandetails.findall('item'):
                    osvdb = item.get('osvdbid')
                    method = item.get('method')
                    uri = item.find('uri').text if item.find('uri') is not None else ""
                    description = item.find('description').text if item.find('description') is not None else ""
                    namelink = item.find('namelink').text if item.find('namelink') is not None else ""

                    full_desc = f"{description} (Method: {method})"
                    severity = get_severity(full_desc)

                    findings['vulns'].append({
                        "title": f"Nikto: {osvdb}" if osvdb and osvdb != "0" else "Nikto Finding",
                        "severity": severity,
                        "details": full_desc[:200],
                        "url": f"{target}{uri}"
                    })

                    if uri and uri != '/':
                         findings['urls'].append(f"{target}{uri}")

        except Exception as e:
            print(f"Nikto XML Parsing failed: {e}. Falling back to text.")
            return self._parse_text_fallback(raw_output, findings, target)

        return findings

    def _parse_text_fallback(self, raw_output, findings, target):
        return super().parse(raw_output, "nikto", target)  # Not actually calling super, but implementing regex fallback logic here if needed
        # Re-implement regex fallback for safety
        vuln_pattern = re.compile(r'^\s*\+\s*(OSVDB-\d+)?:?\s*(.+)', re.MULTILINE)
        for line in raw_output.splitlines():
            vuln_match = vuln_pattern.search(line)
            if vuln_match:
                details = vuln_match.group(2).strip()
                findings["vulns"].append({
                    "title": "Nikto Finding (Text Fallback)",
                    "severity": "medium",
                    "details": details[:200],
                    "url": target
                })
        return findings
