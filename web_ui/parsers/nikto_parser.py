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

        # Severity mapping for known OSVDB and common issues
        severity_keywords = {
            'critical': ['rce', 'remote code', 'command execution', 'backdoor', 'upload'],
            'high': ['xss', 'cross-site', 'injection', 'traversal', 'lfi', 'rfi', 'sql'],
            'medium': ['directory listing', 'information disclosure', 'phpinfo', 'debug']
        }

        def get_severity(text: str) -> str:
            text_lower = text.lower()
            for sev, keywords in severity_keywords.items():
                if any(kw in text_lower for kw in keywords):
                    return sev
            return 'low'  # Default to low if no keywords match

        # Nikto output patterns
        # + OSVDB-3092: /admin/: This might be interesting...
        # + /crossdomain.xml: Flash app allows any domain access
        vuln_pattern = re.compile(r'^\s*\+\s*(OSVDB-\d+)?:?\s*(.+)', re.MULTILINE)

        # Server detection
        server_pattern = re.compile(r'Server:\s*(.+)', re.IGNORECASE)

        # Target IP detection
        target_ip_pattern = re.compile(r'Target IP:\s*([0-9.]+)')

        # Scan timestamp
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Server detection
            server_match = server_pattern.search(line)
            if server_match:
                server = server_match.group(1).strip()
                # Parse server string (e.g., "Apache/2.4.41 (Ubuntu)")
                parts = server.split('/')
                name = parts[0] if parts else server
                version = parts[1].split()[0] if len(parts) > 1 else ""
                findings["technologies"].append({
                    "name": name,
                    "version": version
                })
                continue

            # Vulnerability/finding detection
            vuln_match = vuln_pattern.search(line)
            if vuln_match:
                osvdb = vuln_match.group(1) or ""
                details = vuln_match.group(2).strip()

                # Skip scan metadata lines
                if any(skip in details.lower() for skip in ['start:', 'end:', 'host:', 'target']):
                    continue

                # Extract URL if present
                url_match = re.search(r'(/[^\s:]+)', details)
                if url_match:
                    found_url = url_match.group(1)
                    findings["urls"].append(f"{target}{found_url}")

                severity = get_severity(details)
                title = osvdb if osvdb else "Nikto Finding"

                findings["vulns"].append({
                    "title": title,
                    "severity": severity,
                    "details": details[:200],
                    "url": target
                })

            # X-Powered-By detection
            if 'x-powered-by' in line.lower():
                powered_match = re.search(r'X-Powered-By:\s*(.+)', line, re.IGNORECASE)
                if powered_match:
                    tech = powered_match.group(1).strip()
                    findings["technologies"].append({
                        "name": tech.split('/')[0],
                        "version": tech.split('/')[1] if '/' in tech else ""
                    })

        return findings
