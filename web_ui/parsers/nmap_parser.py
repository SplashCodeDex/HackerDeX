import re
from .base_parser import BaseParser

class NmapParser(BaseParser):
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['nmap', 'network map', 'nmap scan']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Standard Nmap port line: 80/tcp open  http  Apache httpd 2.4.41
        # Also handles: 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+(open|filtered)\s+([^\s]+)\s*(.*)', re.IGNORECASE)

        # Host up detection
        host_up_pattern = re.compile(r'Host is up \(([0-9.]+)s latency\)')

        # OS detection patterns
        os_patterns = [
            re.compile(r'OS details:\s*(.+)', re.IGNORECASE),
            re.compile(r'Running:\s*(.+)', re.IGNORECASE),
            re.compile(r'Aggressive OS guesses:\s*(.+)', re.IGNORECASE),
        ]

        # NSE script vulnerability patterns
        vuln_patterns = [
            re.compile(r'VULNERABLE', re.IGNORECASE),
            re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE),
            re.compile(r'(ssl-heartbleed|smb-vuln|http-vuln)', re.IGNORECASE),
        ]

        current_script = None

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Port detection
            match = port_pattern.search(line)
            if match:
                port = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version = match.group(5).strip()

                # Only add open ports
                if state.lower() == 'open':
                    findings["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "version": version
                    })

                    # Extract technology from version string
                    if version:
                        # Parse version string for common tech (Apache, nginx, OpenSSH, etc.)
                        tech_match = re.match(r'([A-Za-z]+(?:\s+[A-Za-z]+)?)\s+([0-9.]+)', version)
                        if tech_match:
                            findings["technologies"].append({
                                "name": tech_match.group(1),
                                "version": tech_match.group(2)
                            })
                        else:
                            findings["technologies"].append({
                                "name": service.capitalize(),
                                "version": version[:50]  # Truncate long versions
                            })

            # OS detection
            for os_pat in os_patterns:
                os_match = os_pat.search(line)
                if os_match:
                    findings["os_info"]["name"] = os_match.group(1).strip()[:100]
                    break

            # Vulnerability detection from NSE scripts
            for vuln_pat in vuln_patterns:
                if vuln_pat.search(line):
                    # Extract CVE if present
                    cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
                    title = cve_match.group(1) if cve_match else "NSE Vulnerability Detected"

                    findings["vulns"].append({
                        "title": title,
                        "severity": "high",
                        "details": line[:200],
                        "url": target
                    })
                    break

            # HTTP title extraction for web servers
            if '|_http-title:' in line:
                title = line.split('|_http-title:')[1].strip()
                if title and 'Did not follow redirect' not in title:
                    findings["urls"].append(f"http://{target}/ - {title[:50]}")

        return findings
