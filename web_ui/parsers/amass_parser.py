import json
import logging
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

class AmassParser(BaseParser):
    """Parser for Amass subdomain enumeration tool output (JSON Lines format)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['amass', 'amass enum']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        subdomains = set()
        ips = set()

        # Amass -json output is JSON Lines (one JSON object per line)
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # Amass JSON structure:
                # {
                #   "name": "sub.example.com",
                #   "domain": "example.com",
                #   "addresses": [
                #     {"original": "1.2.3.4", "ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 12345, "desc": "Provider"}
                #   ],
                #   ...
                # }

                name = data.get('name')
                if name:
                    subdomains.add(name)
                    # Add as potential URLs (http/https)
                    findings['urls'].append(f"http://{name}")
                    findings['urls'].append(f"https://{name}")

                addresses = data.get('addresses', [])
                for addr in addresses:
                    ip = addr.get('ip')
                    if ip:
                        ips.add(ip)
                        # We could add an 'info' vulnerability or technology note about the IP/ASN
                        desc = addr.get('desc')
                        cidr = addr.get('cidr')
                        asn = addr.get('asn')

                        tech_info = f"IP: {ip}"
                        if desc:
                            tech_info += f" ({desc})"
                        if asn:
                            tech_info += f" ASN: {asn}"

                        # Avoid duplicates if possible, or just append
                        findings['technologies'].append({
                            "name": "Infrastructure",
                            "version": tech_info
                        })

            except json.JSONDecodeError:
                continue

        # Summary
        if subdomains:
            findings['technologies'].append({
                "name": "Amass Enumeration",
                "version": f"Found {len(subdomains)} subdomains"
            })

        return findings
