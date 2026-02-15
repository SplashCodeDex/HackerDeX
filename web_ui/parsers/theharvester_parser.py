import re
from parsers.base_parser import BaseParser

class TheHarvesterParser(BaseParser):
    """Parser for theHarvester OSINT tool output."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['theharvester', 'infoga', 'email osint', 'reconspider']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {},
            "dns_info": {
                "a_records": [],
                "mx_records": [],
                "cname_records": []
            },
            "osint_info": {
                "emails": [],
                "subdomains": [],
                "ips": []
            }
        }

        # Email detection
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = list(set(email_pattern.findall(raw_output)))
        findings["osint_info"]["emails"] = emails

        # Subdomain detection (very naive, usually looks like sub.target.com)
        # We look for strings ending in the target domain
        if '.' in target:
            escaped_target = re.escape(target)
            subdomain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + escaped_target + r')')
            subdomains = list(set(subdomain_pattern.findall(raw_output)))
            findings["osint_info"]["subdomains"] = subdomains

        # IP detection
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ips = list(set(ip_pattern.findall(raw_output)))
        findings["osint_info"]["ips"] = [ip for ip in ips if ip != "127.0.0.1" and ip != "0.0.0.0"]

        # If we found emails, add a medium severity vulnerability for information disclosure
        if emails:
            findings["vulns"].append({
                "title": f"OSINT: {len(emails)} Emails Discovered",
                "severity": "medium",
                "details": f"Discovered emails: {', '.join(emails[:5])}...",
                "url": target,
                "source_layer": "osint"
            })

        if findings["osint_info"]["subdomains"]:
            findings["vulns"].append({
                "title": f"OSINT: {len(findings['osint_info']['subdomains'])} Subdomains Discovered",
                "severity": "low",
                "details": f"Discovered subdomains for {target}",
                "url": target,
                "source_layer": "osint"
            })

        return findings
