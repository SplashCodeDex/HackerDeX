import re
from .base_parser import BaseParser

class GenericParser(BaseParser):
    def can_parse(self, tool_name: str) -> bool:
        return True  # Fallback for all tools

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Regex for IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        # Regex for URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        # Regex for Emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Regex for CVEs
        cve_pattern = r'CVE-\d{4}-\d{4,}'

        ips = set(re.findall(ip_pattern, raw_output))
        urls = set(re.findall(url_pattern, raw_output))
        emails = set(re.findall(email_pattern, raw_output))
        cves = set(re.findall(cve_pattern, raw_output))

        for url in urls:
            findings["urls"].append(url)

        for cve in cves:
            findings["vulns"].append({
                "title": f"Potential Vulnerability: {cve}",
                "severity": "unknown",
                "details": f"Mentioned in scan output of {tool_name}",
                "url": target
            })

        # Add interesting IPs or emails to raw findings if needed (for now just URL/CVE)
        return findings
