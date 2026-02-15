import json
import logging
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

class NaabuParser(BaseParser):
    """Parser for Naabu port scanner output (JSON Lines format)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['naabu']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Naabu -json output: {"ip": "127.0.0.1", "port": 80}
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                ip = data.get('ip')
                port = data.get('port')
                host = data.get('host') # Sometimes present

                if port:
                    findings['ports'].append({
                        "port": int(port),
                        "protocol": "tcp", # Naabu is mostly TCP Syn/Connect
                        "service": "unknown", # Naabu doesn't do service detection by default, just port open
                        "version": ""
                    })

                    # Add generic URL for web ports
                    if port in [80, 443, 8080, 8443]:
                        scheme = "https" if port in [443, 8443] else "http"
                        findings['urls'].append(f"{scheme}://{ip}:{port}")

            except json.JSONDecodeError:
                continue

        findings['technologies'].append({
            "name": "Naabu Port Scan",
            "version": f"Scanned {len(findings['ports'])} open ports"
        })

        return findings
