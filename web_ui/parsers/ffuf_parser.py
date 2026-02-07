import json
import logging
from .base_parser import BaseParser

logger = logging.getLogger(__name__)

class FFUFParser(BaseParser):
    """Parser for FFUF web fuzzing tool output (JSON format)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['ffuf']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        try:
            # FFUF -o output.json -of json produces a single JSON object with a "results" list
            data = json.loads(raw_output)
            results = data.get('results', [])

            for res in results:
                # {
                #   "input": {"FUZZ": "admin"},
                #   "position": 1,
                #   "status": 200,
                #   "length": 1234,
                #   "words": 50,
                #   "lines": 10,
                #   "content-type": "text/html",
                #   "redirectlocation": "",
                #   "url": "http://example.com/admin"
                # }

                url = res.get('url')
                status = res.get('status')
                content_type = res.get('content-type')
                length = res.get('length')
                redirect = res.get('redirectlocation')

                if url:
                    entry = f"{url} (Status: {status}, Size: {length})"
                    if redirect:
                        entry += f" -> {redirect}"

                    findings['urls'].append(entry)

                    # Determine severity based on status and path keywords
                    path = url.split('/')[-1].lower() if url else ""
                    severity = "low"

                    # 200 OK on sensitive paths
                    if status == 200:
                        if path in ['admin', 'config', '.env', '.git', 'backup', 'db', 'phpmyadmin']:
                            severity = "high"
                            if path in ['.env', '.git', 'backup']:
                                severity = "critical"

                        if severity != "low":
                            findings['vulns'].append({
                                "title": f"Sensitive Path Discovered: {path}",
                                "severity": severity,
                                "details": f"Direct access to {path} allowed (Status 200). Content-Type: {content_type}",
                                "url": url
                            })

            findings['technologies'].append({
                "name": "FFUF Fuzzing",
                "version": f"Found {len(results)} items"
            })

        except json.JSONDecodeError:
            logger.error("Failed to parse FFUF JSON output")
            # Fallback for plain text? usage typically enforcement of json in tool wrappers
            pass

        return findings
