import json
import logging
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

class HttpxParser(BaseParser):
    """Parser for Httpx web probing tool output (JSON Lines format)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['httpx']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # httpx -json output
        # {
        #   "timestamp": "...",
        #   "url": "https://example.com",
        #   "webserver": "gunicorn",
        #   "tech": ["Python", "Django"],
        #   "status_code": 200,
        #   "title": "Example Domain"
        # }

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                url = data.get('url')
                status = data.get('status_code')
                title = data.get('title', '')
                webserver = data.get('webserver')
                technologies = data.get('tech', [])

                if url:
                    entry = f"{url} (Status: {status})"
                    if title:
                        entry += f" - {title}"
                    findings['urls'].append(entry)

                if webserver:
                    findings['technologies'].append({
                        "name": "Web Server",
                        "version": webserver
                    })

                for tech in technologies:
                    findings['technologies'].append({
                        "name": tech,
                        "version": "Detected by httpx"
                    })

            except json.JSONDecodeError:
                continue

        return findings
