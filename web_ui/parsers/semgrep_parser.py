import json
import logging
from .base_parser import BaseParser

logger = logging.getLogger(__name__)

class SemgrepParser(BaseParser):
    """Parser for Semgrep static analysis tool output (JSON format)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['semgrep']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        try:
            data = json.loads(raw_output)
            results = data.get('results', [])

            for res in results:
                # {
                #   "check_id": "python.lang.security.audit.exec",
                #   "path": "app.py",
                #   "start": {"line": 10, "col": 5},
                #   "extra": {
                #     "message": "Exec detected",
                #     "severity": "WARNING",
                #     "metadata": {...}
                #   }
                # }

                check_id = res.get('check_id')
                file_path = res.get('path')
                extra = res.get('extra', {})
                message = extra.get('message')
                severity = extra.get('severity', 'simple').lower()

                # Map Semgrep severity to our schema
                # Semgrep: INFO, WARNING, ERROR
                # Ours: low, medium, high, critical
                severity_map = {
                    'info': 'low',
                    'warning': 'medium',
                    'error': 'high'
                }
                normalized_severity = severity_map.get(severity, 'medium')

                # Line number
                start_line = res.get('start', {}).get('line', '?')

                findings['vulns'].append({
                    "title": f"SAST: {check_id}",
                    "severity": normalized_severity,
                    "details": f"{message}\nFile: {file_path}:{start_line}",
                    "url": file_path  # Using file path as 'url' for SAST
                })

            findings['technologies'].append({
                "name": "Semgrep Scan",
                "version": f"Found {len(results)} issues"
            })

        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output")

        return findings
