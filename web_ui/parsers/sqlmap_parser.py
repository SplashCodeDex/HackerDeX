import re
from .base_parser import BaseParser

class SqlmapParser(BaseParser):
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['sqlmap', 'sql injection', 'sqli scanner']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        output_lower = raw_output.lower()

        # Injection confirmation patterns
        injection_patterns = [
            (r"parameter '([^']+)'.*is vulnerable", "critical"),
            (r"(\w+) parameter.*is vulnerable", "critical"),
            (r"Type:\s*([\w\-]+)", None),  # Injection type
        ]

        # Extract injection vulnerability
        if "is vulnerable" in output_lower or "vulnerable to" in output_lower:
            # Try to find the specific parameter
            param_match = re.search(r"parameter '([^']+)'", raw_output, re.IGNORECASE)
            param_name = param_match.group(1) if param_match else "parameter"

            # Detect injection types
            injection_types = []
            type_patterns = [
                ("boolean-based blind", "Boolean Blind"),
                ("time-based blind", "Time Blind"),
                ("error-based", "Error Based"),
                ("union query", "UNION"),
                ("stacked queries", "Stacked"),
            ]
            for pattern, name in type_patterns:
                if pattern in output_lower:
                    injection_types.append(name)

            type_str = ", ".join(injection_types) if injection_types else "SQL Injection"

            findings["vulns"].append({
                "title": f"SQL Injection ({type_str})",
                "severity": "critical",
                "details": f"SQLMap confirmed '{param_name}' is injectable via: {type_str}",
                "url": target
            })

        # Backend DBMS detection
        dbms_match = re.search(r"back-end DBMS:\s*(.*)", raw_output, re.IGNORECASE)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
            # Try to extract version
            version_match = re.search(r"([\d.]+)", dbms)
            version = version_match.group(1) if version_match else ""

            findings["technologies"].append({
                "name": dbms.split()[0] if dbms else "Unknown DBMS",
                "version": version
            })

        # Web server detection
        server_match = re.search(r"web server.*:\s*(.*)", raw_output, re.IGNORECASE)
        if server_match:
            server = server_match.group(1).strip()
            findings["technologies"].append({
                "name": "Web Server",
                "version": server[:50]
            })

        # Current user detection (privilege indicator)
        user_match = re.search(r"current user:\s*'([^']+)'", raw_output, re.IGNORECASE)
        if user_match:
            user = user_match.group(1)
            if user.lower() in ['root', 'sa', 'postgres', 'admin', 'dba']:
                findings["vulns"].append({
                    "title": "Database Admin Privileges",
                    "severity": "critical",
                    "details": f"Running as privileged user: {user}",
                    "url": target
                })

        # File read/write capability (high severity)
        if "file-read" in output_lower or "file-write" in output_lower:
            findings["vulns"].append({
                "title": "File System Access via SQLi",
                "severity": "critical",
                "details": "SQLMap can read/write files via injection",
                "url": target
            })

        # OS command execution
        if "os-shell" in output_lower or "os-cmd" in output_lower:
            findings["vulns"].append({
                "title": "OS Command Execution via SQLi",
                "severity": "critical",
                "details": "SQLMap achieved OS-level command execution",
                "url": target
            })

        return findings
