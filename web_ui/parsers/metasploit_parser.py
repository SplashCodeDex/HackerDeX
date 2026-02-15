import re
from parsers.base_parser import BaseParser

class MetasploitParser(BaseParser):
    """Parser for Metasploit framework output (msfconsole, msfvenom)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['metasploit', 'msfconsole', 'msfvenom', 'msf']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {},
            "sessions": []
        }

        output_lower = raw_output.lower()

        # Session establishment detection
        session_patterns = [
            r"meterpreter session (\d+) opened",
            r"command shell session (\d+) opened",
            r"session (\d+) created"
        ]

        for pattern in session_patterns:
            matches = re.finditer(pattern, raw_output, re.IGNORECASE)
            for match in matches:
                session_id = match.group(1)

                # Try to extract target IP
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                                    raw_output[max(0, match.start()-100):match.end()+100])
                target_ip = ip_match.group(1) if ip_match else target

                findings["sessions"].append({
                    "session_id": session_id,
                    "target_ip": target_ip,
                    "type": "meterpreter" if "meterpreter" in match.group(0).lower() else "shell"
                })

                findings["vulns"].append({
                    "title": f"Metasploit Session Established (ID: {session_id})",
                    "severity": "critical",
                    "details": f"Successfully exploited {target_ip} - Active session available",
                    "url": target_ip
                })

        # Exploit success indicators
        if "exploit completed successfully" in output_lower:
            findings["vulns"].append({
                "title": "Successful Exploitation",
                "severity": "critical",
                "details": "Metasploit exploit completed successfully",
                "url": target
            })

        # Vulnerable service detection
        vuln_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*appears to be vulnerable",
                               raw_output, re.IGNORECASE)
        if vuln_match:
            findings["vulns"].append({
                "title": "Vulnerable Service Detected",
                "severity": "high",
                "details": f"Target {vuln_match.group(1)} appears vulnerable to exploit",
                "url": vuln_match.group(1)
            })

        # Payload generation (msfvenom)
        if "payload size:" in output_lower or "final size" in output_lower:
            size_match = re.search(r"size[:\s]+(\d+)", raw_output, re.IGNORECASE)
            if size_match:
                findings["technologies"].append({
                    "name": "Generated Payload",
                    "version": f"{size_match.group(1)} bytes"
                })

        # Meterpreter commands execution
        if "meterpreter >" in output_lower:
            # Extract system info if available
            os_match = re.search(r"OS\s*:\s*([^\n]+)", raw_output)
            if os_match:
                findings["os_info"]["name"] = os_match.group(1).strip()

            arch_match = re.search(r"Architecture\s*:\s*([^\n]+)", raw_output)
            if arch_match:
                findings["os_info"]["architecture"] = arch_match.group(1).strip()

        return findings
