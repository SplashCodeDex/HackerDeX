import re
import logging
from typing import List, Dict, Any
from vuln_store import VulnStore

class LateralMovementEngine:
    """
    Orchestrates discovery and credential correlation for moving laterally across a network.
    """

    def __init__(self, store: VulnStore):
        self.store = store

    def correlate_credentials(self) -> List[Dict[str, Any]]:
        """
        Looks for credentials discovered in one target and matches them with potential victims.
        """
        harvested_creds = self._harvest_all_credentials()
        potential_moves = []

        if not harvested_creds:
            return []

        for tid, target in self.store.targets.items():
            # Find targets with services that accept credentials (ssh, rdp, mysql, etc.)
            for port in target.get('ports', []):
                service = port.get('service', '').lower()
                if any(s in service for s in ['ssh', 'rdp', 'mysql', 'smb', 'http-auth']):
                    for cred in harvested_creds:
                        potential_moves.append({
                            "target": target['main_target'],
                            "service": service,
                            "port": port['port'],
                            "credential": cred,
                            "reasoning": f"Testing harvested credential '{cred}' against {service} on {target['main_target']}"
                        })

        return potential_moves

    def _harvest_all_credentials(self) -> List[str]:
        """
        Scans all vulnerabilities and OSINT for anything looking like a password or key.
        """
        creds = set()
        password_pattern = re.compile(r'pass(?:word)?:?\s*([^\s,]+)', re.IGNORECASE)

        for target in self.store.targets.values():
            # Check vulnerability details
            for vuln in target.get('vulnerabilities', []):
                details = vuln.get('details', '')
                matches = password_pattern.findall(details)
                for m in matches:
                    creds.add(m)

            # Check OSINT (emails can be usernames)
            osint = target.get('osint_info', {})
            for email in osint.get('emails', []):
                creds.add(email.split('@')[0]) # Add local part as candidate username

        return list(creds)

    def plan_pivot_discovery(self, session_target: str) -> Dict[str, Any]:
        """
        Generates a discovery plan for a node where we have a session.
        """
        return {
            "node": session_target,
            "discovery_tasks": [
                {"tool": "ip_addr", "cmd": "ip addr show || ifconfig"},
                {"tool": "arp_scan", "cmd": "arp -a || ip neighbor show"},
                {"tool": "netstat", "cmd": "netstat -antup || ss -tuln"}
            ]
        }
