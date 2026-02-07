from typing import Dict, Any
from vuln_store import VulnStore

class AgentContext:
    """
    Feeds real-time VulnStore data to the Agent's Brain (Gemini).
    Provides structured summaries of the attack surface.
    """

    def __init__(self, store: VulnStore):
        self.store = store

    def get_mission_context(self, current_target: str) -> str:
        """
        Returns a rich technical context for the current mission.
        """
        profile = self.store.get_target_profile(current_target)
        all_targets = self.store.get_all_targets_summary()
        
        context = f"CURRENT TARGET: {current_target}\n"
        if profile:
            context += f"Risk Score: {profile.get('risk_score', 0):.1f} ({profile.get('priority_level', 'low')})\n"
            context += "Open Ports:\n"
            for p in profile.get('ports', []):
                context += f"- {p['port']}/{p['protocol']} ({p['service']}) {p['version']}\n"
            
            context += "Discovered Vulnerabilities:\n"
            for v in profile.get('vulnerabilities', []):
                context += f"- [{v['severity'].upper()}] {v['title']}: {v['details'][:100]}\n"
                
            if profile.get('osint_info'):
                context += "OSINT Intelligence:\n"
                osint = profile['osint_info']
                context += f"- Subdomains: {', '.join(osint.get('subdomains', [])[:5])}\n"
                context += f"- IPs: {', '.join(osint.get('ips', [])[:5])}\n"

        context += "\nOVERALL ATTACK SURFACE:\n"
        for t in all_targets[:5]:
            if t['target'] != current_target:
                context += f"- {t['target']} (Score: {t['risk_score']:.1f}, Vulns: {t['vulns_count']})\n"
                
        return context