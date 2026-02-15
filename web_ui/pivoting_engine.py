import logging
from typing import List, Dict, Any
from vuln_store import VulnStore
from mission_manager import MissionManager

class PivotingEngine:
    """
    Identifies successful compromises (footholds) and triggers autonomous
    post-exploitation and pivoting workflows.
    """

    def __init__(self, store: VulnStore, mission_mgr: MissionManager):
        self.store = store
        self.mission_mgr = mission_mgr
        self.detected_footholds = set()

    def detect_footholds(self) -> List[Dict[str, Any]]:
        """
        Scans VulnStore for vulnerabilities that provide a strategic foothold.
        """
        footholds = []
        for tid, target in self.store.targets.items():
            if tid in self.detected_footholds:
                continue

            for vuln in target.get('vulnerabilities', []):
                # Criteria for a foothold: RCE, high privilege, or strategic advantage
                is_rce = "rce" in vuln.get('strategic_advantage', '').lower()
                high_priv = vuln.get('privilege_level', '').lower() in ['root', 'admin', 'system']

                if is_rce or high_priv:
                    footholds.append({
                        "target_id": tid,
                        "target": target['main_target'],
                        "vuln": vuln
                    })
                    self.detected_footholds.add(tid)
                    break

        return footholds

    def trigger_post_exploitation(self, foothold: Dict[str, Any]):
        """
        Injects post-exploitation tasks into the current mission.
        """
        target = foothold['target']
        vuln_title = foothold['vuln']['title']

        logging.info(f"Pivoting Engine: Foothold detected on {target} via {vuln_title}")

        post_exploit_phase = {
            "name": "Post-Exploitation & Pivoting",
            "goal": f"Establish persistence and discover internal network from {target}",
            "tasks": [
                "run_post_exploit", # Generic action for the agent
                "auto_enumerate",
                "pivot_scan",
                "install_persistence"
            ],
            "parallel": False,
            "target": target
        }

        self.mission_mgr.active_phases.append(post_exploit_phase)
        logging.info(f"Pivoting Engine: Injected post-exploitation phase for {target}")
