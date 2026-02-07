from typing import List, Set, TYPE_CHECKING
if TYPE_CHECKING:
    from .vuln_store import VulnStore

class Correlator:
    """
    Correlates intelligence across OSINT, Network, and Web layers.
    """

    def __init__(self, store: 'VulnStore'):
        self.store = store

    def correlate_all(self):
        """Perform all correlation logic across the store."""
        self._correlate_aliases_from_osint()
        self._link_related_targets()

    def _correlate_aliases_from_osint(self):
        """
        If a target has IPs or subdomains in its OSINT info, 
        add them as aliases if they aren't already.
        """
        for tid, target in self.store.targets.items():
            osint = target.get("osint_info", {})
            new_aliases = set()
            
            # Add IPs as aliases
            for ip in osint.get("ips", []):
                new_aliases.add(ip)
            
            # Add Subdomains as aliases
            for sub in osint.get("subdomains", []):
                new_aliases.add(sub)
            
            if new_aliases:
                with self.store.lock:
                    for alias in new_aliases:
                        if alias not in target["aliases"]:
                            target["aliases"].append(alias)
                            self.store.alias_index[alias] = tid

    def _link_related_targets(self):
        """
        If two targets share an alias (e.g. same IP), they should be merged or linked.
        For this implementation, we will merge findings into the 'primary' target.
        """
        # This is complex for a simple JSON store, so we'll start with alias consistency.
        pass

    def discover_new_targets(self) -> Set[str]:
        """
        Identifies potential targets found in OSINT data that aren't yet in the main targets list.
        """
        discovered = set()
        known_aliases = set(self.store.alias_index.keys())
        
        for target in self.store.targets.values():
            osint = target.get("osint_info", {})
            for ip in osint.get("ips", []):
                if ip not in known_aliases:
                    discovered.add(ip)
            for sub in osint.get("subdomains", []):
                if sub not in known_aliases:
                    discovered.add(sub)
        
        return discovered
