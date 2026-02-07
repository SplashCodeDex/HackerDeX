import re
from .models import VulnerabilityModel

class Deduper:
    """
    Handles deduplication of security findings across different tools.
    """

    def is_duplicate(self, v1: VulnerabilityModel, v2: VulnerabilityModel) -> bool:
        """
        Determines if two vulnerabilities are likely the same finding.
        """
        # 1. Exact CVE match
        if v1.cve_id and v2.cve_id and v1.cve_id == v2.cve_id:
            return True
            
        # 2. Same URL and similar type
        if v1.affected_url and v2.affected_url:
            if v1.affected_url == v2.affected_url:
                type1 = self._normalize_type(v1.title)
                type2 = self._normalize_type(v2.title)
                if type1 == type2 and type1 != "unknown":
                    return True
                if self._simplify(v1.title) == self._simplify(v2.title):
                    return True
            return False # Different URLs, unlikely to be the same specific finding

        # 3. If no URLs, fallback to simplified title match (e.g. host-level findings)
        if self._simplify(v1.title) == self._simplify(v2.title):
            return True

        return False

    def _normalize_type(self, title: str) -> str:
        """Extracts a normalized vulnerability type from the title."""
        title = title.lower()
        if "sql" in title: return "sqli"
        if "xss" in title or "cross-site scripting" in title: return "xss"
        if "traversal" in title: return "lfi"
        if "execution" in title or "rce" in title: return "rce"
        if "brute" in title: return "bruteforce"
        return "unknown"

    def _simplify(self, text: str) -> str:
        """Simplifies text for comparison by removing non-alphanumeric chars."""
        return re.sub(r'[^a-zA-Z0-9]', '', text).lower()
