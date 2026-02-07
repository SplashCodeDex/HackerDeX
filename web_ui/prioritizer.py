from typing import List
from models import VulnerabilityModel

class Prioritizer:
    """
    Implements the "Advantage-Based" ranking algorithm for security findings.
    """

    SEVERITY_SCORES = {
        "critical": 10.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 2.0,
        "info": 1.0,
        "none": 0.0
    }

    PRIVILEGE_MULTIPLIERS = {
        "admin": 2.0,
        "root": 2.0,
        "system": 2.0,
        "user": 1.5,
        "none": 1.0
    }

    STRATEGIC_ADVANTAGE_BONUS = {
        "rce": 5.0,
        "lateral_movement": 3.0,
        "data_exfiltration": 2.0,
        "credential_access": 2.0,
        "persistence": 2.0
    }

    def calculate_vuln_score(self, vuln: VulnerabilityModel) -> float:
        """
        Calculates a score for a single vulnerability based on its attributes.
        Score = (BaseSeverity * PrivilegeMultiplier) + StrategicBonus) * Confidence
        """
        base_score = self.SEVERITY_SCORES.get(vuln.severity.lower(), 1.0)
        multiplier = self.PRIVILEGE_MULTIPLIERS.get(vuln.privilege_level.lower(), 1.0)
        bonus = self.STRATEGIC_ADVANTAGE_BONUS.get(vuln.strategic_advantage.lower(), 0.0)
        
        score = (base_score * multiplier) + bonus
        return score * vuln.confidence

    def calculate_target_risk(self, vulnerabilities: List[VulnerabilityModel]) -> float:
        """
        Aggregates individual vulnerability scores into a total risk score for a target.
        """
        if not vulnerabilities:
            return 0.0
        return sum(self.calculate_vuln_score(v) for v in vulnerabilities)

    def get_priority_level(self, risk_score: float) -> str:
        """Determines the human-readable priority level based on the score."""
        if risk_score >= 20.0:
            return "critical"
        if risk_score >= 10.0:
            return "high"
        if risk_score >= 5.0:
            return "medium"
        return "low"
