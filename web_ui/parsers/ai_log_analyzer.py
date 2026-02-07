"""
AI-Powered Log Analysis & Anomaly Correlation Engine
Uses Gemini's 2M token context window to analyze massive log datasets
Based on 2026 Security Research - AI-Driven Threat Detection
"""

import json
import re
from typing import Dict, List, Optional
from datetime import datetime
from collections import defaultdict


class GeminiLogAnalyzer:
    """
    Leverages Gemini 2.0's massive context window to correlate logs across
    multiple sources and identify complex attack patterns.
    """
    
    def __init__(self, gemini_client):
        self.client = gemini_client
        self.model = "gemini-2.0-flash-exp"
        self.anomalies = []
    
    def correlate_multi_source_logs(self, log_sources: Dict[str, List[str]]) -> Dict:
        """
        Correlates logs from multiple sources to identify attack chains.
        
        Sources:
        - Kubernetes audit logs
        - Application logs
        - WAF logs
        - Database query logs
        - Network traffic logs
        """
        # Combine first 1000 lines from each source (within token limits)
        combined_logs = ""
        for source_name, logs in log_sources.items():
            combined_logs += f"\n=== {source_name.upper()} LOGS ===\n"
            combined_logs += "\n".join(logs[:1000])
        
        prompt = f"""
You are an expert security analyst correlating logs across multiple systems to identify attack patterns.

MULTI-SOURCE LOGS:
```
{combined_logs[:100000]}  # First 100k chars to stay within limits
```

CORRELATION ANALYSIS:

1. **Attack Chain Detection:**
   - Identify sequences of events across different systems
   - Example: WAF bypass -> SQL injection -> data exfiltration
   - Timeline reconstruction of attacker activity

2. **Anomaly Detection:**
   - Unusual access patterns (e.g., 3am database queries from web server)
   - Privilege escalation sequences
   - Lateral movement indicators

3. **IOC Extraction:**
   - Suspicious IP addresses
   - Malicious user agents
   - Exploit payloads in logs
   - C2 domain patterns

4. **Impact Assessment:**
   - What data was accessed/exfiltrated?
   - Which systems were compromised?
   - Persistence mechanisms deployed?

OUTPUT (JSON):
{{
  "attack_chains": [
    {{
      "name": "SQL Injection -> Data Exfiltration",
      "timeline": [
        {{"timestamp": "...", "source": "waf", "event": "SQLi bypass attempt"}},
        {{"timestamp": "...", "source": "app", "event": "Suspicious query executed"}},
        {{"timestamp": "...", "source": "network", "event": "Large data transfer to external IP"}}
      ],
      "severity": "critical",
      "affected_systems": ["web-app", "database", "network"]
    }}
  ],
  "iocs": {{
    "ip_addresses": ["192.168.1.100"],
    "user_agents": ["..."],
    "domains": ["malicious.com"]
  }},
  "recommendations": ["Immediate actions to take"]
}}
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            result_text = response.text
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            
            analysis = json.loads(result_text)
            
            # Store anomalies
            for chain in analysis.get("attack_chains", []):
                self.anomalies.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": "attack_chain",
                    **chain
                })
            
            return analysis
        except Exception as e:
            return {"error": str(e)}
    
    def extract_versions_from_errors(self, error_logs: List[str]) -> Dict:
        """
        Extracts library/framework versions from error stack traces
        and maps them to known CVEs.
        """
        prompt = f"""
Analyze these error logs to extract software versions and identify vulnerabilities:

ERROR LOGS:
```
{chr(10).join(error_logs[:500])}
```

EXTRACTION TASKS:

1. **Version Detection:**
   - Framework versions (Django 3.2.1, Spring Boot 2.5.0)
   - Library versions (log4j 2.14.1, jackson 2.12.0)
   - Language runtime versions (Python 3.8.5, Node.js 14.17.0)
   - Database versions (PostgreSQL 12.3, MySQL 8.0.23)

2. **Stack Trace Analysis:**
   - Identify vulnerable code paths
   - Detect unsafe deserialization
   - Find SQL injection points
   - Locate file upload vulnerabilities

3. **CVE Mapping:**
   - Match extracted versions to known CVEs
   - Prioritize by exploitability and severity
   - Suggest public exploits for detected versions

4. **Configuration Exposure:**
   - Debug mode enabled?
   - Stack traces revealing internal paths
   - Database credentials in error messages

OUTPUT (JSON):
{{
  "detected_versions": [
    {{
      "component": "log4j",
      "version": "2.14.1",
      "cves": ["CVE-2021-44228"],
      "severity": "critical",
      "public_exploits": ["https://github.com/..."]
    }}
  ],
  "vulnerable_code_paths": ["..."],
  "exploitation_priority": ["log4j RCE (CVE-2021-44228)"]
}}
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            result_text = response.text
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            
            return json.loads(result_text)
        except Exception as e:
            return {"error": str(e)}
    
    def identify_misconfigurations(self, config_files: Dict[str, str]) -> Dict:
        """
        Compares configurations against security baselines to find gaps.
        """
        configs_text = ""
        for filename, content in config_files.items():
            configs_text += f"\n=== {filename} ===\n{content}\n"
        
        prompt = f"""
Analyze these configuration files for security misconfigurations:

CONFIGURATION FILES:
```
{configs_text[:50000]}
```

SECURITY CHECKS:

1. **Authentication & Authorization:**
   - Weak password policies
   - Missing MFA requirements
   - Overly permissive RBAC rules
   - Default credentials

2. **Network Security:**
   - Unnecessary open ports
   - Missing firewall rules
   - Insecure protocol usage (HTTP vs HTTPS)
   - CORS misconfigurations

3. **Data Protection:**
   - Unencrypted sensitive data
   - Weak encryption algorithms
   - Missing data retention policies
   - Insecure backup configurations

4. **Logging & Monitoring:**
   - Insufficient audit logging
   - Missing security alerts
   - Log retention too short
   - PII in logs

5. **Cloud-Specific:**
   - Public S3 buckets
   - Overly permissive IAM policies
   - Missing encryption at rest
   - No VPC isolation

OUTPUT (JSON):
{{
  "critical_misconfigurations": [
    {{
      "file": "app.conf",
      "issue": "Debug mode enabled in production",
      "line": 42,
      "severity": "high",
      "remediation": "Set DEBUG=False",
      "attack_vector": "Exposes stack traces and internal paths"
    }}
  ],
  "compliance_violations": ["PCI-DSS", "GDPR"],
  "security_score": 45  # out of 100
}}
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            result_text = response.text
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            
            return json.loads(result_text)
        except Exception as e:
            return {"error": str(e)}
    
    def predict_exploitation_path(self, reconnaissance_data: Dict) -> Dict:
        """
        Uses AI to predict the most likely attack path based on recon findings.
        """
        prompt = f"""
Based on reconnaissance data, predict the optimal exploitation path:

RECONNAISSANCE DATA:
```json
{json.dumps(reconnaissance_data, indent=2)}
```

ATTACK PATH PREDICTION:

1. **Entry Points Ranked:**
   - Which vulnerabilities are easiest to exploit?
   - Which provide best initial foothold?
   - Stealth vs. reliability tradeoffs

2. **Privilege Escalation:**
   - Path from initial access to admin/root
   - Service account abuse opportunities
   - Kernel exploit applicability

3. **Lateral Movement:**
   - Which systems to pivot to next?
   - Credential reuse patterns
   - Trust relationships to abuse

4. **Persistence Mechanisms:**
   - Best locations for backdoors
   - Scheduled task/cron job opportunities
   - Registry/startup script modification

5. **Data Exfiltration:**
   - High-value targets identified
   - Exfiltration channel recommendations
   - Anti-forensics cleanup steps

OUTPUT (JSON):
{{
  "recommended_attack_path": [
    {{"step": 1, "action": "Exploit CVE-2021-44228 on web server", "success_probability": 0.95}},
    {{"step": 2, "action": "Escalate via sudo misconfiguration", "success_probability": 0.80}},
    {{"step": 3, "action": "Pivot to database server via SSH key reuse", "success_probability": 0.70}}
  ],
  "alternative_paths": ["..."],
  "estimated_time_to_compromise": "2-4 hours",
  "detection_risk": "medium"
}}
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            
            result_text = response.text
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            
            return json.loads(result_text)
        except Exception as e:
            return {"error": str(e)}


# Example usage
if __name__ == "__main__":
    from gemini_config import get_gemini_client
    
    client = get_gemini_client()
    analyzer = GeminiLogAnalyzer(client)
    
    # Example: Correlate logs
    logs = {
        "waf": [
            "[2026-02-07 10:30:15] BLOCKED: SQL injection attempt from 192.168.1.100",
            "[2026-02-07 10:30:45] BYPASSED: Modified payload passed WAF"
        ],
        "application": [
            "[2026-02-07 10:30:50] Query executed: SELECT * FROM users WHERE id='1' OR '1'='1'",
            "[2026-02-07 10:31:00] Large dataset returned (10000 rows)"
        ],
        "network": [
            "[2026-02-07 10:31:30] Outbound connection to 203.0.113.50:443 (5MB transferred)"
        ]
    }
    
    results = analyzer.correlate_multi_source_logs(logs)
    print(json.dumps(results, indent=2))
