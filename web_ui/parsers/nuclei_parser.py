import re
import json
from parsers.base_parser import BaseParser

class NucleiParser(BaseParser):
    """Parser for Nuclei vulnerability scanner (template-based scanning)."""

    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['nuclei', 'nuclei-scanner']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Try to parse JSON output first (if -json flag was used)
        if raw_output.strip().startswith('{'):
            try:
                return self._parse_json_output(raw_output, target)
            except:
                pass  # Fall back to text parsing

        # Pattern for Nuclei findings
        # Format: [template-id] [severity] url
        # Example: [CVE-2021-41773] [critical] http://target.com
        pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)'

        matches = re.finditer(pattern, raw_output, re.MULTILINE)

        for match in matches:
            template_id = match.group(1).strip()
            severity = match.group(2).strip().lower()
            url = match.group(3).strip()

            # Normalize severity
            if severity not in ['critical', 'high', 'medium', 'low', 'info']:
                severity = 'medium'

            # Determine vulnerability type
            vuln_type = self._classify_vulnerability(template_id)

            vuln_entry = {
                "title": self._generate_title(template_id),
                "severity": severity,
                "details": f"Nuclei template {template_id} triggered",
                "url": url,
                "template": template_id
            }

            # Add CVE if detected
            if 'cve-' in template_id.lower():
                cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
                if cve_match:
                    vuln_entry["cve"] = cve_match.group(1).upper()

            # Add exploit recommendation
            vuln_entry["exploit"] = self._get_exploit_recommendation(template_id)

            findings["vulns"].append(vuln_entry)

            # Add URL to findings
            if url not in findings["urls"]:
                findings["urls"].append(url)

        # Exposed sensitive files detection
        sensitive_patterns = {
            '.git': 'Exposed Git Repository',
            '.env': 'Exposed Environment File',
            '.aws': 'Exposed AWS Credentials',
            'config': 'Exposed Configuration File',
            'backup': 'Exposed Backup File',
            '.sql': 'Exposed Database Dump',
            'phpinfo': 'PHP Information Disclosure',
            'admin': 'Exposed Admin Panel',
            'swagger': 'Exposed API Documentation'
        }

        output_lower = raw_output.lower()

        for keyword, title in sensitive_patterns.items():
            if keyword in output_lower:
                # Try to extract the full URL
                url_pattern = rf'(https?://[^\s]+{re.escape(keyword)}[^\s]*)'
                url_matches = re.findall(url_pattern, raw_output, re.IGNORECASE)

                if url_matches:
                    for url in url_matches[:3]:  # Limit to 3 per type
                        findings["vulns"].append({
                            "title": title,
                            "severity": "high" if keyword in ['.git', '.env', '.aws', '.sql'] else "medium",
                            "details": f"{title} detected at {url}",
                            "url": url,
                            "type": "information_disclosure"
                        })

        # Technology detection
        tech_patterns = {
            'apache': 'Apache HTTP Server',
            'nginx': 'Nginx',
            'iis': 'Microsoft IIS',
            'tomcat': 'Apache Tomcat',
            'wordpress': 'WordPress CMS',
            'joomla': 'Joomla CMS',
            'drupal': 'Drupal CMS',
            'laravel': 'Laravel Framework',
            'spring': 'Spring Framework',
            'django': 'Django Framework'
        }

        for keyword, tech_name in tech_patterns.items():
            if keyword in output_lower:
                # Try to extract version
                version_pattern = rf'{keyword}[/\s]+(\d+\.\d+(?:\.\d+)?)'
                version_match = re.search(version_pattern, raw_output, re.IGNORECASE)

                version = version_match.group(1) if version_match else 'detected'

                findings["technologies"].append({
                    "name": tech_name,
                    "version": version
                })

        # CVE statistics
        cve_count = len([v for v in findings["vulns"] if 'cve' in v])
        if cve_count > 0:
            findings["technologies"].append({
                "name": "Nuclei Scan Results",
                "version": f"{cve_count} CVEs detected"
            })

        return findings

    def _parse_json_output(self, raw_output: str, target: str) -> dict:
        """Parse Nuclei JSON output format."""
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        # Parse multiple JSON objects (one per line)
        for line in raw_output.strip().split('\n'):
            if not line.strip():
                continue

            try:
                data = json.loads(line)

                template_id = data.get('template-id', 'unknown')
                severity = data.get('info', {}).get('severity', 'medium').lower()
                url = data.get('matched-at', data.get('host', target))

                vuln_entry = {
                    "title": data.get('info', {}).get('name', self._generate_title(template_id)),
                    "severity": severity,
                    "details": data.get('info', {}).get('description', f"Nuclei template {template_id} triggered"),
                    "url": url,
                    "template": template_id
                }

                # Add tags
                tags = data.get('info', {}).get('tags', [])
                if tags:
                    vuln_entry["tags"] = tags

                # Add CVE reference
                cve = data.get('info', {}).get('classification', {}).get('cve-id')
                if cve:
                    vuln_entry["cve"] = cve

                findings["vulns"].append(vuln_entry)

                if url not in findings["urls"]:
                    findings["urls"].append(url)

            except json.JSONDecodeError:
                continue

        return findings

    def _classify_vulnerability(self, template_id: str) -> str:
        """Classify vulnerability type based on template ID."""
        template_lower = template_id.lower()

        if 'xss' in template_lower:
            return 'Cross-Site Scripting (XSS)'
        elif 'sqli' in template_lower or 'sql-injection' in template_lower:
            return 'SQL Injection'
        elif 'rce' in template_lower or 'remote-code' in template_lower:
            return 'Remote Code Execution'
        elif 'lfi' in template_lower:
            return 'Local File Inclusion'
        elif 'rfi' in template_lower:
            return 'Remote File Inclusion'
        elif 'ssrf' in template_lower:
            return 'Server-Side Request Forgery'
        elif 'xxe' in template_lower:
            return 'XML External Entity Injection'
        elif 'csrf' in template_lower:
            return 'Cross-Site Request Forgery'
        elif 'upload' in template_lower:
            return 'Arbitrary File Upload'
        elif 'auth' in template_lower or 'bypass' in template_lower:
            return 'Authentication Bypass'
        elif 'disclosure' in template_lower or 'exposure' in template_lower:
            return 'Information Disclosure'
        else:
            return 'Security Misconfiguration'

    def _generate_title(self, template_id: str) -> str:
        """Generate human-readable title from template ID."""
        # Check if CVE
        if 'cve-' in template_id.lower():
            cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
            if cve_match:
                return f"Vulnerability {cve_match.group(1).upper()}"

        # Clean up template ID
        title = template_id.replace('-', ' ').replace('_', ' ')
        title = ' '.join(word.capitalize() for word in title.split())

        return title

    def _get_exploit_recommendation(self, template_id: str) -> str:
        """Get exploitation recommendation based on template ID."""
        template_lower = template_id.lower()

        if 'cve-2021-41773' in template_lower:
            return "Apache Path Traversal - Use curl to read /etc/passwd"
        elif 'cve-2021-44228' in template_lower:
            return "Log4Shell - Send JNDI payload to trigger RCE"
        elif '.git' in template_lower:
            return "Use git-dumper or GitHack to download entire repository"
        elif '.env' in template_lower:
            return "Download .env file and extract credentials"
        elif 'sqli' in template_lower:
            return "Use SQLMap to exploit SQL injection"
        elif 'xss' in template_lower:
            return "Inject JavaScript payload to steal cookies"
        elif 'rce' in template_lower:
            return "Execute system commands to gain shell access"
        elif 'upload' in template_lower:
            return "Upload webshell (PHP/ASPX) for remote access"
        elif 'lfi' in template_lower:
            return "Read sensitive files like /etc/passwd or web.config"
        else:
            return "Manually investigate and exploit the vulnerability"
