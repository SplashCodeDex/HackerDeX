import re
from .base_parser import BaseParser

class GobusterParser(BaseParser):
    """Parser for Gobuster, Dirb, and Dirbuster directory enumeration tools."""
    
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['gobuster', 'dirb', 'dirbuster', 'ffuf', 'feroxbuster']
    
    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }
        
        # Pattern for found directories/files with status codes
        # Matches: /admin (Status: 200) or /admin [200] or /admin - 200
        patterns = [
            r'(/[^\s]+)\s+\(Status:\s*(\d{3})\)',  # Gobuster format
            r'(/[^\s]+)\s+\[(\d{3})\]',            # Dirb format
            r'(\S+)\s+-\s+(\d{3})',                 # Alternative format
            r'(/[^\s]+)\s+(\d{3})',                 # Simple format
        ]
        
        sensitive_keywords = ['admin', 'backup', 'config', 'login', 'upload', 
                             'phpmyadmin', 'test', 'dev', 'staging', '.git', 
                             '.env', '.sql', '.bak', '.old', 'password', 'secret']
        
        found_urls = set()
        
        for pattern in patterns:
            matches = re.finditer(pattern, raw_output, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                path = match.group(1)
                status_code = match.group(2)
                
                # Build full URL
                if not target.startswith('http'):
                    target = f'http://{target}'
                
                full_url = f"{target.rstrip('/')}{path}"
                
                if full_url not in found_urls:
                    found_urls.add(full_url)
                    findings["urls"].append(f"{full_url} (Status: {status_code})")
                    
                    # Check for sensitive paths
                    path_lower = path.lower()
                    for keyword in sensitive_keywords:
                        if keyword in path_lower:
                            severity = self._determine_severity(path_lower, status_code)
                            findings["vulns"].append({
                                "title": f"Sensitive Directory/File Exposed: {path}",
                                "severity": severity,
                                "details": f"Found {path} with status {status_code}",
                                "url": full_url
                            })
                            break
        
        # Check for specific high-value findings
        output_lower = raw_output.lower()
        
        # Exposed .git directory
        if '.git' in output_lower and any('200' in line and '.git' in line for line in raw_output.split('\n')):
            findings["vulns"].append({
                "title": "Exposed .git Directory",
                "severity": "critical",
                "details": "Git repository exposed - can download entire source code",
                "url": f"{target}/.git/",
                "exploit": "git-dumper or GitHack to extract repository"
            })
        
        # Exposed .env file
        if '.env' in output_lower and any('200' in line and '.env' in line for line in raw_output.split('\n')):
            findings["vulns"].append({
                "title": "Exposed .env Configuration File",
                "severity": "critical",
                "details": "Environment file exposed - likely contains credentials and API keys",
                "url": f"{target}/.env",
                "exploit": "Download and extract credentials"
            })
        
        # Database backup files
        db_patterns = [r'\.sql', r'\.db', r'backup\.', r'dump\.']
        for db_pattern in db_patterns:
            if re.search(db_pattern, output_lower) and any('200' in line and re.search(db_pattern, line, re.I) for line in raw_output.split('\n')):
                findings["vulns"].append({
                    "title": "Database Backup File Exposed",
                    "severity": "critical",
                    "details": "Database dump accessible - may contain sensitive data",
                    "url": target,
                    "exploit": "Download and analyze database contents"
                })
                break
        
        # phpMyAdmin
        if 'phpmyadmin' in output_lower:
            findings["vulns"].append({
                "title": "phpMyAdmin Panel Accessible",
                "severity": "high",
                "details": "Database management interface exposed",
                "url": f"{target}/phpmyadmin/",
                "exploit": "Attempt default credentials or brute-force"
            })
        
        # Upload directories
        if 'upload' in output_lower:
            findings["vulns"].append({
                "title": "Upload Directory Found",
                "severity": "medium",
                "details": "Potential webshell upload vector",
                "url": f"{target}/upload/ or /uploads/",
                "exploit": "Test for file upload vulnerabilities"
            })
        
        # Statistics
        if len(found_urls) > 0:
            findings["technologies"].append({
                "name": "Directory Enumeration Results",
                "version": f"{len(found_urls)} paths discovered"
            })
        
        return findings
    
    def _determine_severity(self, path: str, status_code: str) -> str:
        """Determine vulnerability severity based on path and status code."""
        critical_keywords = ['.git', '.env', '.sql', 'backup.', 'dump.', 'database']
        high_keywords = ['admin', 'phpmyadmin', 'config', 'password', 'secret', 'key']
        medium_keywords = ['upload', 'test', 'dev', 'staging', 'temp']
        
        # Not accessible = lower severity
        if status_code in ['403', '401']:
            return 'low'
        
        # Check keyword severity
        for keyword in critical_keywords:
            if keyword in path:
                return 'critical'
        
        for keyword in high_keywords:
            if keyword in path:
                return 'high'
        
        for keyword in medium_keywords:
            if keyword in path:
                return 'medium'
        
        return 'low'
