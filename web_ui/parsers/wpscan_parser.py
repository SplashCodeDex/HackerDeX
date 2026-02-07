import re
import json
from .base_parser import BaseParser

class WPScanParser(BaseParser):
    """Parser for WPScan WordPress vulnerability scanner."""
    
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['wpscan', 'wp-scan', 'wordpress-scanner']
    
    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {},
            "wordpress_info": {}
        }
        
        # WordPress version detection
        version_pattern = r'WordPress version (\d+\.\d+(?:\.\d+)?)'
        version_match = re.search(version_pattern, raw_output, re.IGNORECASE)
        
        if version_match:
            wp_version = version_match.group(1)
            findings["technologies"].append({
                "name": "WordPress",
                "version": wp_version
            })
            findings["wordpress_info"]["version"] = wp_version
            
            # Check if version is outdated (simple check for versions < 6.0)
            try:
                major_version = float(wp_version.split('.')[0] + '.' + wp_version.split('.')[1])
                if major_version < 6.0:
                    findings["vulns"].append({
                        "title": f"Outdated WordPress Version ({wp_version})",
                        "severity": "high",
                        "details": f"WordPress {wp_version} is outdated and may contain known vulnerabilities",
                        "url": target,
                        "recommendation": "Update to latest WordPress version"
                    })
            except:
                pass
        
        # Theme detection
        theme_pattern = r'WordPress theme in use: ([^\n]+)'
        theme_match = re.search(theme_pattern, raw_output, re.IGNORECASE)
        
        if theme_match:
            theme_name = theme_match.group(1).strip()
            findings["wordpress_info"]["theme"] = theme_name
            findings["technologies"].append({
                "name": f"WordPress Theme: {theme_name}",
                "version": "detected"
            })
        
        # Plugin detection with vulnerabilities
        plugin_pattern = r'\[!\]\s+([^\n]+?)\s+(\d+\.\d+(?:\.\d+)?)?'
        plugin_matches = re.finditer(plugin_pattern, raw_output, re.MULTILINE)
        
        plugins_found = []
        
        for match in plugin_matches:
            plugin_info = match.group(1).strip()
            
            # Check if it's a plugin line
            if 'plugin' in plugin_info.lower() or '/' in plugin_info:
                plugins_found.append(plugin_info)
        
        # Vulnerability detection
        vuln_patterns = [
            (r'CVE-(\d{4}-\d+)', 'CVE'),
            (r'\[!\].*?(SQL[iI]|XSS|RCE|LFI|RFI|CSRF)', 'vulnerability type'),
            (r'Title:\s*([^\n]+)', 'vulnerability title'),
            (r'References?:\s*([^\n]+)', 'reference')
        ]
        
        detected_vulns = {}
        current_vuln = {}
        
        lines = raw_output.split('\n')
        for i, line in enumerate(lines):
            # CVE detection
            cve_match = re.search(r'CVE-(\d{4}-\d+)', line, re.IGNORECASE)
            if cve_match:
                cve_id = f"CVE-{cve_match.group(1)}"
                
                # Try to find severity and title in surrounding lines
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+4)])
                
                title = "WordPress Vulnerability"
                if 'Title:' in context:
                    title_match = re.search(r'Title:\s*([^\n]+)', context)
                    if title_match:
                        title = title_match.group(1).strip()
                
                # Determine severity
                severity = 'medium'
                if any(keyword in context.lower() for keyword in ['critical', 'rce', 'remote code execution']):
                    severity = 'critical'
                elif any(keyword in context.lower() for keyword in ['high', 'sqli', 'sql injection', 'auth bypass']):
                    severity = 'high'
                elif any(keyword in context.lower() for keyword in ['xss', 'csrf', 'lfi']):
                    severity = 'medium'
                
                findings["vulns"].append({
                    "title": f"{title} ({cve_id})",
                    "severity": severity,
                    "details": f"WordPress vulnerability {cve_id} detected",
                    "url": target,
                    "cve": cve_id
                })
        
        # User enumeration
        user_pattern = r'Found By: Author Id Brute Forcing.*?([^\n]+)'
        user_matches = re.finditer(user_pattern, raw_output, re.IGNORECASE | re.DOTALL)
        
        users_found = []
        
        # Alternative user pattern
        username_pattern = r'\[\+\]\s+(\w+)'
        for match in re.finditer(username_pattern, raw_output):
            potential_user = match.group(1)
            if len(potential_user) > 2 and potential_user not in users_found:
                # Check if it looks like a username (not a common word)
                if potential_user.lower() not in ['wordpress', 'version', 'theme', 'plugin', 'scanning']:
                    users_found.append(potential_user)
        
        if users_found:
            findings["wordpress_info"]["users"] = users_found
            findings["vulns"].append({
                "title": "WordPress User Enumeration",
                "severity": "low",
                "details": f"Enumerated usernames: {', '.join(users_found[:5])}",
                "url": target,
                "usernames": users_found
            })
        
        # Upload directory detection
        if 'wp-content/uploads' in raw_output.lower():
            upload_accessible = False
            
            # Check if accessible
            if '200' in raw_output or 'directory listing' in raw_output.lower():
                upload_accessible = True
            
            findings["urls"].append(f"{target}/wp-content/uploads/")
            
            if upload_accessible:
                findings["vulns"].append({
                    "title": "WordPress Upload Directory Accessible",
                    "severity": "medium",
                    "details": "Upload directory is accessible - potential webshell upload vector",
                    "url": f"{target}/wp-content/uploads/",
                    "exploit": "Test for arbitrary file upload vulnerabilities"
                })
        
        # XML-RPC detection
        if 'xmlrpc.php' in raw_output.lower():
            xmlrpc_enabled = 'enabled' in raw_output.lower() or '200' in raw_output
            
            if xmlrpc_enabled:
                findings["vulns"].append({
                    "title": "WordPress XML-RPC Enabled",
                    "severity": "medium",
                    "details": "XML-RPC interface is enabled - can be used for brute-force attacks",
                    "url": f"{target}/xmlrpc.php",
                    "exploit": "Use for credential brute-forcing or DDoS amplification"
                })
        
        # Interesting findings
        interesting_pattern = r'\[!\] ([^\n]+)'
        for match in re.finditer(interesting_pattern, raw_output):
            finding = match.group(1).strip()
            
            # Avoid duplicates
            if finding and len(finding) > 10:
                # Check if it's a new finding
                is_new = True
                for existing_vuln in findings["vulns"]:
                    if finding in existing_vuln.get("details", ""):
                        is_new = False
                        break
                
                if is_new and any(keyword in finding.lower() for keyword in 
                                  ['vulnerable', 'outdated', 'exposed', 'accessible', 'found']):
                    findings["vulns"].append({
                        "title": "WordPress Security Finding",
                        "severity": "low",
                        "details": finding,
                        "url": target
                    })
        
        # Plugin vulnerability summary
        if plugins_found:
            findings["wordpress_info"]["plugins"] = plugins_found
            findings["technologies"].append({
                "name": "WordPress Plugins Detected",
                "version": f"{len(plugins_found)} plugins found"
            })
        
        # WAF detection
        if 'firewall' in raw_output.lower() or 'waf' in raw_output.lower():
            findings["technologies"].append({
                "name": "Web Application Firewall (WAF)",
                "version": "detected"
            })
        
        return findings
