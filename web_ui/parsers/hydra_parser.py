import re
from .base_parser import BaseParser

class HydraParser(BaseParser):
    """Parser for Hydra credential brute-forcing tool."""
    
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['hydra', 'thc-hydra', 'medusa', 'ncrack']
    
    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {},
            "credentials": []
        }
        
        # Pattern for successful login
        # Format: [22][ssh] host: 192.168.1.1   login: admin   password: password123
        # Format: [80][http-post-form] host: example.com   login: admin   password: admin
        pattern = r'\[(\d+)\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)'
        
        matches = re.finditer(pattern, raw_output, re.IGNORECASE | re.MULTILINE)
        
        valid_credentials = []
        
        for match in matches:
            port = match.group(1)
            service = match.group(2)
            host = match.group(3)
            username = match.group(4)
            password = match.group(5)
            
            credential_entry = {
                "username": username,
                "password": password,
                "service": service,
                "port": port,
                "host": host
            }
            
            valid_credentials.append(credential_entry)
            findings["credentials"].append(credential_entry)
            
            # Create vulnerability entry
            findings["vulns"].append({
                "title": f"Weak {service.upper()} Credentials",
                "severity": "critical",
                "details": f"Valid credentials found: {username}:{password}",
                "url": f"{service}://{host}:{port}",
                "username": username,
                "password": password,
                "protocol": service,
                "port": port
            })
        
        # Alternative success patterns
        # Format: [STATUS] target 192.168.1.1 - login "admin" - pass "password123" - [ssh]
        alt_pattern = r'target\s+(\S+)\s+-\s+login\s+"([^"]+)"\s+-\s+pass\s+"([^"]+)"\s+-\s+\[([^\]]+)\]'
        
        alt_matches = re.finditer(alt_pattern, raw_output, re.IGNORECASE | re.MULTILINE)
        
        for match in alt_matches:
            host = match.group(1)
            username = match.group(2)
            password = match.group(3)
            service = match.group(4)
            
            credential_entry = {
                "username": username,
                "password": password,
                "service": service,
                "host": host
            }
            
            if credential_entry not in valid_credentials:
                valid_credentials.append(credential_entry)
                findings["credentials"].append(credential_entry)
                
                findings["vulns"].append({
                    "title": f"Weak {service.upper()} Credentials",
                    "severity": "critical",
                    "details": f"Valid credentials found: {username}:{password}",
                    "url": f"{service}://{host}",
                    "username": username,
                    "password": password,
                    "protocol": service
                })
        
        # Check for "valid password found" messages
        if "valid password found" in raw_output.lower() or "login successful" in raw_output.lower():
            # Try to extract any username:password combinations
            cred_pattern = r'(\w+):(\S+)'
            potential_creds = re.findall(cred_pattern, raw_output)
            
            for username, password in potential_creds:
                if len(username) > 2 and len(password) > 2:  # Filter out noise
                    credential_entry = {
                        "username": username,
                        "password": password,
                        "service": "unknown",
                        "host": target
                    }
                    
                    if credential_entry not in valid_credentials:
                        findings["credentials"].append(credential_entry)
        
        # Detect brute-force attempt statistics
        attempts_match = re.search(r'(\d+)\s+valid\s+password', raw_output, re.IGNORECASE)
        if attempts_match:
            count = attempts_match.group(1)
            findings["technologies"].append({
                "name": "Credential Brute-Force Results",
                "version": f"{count} valid credentials found"
            })
        
        # Detect service type from output
        service_indicators = {
            'ssh': ['ssh', 'openssh', 'port 22'],
            'ftp': ['ftp', 'vsftpd', 'port 21'],
            'http': ['http', 'web', 'port 80'],
            'https': ['https', 'ssl', 'port 443'],
            'rdp': ['rdp', 'remote desktop', 'port 3389'],
            'smb': ['smb', 'samba', 'port 445'],
            'mysql': ['mysql', 'mariadb', 'port 3306'],
            'postgres': ['postgres', 'postgresql', 'port 5432']
        }
        
        output_lower = raw_output.lower()
        detected_service = None
        
        for service, keywords in service_indicators.items():
            if any(keyword in output_lower for keyword in keywords):
                detected_service = service
                break
        
        # Add port information if service detected
        if detected_service and len(valid_credentials) > 0:
            service_ports = {
                'ssh': 22, 'ftp': 21, 'http': 80, 'https': 443,
                'rdp': 3389, 'smb': 445, 'mysql': 3306, 'postgres': 5432
            }
            
            if detected_service in service_ports:
                findings["ports"].append({
                    "port": service_ports[detected_service],
                    "service": detected_service,
                    "state": "open",
                    "credentials": len(valid_credentials)
                })
        
        # Create session recommendations
        if len(valid_credentials) > 0:
            findings["session_recommendations"] = []
            
            for cred in valid_credentials:
                service = cred.get('service', 'unknown')
                
                if 'ssh' in service.lower():
                    findings["session_recommendations"].append({
                        "type": "ssh",
                        "command": f"ssh {cred['username']}@{cred.get('host', target)}",
                        "credentials": cred
                    })
                elif 'rdp' in service.lower():
                    findings["session_recommendations"].append({
                        "type": "rdp",
                        "command": f"rdesktop {cred.get('host', target)} -u {cred['username']} -p {cred['password']}",
                        "credentials": cred
                    })
                elif 'ftp' in service.lower():
                    findings["session_recommendations"].append({
                        "type": "ftp",
                        "command": f"ftp {cred.get('host', target)}",
                        "credentials": cred
                    })
        
        return findings
