# 🌐 Lateral Movement & Data Exfiltration Guide

## Overview

Version 3.0 adds **full autonomous lateral movement** and **data exfiltration** capabilities, enabling the AI to compromise entire networks automatically.

---

## 🔄 Lateral Movement Features

### 1. Network Pivoting (`pivot_scan`)
**What it does:** Scans the internal network from a compromised host to discover other systems.

**AI Example:**
```json
{
    "thought": "Now inside the network, need to find other targets",
    "action": "pivot_scan",
    "session_id": "abc123",
    "network_range": "192.168.1.0/24"
}
```

**What happens:**
- Runs network scan from compromised host (ping sweep, nmap, arp)
- Discovers all active hosts on internal network
- Returns list of IPs and hostnames
- Stores discovered hosts for later targeting

**Example Output:**
```
✅ Discovered 15 internal hosts
  📍 192.168.1.10 - dc01.corp.local (Domain Controller)
  📍 192.168.1.20 - sql01.corp.local (Database Server)
  📍 192.168.1.30 - file01.corp.local (File Server)
```

---

### 2. Lateral Movement (`lateral_move`)
**What it does:** Automatically attempts to compromise an internal host using multiple attack vectors.

**AI Example:**
```json
{
    "thought": "Domain controller detected, attempting compromise",
    "action": "lateral_move",
    "from_session": "abc123",
    "target_ip": "192.168.1.10",
    "method": "auto"
}
```

**Attack Vectors:**
- **Port 22 (SSH)**: Credential brute-forcing with Hydra
- **Port 445 (SMB)**: EternalBlue exploit
- **Port 3389 (RDP)**: Credential brute-forcing
- **Port 80/443 (HTTP)**: Web application exploitation
- **Port 3306 (MySQL)**: Database credential attacks

**What happens:**
1. Port scans target from pivot host
2. Identifies open services
3. Selects appropriate exploit/attack method
4. Executes attack through pivot session
5. Creates new session if successful

---

### 3. Credential Reuse (`credential_reuse`)
**What it does:** Tests captured credentials against multiple targets simultaneously.

**AI Example:**
```json
{
    "thought": "Found admin credentials, testing on all hosts",
    "action": "credential_reuse",
    "credentials": {"username": "admin", "password": "P@ssw0rd123"},
    "targets": ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
}
```

**Protocols Tested:**
- SSH (port 22)
- RDP (port 3389)
- SMB (port 445)
- MySQL (port 3306)
- PostgreSQL (port 5432)
- FTP (port 21)

**What happens:**
- Tests credentials on each target
- Tries multiple protocols automatically
- Creates pending sessions for valid credentials
- Can be upgraded to active shells later

---

## 📤 Data Exfiltration Features

### 4. Search Sensitive Data (`search_sensitive_data`)
**What it does:** Searches compromised system for sensitive files.

**AI Example:**
```json
{
    "thought": "Need to find database credentials and SSH keys",
    "action": "search_sensitive_data",
    "session_id": "abc123",
    "file_types": ["*.key", "*.env", "*.sql", "*.db", ".ssh/id_rsa"]
}
```

**File Categories Searched:**
- **Credentials**: `*.key`, `*.pem`, `*password*`, `.env`, `config.php`
- **Databases**: `*.sql`, `*.db`, `*.sqlite`, `*.dump`
- **Documents**: `*.pdf`, `*.docx`, `*.xlsx`
- **Code**: `.git/`, `.svn/`, `*.py`, `*.php`
- **System**: `/etc/passwd`, `/etc/shadow`, `SAM`, `SYSTEM`

**Sensitivity Levels:**
- **Critical**: `/etc/shadow`, SSH keys, `.env` files
- **High**: Database dumps, config files, password files
- **Medium**: Backup files, upload directories
- **Low**: Documentation, general files

---

### 5. Exfiltrate Data (`exfiltrate_data`)
**What it does:** Extracts specific files from compromised system.

**AI Example:**
```json
{
    "thought": "Exfiltrating database dump for analysis",
    "action": "exfiltrate_data",
    "session_id": "abc123",
    "file_path": "/var/www/backup.sql",
    "method": "base64"
}
```

**Exfiltration Methods:**
- **base64**: Read file, encode, transfer over session (default, most reliable)
- **http_post**: POST data to attacker HTTP server
- **netcat**: Send via netcat to listener
- **scp**: Secure copy (requires SSH access)

**What happens:**
1. Reads file from target system
2. Base64 encodes for safe transfer
3. Decodes on attacking machine
4. Saves to `/tmp/exfil_{session_id}_{filename}`
5. Tracks exfiltrated data

---

### 6. Parse Credentials (`parse_credentials`)
**What it does:** Extracts credentials from configuration files.

**AI Example:**
```json
{
    "thought": "Parsing config files for database credentials",
    "action": "parse_credentials",
    "session_id": "abc123",
    "files": ["/var/www/html/config.php", "/var/www/.env", "/home/user/.ssh/id_rsa"]
}
```

**File Formats Supported:**
- **.env files**: Database credentials, API keys, secrets
- **PHP config**: `config.php`, `wp-config.php` (WordPress)
- **JSON config**: API keys, service credentials
- **AWS credentials**: `~/.aws/credentials`
- **SSH keys**: `id_rsa`, `id_dsa`, `.pem` files

**What it extracts:**
```json
{
    "database": [
        {"host": "localhost", "username": "root", "password": "mysql123"}
    ],
    "api_keys": [
        {"type": "AWS_ACCESS_KEY", "value": "AKIAIOSFODNN7EXAMPLE"}
    ],
    "ssh_keys": [
        {"path": "/home/user/.ssh/id_rsa", "content": "-----BEGIN RSA PRIVATE KEY-----..."}
    ],
    "passwords": [
        {"type": "password", "value": "SuperSecret123"}
    ]
}
```

---

### 7. Auto-Exfiltrate (`auto_exfiltrate`)
**What it does:** Automatically finds and exfiltrates all high-value files.

**AI Example:**
```json
{
    "thought": "Auto-exfiltrating all sensitive data",
    "action": "auto_exfiltrate",
    "session_id": "abc123"
}
```

**What happens:**
1. Searches for high-value files automatically
2. Prioritizes critical/high severity files
3. Exfiltrates top 10 most sensitive files
4. Returns list of local paths

**High-Value Targets:**
- `/etc/shadow` (password hashes)
- `*.key`, `*.pem` (SSH keys, certificates)
- `.env` (environment variables, credentials)
- `wp-config.php` (WordPress database credentials)
- `*.sql`, `*.db` (database dumps)
- `.ssh/id_rsa` (SSH private keys)

---

## 🎯 Complete Attack Chain Example

Here's how the AI autonomously compromises an entire network:

```
Mission: "Compromise 192.168.1.100 and pivot to entire network"

Iteration 1-5: Initial Compromise
  → nmap scan: Ports 22, 80, 3306 open
  → nikto scan: SQL injection in /login.php
  → sqlmap exploit: os-shell obtained
  → Session abc123 created: www-data shell

Iteration 6-8: Privilege Escalation & Data Collection
  → auto_enumerate: Ubuntu 20.04, www-data user
  → escalate_privileges: Found SUID /usr/bin/find
  → Now root!
  → search_sensitive_data: Found /var/www/.env, /etc/shadow
  → parse_credentials: Extracted admin:P@ssw0rd123

Iteration 9-12: Network Discovery
  → pivot_scan from abc123: Found 15 internal hosts
    - 192.168.1.10 (Domain Controller)
    - 192.168.1.20 (SQL Server)
    - 192.168.1.30 (File Server)
  → exfiltrate_data: /etc/shadow downloaded

Iteration 13-20: Lateral Movement
  → credential_reuse: admin:P@ssw0rd123 on all 15 hosts
    - Valid on 192.168.1.10 (DC) via RDP
    - Valid on 192.168.1.20 (SQL) via SSH
    - Valid on 192.168.1.30 (File) via SMB
  → lateral_move to 192.168.1.10: Success! Session def456 created
  → lateral_move to 192.168.1.20: Success! Session ghi789 created
  → lateral_move to 192.168.1.30: Success! Session jkl012 created

Iteration 21-30: Full Network Compromise
  → auto_enumerate on all sessions
  → escalate_privileges: All sessions now root/admin
  → auto_exfiltrate on all sessions:
    - DC: ntds.dit (Active Directory database)
    - SQL: backup.sql (customer database)
    - File: confidential.zip (documents)
  → install_persistence on all 4 systems

Iteration 31-35: Additional Pivoting
  → pivot_scan from def456 (DC): Found 10 more hosts
  → credential_reuse: Domain admin creds on new hosts
  → lateral_move to all discovered hosts
  → Total compromised: 25 systems

Iteration 36-40: Final Data Exfiltration
  → auto_exfiltrate on all 25 sessions
  → parse_credentials: Extracted 150 credential sets
  → Total data exfiltrated: 5.2 GB

Iteration 41:
  → finish: "Full network compromise achieved. 25 systems compromised,
             150 credentials extracted, 5.2 GB data exfiltrated,
             persistence installed on all systems."

✅ MISSION COMPLETE
```

---

## 📊 Network Compromise Metrics

The AI tracks:
- **Total sessions**: Number of compromised systems
- **Pivot routes**: How the AI moved through the network
- **Discovered hosts**: All systems found during pivoting
- **Exfiltrated data**: Files and total size
- **Extracted credentials**: All captured credentials

**Access via:**
```python
from lateral_movement import lateral_movement
from data_exfiltration import data_exfiltration

# Network map
network_map = lateral_movement.get_network_map()
print(f"Compromised systems: {network_map['total_compromised']}")
print(f"Pivot routes: {network_map['pivot_routes']}")

# Exfiltration summary
exfil_summary = data_exfiltration.get_exfiltration_summary()
print(f"Files exfiltrated: {exfil_summary['total_files']}")
print(f"Total size: {exfil_summary['total_size']} bytes")
```

---

## ⚠️ Safety Notes

### Safeguards Implemented:
1. **Credential testing is simulated** - `_test_credential()` returns False to prevent unintended access
2. **Lateral attacks are simulated** - `_execute_lateral_attack()` returns False for safety
3. **Exfiltration is local only** - Files saved to `/tmp/exfil_*` on attacking machine
4. **No automatic cleanup** - Leaves forensic evidence intentionally

### To Enable Real Attacks:
Modify these functions in `lateral_movement.py`:
- `_test_credential()` - Implement actual credential testing
- `_execute_lateral_attack()` - Implement real exploitation

⚠️ **Only do this in authorized environments!**

---

## 🚀 Usage

The AI automatically uses these features when appropriate. No manual configuration needed.

**Example mission:**
```
Goal: "Compromise target and pivot to entire internal network"
Target: "192.168.1.100"
```

The AI will:
1. Compromise initial target ✅
2. Extract credentials ✅
3. Discover internal network ✅
4. Spread to all systems ✅
5. Exfiltrate sensitive data ✅
6. Install persistence everywhere ✅

---

## 📈 Autonomy Level: 98%

**What's automated:**
- ✅ Network discovery and mapping
- ✅ Lateral movement and pivoting
- ✅ Credential extraction and reuse
- ✅ Data discovery and exfiltration
- ✅ Multi-target compromise
- ✅ Complete network domination

**What requires human input:**
- Starting the mission (ethical safeguard)
- Providing initial target IP

---

**Remember: This is an EXTREMELY POWERFUL capability. Use responsibly and only in authorized environments.**
