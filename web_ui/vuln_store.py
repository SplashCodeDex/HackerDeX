import json
import os
import threading
from datetime import datetime
import hashlib

class VulnStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(VulnStore, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.data_path = os.path.join(os.path.dirname(__file__), 'data', 'vuln_store.json')
        os.makedirs(os.path.dirname(self.data_path), exist_ok=True)

        self.targets = {}
        self.alias_index = {}
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat(),
            "total_findings": 0
        }
        self.lock = threading.Lock()
        self.load_from_disk()
        self._initialized = True

    def _get_target_id(self, target_str):
        """Generate a consistent ID for a target string (IP or Domain)."""
        # Normalize: lower case and strip protocol/slashes
        normalized = target_str.lower().replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def get_or_create_target(self, target_str):
        target_id = self.alias_index.get(target_str)
        if not target_id:
            target_id = self._get_target_id(target_str)

        with self.lock:
            if target_id not in self.targets:
                self.targets[target_id] = {
                    "id": target_id,
                    "main_target": target_str,
                    "aliases": [target_str],
                    "ports": [],
                    "vulnerabilities": [],
                    "urls": [],
                    "technologies": [],
                    "os_info": {},
                    "scan_history": [],
                    "last_seen": datetime.now().isoformat()
                }
                self.alias_index[target_str] = target_id
            return target_id

    def add_port(self, target_id, port, protocol, service, version=""):
        with self.lock:
            target = self.targets.get(target_id)
            if not target: return

            # Check if port exists
            exists = False
            for p in target['ports']:
                if p['port'] == port and p['protocol'] == protocol:
                    p.update({"service": service, "version": version, "last_seen": datetime.now().isoformat()})
                    exists = True
                    break

            if not exists:
                target['ports'].append({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "last_seen": datetime.now().isoformat()
                })
            self._update_metadata()

    def add_vulnerability(self, target_id, title, severity, details="", url="", tool=""):
        with self.lock:
            target = self.targets.get(target_id)
            if not target: return

            vuln_id = hashlib.md5(f"{title}{url}".encode()).hexdigest()[:8]

            # Dedup by title and URL
            for v in target['vulnerabilities']:
                if v.get('finding_id') == vuln_id:
                    return

            target['vulnerabilities'].append({
                "finding_id": vuln_id,
                "title": title,
                "severity": severity,
                "details": details,
                "affected_url": url,
                "source_tool": tool,
                "discovered_at": datetime.now().isoformat()
            })
            self._update_metadata()

    def add_url(self, target_id, url, method="GET", tool=""):
        with self.lock:
            target = self.targets.get(target_id)
            if not target: return

            if url not in target['urls']:
                target['urls'].append(url)
            self._update_metadata()

    def add_technology(self, target_id, tech_name, version=""):
        with self.lock:
            target = self.targets.get(target_id)
            if not target: return

            exists = False
            for t in target['technologies']:
                if t['name'] == tech_name:
                    t['version'] = version
                    exists = True
                    break

            if not exists:
                target['technologies'].append({"name": tech_name, "version": version})
            self._update_metadata()

    def _update_metadata(self):
        self.metadata["last_modified"] = datetime.now().isoformat()
        # count total findings
        total = 0
        for t in self.targets.values():
            total += len(t['ports']) + len(t['vulnerabilities'])
        self.metadata["total_findings"] = total
        self.save_to_disk()

    def save_to_disk(self):
        try:
            with open(self.data_path, 'w') as f:
                json.dump({
                    "targets": self.targets,
                    "alias_index": self.alias_index,
                    "metadata": self.metadata
                }, f, indent=4)
        except Exception as e:
            print(f"Error saving VulnStore: {e}")

    def load_from_disk(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, 'r') as f:
                    content = json.load(f)
                    self.targets = content.get("targets", {})
                    self.alias_index = content.get("alias_index", {})
                    self.metadata = content.get("metadata", self.metadata)
            except Exception as e:
                print(f"Error loading VulnStore: {e}")

    def get_target_profile(self, target_str):
        target_id = self.alias_index.get(target_str)
        if not target_id:
            target_id = self._get_target_id(target_str)
        return self.targets.get(target_id)

    def get_all_targets_summary(self):
        return [
            {
                "id": t['id'],
                "target": t['main_target'],
                "vulns_count": len(t['vulnerabilities']),
                "ports_count": len(t['ports']),
                "last_seen": t['last_seen']
            } for t in self.targets.values()
        ]
