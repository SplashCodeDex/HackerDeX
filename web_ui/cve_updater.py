"""
CVE Database Updater
Automatically fetches and maintains latest CVEs from multiple sources
"""

import requests
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class CVEUpdater:
    """
    Manages CVE database updates from multiple sources:
    - NVD (National Vulnerability Database)
    - Nuclei Templates (GitHub)
    - Metasploit Modules
    - ExploitDB
    """

    def __init__(self, db_path='web_ui/data/cve_database.json'):
        self.db_path = db_path
        self.cve_db = self._load_database()

        # API endpoints
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nuclei_templates_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
        self.metasploit_search_url = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
        self.exploitdb_api = "https://www.exploit-db.com/search"

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def update_all_sources(self, callback=None) -> Dict:
        """
        Update CVE database from all sources.

        Returns:
            Dictionary with update statistics
        """
        if callback:
            callback({'message': '🔄 Updating CVE database from all sources...'})

        stats = {
            'nvd': 0,
            'nuclei': 0,
            'metasploit': 0,
            'exploitdb': 0,
            'total_new': 0
        }

        # Update from NVD (2024-2026 CVEs)
        if callback:
            callback({'message': '  📡 Fetching from NVD API...'})
        nvd_cves = self.fetch_nvd_cves(year=2026)
        stats['nvd'] = len(nvd_cves)

        # Update from Nuclei templates
        if callback:
            callback({'message': '  🧬 Fetching Nuclei templates...'})
        nuclei_cves = self.fetch_nuclei_templates()
        stats['nuclei'] = len(nuclei_cves)

        # Update from Metasploit
        if callback:
            callback({'message': '  🎯 Fetching Metasploit modules...'})
        msf_cves = self.fetch_metasploit_modules()
        stats['metasploit'] = len(msf_cves)

        # Update from ExploitDB
        if callback:
            callback({'message': '  💣 Fetching ExploitDB entries...'})
        edb_cves = self.fetch_exploitdb()
        stats['exploitdb'] = len(edb_cves)

        # Merge all sources
        all_cves = {**nvd_cves, **nuclei_cves, **msf_cves, **edb_cves}

        # Update database
        new_count = 0
        for cve_id, cve_data in all_cves.items():
            if cve_id not in self.cve_db:
                new_count += 1

            # Merge data from multiple sources
            if cve_id in self.cve_db:
                self.cve_db[cve_id].update(cve_data)
            else:
                self.cve_db[cve_id] = cve_data

        stats['total_new'] = new_count

        # Save updated database
        self._save_database()

        if callback:
            callback({'message': f'✅ CVE database updated! {new_count} new CVEs added'})
            callback({'message': f'  Total CVEs in database: {len(self.cve_db)}'})

        return stats

    def fetch_nvd_cves(self, year: int = 2026, days_back: int = 30) -> Dict:
        """
        Fetch CVEs from National Vulnerability Database.

        Args:
            year: Year to fetch CVEs for
            days_back: Number of days to look back

        Returns:
            Dictionary of CVE_ID -> CVE_DATA
        """
        cves = {}

        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)

            # NVD API v2.0 request
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            }

            from network_client import get_network_client
            network_client = get_network_client()
            response = network_client.get(self.nvd_api, params=params, timeout=(10, 30))

            if response.status_code == 200:
                data = response.json()

                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id')

                    if not cve_id:
                        continue

                    # Extract CVSS score
                    cvss_data = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                    cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0)

                    # Determine severity
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'

                    # Extract description
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''

                    cves[cve_id] = {
                        'cve_id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published': cve.get('published', ''),
                        'source': 'NVD',
                        'references': [ref.get('url') for ref in cve.get('references', [])[:5]]
                    }

                self.logger.info(f"Fetched {len(cves)} CVEs from NVD")

        except Exception as e:
            self.logger.error(f"Error fetching NVD CVEs: {e}")

        return cves

    def fetch_nuclei_templates(self) -> Dict:
        """
        Fetch CVE templates from Nuclei (ProjectDiscovery).

        Returns:
            Dictionary of CVE_ID -> CVE_DATA with Nuclei template info
        """
        cves = {}

        try:
            # Fetch directory listing
            from network_client import get_network_client
            network_client = get_network_client()
            response = network_client.get(self.nuclei_templates_url, timeout=(10, 30))

            if response.status_code == 200:
                files = response.json()

                # Get CVE years (2024, 2025, 2026)
                for item in files:
                    if item.get('type') == 'dir' and item.get('name').startswith('202'):
                        year = item.get('name')
                        year_url = item.get('url')

                        # Fetch templates for this year
                        from network_client import get_network_client
                        network_client = get_network_client()
                        year_response = network_client.get(year_url, timeout=(10, 30))
                        if year_response.status_code == 200:
                            templates = year_response.json()

                            for template in templates:
                                if template.get('type') == 'file' and template.get('name').endswith('.yaml'):
                                    # Extract CVE ID from filename
                                    filename = template.get('name', '')
                                    cve_match = filename.split('.yaml')[0]

                                    if 'CVE-' in cve_match.upper():
                                        cve_id = cve_match.upper().replace('CVE-', 'CVE-')

                                        # Download template content
                                        download_url = template.get('download_url')
                                        if download_url:
                                            from network_client import get_network_client
                                            network_client = get_network_client()
                                            template_content = network_client.get(download_url, timeout=(5, 10)).text

                                            cves[cve_id] = {
                                                'cve_id': cve_id,
                                                'source': 'Nuclei',
                                                'nuclei_template': download_url,
                                                'template_content': template_content[:500],  # Preview
                                                'exploitable': True,
                                                'tool': 'nuclei'
                                            }

                self.logger.info(f"Fetched {len(cves)} CVE templates from Nuclei")

        except Exception as e:
            self.logger.error(f"Error fetching Nuclei templates: {e}")

        return cves

    def fetch_metasploit_modules(self) -> Dict:
        """
        Fetch Metasploit modules that target CVEs.

        Returns:
            Dictionary of CVE_ID -> CVE_DATA with Metasploit module info
        """
        cves = {}

        try:
            # Fetch Metasploit module metadata
            from network_client import get_network_client
            network_client = get_network_client()
            response = network_client.get(self.metasploit_search_url, timeout=(10, 30))

            if response.status_code == 200:
                modules = response.json()

                for module_path, module_data in modules.items():
                    # Extract CVE references
                    references = module_data.get('references', [])

                    for ref in references:
                        if ref.startswith('CVE-'):
                            cve_id = ref

                            if cve_id not in cves:
                                cves[cve_id] = {
                                    'cve_id': cve_id,
                                    'source': 'Metasploit',
                                    'metasploit_modules': [],
                                    'exploitable': True,
                                    'tool': 'metasploit'
                                }

                            cves[cve_id]['metasploit_modules'].append({
                                'path': module_path,
                                'name': module_data.get('name', ''),
                                'rank': module_data.get('rank', ''),
                                'description': module_data.get('description', '')[:200]
                            })

                self.logger.info(f"Fetched {len(cves)} CVEs from Metasploit")

        except Exception as e:
            self.logger.error(f"Error fetching Metasploit modules: {e}")

        return cves

    def fetch_exploitdb(self) -> Dict:
        """
        Fetch exploits from ExploitDB.

        Returns:
            Dictionary of CVE_ID -> CVE_DATA with ExploitDB info
        """
        cves = {}

        try:
            # ExploitDB CSV database
            edb_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

            from network_client import get_network_client
            network_client = get_network_client()
            response = network_client.get(edb_url, timeout=(10, 30))

            if response.status_code == 200:
                import csv
                import io

                csv_data = csv.DictReader(io.StringIO(response.text))

                for row in csv_data:
                    # Check if CVE is mentioned
                    description = row.get('description', '')
                    codes = row.get('codes', '')

                    if 'CVE-' in description or 'CVE-' in codes:
                        # Extract CVE ID
                        import re
                        cve_matches = re.findall(r'CVE-\d{4}-\d+', description + ' ' + codes)

                        for cve_id in cve_matches:
                            if cve_id not in cves:
                                cves[cve_id] = {
                                    'cve_id': cve_id,
                                    'source': 'ExploitDB',
                                    'exploitdb_entries': [],
                                    'exploitable': True,
                                    'tool': 'manual'
                                }

                            cves[cve_id]['exploitdb_entries'].append({
                                'edb_id': row.get('id', ''),
                                'description': description[:200],
                                'platform': row.get('platform', ''),
                                'type': row.get('type', ''),
                                'url': f"https://www.exploit-db.com/exploits/{row.get('id', '')}"
                            })

                self.logger.info(f"Fetched {len(cves)} CVEs from ExploitDB")

        except Exception as e:
            self.logger.error(f"Error fetching ExploitDB: {e}")

        return cves

    def search_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Search for a specific CVE in the database.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2026-12345")

        Returns:
            CVE data or None
        """
        return self.cve_db.get(cve_id.upper())

    def get_exploitable_cves(self, severity: str = None) -> List[Dict]:
        """
        Get all CVEs that have known exploits.

        Args:
            severity: Filter by severity (critical, high, medium, low)

        Returns:
            List of exploitable CVEs
        """
        exploitable = []

        for cve_id, cve_data in self.cve_db.items():
            if cve_data.get('exploitable'):
                if severity and cve_data.get('severity') != severity:
                    continue

                exploitable.append(cve_data)

        # Sort by CVSS score (highest first)
        exploitable.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)

        return exploitable

    def get_latest_cves(self, days: int = 7, limit: int = 50) -> List[Dict]:
        """
        Get the most recently published CVEs.

        Args:
            days: Look back this many days
            limit: Maximum number of CVEs to return

        Returns:
            List of recent CVEs
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        recent = []

        for cve_id, cve_data in self.cve_db.items():
            published = cve_data.get('published', '')
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    if pub_date >= cutoff_date:
                        recent.append(cve_data)
                except Exception as e:
                    from error_handler import get_error_handler, ErrorCategory, ErrorSeverity
                    get_error_handler().log_error(
                        e,
                        severity=ErrorSeverity.LOW,
                        category=ErrorCategory.PARSING,
                        context={'operation': 'exploit_db_parsing'}
                    )

        # Sort by publish date (newest first)
        recent.sort(key=lambda x: x.get('published', ''), reverse=True)

        return recent[:limit]

    def _load_database(self) -> Dict:
        """Load CVE database from file."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading CVE database: {e}")

        return {}

    def _save_database(self):
        """Save CVE database to file."""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

            with open(self.db_path, 'w') as f:
                json.dump(self.cve_db, f, indent=2)

            self.logger.info(f"CVE database saved: {len(self.cve_db)} entries")

        except Exception as e:
            self.logger.error(f"Error saving CVE database: {e}")

# Singleton instance
cve_updater = CVEUpdater()
