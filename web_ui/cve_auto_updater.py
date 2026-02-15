"""
CVE Auto-Update Scheduler
Automatically updates CVE database daily
"""

import schedule
import time
import threading
import logging
from cve_updater import cve_updater

class CVEAutoUpdater:
    """Automatic CVE database updater that runs in background."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.update_thread = None

    def start(self):
        """Start the auto-updater in background."""
        if self.running:
            self.logger.warning("Auto-updater already running")
            return

        self.running = True

        # Schedule daily updates at 3 AM
        schedule.every().day.at("03:00").do(self.update_cves)

        # Also update every 6 hours
        schedule.every(6).hours.do(self.update_cves)

        # Start scheduler in background thread
        self.update_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.update_thread.start()

        self.logger.info("CVE auto-updater started (updates every 6 hours)")

        # Run initial update
        self.update_cves()

    def stop(self):
        """Stop the auto-updater."""
        self.running = False
        schedule.clear()
        self.logger.info("CVE auto-updater stopped")

    def update_cves(self):
        """Perform CVE database update."""
        try:
            self.logger.info("Starting scheduled CVE update...")
            stats = cve_updater.update_all_sources()
            self.logger.info(f"CVE update complete: {stats['total_new']} new CVEs added")
        except Exception as e:
            self.logger.error(f"CVE update failed: {e}")

    def _run_scheduler(self):
        """Run the scheduler loop."""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

# Global auto-updater instance
auto_updater = CVEAutoUpdater()
