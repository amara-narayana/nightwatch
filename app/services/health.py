"""
NIGHTWATCH — System Health & Performance Telemetry
Captures real host and process metrics: RAM, CPU, disk, event counts, and alert distribution.
"""

import os
import time
from typing import Any, Dict, Optional
import psutil

from app.core.config import get_settings
from app.services.retention import get_retention_service
from app.storage.engine import get_storage_engine

_APP_START_TIME = time.time()


class HealthService:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.retention = get_retention_service()
        self.process = psutil.Process(os.getpid())

    def get_system_telemetry(self) -> Dict[str, Any]:
        """Gathers real-time performance and resource metrics."""
        now = time.time()
        uptime_seconds = int(now - _APP_START_TIME)

        # 1. Process Memory & CPU Metrics
        mem_info = self.process.memory_info()
        proc_rss_mb = round(mem_info.rss / (1024 * 1024), 2)
        proc_vms_mb = round(mem_info.vms / (1024 * 1024), 2)
        proc_cpu_pct = round(self.process.cpu_percent(interval=None), 1)

        # 2. Host RAM Metrics
        vm = psutil.virtual_memory()
        host_total_ram_mb = round(vm.total / (1024 * 1024), 2)
        host_used_ram_mb = round(vm.used / (1024 * 1024), 2)
        host_free_ram_mb = round(vm.available / (1024 * 1024), 2)
        host_ram_percent = vm.percent

        # 3. Host CPU Metrics
        host_cpu_pct = psutil.cpu_percent(interval=None)

        # 4. Storage & Database Metrics
        db_size_mb = self.storage.get_db_size_mb()
        total_events = self.storage.count_events()
        disk_status = self.retention.check_disk_space()

        # 5. Database Distribution Aggregations
        sourcetype_counts = {}
        severity_counts = {}
        with self.storage.get_connection() as conn:
            cur = conn.execute("SELECT sourcetype, COUNT(*) as cnt FROM events GROUP BY sourcetype ORDER BY cnt DESC;")
            for r in cur.fetchall():
                sourcetype_counts[r["sourcetype"]] = r["cnt"]

            cur = conn.execute("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC;")
            for r in cur.fetchall():
                severity_counts[r["severity"]] = r["cnt"]

            cur = conn.execute("SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status;")
            alert_status_counts = {r["status"]: r["cnt"] for r in cur.fetchall()}

            cur = conn.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity;")
            alert_severity_counts = {r["severity"]: r["cnt"] for r in cur.fetchall()}

        return {
            "application": {
                "name": self.settings.app_name,
                "title": self.settings.app_title,
                "version": self.settings.version,
                "uptime_seconds": uptime_seconds,
                "process_rss_mb": proc_rss_mb,
                "process_vms_mb": proc_vms_mb,
                "process_cpu_percent": proc_cpu_pct
            },
            "host": {
                "total_ram_mb": host_total_ram_mb,
                "used_ram_mb": host_used_ram_mb,
                "free_ram_mb": host_free_ram_mb,
                "ram_percent": host_ram_percent,
                "cpu_percent": host_cpu_pct,
                "disk": disk_status
            },
            "database": {
                "db_size_mb": db_size_mb,
                "max_storage_mb": self.settings.storage.max_storage_mb,
                "total_events": total_events,
                "sourcetype_counts": sourcetype_counts,
                "severity_counts": severity_counts
            },
            "alerts": {
                "status_counts": alert_status_counts,
                "severity_counts": alert_severity_counts,
                "total_alerts": sum(alert_status_counts.values())
            }
        }


_health_service: Optional[HealthService] = None


def get_health_service() -> HealthService:
    global _health_service
    if _health_service is None:
        _health_service = HealthService()
    return _health_service
