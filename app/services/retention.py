"""
NIGHTWATCH — Data Retention & Disk Guardian Service
Automates age-based event pruning, enforces storage quotas, and guards disk safety.
"""

import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional
import psutil

from app.core.config import get_settings
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.retention")


class RetentionService:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()

    def run_retention_cycle(self) -> Dict[str, Any]:
        """
        Executes a complete retention cycle:
        1. Age-based pruning
        2. Size-based pruning if DB exceeds max_storage_mb
        3. Disk safety check
        """
        now = time.time()
        retention_days = self.settings.storage.retention_days
        cutoff_epoch = now - (retention_days * 86400)

        # 1. Age-based Pruning
        deleted_by_age = self.storage.delete_events_older_than(cutoff_epoch)
        if deleted_by_age > 0:
            logger.info(f"Retention: Deleted {deleted_by_age} events older than {retention_days} days.")

        # 2. Size-based Pruning
        max_mb = self.settings.storage.max_storage_mb
        current_db_mb = self.storage.get_db_size_mb()
        deleted_by_size = 0

        if current_db_mb > max_mb:
            logger.warning(f"Storage: Database size ({current_db_mb} MB) exceeds quota ({max_mb} MB). Pruning oldest events.")
            # Prune in batches of 5,000 until within quota or no more events
            while current_db_mb > max_mb:
                pruned = self.storage.prune_oldest_events(5000)
                if pruned == 0:
                    break
                deleted_by_size += pruned
                current_db_mb = self.storage.get_db_size_mb()

        # Reclaim space if significant deletions occurred
        if (deleted_by_age + deleted_by_size) > 10000:
            try:
                self.storage.run_vacuum()
                current_db_mb = self.storage.get_db_size_mb()
            except Exception as e:
                logger.error(f"Error during VACUUM: {e}")

        # 3. Disk Space Safety Check
        disk_status = self.check_disk_space()

        return {
            "deleted_by_age": deleted_by_age,
            "deleted_by_size": deleted_by_size,
            "current_db_size_mb": current_db_mb,
            "max_storage_mb": max_mb,
            "disk_status": disk_status
        }

    def check_disk_space(self) -> Dict[str, Any]:
        """Inspects host partition where database resides."""
        db_path = Path(self.storage.db_path).resolve()
        parent_dir = db_path.parent
        usage = shutil.disk_usage(parent_dir)

        total_gb = round(usage.total / (1024 ** 3), 2)
        used_gb = round(usage.used / (1024 ** 3), 2)
        free_gb = round(usage.free / (1024 ** 3), 2)
        free_mb = round(usage.free / (1024 ** 2), 2)

        min_free_mb = self.settings.storage.min_free_disk_mb
        warning = free_mb < min_free_mb

        return {
            "total_gb": total_gb,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "free_mb": free_mb,
            "min_free_mb": min_free_mb,
            "low_disk_warning": warning
        }


_retention_service: Optional[RetentionService] = None


def get_retention_service() -> RetentionService:
    global _retention_service
    if _retention_service is None:
        _retention_service = RetentionService()
    return _retention_service
