"""
NIGHTWATCH Forwarder Receiver — Health & Operational Telemetry
Tracks real operational metrics, connection states, payload counts, and resource utilization.
"""

import os
import threading
import time
from typing import Any, Dict, Optional

try:
    import psutil
except ImportError:
    psutil = None


class ReceiverHealthMonitor:
    """Thread-safe operational telemetry for NIGHTWATCH receiver."""

    def __init__(self, storage_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._start_time = time.time()
        self.storage_path = storage_path

        self.active_connections = 0
        self.total_connections = 0
        self.total_frames_received = 0
        self.total_events_received = 0
        self.total_events_accepted = 0
        self.total_duplicates_detected = 0
        self.total_bytes_received = 0
        self.total_acks_sent = 0
        self.total_nacks_sent = 0
        self.total_errors = 0

        self._process = psutil.Process() if psutil else None

    def inc_connection(self) -> None:
        with self._lock:
            self.active_connections += 1
            self.total_connections += 1

    def dec_connection(self) -> None:
        with self._lock:
            if self.active_connections > 0:
                self.active_connections -= 1

    def record_batch(self, count: int, accepted: int, duplicates: int, raw_bytes: int) -> None:
        with self._lock:
            self.total_frames_received += 1
            self.total_events_received += count
            self.total_events_accepted += accepted
            self.total_duplicates_detected += duplicates
            self.total_bytes_received += raw_bytes

    def record_ack(self) -> None:
        with self._lock:
            self.total_acks_sent += 1

    def record_nack(self) -> None:
        with self._lock:
            self.total_nacks_sent += 1

    def record_error(self) -> None:
        with self._lock:
            self.total_errors += 1

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            uptime = time.time() - self._start_time
            metrics = {
                "uptime_seconds": round(uptime, 2),
                "active_connections": self.active_connections,
                "total_connections": self.total_connections,
                "total_frames_received": self.total_frames_received,
                "total_events_received": self.total_events_received,
                "total_events_accepted": self.total_events_accepted,
                "total_duplicates_detected": self.total_duplicates_detected,
                "total_bytes_received": self.total_bytes_received,
                "total_acks_sent": self.total_acks_sent,
                "total_nacks_sent": self.total_nacks_sent,
                "total_errors": self.total_errors,
            }

        if self._process:
            try:
                mem = self._process.memory_info()
                metrics["rss_memory_mb"] = round(mem.rss / (1024 * 1024), 2)
                metrics["cpu_percent"] = self._process.cpu_percent(interval=None)
            except Exception:
                pass

        if self.storage_path and os.path.exists(self.storage_path):
            try:
                metrics["storage_size_bytes"] = os.path.getsize(self.storage_path)
            except Exception:
                pass

        return metrics
