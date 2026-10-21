"""
NIGHTWATCH Forwarder Agent — Health & Diagnostics Telemetry
Measures genuine endpoint CPU, resident RAM, queue depth, disk usage, and delivery statistics.
"""

import os
import time
from typing import Any, Dict
import psutil

from forwarder.agent.queue import DurableQueue


class AgentHealthMonitor:
    """Measures and reports genuine agent resource utilization and delivery statistics."""

    def __init__(self, queue: DurableQueue):
        self.queue = queue
        self.start_time = time.time()
        self.process = psutil.Process(os.getpid())

        self.total_collected = 0
        self.total_delivered = 0
        self.total_failed_attempts = 0
        self.connection_status = "disconnected"
        self.last_delivery_time = 0.0

    def record_collected(self, count: int) -> None:
        self.total_collected += count

    def record_delivered(self, count: int) -> None:
        self.total_delivered += count
        self.last_delivery_time = time.time()

    def record_failure(self) -> None:
        self.total_failed_attempts += 1

    def set_connection_status(self, status: str) -> None:
        self.connection_status = status

    def get_snapshot(self) -> Dict[str, Any]:
        """Returns comprehensive diagnostic telemetry."""
        mem_info = self.process.memory_info()
        uptime_sec = time.time() - self.start_time
        queue_stats = self.queue.get_health_metrics()

        return {
            "uptime_seconds": round(uptime_sec, 2),
            "connection_status": self.connection_status,
            "process": {
                "pid": os.getpid(),
                "rss_mb": round(mem_info.rss / (1024 * 1024), 2),
                "vms_mb": round(mem_info.vms / (1024 * 1024), 2),
                "cpu_percent": self.process.cpu_percent(interval=None)
            },
            "delivery": {
                "total_collected": self.total_collected,
                "total_delivered": self.total_delivered,
                "total_failures": self.total_failed_attempts,
                "last_delivery_seconds_ago": round(time.time() - self.last_delivery_time, 2) if self.last_delivery_time else None
            },
            "queue": queue_stats
        }
