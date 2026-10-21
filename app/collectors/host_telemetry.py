"""
NIGHTWATCH — Real-Time Host Telemetry & Process Collector
Continuously monitors live processes, command executions, and network socket activity
using native OS telemetry with zero synthetic or simulated data.
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import psutil

from app.core.config import get_settings
from app.models.event import NormalizedEvent
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.collector.host")


class HostTelemetryCollector:
    """Collects real-time live process spawns, system telemetry, and active socket connections."""

    def __init__(self, poll_interval: float = 4.0):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.poll_interval = poll_interval

        self.known_pids: Set[int] = set()
        self.known_connections: Set[str] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.total_collected = 0

    def start(self) -> None:
        """Starts real-time host monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="NightwatchHostTelemetryCollector",
            daemon=True
        )
        self._thread.start()
        logger.info("NIGHTWATCH Real-Time Host Telemetry Collector started.")

    def stop(self) -> None:
        """Stops real-time host monitoring thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("NIGHTWATCH Real-Time Host Telemetry Collector stopped.")

    def _run_loop(self) -> None:
        # Prime known PIDs
        try:
            self.known_pids = set(psutil.pids())
        except Exception:
            pass

        while self._running:
            try:
                self.collect_once()
            except Exception as e:
                logger.error(f"Error in HostTelemetryCollector loop: {e}")
            time.sleep(self.poll_interval)

    def collect_once(self) -> int:
        """Executes one scan of newly spawned processes and network sockets."""
        events: List[NormalizedEvent] = []
        host_name = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"

        # 1. Process Activity Detection
        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - self.known_pids
            self.known_pids = current_pids

            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    p_name = p.name()
                    try:
                        p_cmd = " ".join(p.cmdline())
                    except Exception:
                        p_cmd = p_name
                    try:
                        p_user = p.username()
                    except Exception:
                        p_user = "SYSTEM"
                    try:
                        ppid = p.ppid()
                    except Exception:
                        ppid = 0

                    # Check for suspicious command patterns
                    cmd_lower = p_cmd.lower()
                    severity = "info"
                    suspicious_indicators = [
                        "mimikatz", "certutil", "whoami", "-enc", "encodedcommand",
                        "vssadmin", "net user", "net localgroup", "rundll32", "psexec",
                        "downloadstring", "invoke-expression", "iex"
                    ]
                    if any(s in cmd_lower for s in suspicious_indicators):
                        severity = "high"

                    raw_msg = f"Process Created: pid={pid} name={p_name} user={p_user} ppid={ppid} cmd=\"{p_cmd}\""

                    ev = NormalizedEvent.create(
                        raw=raw_msg,
                        host=host_name,
                        source="HostProcessMonitor",
                        sourcetype="host:process",
                        index_name="security" if severity != "info" else "main",
                        severity=severity,
                        category="process",
                        fields={
                            "pid": pid,
                            "process_name": p_name,
                            "process": p_name,
                            "command_line": p_cmd,
                            "user": p_user,
                            "parent_pid": ppid,
                            "action": "process_create",
                            "severity": severity
                        }
                    )
                    events.append(ev)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logger.debug(f"Process monitoring scan error: {e}")

        # 2. Network Socket Activity
        try:
            connections = psutil.net_connections(kind="inet")
            current_conn_keys = set()

            for conn in connections:
                if not conn.raddr:
                    continue  # Skip listening-only ports for connection events

                l_ip, l_port = conn.laddr.ip, conn.laddr.port
                r_ip, r_port = conn.raddr.ip, conn.raddr.port
                conn_key = f"{l_ip}:{l_port}->{r_ip}:{r_port}:{conn.status}"
                current_conn_keys.add(conn_key)

                # Only emit event for newly established connections
                if conn_key not in self.known_connections and conn.status == "ESTABLISHED":
                    proc_name = "unknown"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except Exception:
                            pass

                    raw_net = f"Network Connection: local={l_ip}:{l_port} remote={r_ip}:{r_port} status={conn.status} pid={conn.pid} process={proc_name}"
                    net_ev = NormalizedEvent.create(
                        raw=raw_net,
                        host=host_name,
                        source="HostNetworkMonitor",
                        sourcetype="host:network",
                        index_name="main",
                        severity="info",
                        category="network",
                        fields={
                            "src_ip": l_ip,
                            "src_port": l_port,
                            "dest_ip": r_ip,
                            "dest_port": r_port,
                            "status": conn.status,
                            "pid": conn.pid,
                            "process_name": proc_name,
                            "action": "network_connection"
                        }
                    )
                    events.append(net_ev)

            self.known_connections = current_conn_keys

        except Exception as e:
            logger.debug(f"Network connection scan error: {e}")

        if events:
            self.storage.insert_events_batch(events)
            with self._lock:
                self.total_collected += len(events)

        return len(events)


_host_telemetry_instance: Optional[HostTelemetryCollector] = None


def get_host_telemetry_collector() -> HostTelemetryCollector:
    global _host_telemetry_instance
    if _host_telemetry_instance is None:
        _host_telemetry_instance = HostTelemetryCollector()
    return _host_telemetry_instance
