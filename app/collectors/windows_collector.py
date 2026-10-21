"""
NIGHTWATCH — Real-Time Windows Event Log Collector
Polls native Windows Event Log channels (System, Application, PowerShell, Security)
in real-time using wevtutil and converts events into normalized CIM records.
"""

import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.models.event import NormalizedEvent
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.collector.windows")


class WindowsEventCollector:
    """Real-time incremental collector for native Windows Event Logs."""

    def __init__(self, poll_interval: float = 3.0, batch_size: int = 50):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.poll_interval = poll_interval
        self.batch_size = batch_size

        # Default real Windows channels to monitor
        self.channels = [
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational"
        ]

        self.last_seen_times: Dict[str, str] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.total_collected = 0

    def start(self) -> None:
        """Starts background collection thread."""
        if self._running:
            return
        if os.name != "nt":
            logger.info("Non-Windows OS detected. WindowsEventCollector disabled.")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="NightwatchWindowsEventCollector",
            daemon=True
        )
        self._thread.start()
        logger.info("NIGHTWATCH Real-Time Windows Event Collector started.")

    def stop(self) -> None:
        """Stops background collection thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("NIGHTWATCH Real-Time Windows Event Collector stopped.")

    def _run_loop(self) -> None:
        # Initial priming: fetch latest 10 events per channel on startup
        for ch in self.channels:
            try:
                self.poll_channel(ch, count=10, initial=True)
            except Exception as e:
                logger.debug(f"Initial poll of channel {ch}: {e}")

        while self._running:
            try:
                self.poll_all_channels()
            except Exception as e:
                logger.error(f"Error in WindowsEventCollector cycle: {e}")
            time.sleep(self.poll_interval)

    def poll_all_channels(self) -> int:
        """Polls all monitored channels for new real-time events."""
        total = 0
        for ch in self.channels:
            try:
                count = self.poll_channel(ch, count=self.batch_size)
                total += count
            except Exception as e:
                logger.debug(f"Failed polling channel {ch}: {e}")
        return total

    def poll_channel(self, channel: str, count: int = 20, initial: bool = False) -> int:
        """Queries events from a specific Windows log channel using wevtutil."""
        cmd = ["wevtutil", "qe", channel, f"/c:{count}", "/rd:true", "/f:text"]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=5
            )
            if res.returncode != 0:
                return 0

            raw_blocks = res.stdout.split("Event[")
            parsed_events: List[Dict[str, Any]] = []

            for block in raw_blocks:
                if not block.strip():
                    continue
                parsed = self._parse_event_block(channel, block)
                if parsed:
                    parsed_events.append(parsed)

            if not parsed_events:
                return 0

            # Filter out events older than or equal to last seen timestamp
            last_seen = self.last_seen_times.get(channel)
            new_events = []
            newest_time = None

            for ev in parsed_events:
                ev_time = ev.get("Date")
                if not ev_time:
                    continue
                if newest_time is None or ev_time > newest_time:
                    newest_time = ev_time

                if last_seen and ev_time <= last_seen and not initial:
                    continue
                new_events.append(ev)

            if newest_time:
                self.last_seen_times[channel] = newest_time

            if not new_events:
                return 0

            # Convert to NormalizedEvents and insert into storage
            normalized = []
            for ev in new_events:
                norm_ev = self._normalize_event(channel, ev)
                if norm_ev:
                    normalized.append(norm_ev)

            if normalized:
                self.storage.insert_events_batch(normalized)
                with self._lock:
                    self.total_collected += len(normalized)

            return len(normalized)

        except Exception as e:
            logger.debug(f"Error querying {channel}: {e}")
            return 0

    def _parse_event_block(self, channel: str, block: str) -> Optional[Dict[str, Any]]:
        """Parses wevtutil text output block into a key-value dictionary."""
        props: Dict[str, Any] = {"channel": channel}
        desc_lines: List[str] = []
        is_desc = False

        for line in block.splitlines():
            cleaned_line = line.replace("\x00", "").strip()
            if cleaned_line.startswith("Description:"):
                is_desc = True
                continue
            if is_desc:
                if cleaned_line:
                    desc_lines.append(cleaned_line)
            else:
                m = re.match(r"^\s*([^:]+):\s*(.*)$", cleaned_line)
                if m:
                    key = m.group(1).replace("\x00", "").strip()
                    val = m.group(2).replace("\x00", "").strip()
                    props[key] = val

        props["description"] = " ".join(desc_lines).strip()
        return props if "Date" in props or "Event ID" in props else None

    def _normalize_event(self, channel: str, data: Dict[str, Any]) -> NormalizedEvent:
        """Converts raw Windows event properties into a CIM-compliant NormalizedEvent."""
        # Timestamp parsing
        raw_date = data.get("Date", "").replace("\x00", "").strip()
        dt = datetime.now(timezone.utc)
        if raw_date:
            try:
                # Format: 2026-10-21T13:40:54.1030000Z
                cleaned = raw_date.replace("Z", "+00:00")
                if "." in cleaned:
                    parts = cleaned.split(".")
                    cleaned = parts[0] + "." + parts[1][:6] + "+00:00"
                dt = datetime.fromisoformat(cleaned)
            except Exception:
                dt = datetime.now(timezone.utc)

        computer = data.get("Computer", "localhost").replace("\x00", "").strip()
        user = (data.get("User Name") or data.get("User") or "SYSTEM").replace("\x00", "").strip()
        event_id = data.get("Event ID", "0").replace("\x00", "").strip()
        source = data.get("Source", channel).replace("\x00", "").strip()
        level = (data.get("Level") or "Information").replace("\x00", "").strip().lower()
        desc = data.get("description", "").replace("\x00", "").strip()

        # Severity mapping
        if "crit" in level:
            severity = "critical"
        elif "err" in level:
            severity = "high"
        elif "warn" in level:
            severity = "medium"
        else:
            severity = "info"

        sourcetype = f"winevt:{channel.lower().replace('/', '_').replace('-', '_')}"
        raw_text = f"WinEvent LogName={channel} EventID={event_id} Source={source} Computer={computer} User={user} Level={level}: {desc}"

        fields = {
            "event_id": event_id,
            "provider": source,
            "computer": computer,
            "user": user,
            "channel": channel,
            "level": level,
            "description": desc,
            "task": data.get("Task", "N/A"),
            "action": "logon" if event_id in ("4624", "4625") else ("process_create" if event_id == "4688" else "system_event")
        }

        return NormalizedEvent.create(
            raw=raw_text,
            timestamp=dt,
            index_name="security" if "sec" in channel.lower() else "main",
            host=computer,
            source=f"WinEvent:{channel}",
            sourcetype=sourcetype,
            severity=severity,
            category="audit" if "sec" in channel.lower() else "system",
            fields=fields
        )


_windows_collector_instance: Optional[WindowsEventCollector] = None


def get_windows_collector() -> WindowsEventCollector:
    global _windows_collector_instance
    if _windows_collector_instance is None:
        _windows_collector_instance = WindowsEventCollector()
    return _windows_collector_instance
