"""
NIGHTWATCH Forwarder Agent — Real Windows Event Log Collector
Collects genuine Windows Event Logs using native win32evtlog APIs with fallback to wevtutil,
preserving Record IDs, Provider, Event ID, User, Computer, and structured metadata.
"""

import logging
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from forwarder.agent.checkpoint import CheckpointStore, WindowsCheckpoint
from forwarder.agent.collectors.base import BaseCollector
from forwarder.agent.config import WindowsChannelConfig
from forwarder.agent.event_schema import ForwarderEvent

logger = logging.getLogger("nightwatch.forwarder.collector.windows")

# Check if pywin32 / win32evtlog is available
try:
    import win32evtlog
    import win32evtlogutil
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class WindowsEventLogCollector(BaseCollector):
    """
    Genuine Windows Event Log collector supporting System, Application, Security channels.
    Maintains durable record ID checkpoints and detects log clearing / retention gaps.
    """

    def __init__(
        self,
        channel_cfg: WindowsChannelConfig,
        checkpoint_store: CheckpointStore,
        agent_id: str,
        hostname: str,
        max_events_per_poll: int = 200
    ):
        self.cfg = channel_cfg
        self.checkpoint_store = checkpoint_store
        self.agent_id = agent_id
        self.hostname = hostname
        self.max_events_per_poll = max_events_per_poll

        self.channel = self.cfg.channel
        self._current_cp: WindowsCheckpoint = self.checkpoint_store.get_windows_checkpoint(self.channel)
        self._pending_record_id: int = self._current_cp.last_record_id
        self._pending_timestamp: str = self._current_cp.last_timestamp

    def collect(self) -> List[ForwarderEvent]:
        """
        Polls for genuine Windows Event Log records appended since last checkpoint.
        """
        if os.name != "nt":
            # Non-Windows endpoint
            return []

        # Attempt collection via pywin32, fallback to wevtutil
        events = []
        if HAS_PYWIN32 and self.channel.lower() in ("system", "application", "security"):
            try:
                events = self._collect_via_pywin32()
            except Exception as e:
                logger.debug(f"pywin32 collection failed for {self.channel}: {e}. Trying wevtutil.")
                events = self._collect_via_wevtutil()
        else:
            events = self._collect_via_wevtutil()

        return events

    def _collect_via_pywin32(self) -> List[ForwarderEvent]:
        """Collects events using Win32 ReadEventLog API."""
        events: List[ForwarderEvent] = []
        try:
            h_log = win32evtlog.OpenEventLog(None, self.channel)
        except Exception as e:
            logger.warning(f"Access denied or unavailable channel '{self.channel}': {e}")
            return []

        try:
            num_records = win32evtlog.GetNumberOfEventLogRecords(h_log)
            oldest_record = win32evtlog.GetOldestEventLogRecord(h_log)

            if num_records == 0:
                return []

            # Check for log clearing: if oldest_record > last_record_id, log was rotated/cleared
            if self._current_cp.last_record_id > 0 and oldest_record > self._current_cp.last_record_id:
                logger.warning(
                    f"Event log gap/clear detected for channel '{self.channel}'. "
                    f"Last record: {self._current_cp.last_record_id}, Current oldest: {oldest_record}. Resetting."
                )
                self._current_cp.last_record_id = oldest_record - 1

            flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
            # If we already have a record ID, we read forwards
            raw_records = win32evtlog.ReadEventLog(h_log, flags, 0)
            highest_seen = self._current_cp.last_record_id
            latest_ts_seen = self._current_cp.last_timestamp

            while raw_records and len(events) < self.max_events_per_poll:
                for r in raw_records:
                    rec_id = r.RecordNumber
                    if rec_id <= self._current_cp.last_record_id:
                        continue

                    if rec_id > highest_seen:
                        highest_seen = rec_id

                    ev_id = str(r.EventID & 0xFFFF)
                    time_gen = r.TimeGenerated
                    ev_dt = datetime.fromtimestamp(time_gen.timestamp(), tz=timezone.utc)
                    latest_ts_seen = ev_dt.isoformat()

                    # Format string description
                    desc_strings = r.StringInserts or []
                    msg_text = " ".join(desc_strings).strip() if desc_strings else f"Event ID {ev_id} from {r.SourceName}"
                    raw_line = f"WinEvent Log={self.channel} EventID={ev_id} RecordID={rec_id} Source={r.SourceName}: {msg_text}"

                    severity = "info"
                    if r.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                        severity = "high"
                    elif r.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                        severity = "medium"

                    metadata = {
                        "event_id": ev_id,
                        "record_id": rec_id,
                        "source": r.SourceName,
                        "channel": self.channel,
                        "computer": r.ComputerName,
                        "event_category": r.EventCategory
                    }

                    ev = ForwarderEvent.create(
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        platform="windows",
                        source_type=self.cfg.source_type,
                        source_name=self.channel,
                        message=raw_line,
                        event_timestamp=ev_dt,
                        severity=severity,
                        source_event_id=ev_id,
                        source_record_id=str(rec_id),
                        metadata=metadata
                    )
                    events.append(ev)

                raw_records = win32evtlog.ReadEventLog(h_log, flags, 0)

            self._pending_record_id = highest_seen
            self._pending_timestamp = latest_ts_seen

        finally:
            win32evtlog.CloseEventLog(h_log)

        return events

    def _collect_via_wevtutil(self) -> List[ForwarderEvent]:
        """Fallback querying Windows events using native wevtutil utility."""
        events: List[ForwarderEvent] = []
        cmd = ["wevtutil", "qe", self.channel, f"/c:{self.max_events_per_poll}", "/rd:true", "/f:text"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8)
            if res.returncode != 0:
                logger.debug(f"wevtutil returned non-zero ({res.returncode}) for {self.channel}: {res.stderr.strip()}")
                return []

            blocks = res.stdout.split("Event[")
            highest_ts = self._current_cp.last_timestamp

            for block in blocks:
                if not block.strip():
                    continue

                props: Dict[str, Any] = {"channel": self.channel}
                desc_lines = []
                is_desc = False

                for line in block.splitlines():
                    cleaned = line.replace("\x00", "").strip()
                    if cleaned.startswith("Description:"):
                        is_desc = True
                        continue
                    if is_desc:
                        if cleaned:
                            desc_lines.append(cleaned)
                    else:
                        m = re.match(r"^\s*([^:]+):\s*(.*)$", cleaned)
                        if m:
                            props[m.group(1).strip()] = m.group(2).strip()

                props["description"] = " ".join(desc_lines).strip()
                ev_time_raw = props.get("Date")
                if not ev_time_raw:
                    continue

                # Filter out previously checkpointed timestamps
                if self._current_cp.last_timestamp and ev_time_raw <= self._current_cp.last_timestamp:
                    continue

                if not highest_ts or ev_time_raw > highest_ts:
                    highest_ts = ev_time_raw

                ev_id = props.get("Event ID", "0")
                provider = props.get("Source", self.channel)
                computer = props.get("Computer", self.hostname)
                user = props.get("User Name") or props.get("User") or "SYSTEM"
                level = props.get("Level", "Information").lower()
                desc = props.get("description", "")

                try:
                    cleaned_iso = ev_time_raw.replace("Z", "+00:00")
                    if "." in cleaned_iso:
                        p = cleaned_iso.split(".")
                        cleaned_iso = p[0] + "." + p[1][:6] + "+00:00"
                    dt = datetime.fromisoformat(cleaned_iso)
                except Exception:
                    dt = datetime.now(timezone.utc)

                severity = "critical" if "crit" in level else ("high" if "err" in level else ("medium" if "warn" in level else "info"))
                raw_line = f"WinEvent Log={self.channel} EventID={ev_id} Source={provider} Computer={computer} User={user} Level={level}: {desc}"

                metadata = {
                    "event_id": ev_id,
                    "provider": provider,
                    "computer": computer,
                    "user": user,
                    "level": level,
                    "task": props.get("Task", "N/A")
                }

                ev = ForwarderEvent.create(
                    agent_id=self.agent_id,
                    hostname=self.hostname,
                    platform="windows",
                    source_type=self.cfg.source_type,
                    source_name=self.channel,
                    message=raw_line,
                    event_timestamp=dt,
                    severity=severity,
                    source_event_id=ev_id,
                    metadata=metadata
                )
                events.append(ev)

            self._pending_timestamp = highest_ts

        except Exception as e:
            logger.debug(f"Error querying {self.channel} via wevtutil: {e}")

        return events

    def commit_checkpoint(self) -> None:
        """Commits latest record ID and timestamp after events are safely queued."""
        updated = False
        if self._pending_record_id > self._current_cp.last_record_id:
            self._current_cp.last_record_id = self._pending_record_id
            updated = True
        if self._pending_timestamp and self._pending_timestamp != self._current_cp.last_timestamp:
            self._current_cp.last_timestamp = self._pending_timestamp
            updated = True

        if updated:
            self.checkpoint_store.save_windows_checkpoint(self._current_cp)
