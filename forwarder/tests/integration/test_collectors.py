"""
Integration Tests for Linux File Collector and Windows Event Log Collector
Uses genuine filesystem I/O and native Windows Event Log APIs.
"""

import os
import platform
import tempfile
import time
from pathlib import Path

from forwarder.agent.checkpoint import CheckpointStore
from forwarder.agent.collectors.linux_files import LinuxFileCollector
from forwarder.agent.collectors.windows_eventlog import WindowsEventLogCollector
from forwarder.agent.config import LogSourceConfig, WindowsChannelConfig


def test_linux_file_collector_incremental_and_incomplete():
    with tempfile.TemporaryDirectory() as td:
        log_file = Path(td) / "auth.log"
        cp_path = str(Path(td) / "checkpoints.db")
        store = CheckpointStore(cp_path)

        src_cfg = LogSourceConfig(path=str(log_file), source_type="linux:auth")
        collector = LinuxFileCollector(
            source_cfg=src_cfg,
            checkpoint_store=store,
            agent_id="test-linux-agent",
            hostname="localhost"
        )

        # 1. Write initial complete lines + one incomplete line (no ending \n)
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("Line 1: Accepted publickey for user admin\n")
            f.write("Line 2: session opened for user admin\n")
            f.write("Line 3: Incomplete line without newline yet")

        events = collector.collect()
        assert len(events) == 2
        assert "Line 1" in events[0].message
        assert "Line 2" in events[1].message

        # Commit checkpoint
        collector.commit_checkpoint()

        # 2. Append remainder of incomplete line and another line
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(" now completed!\n")
            f.write("Line 4: session closed\n")

        events2 = collector.collect()
        assert len(events2) == 2
        assert "Line 3: Incomplete line without newline yet now completed!" in events2[0].message
        assert "Line 4: session closed" in events2[1].message
        collector.commit_checkpoint()

        # 3. No new events if file is unchanged
        assert len(collector.collect()) == 0


def test_windows_eventlog_collector_genuine():
    if platform.system() != "Windows":
        return  # Skipped on non-Windows

    with tempfile.TemporaryDirectory() as td:
        cp_path = str(Path(td) / "checkpoints.db")
        store = CheckpointStore(cp_path)

        channel_cfg = WindowsChannelConfig(channel="System")
        collector = WindowsEventLogCollector(
            channel_cfg=channel_cfg,
            checkpoint_store=store,
            agent_id="test-win-agent",
            hostname="localhost"
        )

        # Read actual genuine Windows events from the system
        events = collector.collect()
        assert len(events) > 0, "Expected to read genuine Windows Event Log records"

        # Validate that real Windows event fields are present
        sample = events[0]
        assert sample.platform == "windows"
        assert sample.source_type == "winevt"
        assert sample.source_name == "System"
        assert len(sample.event_id) == 64
        assert sample.message != ""
        assert sample.source_record_id is not None
        assert int(sample.source_record_id) > 0

        # Commit checkpoint
        collector.commit_checkpoint()

        # Verify checkpoint was stored
        wcp = store.get_windows_checkpoint(sample.source_name)
        assert wcp is not None
        assert wcp.last_record_id >= int(sample.source_record_id)
