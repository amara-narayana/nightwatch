"""
NIGHTWATCH Forwarder Agent — Real Linux & Cross-Platform File Log Collector
Reads genuine operating system log files incrementally with inode rotation detection,
truncation handling, incomplete line buffering, and bounded reads.
"""

import logging
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from forwarder.agent.checkpoint import CheckpointStore, FileCheckpoint
from forwarder.agent.collectors.base import BaseCollector
from forwarder.agent.config import LogSourceConfig
from forwarder.agent.event_schema import ForwarderEvent

logger = logging.getLogger("nightwatch.forwarder.collector.file")


class LinuxFileCollector(BaseCollector):
    """
    Incremental file tailer for text log sources (Linux /var/log/auth.log, syslog, Nginx, etc.).
    """

    def __init__(
        self,
        source_cfg: LogSourceConfig,
        checkpoint_store: CheckpointStore,
        agent_id: str,
        hostname: str,
        max_lines_per_poll: int = 500
    ):
        self.cfg = source_cfg
        self.checkpoint_store = checkpoint_store
        self.agent_id = agent_id
        self.hostname = hostname
        self.max_lines_per_poll = max_lines_per_poll

        self.resolved_path = os.path.abspath(self.cfg.path)
        self._current_cp: FileCheckpoint = self.checkpoint_store.get_file_checkpoint(self.resolved_path)
        self._pending_offset: int = self._current_cp.last_byte_offset
        self._pending_stat: Optional[tuple] = None

    def collect(self) -> List[ForwarderEvent]:
        """
        Reads genuine lines appended since last checkpoint.
        Handles truncation and rotation.
        """
        if not os.path.exists(self.resolved_path):
            return []

        # Check permissions
        if not os.access(self.resolved_path, os.R_OK):
            logger.warning(f"Permission denied reading log source: {self.resolved_path}")
            return []

        was_rotated, was_truncated = self.checkpoint_store.check_file_rotation_or_truncation(self._current_cp)
        if was_rotated or was_truncated:
            logger.info(
                f"File rotation/truncation detected for {self.resolved_path} "
                f"(rotated={was_rotated}, truncated={was_truncated}). Resetting offset to 0."
            )
            self._current_cp.last_byte_offset = 0
            self._pending_offset = 0

        ino, dev, file_size, mtime = self.checkpoint_store.get_file_stat(self.resolved_path)
        if file_size <= self._current_cp.last_byte_offset:
            # No new data appended
            return []

        events: List[ForwarderEvent] = []
        new_offset = self._current_cp.last_byte_offset

        try:
            with open(self.resolved_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._current_cp.last_byte_offset)

                line_count = 0
                while line_count < self.max_lines_per_poll:
                    line = f.readline()
                    if not line:
                        break

                    # Incomplete record check: if line does not end with newline and we reached EOF,
                    # do NOT advance offset past the incomplete fragment!
                    if not line.endswith("\n") and f.tell() >= file_size:
                        logger.debug("Incomplete final line encountered. Deferring until next poll.")
                        break

                    new_offset = f.tell()
                    stripped = line.strip()
                    if not stripped:
                        continue

                    line_count += 1
                    # Generate stable event
                    ev = ForwarderEvent.create(
                        agent_id=self.agent_id,
                        hostname=self.hostname,
                        platform="linux" if "linux" in platform.system().lower() else platform.system().lower(),
                        source_type=self.cfg.source_type,
                        source_name=self.cfg.path,
                        message=stripped,
                        source_record_id=str(new_offset),
                        metadata={"file_offset": new_offset, "file_path": self.resolved_path}
                    )
                    events.append(ev)

            # Stage checkpoint updates
            self._pending_offset = new_offset
            self._pending_stat = (ino, dev, file_size, mtime)

        except Exception as e:
            logger.error(f"Error reading {self.resolved_path}: {e}")
            return []

        return events

    def commit_checkpoint(self) -> None:
        """
        Commits byte offset and file stat to SQLite only after events are safely enqueued.
        """
        if self._pending_offset != self._current_cp.last_byte_offset:
            self._current_cp.last_byte_offset = self._pending_offset
            if self._pending_stat:
                ino, dev, size, mtime = self._pending_stat
                self._current_cp.inode = ino
                self._current_cp.device_id = dev
                self._current_cp.file_size = size
                self._current_cp.last_modified = mtime
                self._current_cp.header_hash = self.checkpoint_store.compute_header_hash(self.resolved_path)

            self.checkpoint_store.save_file_checkpoint(self._current_cp)
            self._pending_stat = None
