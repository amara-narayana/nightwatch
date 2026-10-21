"""
NIGHTWATCH — Continuous File Collector & Ingestion Pipeline
Monitors log files, tracks persistent byte offsets, handles rotation/truncation,
and batches normalized records into SQLite/FTS5 storage.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.collectors.checkpoint import CheckpointManager
from app.core.config import get_settings
from app.models.event import NormalizedEvent
from app.parsers.auto import get_auto_parser
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.collector")


class LogInput(BaseModel):
    id: str
    path: str
    sourcetype: str = "auto"
    index: str = "main"
    enabled: bool = True
    description: Optional[str] = ""
    last_read_offset: int = 0
    total_events_read: int = 0
    last_read_time: Optional[float] = None


class FileCollector:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.checkpoint_mgr = CheckpointManager()
        self.auto_parser = get_auto_parser()

        self.inputs_config_path = Path(self.settings.base_dir) / "config" / "inputs.json"
        self.inputs: Dict[str, LogInput] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.load_inputs()

    def load_inputs(self) -> None:
        """Loads inputs configuration from inputs.json."""
        with self._lock:
            if self.inputs_config_path.exists():
                try:
                    with open(self.inputs_config_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    for item in data.get("inputs", []):
                        inp = LogInput(**item)
                        self.inputs[inp.id] = inp
                except Exception as e:
                    logger.error(f"Error loading {self.inputs_config_path}: {e}")

    def save_inputs(self) -> None:
        """Saves current inputs configuration to inputs.json."""
        with self._lock:
            try:
                data = {"inputs": [inp.model_dump() for inp in self.inputs.values()]}
                with open(self.inputs_config_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                logger.error(f"Error saving {self.inputs_config_path}: {e}")

    def add_input(self, inp: LogInput) -> None:
        with self._lock:
            self.inputs[inp.id] = inp
        self.save_inputs()

    def remove_input(self, input_id: str) -> bool:
        with self._lock:
            if input_id in self.inputs:
                del self.inputs[input_id]
                removed = True
            else:
                removed = False
        if removed:
            self.save_inputs()
        return removed

    def get_inputs(self) -> List[LogInput]:
        with self._lock:
            return list(self.inputs.values())

    def start(self) -> None:
        """Starts background continuous file collector thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, name="NightwatchFileCollector", daemon=True)
        self._thread.start()
        logger.info("NIGHTWATCH File Collector started.")

    def stop(self) -> None:
        """Stops background file collector."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("NIGHTWATCH File Collector stopped.")

    def _run_loop(self) -> None:
        while self._running:
            try:
                self.collect_once()
            except Exception as e:
                logger.error(f"Collector cycle error: {e}", exc_info=True)
            time.sleep(self.settings.ingestion.poll_interval_seconds)

    def collect_once(self) -> int:
        """Runs a single pass across all enabled inputs. Returns total ingested count."""
        total_ingested = 0
        with self._lock:
            current_inputs = list(self.inputs.values())

        for inp in current_inputs:
            if not inp.enabled:
                continue
            resolved_path = self.settings.resolve_path(inp.path)
            if not os.path.exists(resolved_path):
                continue

            count = self.process_file(resolved_path, inp)
            total_ingested += count

        return total_ingested

    def process_file(self, file_path: str, inp: LogInput) -> int:
        """Reads new bytes from file_path incrementally, parses events, and commits to DB."""
        cp = self.checkpoint_mgr.get_or_create_checkpoint(file_path)
        was_rotated, was_truncated = self.checkpoint_mgr.check_file_rotation_or_truncation(cp)

        if was_rotated or was_truncated:
            logger.info(f"Rotation/truncation detected for {file_path}. Resetting offset to 0.")
            cp.last_offset = 0
            cp.inode, cp.device, cp.file_size, cp.last_modified = self.checkpoint_mgr.get_file_stat(file_path)
            cp.header_hash = self.checkpoint_mgr.compute_header_hash(file_path)

        events_batch: List[NormalizedEvent] = []
        batch_size = self.settings.ingestion.batch_size
        new_offset = cp.last_offset

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(cp.last_offset)
                while True:
                    line = f.readline()
                    if not line:
                        break

                    # Update offset tracking
                    new_offset = f.tell()
                    stripped = line.strip()
                    if not stripped:
                        continue

                    # Parse into NormalizedEvent
                    ev = self.auto_parser.parse_with_sourcetype(
                        raw_line=stripped,
                        sourcetype=inp.sourcetype,
                        source=inp.path,
                        default_host="localhost"
                    )

                    if ev:
                        ev.index_name = inp.index
                        events_batch.append(ev)

                    # Flush batch when size limit reached
                    if len(events_batch) >= batch_size:
                        self.storage.insert_events_batch(events_batch)
                        events_batch.clear()

            # Flush remaining batch
            if events_batch:
                self.storage.insert_events_batch(events_batch)

            # Update checkpoint state
            _, _, file_size, mtime = self.checkpoint_mgr.get_file_stat(file_path)
            cp.last_offset = new_offset
            cp.file_size = file_size
            cp.last_modified = mtime
            cp.updated_at = time.time()
            self.checkpoint_mgr.save_checkpoint(cp)

            # Update input stats
            ingested_count = len(events_batch)
            inp.last_read_offset = new_offset
            inp.total_events_read += ingested_count
            inp.last_read_time = time.time()

            return ingested_count

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return 0


_collector_instance: Optional[FileCollector] = None


def get_file_collector() -> FileCollector:
    global _collector_instance
    if _collector_instance is None:
        _collector_instance = FileCollector()
    return _collector_instance
