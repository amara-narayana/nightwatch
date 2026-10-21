"""
NIGHTWATCH — Collector and Checkpoint Subsystem Unit Tests
"""

import os
import tempfile
import time
from pathlib import Path
import pytest

from app.collectors.checkpoint import Checkpoint, CheckpointManager
from app.collectors.file_collector import FileCollector, LogInput
from app.storage.engine import StorageEngine


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_collector.db"
    return StorageEngine(str(db_file))


def test_checkpoint_tracking(temp_db, tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("line 1\nline 2\n", encoding="utf-8")

    mgr = CheckpointManager()
    mgr.storage = temp_db

    cp = mgr.get_or_create_checkpoint(str(log_file))
    assert cp.last_offset == 0
    assert cp.file_size > 0

    # Update offset
    cp.last_offset = 7
    mgr.save_checkpoint(cp)

    cp_loaded = mgr.get_or_create_checkpoint(str(log_file))
    assert cp_loaded.last_offset == 7


def test_file_truncation_detection(temp_db, tmp_path):
    log_file = tmp_path / "trunc.log"
    log_file.write_text("A" * 1000, encoding="utf-8")

    mgr = CheckpointManager()
    mgr.storage = temp_db

    cp = mgr.get_or_create_checkpoint(str(log_file))
    cp.last_offset = 800
    mgr.save_checkpoint(cp)

    # Truncate file to 100 bytes
    log_file.write_text("B" * 100, encoding="utf-8")

    rotated, truncated = mgr.check_file_rotation_or_truncation(cp)
    assert truncated is True


def test_collector_incremental_processing(temp_db, tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("Oct 21 05:00:01 host1 sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n", encoding="utf-8")

    collector = FileCollector()
    collector.storage = temp_db
    collector.checkpoint_mgr.storage = temp_db

    inp = LogInput(
        id="test_inp",
        path=str(log_file),
        sourcetype="linux_auth",
        index="test"
    )

    count = collector.process_file(str(log_file), inp)
    assert count == 1
    assert temp_db.count_events() == 1

    # Second pass without new data should ingest 0
    count_pass2 = collector.process_file(str(log_file), inp)
    assert count_pass2 == 0
    assert temp_db.count_events() == 1

    # Append new line
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("Oct 21 05:00:02 host1 sshd[2]: Accepted publickey for user1 from 1.1.1.2 port 22 ssh2\n")

    count_pass3 = collector.process_file(str(log_file), inp)
    assert count_pass3 == 1
    assert temp_db.count_events() == 2
