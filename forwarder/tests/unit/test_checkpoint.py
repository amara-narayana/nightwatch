"""
Unit Tests for Persistent Checkpoint Store
"""

import tempfile
from pathlib import Path

from forwarder.agent.checkpoint import CheckpointStore, LinuxCheckpoint, WindowsCheckpoint


def test_linux_checkpoint_persistence():
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "checkpoints.db")
        store = CheckpointStore(db_path)

        cp = LinuxCheckpoint(
            source_path="/var/log/syslog",
            inode=123456,
            device_id=65,
            byte_offset=4096,
            file_size=8192,
            header_hash="abc123hash"
        )
        store.save_linux_checkpoint(cp)

        # Retrieve checkpoint
        loaded = store.get_linux_checkpoint("/var/log/syslog")
        assert loaded is not None
        assert loaded.inode == 123456
        assert loaded.byte_offset == 4096
        assert loaded.header_hash == "abc123hash"

        # Update checkpoint offset
        cp.byte_offset = 6000
        store.save_linux_checkpoint(cp)
        updated = store.get_linux_checkpoint("/var/log/syslog")
        assert updated.byte_offset == 6000

        # Non-existent source defaults to offset 0
        assert store.get_linux_checkpoint("/non/existent.log").byte_offset == 0


def test_windows_checkpoint_persistence():
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "checkpoints.db")
        store = CheckpointStore(db_path)

        wcp = WindowsCheckpoint(
            channel_name="System",
            last_record_id=98765,
            last_event_time_iso="2026-10-21T12:00:00Z"
        )
        store.save_windows_checkpoint(wcp)

        loaded = store.get_windows_checkpoint("System")
        assert loaded is not None
        assert loaded.channel_name == "System"
        assert loaded.last_record_id == 98765

        # Reopen store in new instance (simulate process crash/restart)
        store2 = CheckpointStore(db_path)
        recovered = store2.get_windows_checkpoint("System")
        assert recovered is not None
        assert recovered.last_record_id == 98765
