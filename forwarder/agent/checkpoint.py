"""
NIGHTWATCH Forwarder Agent — Persistent Crash-Safe Checkpoint Store
Tracks byte offsets, file identity (inode/device/header hash), and Windows Event Log record IDs
backed by an atomic SQLite database with WAL durability.
"""

import hashlib
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger("nightwatch.forwarder.checkpoint")


class FileCheckpoint:
    def __init__(
        self,
        source_path: str,
        inode: int = 0,
        device_id: int = 0,
        last_byte_offset: int = 0,
        file_size: int = 0,
        header_hash: str = "",
        last_modified: float = 0.0,
        updated_at: float = 0.0,
        **kwargs
    ):
        self.source_path = source_path
        self.inode = inode
        self.device_id = device_id
        self.last_byte_offset = kwargs.get("byte_offset", last_byte_offset)
        self.file_size = file_size
        self.header_hash = header_hash
        self.last_modified = last_modified
        self.updated_at = updated_at or time.time()

    @property
    def byte_offset(self) -> int:
        return self.last_byte_offset

    @byte_offset.setter
    def byte_offset(self, val: int) -> None:
        self.last_byte_offset = val


# Alias for explicit Linux naming
LinuxCheckpoint = FileCheckpoint


class WindowsCheckpoint:
    def __init__(
        self,
        channel: str = "",
        last_record_id: int = 0,
        last_timestamp: str = "",
        oldest_record_id: int = 0,
        total_collected: int = 0,
        updated_at: float = 0.0,
        **kwargs
    ):
        self.channel = kwargs.get("channel_name", channel)
        self.last_record_id = last_record_id
        self.last_timestamp = kwargs.get("last_event_time_iso", last_timestamp)
        self.oldest_record_id = oldest_record_id
        self.total_collected = total_collected
        self.updated_at = updated_at or time.time()

    @property
    def channel_name(self) -> str:
        return self.channel


class CheckpointStore:
    """
    SQLite-backed durable checkpoint manager.
    Guarantees crash-safe persistence and atomic updates.
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30.0)

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            with conn:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS file_checkpoints (
                        source_path TEXT PRIMARY KEY,
                        inode INTEGER NOT NULL DEFAULT 0,
                        device_id INTEGER NOT NULL DEFAULT 0,
                        last_byte_offset INTEGER NOT NULL DEFAULT 0,
                        file_size INTEGER NOT NULL DEFAULT 0,
                        header_hash TEXT NOT NULL DEFAULT '',
                        last_modified REAL NOT NULL DEFAULT 0.0,
                        updated_at REAL NOT NULL
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS windows_checkpoints (
                        channel TEXT PRIMARY KEY,
                        last_record_id INTEGER NOT NULL DEFAULT 0,
                        last_timestamp TEXT NOT NULL DEFAULT '',
                        oldest_record_id INTEGER NOT NULL DEFAULT 0,
                        total_collected INTEGER NOT NULL DEFAULT 0,
                        updated_at REAL NOT NULL
                    );
                """)
        finally:
            conn.close()

    # --- File Checkpoints (Linux & Text Logs) ---

    def get_file_checkpoint(self, source_path: str) -> FileCheckpoint:
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM file_checkpoints WHERE source_path = ?;", (source_path,))
            row = cur.fetchone()
            if row:
                return FileCheckpoint(
                    source_path=row["source_path"],
                    inode=row["inode"],
                    device_id=row["device_id"],
                    last_byte_offset=row["last_byte_offset"],
                    file_size=row["file_size"],
                    header_hash=row["header_hash"],
                    last_modified=row["last_modified"],
                    updated_at=row["updated_at"]
                )
        finally:
            conn.close()
        return FileCheckpoint(source_path=source_path)

    def save_file_checkpoint(self, cp: FileCheckpoint) -> None:
        now = time.time()
        conn = self._get_conn()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO file_checkpoints (
                        source_path, inode, device_id, last_byte_offset, file_size, header_hash, last_modified, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source_path) DO UPDATE SET
                        inode = excluded.inode,
                        device_id = excluded.device_id,
                        last_byte_offset = excluded.last_byte_offset,
                        file_size = excluded.file_size,
                        header_hash = excluded.header_hash,
                        last_modified = excluded.last_modified,
                        updated_at = excluded.updated_at;
                """, (
                    cp.source_path, cp.inode, cp.device_id, cp.last_byte_offset,
                    cp.file_size, cp.header_hash, cp.last_modified, now
                ))
        finally:
            conn.close()

    get_linux_checkpoint = get_file_checkpoint
    save_linux_checkpoint = save_file_checkpoint

    @staticmethod
    def get_file_stat(file_path: str) -> Tuple[int, int, int, float]:
        """Returns (inode, device, size, mtime). Mask 64-bit on Windows to prevent overflow."""
        try:
            st = os.stat(file_path)
            # Mask st_ino to 63-bit signed integer to avoid SQLite integer overflow on Windows
            ino = st.st_ino & 0x7FFFFFFFFFFFFFFF
            dev = st.st_dev & 0x7FFFFFFFFFFFFFFF
            return ino, dev, st.st_size, st.st_mtime
        except Exception:
            return 0, 0, 0, 0.0

    @staticmethod
    def compute_header_hash(file_path: str, num_bytes: int = 512) -> str:
        """Computes SHA-256 hash of the initial file segment for rotation detection."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(num_bytes)
                return hashlib.sha256(data).hexdigest()
        except Exception:
            return ""

    def check_file_rotation_or_truncation(self, cp: FileCheckpoint) -> Tuple[bool, bool]:
        """
        Detects whether file has been rotated (inode or header mismatch) or truncated (size < offset).
        Returns (was_rotated, was_truncated).
        """
        if not os.path.exists(cp.source_path):
            return False, False

        curr_ino, curr_dev, curr_size, _ = self.get_file_stat(cp.source_path)

        # 1. Truncation: current size is strictly less than previous byte offset
        was_truncated = curr_size < cp.last_byte_offset

        # 2. Rotation: inode changed (Linux) or header hash changed if size restarted
        was_rotated = False
        if cp.inode != 0 and curr_ino != 0 and curr_ino != cp.inode:
            was_rotated = True
        elif was_truncated and cp.header_hash:
            curr_hash = self.compute_header_hash(cp.source_path)
            if curr_hash and curr_hash != cp.header_hash:
                was_rotated = True

        return was_rotated, was_truncated

    # --- Windows Event Log Checkpoints ---

    def get_windows_checkpoint(self, channel: str) -> WindowsCheckpoint:
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM windows_checkpoints WHERE channel = ?;", (channel,))
            row = cur.fetchone()
            if row:
                return WindowsCheckpoint(
                    channel=row["channel"],
                    last_record_id=row["last_record_id"],
                    last_timestamp=row["last_timestamp"],
                    oldest_record_id=row["oldest_record_id"],
                    total_collected=row["total_collected"],
                    updated_at=row["updated_at"]
                )
        finally:
            conn.close()
        return WindowsCheckpoint(channel=channel)

    def save_windows_checkpoint(self, cp: WindowsCheckpoint) -> None:
        now = time.time()
        conn = self._get_conn()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO windows_checkpoints (
                        channel, last_record_id, last_timestamp, oldest_record_id, total_collected, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(channel) DO UPDATE SET
                        last_record_id = excluded.last_record_id,
                        last_timestamp = excluded.last_timestamp,
                        oldest_record_id = excluded.oldest_record_id,
                        total_collected = excluded.total_collected,
                        updated_at = excluded.updated_at;
                """, (
                    cp.channel, cp.last_record_id, cp.last_timestamp,
                    cp.oldest_record_id, cp.total_collected, now
                ))
        finally:
            conn.close()
