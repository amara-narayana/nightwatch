"""
NIGHTWATCH — Ingestion Checkpoint Sentinel
Tracks file offsets, file sizes, inodes, and header fingerprints to detect rotations and truncations.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field

from app.storage.engine import get_storage_engine


class Checkpoint(BaseModel):
    source_path: str
    inode: int = 0
    device: int = 0
    last_offset: int = 0
    file_size: int = 0
    header_hash: str = ""
    last_modified: float = 0.0
    updated_at: float = Field(default_factory=time.time)


class CheckpointManager:
    def __init__(self):
        self.storage = get_storage_engine()

    @staticmethod
    def compute_header_hash(path: str, num_bytes: int = 512) -> str:
        """Computes a SHA-256 hash of the first 512 bytes of a file for rotation detection."""
        try:
            with open(path, "rb") as f:
                header = f.read(num_bytes)
                return hashlib.sha256(header).hexdigest()
        except Exception:
            return ""

    def get_or_create_checkpoint(self, path: str) -> Checkpoint:
        norm_path = str(Path(path).resolve())
        data = self.storage.get_checkpoint(norm_path)
        if data:
            return Checkpoint(**data)

        # Initial checkpoint for new file
        inode, device, file_size, mtime = self.get_file_stat(norm_path)
        h_hash = self.compute_header_hash(norm_path)
        cp = Checkpoint(
            source_path=norm_path,
            inode=inode,
            device=device,
            last_offset=0,
            file_size=file_size,
            header_hash=h_hash,
            last_modified=mtime,
            updated_at=time.time()
        )
        self.save_checkpoint(cp)
        return cp

    def save_checkpoint(self, cp: Checkpoint) -> None:
        self.storage.save_checkpoint(
            source_path=cp.source_path,
            inode=cp.inode,
            device=cp.device,
            last_offset=cp.last_offset,
            file_size=cp.file_size,
            header_hash=cp.header_hash,
            last_modified=cp.last_modified
        )

    @staticmethod
    def get_file_stat(path: str):
        try:
            st = os.stat(path)
            ino = getattr(st, "st_ino", 0) & 0x7FFFFFFFFFFFFFFF
            dev = getattr(st, "st_dev", 0) & 0x7FFFFFFFFFFFFFFF
            return ino, dev, st.st_size, st.st_mtime
        except Exception:
            return 0, 0, 0, 0.0

    def check_file_rotation_or_truncation(self, cp: Checkpoint) -> Tuple[bool, bool]:
        """
        Returns (was_rotated, was_truncated).
        """
        path = cp.source_path
        if not os.path.exists(path):
            return False, False

        inode, dev, current_size, mtime = self.get_file_stat(path)
        was_rotated = False
        was_truncated = False

        # 1. Truncation detection: file is now smaller than our previous read offset
        if current_size < cp.last_offset:
            was_truncated = True

        # 2. Rotation detection:
        # On POSIX systems with inode support: if inode changed, file was rotated
        if inode != 0 and cp.inode != 0 and inode != cp.inode:
            was_rotated = True
        else:
            # On Windows or where inode is 0: check if header hash changed and size < last_offset
            if current_size >= 512:
                current_hash = self.compute_header_hash(path)
                if cp.header_hash and current_hash != cp.header_hash and was_truncated:
                    was_rotated = True

        return was_rotated, was_truncated
