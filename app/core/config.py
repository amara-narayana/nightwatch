"""
NIGHTWATCH — Core Configuration Module
"""

import json
import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    cors_origins: List[str] = ["*"]


class StorageConfig(BaseModel):
    db_path: str = "data/nightwatch.db"
    wal_mode: bool = True
    cache_size_kb: int = 32000
    retention_days: int = 30
    max_storage_mb: int = 15000
    min_free_disk_mb: int = 5000


class IngestionConfig(BaseModel):
    batch_size: int = 500
    poll_interval_seconds: float = 1.0
    max_queue_size: int = 5000
    checkpoint_file: str = "data/checkpoints.json"


class SearchConfig(BaseModel):
    default_limit: int = 1000
    max_limit: int = 50000
    timeout_seconds: int = 30


class DetectionConfig(BaseModel):
    enabled: bool = True
    interval_seconds: int = 30
    suppression_window_minutes: int = 15


class Settings(BaseModel):
    app_name: str = "NIGHTWATCH"
    app_title: str = "NIGHTWATCH — Lightweight Security Intelligence Platform"
    version: str = "1.0.0"
    base_dir: str = str(Path(__file__).resolve().parent.parent.parent)
    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    search: SearchConfig = Field(default_factory=SearchConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)

    def resolve_path(self, rel_or_abs: str) -> str:
        """Resolves relative paths against the project root."""
        p = Path(rel_or_abs)
        if p.is_absolute():
            return str(p)
        return str(Path(self.base_dir) / p)


_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        config_path = Path(__file__).resolve().parent.parent.parent / "config" / "settings.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                _settings_instance = Settings(**data)
            except Exception as e:
                print(f"[NIGHTWATCH] Warning: Could not load config/settings.json ({e}). Using defaults.")
                _settings_instance = Settings()
        else:
            _settings_instance = Settings()
    return _settings_instance
