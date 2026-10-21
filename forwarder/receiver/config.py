"""
NIGHTWATCH Forwarder Receiver — Configuration
"""

import json
import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


class ReceiverConfig(BaseModel):
    listen_host: str = Field(default="0.0.0.0")
    listen_port: int = Field(default=9997, ge=1, le=65535)

    # TLS / mTLS configuration
    ca_cert_path: str = Field(..., description="Path to trusted Root CA certificate")
    server_cert_path: str = Field(..., description="Path to receiver server TLS certificate")
    server_key_path: str = Field(..., description="Path to receiver server TLS private key")
    require_client_cert: bool = Field(default=True, description="Enforce mutual TLS client authentication")

    # Authorization
    allowed_agents: List[str] = Field(
        default_factory=list,
        description="List of authorized agent IDs/Common Names. Empty list allows any valid cert from trusted CA."
    )

    # Persistence
    storage_path: str = Field(default="forwarder/data/receiver/receiver.db")
    integrate_nightwatch_db: bool = Field(
        default=True,
        description="Whether to replicate accepted events into central NIGHTWATCH storage"
    )
    nightwatch_db_path: str = Field(default="data/nightwatch.db")

    # Limits
    max_connections: int = Field(default=500, ge=1, le=10000)
    connection_timeout_seconds: float = Field(default=60.0, ge=5.0, le=600.0)

    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    @classmethod
    def from_file(cls, path: str) -> "ReceiverConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    def resolve_paths(self, base_dir: Path) -> None:
        if not os.path.isabs(self.ca_cert_path):
            self.ca_cert_path = str((base_dir / self.ca_cert_path).resolve())
        if not os.path.isabs(self.server_cert_path):
            self.server_cert_path = str((base_dir / self.server_cert_path).resolve())
        if not os.path.isabs(self.server_key_path):
            self.server_key_path = str((base_dir / self.server_key_path).resolve())
        if not os.path.isabs(self.storage_path):
            self.storage_path = str((base_dir / self.storage_path).resolve())
        if not os.path.isabs(self.nightwatch_db_path):
            self.nightwatch_db_path = str((base_dir / self.nightwatch_db_path).resolve())
