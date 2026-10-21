"""
NIGHTWATCH Forwarder Agent — Configuration
Provides strict validation, defaults, and path resolution for endpoint agents.
"""

import json
import os
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class LogSourceConfig(BaseModel):
    path: str
    source_type: str = "generic:log"
    index: str = "main"
    enabled: bool = True


class WindowsChannelConfig(BaseModel):
    channel: str
    source_type: str = "winevt"
    index: str = "main"
    enabled: bool = True


class AgentConfig(BaseModel):
    agent_id: str = Field(..., description="Unique client identifier matching client certificate CN")
    hostname: str = Field(default_factory=socket.gethostname)
    receiver_host: str = Field(default="127.0.0.1")
    receiver_port: int = Field(default=9997, ge=1, le=65535)

    # TLS / mTLS configuration
    ca_cert_path: str = Field(..., description="Path to trusted Root CA certificate")
    client_cert_path: str = Field(..., description="Path to agent client certificate")
    client_key_path: str = Field(..., description="Path to agent client private key")
    tls_verify_server: bool = Field(default=True, description="Enforce strict server cert verification")

    # Storage and queues
    state_dir: str = Field(default="forwarder/data/agent")
    max_queue_size_mb: int = Field(default=500, ge=10, le=10000)
    max_queue_events: int = Field(default=100000, ge=100, le=5000000)
    queue_full_policy: str = Field(default="pause_collection", pattern="^(pause_collection|drop_oldest)$")

    # Batching and polling
    batch_size: int = Field(default=100, ge=1, le=2000)
    poll_interval_seconds: float = Field(default=2.0, ge=0.1, le=60.0)
    connect_timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)

    # Retry backoff
    retry_initial_backoff_seconds: float = Field(default=1.0, ge=0.1)
    retry_max_backoff_seconds: float = Field(default=60.0, ge=1.0)
    retry_backoff_factor: float = Field(default=2.0, ge=1.1)

    # Monitored sources
    file_sources: List[LogSourceConfig] = Field(default_factory=list)
    windows_channels: List[WindowsChannelConfig] = Field(default_factory=list)

    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    model_config = {"extra": "allow"}

    @field_validator("file_sources", mode="before")
    @classmethod
    def parse_file_sources(cls, v: Any) -> List[Any]:
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"path": item})
                else:
                    res.append(item)
            return res
        return v

    @field_validator("windows_channels", mode="before")
    @classmethod
    def parse_windows_channels(cls, v: Any) -> List[Any]:
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append({"channel": item})
                else:
                    res.append(item)
            return res
        return v

    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    def resolve_paths(self, base_dir: Path) -> None:
        """Resolves relative file paths against base directory."""
        if not os.path.isabs(self.ca_cert_path):
            self.ca_cert_path = str((base_dir / self.ca_cert_path).resolve())
        if not os.path.isabs(self.client_cert_path):
            self.client_cert_path = str((base_dir / self.client_cert_path).resolve())
        if not os.path.isabs(self.client_key_path):
            self.client_key_path = str((base_dir / self.client_key_path).resolve())
        if not os.path.isabs(self.state_dir):
            self.state_dir = str((base_dir / self.state_dir).resolve())
