"""
NIGHTWATCH API — Forwarder Remote Auto-Enrollment & Management Routes
Allows target endpoints to enroll with 1 command, receive signed mTLS certificates,
and immediately begin forwarding genuine OS telemetry to the central receiver.
"""

import logging
import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from forwarder.scripts.issue_certificates import (
    create_agent_credentials_pem,
    ensure_ca_and_server_certs,
)

logger = logging.getLogger("nightwatch.api.forwarder")
router = APIRouter(prefix="/api/forwarder", tags=["forwarder"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CA_DIR = BASE_DIR / "forwarder" / "certs" / "ca"


class ForwarderEnrollRequest(BaseModel):
    hostname: str = Field(..., description="Endpoint hostname")
    platform: str = Field(default="unknown", description="Endpoint operating system")
    agent_id: Optional[str] = Field(default=None, description="Optional custom agent identifier")


@router.post("/enroll")
def enroll_forwarder(req: ForwarderEnrollRequest, request: Request):
    """
    Auto-enrolls a remote endpoint: generates a dedicated mTLS client certificate
    signed by the central NIGHTWATCH Root CA and returns configuration credentials.
    """
    ensure_ca_and_server_certs(BASE_DIR / "forwarder" / "certs")

    # Sanitize hostname to create unique agent_id
    clean_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "", req.hostname).strip() or "endpoint"
    agent_id = req.agent_id or f"agent-{clean_host.lower()}"

    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Auto-enrolling remote forwarder '{agent_id}' from {client_ip} ({req.platform})")

    try:
        ca_pem, cert_pem, key_pem = create_agent_credentials_pem(CA_DIR, agent_id, days=365)
    except Exception as e:
        logger.error(f"Failed generating certificate for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Certificate issuance error: {e}")

    # Determine receiver host (from incoming request Host header)
    host_header = request.headers.get("host", "127.0.0.1:8000")
    receiver_host = host_header.split(":")[0]

    return {
        "status": "success",
        "agent_id": agent_id,
        "receiver_host": receiver_host,
        "receiver_port": 9997,
        "ca_cert": ca_pem,
        "client_cert": cert_pem,
        "client_key": key_pem
    }
