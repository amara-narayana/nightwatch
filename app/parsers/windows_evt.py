"""
NIGHTWATCH — Windows Security Event Log Parser
Handles Windows Security & Sysmon events in JSON format (e.g. 4624, 4625, 4688, 4720).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dateutil import parser as dt_parser

from app.models.event import NormalizedEvent
from app.normalization.cim import normalize_fields
from app.parsers.base import BaseParser


class WindowsEventParser(BaseParser):
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "win-endpoint") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        # Extract EventID
        event_id = data.get("EventID") or data.get("event_id") or data.get("Event", {}).get("System", {}).get("EventID")
        try:
            event_id = int(event_id)
        except Exception:
            event_id = 0

        # Timestamp
        ts_raw = (
            data.get("TimeCreated")
            or data.get("timestamp")
            or data.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("@SystemTime")
        )
        if ts_raw:
            try:
                dt = dt_parser.parse(str(ts_raw))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        # Host
        host = (
            data.get("Computer")
            or data.get("host")
            or data.get("Event", {}).get("System", {}).get("Computer")
            or default_host
        )

        event_data = data.get("EventData", {})
        if not isinstance(event_data, dict):
            event_data = {}

        severity = "info"
        category = "security"
        action = "info"
        user = (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or data.get("user")
            or data.get("username")
        )
        src_ip = event_data.get("IpAddress") or data.get("src_ip")
        if src_ip in ("-", "127.0.0.1", "::1"):
            src_ip = "127.0.0.1"

        fields: Dict[str, Any] = {
            "event_id": event_id,
            "channel": data.get("Channel", "Security"),
            "provider": data.get("ProviderName"),
            "user": user,
            "src_ip": src_ip,
            "src_port": event_data.get("IpPort") or data.get("src_port"),
            "logon_type": event_data.get("LogonType"),
            "process": event_data.get("NewProcessName") or event_data.get("ProcessName") or data.get("process"),
            "command": event_data.get("CommandLine") or data.get("command"),
            "parent_process": event_data.get("ParentProcessName")
        }

        # Event ID Specific Logic
        if event_id == 4624:
            action = "success"
            category = "authentication"
            severity = "info"
            fields["signature"] = "Successful Logon"
        elif event_id == 4625:
            action = "failure"
            category = "authentication"
            severity = "medium"
            fields["signature"] = "Failed Logon"
            fields["failure_status"] = event_data.get("Status")
            fields["sub_status"] = event_data.get("SubStatus")
        elif event_id == 4688:
            action = "created"
            category = "process"
            severity = "info"
            fields["signature"] = "Process Creation"
        elif event_id == 4720:
            action = "created"
            category = "account_management"
            severity = "medium"
            fields["signature"] = "User Account Created"
        elif event_id == 4728 or event_id == 4732:
            action = "modified"
            category = "account_management"
            severity = "medium"
            fields["signature"] = "Member Added to Security Group"

        fields["action"] = action
        clean_fields = {k: v for k, v in fields.items() if v is not None and v != "-"}
        normalized = normalize_fields(clean_fields)

        return NormalizedEvent.create(
            raw=raw_line,
            timestamp=dt,
            index_name="security",
            host=host,
            source=source,
            sourcetype="winevt",
            severity=severity,
            category=category,
            fields=normalized
        )
