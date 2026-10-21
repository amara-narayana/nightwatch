"""
NIGHTWATCH — Suricata EVE JSON Parser
Handles Suricata EVE JSON events (alerts, DNS, HTTP, flow, TLS).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dateutil import parser as dt_parser

from app.models.event import NormalizedEvent
from app.normalization.cim import normalize_fields, normalize_severity
from app.parsers.base import BaseParser


class SuricataEveParser(BaseParser):
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "ids-sensor") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        # 1. Timestamp extraction
        ts_raw = data.get("timestamp")
        if ts_raw:
            try:
                dt = dt_parser.parse(ts_raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        # 2. Extract Network coordinates
        host = data.get("host") or default_host
        event_type = data.get("event_type", "network")
        category = "network"
        severity = "info"

        fields: Dict[str, Any] = {
            "event_type": event_type,
            "proto": data.get("proto"),
            "src_ip": data.get("src_ip"),
            "src_port": data.get("src_port"),
            "dest_ip": data.get("dest_ip"),
            "dest_port": data.get("dest_port"),
            "flow_id": data.get("flow_id"),
            "in_iface": data.get("in_iface")
        }

        # 3. Handle Alert-specific details
        if event_type == "alert" and "alert" in data:
            al = data["alert"]
            category = "ids"
            sev_num = al.get("severity", 3)
            # Suricata severity: 1 is Critical, 2 is High, 3 is Medium, 4 is Low
            if sev_num == 1:
                severity = "critical"
            elif sev_num == 2:
                severity = "high"
            elif sev_num == 3:
                severity = "medium"
            else:
                severity = "low"

            fields.update({
                "signature": al.get("signature"),
                "signature_id": al.get("signature_id"),
                "alert_category": al.get("category"),
                "action": al.get("action", "allowed")
            })

        # 4. Handle HTTP details
        elif event_type == "http" and "http" in data:
            http_data = data["http"]
            fields.update({
                "http_method": http_data.get("http_method"),
                "http_uri": http_data.get("url"),
                "http_host": http_data.get("hostname"),
                "http_user_agent": http_data.get("http_user_agent"),
                "status_code": http_data.get("status")
            })

        # 5. Handle DNS details
        elif event_type == "dns" and "dns" in data:
            dns_data = data["dns"]
            fields.update({
                "dns_query": dns_data.get("rrname"),
                "dns_type": dns_data.get("rrtype"),
                "dns_rcode": dns_data.get("rcode")
            })

        # Filter None values
        clean_fields = {k: v for k, v in fields.items() if v is not None}
        normalized = normalize_fields(clean_fields)

        return NormalizedEvent.create(
            raw=raw_line,
            timestamp=dt,
            index_name="ids",
            host=host,
            source=source,
            sourcetype="suricata_eve",
            severity=severity,
            category=category,
            fields=normalized
        )
