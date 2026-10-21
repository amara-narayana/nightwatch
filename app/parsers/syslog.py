"""
NIGHTWATCH — Standard Syslog Parser (RFC 3164 / RFC 5424)
"""

import re
from typing import Optional
from app.models.event import NormalizedEvent
from app.normalization.cim import normalize_fields
from app.parsers.base import BaseParser

# RFC 3164 / standard syslog pattern: <PRI>TIMESTAMP HOST PROCESS[PID]: MESSAGE
RE_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<process>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)"
)


class SyslogParser(BaseParser):
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "localhost") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        m = RE_SYSLOG.match(line)
        if m:
            dt, _ = self.extract_timestamp(m.group("timestamp"))
            host = m.group("host") or default_host
            process = m.group("process")
            pid = m.group("pid")
            msg = m.group("message")
            pri = m.group("pri")

            severity = "info"
            if pri:
                # Severity is lowest 3 bits in Syslog priority
                try:
                    sev_code = int(pri) & 7
                    if sev_code <= 2:
                        severity = "critical"
                    elif sev_code <= 4:
                        severity = "high"
                    elif sev_code <= 5:
                        severity = "medium"
                    else:
                        severity = "info"
                except Exception:
                    pass

            fields = {
                "process": process,
                "message": msg,
                "host": host
            }
            if pid:
                fields["process_id"] = int(pid)

            normalized = normalize_fields(fields)
            return NormalizedEvent.create(
                raw=raw_line,
                timestamp=dt,
                index_name="main",
                host=host,
                source=source,
                sourcetype="syslog",
                severity=severity,
                category="system",
                fields=normalized
            )

        # Fallback if syslog regex doesn't match
        dt, remainder = self.extract_timestamp(line)
        return NormalizedEvent.create(
            raw=raw_line,
            timestamp=dt,
            index_name="main",
            host=default_host,
            source=source,
            sourcetype="syslog",
            severity="info",
            category="system",
            fields={"message": remainder}
        )
