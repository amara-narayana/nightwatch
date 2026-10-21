"""
NIGHTWATCH — Auto Parser Router
Dynamically routes raw logs to the optimal parser based on sourcetype or signature inspection.
"""

import json
from typing import Dict, Optional
from app.models.event import NormalizedEvent
from app.parsers.base import BaseParser
from app.parsers.generic_json import GenericJsonParser
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.suricata import SuricataEveParser
from app.parsers.syslog import SyslogParser
from app.parsers.windows_evt import WindowsEventParser


class AutoParser(BaseParser):
    def __init__(self):
        self.parsers: Dict[str, BaseParser] = {
            "linux_auth": LinuxAuthParser(),
            "suricata_eve": SuricataEveParser(),
            "winevt": WindowsEventParser(),
            "syslog": SyslogParser(),
            "json": GenericJsonParser(),
        }

    def parse_with_sourcetype(
        self,
        raw_line: str,
        sourcetype: str,
        source: str = "unknown",
        default_host: str = "localhost"
    ) -> Optional[NormalizedEvent]:
        st = sourcetype.lower().strip()
        parser = self.parsers.get(st)
        if parser:
            res = parser.parse(raw_line, source=source, default_host=default_host)
            if res:
                return res
        return self.parse(raw_line, source=source, default_host=default_host)

    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "localhost") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        # Check for JSON first
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    # Check for Suricata signature
                    if "event_type" in data and ("alert" in data or "flow" in data or "dns" in data or "http" in data):
                        return self.parsers["suricata_eve"].parse(raw_line, source=source, default_host=default_host)
                    # Check for Windows Event signature
                    if "EventID" in data or "EventData" in data or ("Event" in data and "System" in data.get("Event", {})):
                        return self.parsers["winevt"].parse(raw_line, source=source, default_host=default_host)
                    # Generic JSON
                    return self.parsers["json"].parse(raw_line, source=source, default_host=default_host)
            except Exception:
                pass

        # Check for Linux auth signatures
        if "sshd[" in line or "sudo:" in line or "su[" in line or "pam_unix" in line:
            return self.parsers["linux_auth"].parse(raw_line, source=source, default_host=default_host)

        # Fall back to Syslog parser
        return self.parsers["syslog"].parse(raw_line, source=source, default_host=default_host)


_auto_parser_instance: Optional[AutoParser] = None


def get_auto_parser() -> AutoParser:
    global _auto_parser_instance
    if _auto_parser_instance is None:
        _auto_parser_instance = AutoParser()
    return _auto_parser_instance
