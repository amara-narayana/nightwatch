"""
NIGHTWATCH — Parser Base Class & Timestamp Utilities
"""

import abc
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from dateutil import parser as dt_parser

from app.models.event import NormalizedEvent


# Timestamp regex patterns
ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
SYSLOG_BSD_PATTERN = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


class BaseParser(abc.ABC):
    @abc.abstractmethod
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "localhost") -> Optional[NormalizedEvent]:
        """Parses a single raw line into a NormalizedEvent."""
        pass

    @staticmethod
    def extract_timestamp(text: str) -> Tuple[datetime, str]:
        """
        Attempts to extract and parse a timestamp from text.
        Returns (parsed_datetime_utc, remainder_text).
        """
        now = datetime.now(timezone.utc)

        # 1. Check for ISO-8601 / RFC-3339 style timestamp at start
        m_iso = ISO_PATTERN.match(text)
        if m_iso:
            ts_str = m_iso.group(0)
            try:
                dt = dt_parser.parse(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                remainder = text[m_iso.end():].strip()
                return dt, remainder
            except Exception:
                pass

        # 2. Check for BSD Syslog style timestamp (e.g. "Oct 21 05:15:32")
        m_bsd = SYSLOG_BSD_PATTERN.match(text)
        if m_bsd:
            ts_str = m_bsd.group(1)
            try:
                # Add current year since BSD syslog lacks year
                full_ts = f"{ts_str} {now.year}"
                dt = datetime.strptime(full_ts, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                remainder = text[m_bsd.end():].strip()
                return dt, remainder
            except Exception:
                pass

        # Default fallback to current time
        return now, text
