"""
NIGHTWATCH — Parsers Package
"""
from app.parsers.base import BaseParser
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.suricata import SuricataEveParser
from app.parsers.windows_evt import WindowsEventParser
from app.parsers.syslog import SyslogParser
from app.parsers.generic_json import GenericJsonParser
from app.parsers.auto import AutoParser, get_auto_parser

__all__ = [
    "BaseParser",
    "LinuxAuthParser",
    "SuricataEveParser",
    "WindowsEventParser",
    "SyslogParser",
    "GenericJsonParser",
    "AutoParser",
    "get_auto_parser",
]
