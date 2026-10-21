"""
NIGHTWATCH — Linux Authentication Log Parser (/var/log/auth.log)
"""

import re
from typing import Optional
from app.models.event import NormalizedEvent
from app.normalization.cim import normalize_fields
from app.parsers.base import BaseParser

# Regex patterns for SSHD
RE_SSHD_FAILED_INVALID = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Failed password for invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
RE_SSHD_FAILED = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
RE_SSHD_ACCEPTED = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
RE_SSHD_INVALID_USER = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
RE_SUDO_COMMAND = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+);\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)"
)
RE_SU = re.compile(
    r"su\[(?P<pid>\d+)\]:\s+(?P<action>Successful|FAILED)\s+su\s+for\s+(?P<target_user>\S+)\s+by\s+(?P<user>\S+)"
)
RE_HOST_PREFIX = re.compile(r"^(?P<host>[a-zA-Z0-9_\-\.]+)\s+(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)")


class LinuxAuthParser(BaseParser):
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "localhost") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        # 1. Extract Timestamp
        dt, remainder = self.extract_timestamp(line)

        # 2. Extract Host and Process prefix if present
        host = default_host
        process = "auth"
        pid = None
        msg = remainder

        m_host = RE_HOST_PREFIX.match(remainder)
        if m_host:
            host = m_host.group("host") or default_host
            process = m_host.group("process") or "auth"
            pid = m_host.group("pid")
            msg = remainder

        # Default classification
        severity = "info"
        category = "authentication"
        fields = {
            "process": process,
            "host": host
        }
        if pid:
            fields["process_id"] = int(pid)

        # 3. Match Specific SSH & Auth Signatures
        m = RE_SSHD_FAILED_INVALID.search(msg)
        if m:
            fields.update({
                "action": "failure",
                "user": m.group("user"),
                "src_ip": m.group("src_ip"),
                "src_port": int(m.group("src_port")),
                "app": "sshd",
                "reason": "invalid_user"
            })
            severity = "high"
        else:
            m = RE_SSHD_FAILED.search(msg)
            if m:
                fields.update({
                    "action": "failure",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "src_port": int(m.group("src_port")),
                    "app": "sshd"
                })
                severity = "medium"
            else:
                m = RE_SSHD_ACCEPTED.search(msg)
                if m:
                    fields.update({
                        "action": "success",
                        "user": m.group("user"),
                        "src_ip": m.group("src_ip"),
                        "src_port": int(m.group("src_port")),
                        "app": "sshd"
                    })
                    severity = "info"
                else:
                    m = RE_SSHD_INVALID_USER.search(msg)
                    if m:
                        fields.update({
                            "action": "failure",
                            "user": m.group("user"),
                            "src_ip": m.group("src_ip"),
                            "src_port": int(m.group("src_port")),
                            "app": "sshd",
                            "reason": "invalid_user"
                        })
                        severity = "medium"
                    else:
                        m = RE_SUDO_COMMAND.search(msg)
                        if m:
                            fields.update({
                                "action": "success",
                                "user": m.group("user"),
                                "target_user": m.group("target_user"),
                                "command": m.group("command").strip(),
                                "pwd": m.group("pwd").strip(),
                                "app": "sudo"
                            })
                            category = "privilege"
                            severity = "low"
                        else:
                            m = RE_SU.search(msg)
                            if m:
                                act = "success" if m.group("action").lower() == "successful" else "failure"
                                fields.update({
                                    "action": act,
                                    "user": m.group("user"),
                                    "target_user": m.group("target_user"),
                                    "app": "su"
                                })
                                category = "privilege"
                                severity = "medium" if act == "failure" else "low"

        normalized = normalize_fields(fields)

        return NormalizedEvent.create(
            raw=raw_line,
            timestamp=dt,
            index_name="security",
            host=host,
            source=source,
            sourcetype="linux_auth",
            severity=severity,
            category=category,
            fields=normalized
        )
