"""
NIGHTWATCH — Common Information Model (CIM) Normalizer
Maps vendor-specific log fields into standardized security fields.
"""

from typing import Any, Dict


# Common field mapping synonyms to canonical CIM names
FIELD_SYNONYMS = {
    "src_ip": ["src", "source_ip", "sourceip", "client_ip", "clientip", "srcip", "ip_src", "remote_ip", "c_ip"],
    "dest_ip": ["dst", "destination_ip", "destinationip", "destip", "server_ip", "serverip", "dstip", "ip_dst"],
    "src_port": ["srcport", "source_port", "client_port", "sport"],
    "dest_port": ["dstport", "destination_port", "destport", "server_port", "dport"],
    "user": ["username", "user_name", "account", "login", "usr", "actor", "target_user"],
    "action": ["status", "result", "outcome", "disposition"],
    "process": ["process_name", "proc", "app", "application", "image", "command"],
    "process_id": ["pid", "proc_id"],
    "signature": ["sig", "alert_name", "threat", "rule_name", "signature_name", "event_type"],
}

# Standardized actions
ACTION_NORMALIZATION = {
    "accepted": "success",
    "success": "success",
    "successful": "success",
    "authenticated": "success",
    "allowed": "allowed",
    "failed": "failure",
    "failure": "failure",
    "denied": "failure",
    "invalid": "failure",
    "blocked": "blocked",
    "drop": "blocked",
    "dropped": "blocked"
}

# Standardized severities
SEVERITY_NORMALIZATION = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warn": "medium",
    "warning": "medium",
    "medium": "medium",
    "notice": "low",
    "low": "low",
    "info": "info",
    "informational": "info",
    "debug": "info",
    "1": "critical",  # Suricata severity 1 = highest
    "2": "high",      # Suricata severity 2
    "3": "medium",    # Suricata severity 3
    "4": "low"
}


def normalize_fields(raw_fields: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes raw dictionary fields into standardized CIM fields."""
    normalized: Dict[str, Any] = {}

    # Copy raw fields lowercased for lookup
    lower_map = {k.lower(): v for k, v in raw_fields.items()}

    # Map canonical fields
    for canonical, synonyms in FIELD_SYNONYMS.items():
        if canonical in lower_map:
            normalized[canonical] = lower_map[canonical]
        else:
            for syn in synonyms:
                if syn in lower_map:
                    normalized[canonical] = lower_map[syn]
                    break

    # Normalize action if present
    if "action" in normalized and isinstance(normalized["action"], str):
        act_lower = normalized["action"].lower()
        normalized["action"] = ACTION_NORMALIZATION.get(act_lower, act_lower)

    # Carry over other specific attributes
    for k, v in raw_fields.items():
        if k not in normalized:
            normalized[k] = v

    return normalized


def normalize_severity(severity_input: Any) -> str:
    s = str(severity_input).strip().lower()
    return SEVERITY_NORMALIZATION.get(s, "info")
