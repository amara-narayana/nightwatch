"""
NIGHTWATCH — Security Detection Rules Registry and Logic Evaluators
"""

import json
import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.models.alert import DetectionRule, SecurityAlert
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.detection")


class DetectionRuleRegistry:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.rules_file = Path(self.settings.base_dir) / "config" / "detection_rules.json"
        self.rules: Dict[str, DetectionRule] = {}
        self.load_rules()

    def load_rules(self) -> None:
        if self.rules_file.exists():
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data.get("rules", []):
                    r = DetectionRule(**item)
                    self.rules[r.id] = r
            except Exception as e:
                logger.error(f"Error loading {self.rules_file}: {e}")

    def save_rules(self) -> None:
        try:
            data = {"rules": [r.model_dump() for r in self.rules.values()]}
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving {self.rules_file}: {e}")

    def get_all_rules(self) -> List[DetectionRule]:
        return list(self.rules.values())

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        return self.rules.get(rule_id)

    def update_rule(self, rule: DetectionRule) -> None:
        self.rules[rule.id] = rule
        self.save_rules()


class RuleEvaluator:
    @staticmethod
    def evaluate_rule(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """Evaluates a detection rule against a window of events. Returns generated alerts."""
        if not rule.enabled or not events:
            return []

        alerts: List[SecurityAlert] = []

        if rule.rule_type == "threshold":
            alerts.extend(RuleEvaluator._eval_threshold(rule, events))
        elif rule.rule_type == "distinct_threshold":
            alerts.extend(RuleEvaluator._eval_distinct_threshold(rule, events))
        elif rule.rule_type == "sequence":
            alerts.extend(RuleEvaluator._eval_sequence(rule, events))
        elif rule.rule_type == "privileged_target":
            alerts.extend(RuleEvaluator._eval_privileged(rule, events))
        elif rule.rule_type == "ids_alert":
            alerts.extend(RuleEvaluator._eval_ids(rule, events))
        elif rule.rule_type == "regex_pattern":
            alerts.extend(RuleEvaluator._eval_regex(rule, events))

        return alerts

    @staticmethod
    def _eval_threshold(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        alerts = []
        group_field = rule.group_by or "src_ip"
        grouped_events: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)

        for e in events:
            # Check conditions
            match = True
            for k, v in rule.conditions.items():
                if str(e.get(k, "")).lower() != str(v).lower():
                    match = False
                    break
            if match:
                key = e.get(group_field)
                if key:
                    grouped_events[key].append(e)

        for key, matched_list in grouped_events.items():
            if len(matched_list) >= rule.threshold:
                evidence = [
                    {"id": ev["id"], "time": ev["timestamp"], "host": ev["host"], "src_ip": ev.get("src_ip"), "user": ev.get("user"), "raw": ev["raw"]}
                    for ev in matched_list[:10]
                ]
                desc = f"{rule.name}: {len(matched_list)} matching events from {group_field}='{key}' (Threshold: {rule.threshold})"
                alerts.append(SecurityAlert.create(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=desc,
                    severity=rule.severity,
                    category=rule.category,
                    event_count=len(matched_list),
                    evidence=evidence
                ))

        return alerts

    @staticmethod
    def _eval_distinct_threshold(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        alerts = []
        group_field = rule.group_by or "src_ip"
        dist_field = rule.distinct_field or "user"

        # group_val -> { distinct_val -> list of events }
        grouped: Dict[Any, Dict[Any, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))

        for e in events:
            # Check conditions
            match = True
            for k, v in rule.conditions.items():
                if str(e.get(k, "")).lower() != str(v).lower():
                    match = False
                    break
            if match:
                g_key = e.get(group_field)
                d_key = e.get(dist_field)
                if g_key and d_key:
                    grouped[g_key][d_key].append(e)

        for g_key, dist_map in grouped.items():
            distinct_count = len(dist_map)
            if distinct_count >= rule.threshold:
                all_events = [ev for ev_list in dist_map.values() for ev in ev_list]
                evidence = [
                    {"id": ev["id"], "time": ev["timestamp"], "host": ev["host"], "src_ip": ev.get("src_ip"), "user": ev.get("user"), "raw": ev["raw"]}
                    for ev in all_events[:10]
                ]
                sample_distinct = list(dist_map.keys())[:5]
                desc = f"{rule.name}: {group_field}='{g_key}' targeted {distinct_count} distinct {dist_field}s (e.g. {sample_distinct})"
                alerts.append(SecurityAlert.create(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=desc,
                    severity=rule.severity,
                    category=rule.category,
                    event_count=len(all_events),
                    evidence=evidence
                ))

        return alerts

    @staticmethod
    def _eval_sequence(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """Detects failures followed by a success for the same entity."""
        alerts = []
        group_field = rule.group_by or "user"
        threshold = rule.failure_threshold or 3

        # Sort chronologically
        sorted_events = sorted(events, key=lambda x: x.get("epoch", 0.0))
        grouped: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)

        for e in sorted_events:
            key = e.get(group_field)
            if key:
                grouped[key].append(e)

        for key, ev_list in grouped.items():
            fail_count = 0
            fail_events = []
            for ev in ev_list:
                act = str(ev.get("action", "")).lower()
                if act in ("failure", "failed", "denied"):
                    fail_count += 1
                    fail_events.append(ev)
                elif act in ("success", "accepted", "authenticated") and fail_count >= threshold:
                    # Successful login after repeated failures!
                    evidence_list = [
                        {"id": fe["id"], "time": fe["timestamp"], "action": fe.get("action"), "src_ip": fe.get("src_ip"), "raw": fe["raw"]}
                        for fe in fail_events[-threshold:]
                    ]
                    evidence_list.append({
                        "id": ev["id"], "time": ev["timestamp"], "action": ev.get("action"), "src_ip": ev.get("src_ip"), "raw": ev["raw"]
                    })
                    desc = f"{rule.name}: Account '{key}' experienced {fail_count} failed logins followed by successful authentication."
                    alerts.append(SecurityAlert.create(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=desc,
                        severity=rule.severity,
                        category=rule.category,
                        event_count=fail_count + 1,
                        evidence=evidence_list
                    ))
                    # Reset counter for next window
                    fail_count = 0
                    fail_events.clear()

        return alerts

    @staticmethod
    def _eval_privileged(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        alerts = []
        priv_set = {u.lower() for u in rule.privileged_users}
        grouped_events: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)

        for e in events:
            user = str(e.get("user", "")).lower()
            if user in priv_set:
                src = e.get(rule.group_by or "src_ip")
                if src:
                    grouped_events[src].append(e)

        for src, matched_list in grouped_events.items():
            if len(matched_list) >= rule.threshold:
                evidence = [
                    {"id": ev["id"], "time": ev["timestamp"], "user": ev.get("user"), "src_ip": ev.get("src_ip"), "raw": ev["raw"]}
                    for ev in matched_list[:10]
                ]
                desc = f"{rule.name}: {len(matched_list)} attempts targeting privileged accounts ({priv_set}) from {src}"
                alerts.append(SecurityAlert.create(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=desc,
                    severity=rule.severity,
                    category=rule.category,
                    event_count=len(matched_list),
                    evidence=evidence
                ))

        return alerts

    @staticmethod
    def _eval_ids(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        alerts = []
        for e in events:
            if e.get("sourcetype") == "suricata_eve" and e.get("category") == "ids":
                sev = str(e.get("severity", "")).lower()
                if sev in ("critical", "high"):
                    sig = e.get("signature") or "High Severity Intrusion Alert"
                    desc = f"{rule.name}: {sig} detected from {e.get('src_ip')} -> {e.get('dest_ip')}"
                    evidence = [{
                        "id": e["id"],
                        "time": e["timestamp"],
                        "src_ip": e.get("src_ip"),
                        "dest_ip": e.get("dest_ip"),
                        "signature": sig,
                        "raw": e["raw"]
                    }]
                    alerts.append(SecurityAlert.create(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        description=desc,
                        severity=rule.severity,
                        category=rule.category,
                        event_count=1,
                        evidence=evidence
                    ))
        return alerts

    @staticmethod
    def _eval_regex(rule: DetectionRule, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        alerts = []
        if not rule.regex:
            return alerts

        try:
            pat = re.compile(rule.regex, re.IGNORECASE)
        except Exception:
            return alerts

        matched_events = []
        for e in events:
            raw = e.get("raw") or e.get("_raw", "")
            cmd = e.get("command", "")
            if pat.search(raw) or pat.search(cmd):
                matched_events.append(e)

        if matched_events:
            for ev in matched_events[:5]:
                desc = f"{rule.name}: Matched suspicious pattern in host={ev.get('host')} user={ev.get('user', 'unknown')}"
                evidence = [{
                    "id": ev["id"],
                    "time": ev["timestamp"],
                    "host": ev["host"],
                    "user": ev.get("user"),
                    "process": ev.get("process"),
                    "command": ev.get("command"),
                    "raw": ev["raw"]
                }]
                alerts.append(SecurityAlert.create(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=desc,
                    severity=rule.severity,
                    category=rule.category,
                    event_count=1,
                    evidence=evidence
                ))

        return alerts
