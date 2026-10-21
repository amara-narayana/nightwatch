"""
NIGHTWATCH — Background Detection Engine
Schedules periodic evaluation of detection rules and manages alert deduplication.
"""

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.detection.rules import DetectionRuleRegistry, RuleEvaluator
from app.models.alert import SecurityAlert
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.detection_engine")


class DetectionEngine:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.registry = DetectionRuleRegistry()

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not self.settings.detection.enabled:
            logger.info("Detection engine disabled in configuration.")
            return

        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, name="NightwatchDetectionEngine", daemon=True)
        self._thread.start()
        logger.info("NIGHTWATCH Detection Engine started.")

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("NIGHTWATCH Detection Engine stopped.")

    def _run_loop(self) -> None:
        while self._running:
            try:
                self.run_detection_cycle()
            except Exception as e:
                logger.error(f"Detection cycle error: {e}", exc_info=True)
            time.sleep(self.settings.detection.interval_seconds)

    def run_detection_cycle(self) -> int:
        """Executes a single evaluation pass for all enabled rules."""
        rules = [r for r in self.registry.get_all_rules() if r.enabled]
        if not rules:
            return 0

        now = time.time()
        max_window = max(r.time_window_seconds for r in rules)

        with self.storage.get_connection() as conn:
            cur = conn.execute("SELECT MAX(epoch) as max_ep FROM events;")
            max_row = cur.fetchone()
            latest_db_epoch = max_row["max_ep"] if (max_row and max_row["max_ep"]) else now

        # Evaluate either against live real-time or against latest ingested event window
        eval_time = latest_db_epoch if (latest_db_epoch and (now - latest_db_epoch) > max_window) else now
        window_start = eval_time - max_window

        # Fetch candidate events within the evaluation window
        with self.storage.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE epoch >= ? AND epoch <= ? ORDER BY epoch ASC LIMIT 10000;",
                (window_start, eval_time)
            )
            raw_rows = cur.fetchall()

        if not raw_rows:
            return 0

        # Unpack rows into event dicts
        events: List[Dict[str, Any]] = []
        for r in raw_rows:
            d = dict(r)
            if d.get("fields_json"):
                try:
                    f_dict = json.loads(d["fields_json"])
                    for k, v in f_dict.items():
                        if k not in d:
                            d[k] = v
                except Exception:
                    pass
            events.append(d)

        new_alerts_count = 0

        for rule in rules:
            rule_cutoff = eval_time - rule.time_window_seconds
            rule_events = [e for e in events if e.get("epoch", 0.0) >= rule_cutoff]

            alerts = RuleEvaluator.evaluate_rule(rule, rule_events)
            for alert in alerts:
                # Check suppression window
                suppress_cutoff = now - rule.suppression_window_seconds
                if self.storage.check_recent_alert_exists(rule.id, suppress_cutoff):
                    logger.debug(f"Suppressed duplicate alert for rule {rule.id}")
                    continue

                # Store alert
                self.storage.insert_alert(alert)
                new_alerts_count += 1
                logger.warning(f"🚨 [NIGHTWATCH ALERT] {alert.severity.upper()}: {alert.rule_name} (ID: {alert.id[:8]})")

        return new_alerts_count


_detection_engine_instance: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    global _detection_engine_instance
    if _detection_engine_instance is None:
        _detection_engine_instance = DetectionEngine()
    return _detection_engine_instance
