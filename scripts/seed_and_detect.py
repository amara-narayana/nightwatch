"""
NIGHTWATCH — Seed Data & Run Detections Script
Ingests samples/ into nightwatch.db and triggers detection evaluation.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.collectors.file_collector import get_file_collector
from app.detection.engine import get_detection_engine
from app.storage.engine import get_storage_engine


def seed():
    print("[NIGHTWATCH] Ingesting configured sample log files...")
    collector = get_file_collector()
    ingested = collector.collect_once()
    print(f"[NIGHTWATCH] Ingested {ingested} events into database.")

    storage = get_storage_engine()
    total = storage.count_events()
    print(f"[NIGHTWATCH] Total events in database: {total}")

    print("[NIGHTWATCH] Evaluating security detection rules...")
    detector = get_detection_engine()
    alerts_count = detector.run_detection_cycle()
    print(f"[NIGHTWATCH] Generated {alerts_count} security alerts.")

    alerts = storage.get_alerts()
    print(f"\n[NIGHTWATCH] Active Security Alerts ({len(alerts)}):")
    for a in alerts:
        print(f"  [{a.severity.upper()}] {a.rule_name} — {a.description} (Evidence events: {len(a.evidence)})")


if __name__ == "__main__":
    seed()
