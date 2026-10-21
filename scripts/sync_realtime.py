"""
NIGHTWATCH — Real-Time Live Host Ingestion & Detection Sync
Collects 100% real live events from native Windows Event Logs and OS process/socket telemetry,
with zero synthetic data and zero simulations.
"""

import os
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.collectors.host_telemetry import get_host_telemetry_collector
from app.collectors.windows_collector import get_windows_collector
from app.detection.engine import get_detection_engine
from app.storage.engine import get_storage_engine


def main():
    print("=" * 70)
    print(" NIGHTWATCH — Real-Time Live Host Ingestion Engine")
    print(" 100% Real Live Telemetry | Zero Simulations | Zero Synthetic Data")
    print("=" * 70)

    storage = get_storage_engine()
    print(f"[NIGHTWATCH] Storage database: {storage.db_path}")

    # 1. Ingest Real Windows Event Logs
    print("\n[1/3] Polling Native Windows Event Logs...")
    win_collector = get_windows_collector()
    win_events = 0
    for ch in ["System", "Application", "Microsoft-Windows-PowerShell/Operational"]:
        try:
            cnt = win_collector.poll_channel(ch, count=25, initial=True)
            print(f"  -> Channel '{ch}': Ingested {cnt} real host events")
            win_events += cnt
        except Exception as e:
            print(f"  -> Channel '{ch}': {e}")

    # 2. Ingest Real Process & Network Telemetry
    print("\n[2/3] Collecting Real Host Process & Socket Telemetry...")
    host_collector = get_host_telemetry_collector()
    host_events = host_collector.collect_once()
    print(f"  -> Ingested {host_events} real process/network events from host")

    total_events = storage.count_events()
    print(f"\n[NIGHTWATCH] Total Real Events Indexed in SQLite+FTS5: {total_events}")

    # 3. Real-Time Detection Cycle
    print("\n[3/3] Evaluating Security Detection Rules Against Real Events...")
    detector = get_detection_engine()
    alerts_generated = detector.run_detection_cycle()
    print(f"  -> Generated {alerts_generated} security alerts from live host stream")

    alerts = storage.get_alerts()
    print(f"\n[NIGHTWATCH] Active Real Alerts ({len(alerts)}):")
    for a in alerts[:5]:
        print(f"  [{a.severity.upper()}] {a.rule_name} — {a.description} (Evidence: {len(a.evidence)} events)")

    print("\n" + "=" * 70)
    print(" Real-Time Live Ingestion Complete. View live at http://127.0.0.1:8000")
    print("=" * 70)


if __name__ == "__main__":
    main()
