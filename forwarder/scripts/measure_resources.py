"""
NIGHTWATCH Forwarder & Receiver — Resource Consumption & Throughput Benchmark
Measures genuine process RSS memory, CPU utilization, disk queue footprint,
and wire event-processing throughput on the host machine.
"""

import os
import sqlite3
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import psutil
from forwarder.agent.config import AgentConfig
from forwarder.agent.service import ForwarderAgentService
from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.tls_server import TlsReceiverServer


def measure():
    print("================================================================")
    print("   NIGHTWATCH Forwarder & Receiver Resource Measurement Report   ")
    print("================================================================\n")

    cfg_dir = BASE_DIR / "forwarder" / "config"
    rec_cfg = ReceiverConfig.from_file(str(cfg_dir / "receiver.test.json"))
    rec_cfg.resolve_paths(BASE_DIR)
    agt_cfg = AgentConfig.from_file(str(cfg_dir / "agent.test.json"))
    agt_cfg.resolve_paths(BASE_DIR)

    process = psutil.Process()

    # Initial baseline
    initial_rss_mb = round(process.memory_info().rss / (1024 * 1024), 2)
    print(f"[*] Baseline Python Process Memory (before services): {initial_rss_mb} MB")

    receiver = TlsReceiverServer(rec_cfg)
    receiver.start()

    agent = ForwarderAgentService(agt_cfg)
    agent.start()

    print("[*] Forwarder Agent & Receiver running. Measuring for 5 seconds...")
    cpu_samples = []
    mem_samples = []
    start_time = time.time()

    initial_rec_events = receiver.storage.get_event_count()

    for _ in range(5):
        time.sleep(1.0)
        cpu_samples.append(process.cpu_percent(interval=None))
        mem_samples.append(round(process.memory_info().rss / (1024 * 1024), 2))

    duration = time.time() - start_time
    final_rec_events = receiver.storage.get_event_count()
    events_processed = final_rec_events - initial_rec_events

    agent.stop()
    receiver.stop()

    avg_cpu = round(sum(cpu_samples) / max(1, len(cpu_samples)), 2)
    peak_mem = max(mem_samples) if mem_samples else initial_rss_mb
    throughput = round(events_processed / duration, 1)

    # Queue file sizes
    q_path = Path(agt_cfg.state_dir) / "queue.db"
    q_size_kb = round(q_path.stat().st_size / 1024, 2) if q_path.exists() else 0

    print("\n---------------- Resource Utilization Results ------------------")
    print(f"  Target Platform:             {sys.platform} ({os.name})")
    print(f"  Python Version:              {sys.version.split()[0]}")
    print(f"  Average CPU Utilization:     {avg_cpu}%")
    print(f"  Peak RSS Working Set Memory: {peak_mem} MB (Baseline: {initial_rss_mb} MB)")
    print(f"  Memory Footprint Delta:      +{round(peak_mem - initial_rss_mb, 2)} MB")
    print(f"  Persistent Queue Disk Size:  {q_size_kb} KB")
    print(f"  Delivery Throughput:         {throughput} events/sec")
    print("----------------------------------------------------------------\n")


if __name__ == "__main__":
    measure()
