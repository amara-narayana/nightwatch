"""
NIGHTWATCH Forwarder Agent — Core Service Orchestrator
Coordinates concurrent log collection, durable queue staging, checkpoint consistency,
and authenticated mTLS transmission with exponential backoff.
"""

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import List, Optional

from forwarder.agent.checkpoint import CheckpointStore
from forwarder.agent.collectors.base import BaseCollector
from forwarder.agent.collectors.linux_files import LinuxFileCollector
from forwarder.agent.collectors.windows_eventlog import WindowsEventLogCollector
from forwarder.agent.config import AgentConfig
from forwarder.agent.health import AgentHealthMonitor
from forwarder.agent.queue import DurableQueue, QueueFullError
from forwarder.agent.retry import RetryBackoff
from forwarder.agent.transport import TlsAgentTransport, TransportError

logger = logging.getLogger("nightwatch.forwarder.agent")


class ForwarderAgentService:
    """
    Main runtime orchestrator for the NIGHTWATCH Forwarder endpoint agent.
    Runs isolated collection and transmission threads.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.base_dir = Path(self.config.state_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # 1. State stores
        cp_db = str(self.base_dir / "checkpoints.db")
        q_db = str(self.base_dir / "queue.db")

        self.checkpoint_store = CheckpointStore(cp_db)
        self.queue = DurableQueue(
            db_path=q_db,
            max_size_mb=self.config.max_queue_size_mb,
            max_events=self.config.max_queue_events,
            full_policy=self.config.queue_full_policy
        )

        # 2. Telemetry and resilience
        self.health = AgentHealthMonitor(self.queue)
        self.backoff = RetryBackoff(
            initial_delay=self.config.retry_initial_backoff_seconds,
            max_delay=self.config.retry_max_backoff_seconds,
            factor=self.config.retry_backoff_factor
        )

        # 3. Transport
        self.transport = TlsAgentTransport(self.config)

        # 4. Collectors
        self.collectors: List[BaseCollector] = []
        self._init_collectors()

        self._running = False
        self._collector_thread: Optional[threading.Thread] = None
        self._sender_thread: Optional[threading.Thread] = None

    def _init_collectors(self) -> None:
        """Initializes configured platform collectors."""
        # Linux / file sources
        for src in self.config.file_sources:
            if src.enabled:
                col = LinuxFileCollector(
                    source_cfg=src,
                    checkpoint_store=self.checkpoint_store,
                    agent_id=self.config.agent_id,
                    hostname=self.config.hostname
                )
                self.collectors.append(col)
                logger.info(f"Registered file log collector for: {src.path} (type={src.source_type})")

        # Windows Event Log channels
        if os.name == "nt":
            for win_src in self.config.windows_channels:
                if win_src.enabled:
                    wcol = WindowsEventLogCollector(
                        channel_cfg=win_src,
                        checkpoint_store=self.checkpoint_store,
                        agent_id=self.config.agent_id,
                        hostname=self.config.hostname
                    )
                    self.collectors.append(wcol)
                    logger.info(f"Registered Windows Event Log collector for channel: {win_src.channel}")

    def start(self) -> None:
        """Starts background collection and transmission threads."""
        if self._running:
            return
        self._running = True

        logger.info(f"Starting NIGHTWATCH Forwarder Agent (ID: {self.config.agent_id})...")

        self._collector_thread = threading.Thread(
            target=self._collection_loop,
            name="NW-CollectorThread",
            daemon=True
        )
        self._sender_thread = threading.Thread(
            target=self._transmission_loop,
            name="NW-SenderThread",
            daemon=True
        )

        self._collector_thread.start()
        self._sender_thread.start()
        logger.info("NIGHTWATCH Forwarder Agent running.")

    def stop(self) -> None:
        """Performs graceful shutdown, releasing resources and persisting state."""
        if not self._running:
            return
        logger.info("Initiating graceful shutdown of NIGHTWATCH Forwarder Agent...")
        self._running = False

        if self._collector_thread and self._collector_thread.is_alive():
            self._collector_thread.join(timeout=3.0)
        if self._sender_thread and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=3.0)

        self.transport.close()
        logger.info("NIGHTWATCH Forwarder Agent stopped.")

    def _collection_loop(self) -> None:
        """Continuous log collection loop."""
        while self._running:
            for col in self.collectors:
                if not self._running:
                    break
                try:
                    events = col.collect()
                    if events:
                        # Enqueue durably first
                        inserted = self.queue.enqueue_batch(events)
                        # ONLY advance checkpoint after queue confirms commit
                        col.commit_checkpoint()
                        self.health.record_collected(inserted)
                        logger.debug(f"Collected and enqueued {inserted} events from {col}")
                except QueueFullError as e:
                    logger.warning(f"Collection throttled: {e}")
                    time.sleep(2.0)
                except Exception as e:
                    logger.error(f"Error in collector {col}: {e}", exc_info=True)

            time.sleep(self.config.poll_interval_seconds)

    def _transmission_loop(self) -> None:
        """Continuous mTLS delivery loop with exponential backoff and ACK processing."""
        while self._running:
            pending_count = self.queue.count_pending()

            if pending_count == 0:
                time.sleep(0.5)
                continue

            # Ensure transport is connected
            if not self.transport.is_connected():
                self.health.set_connection_status("connecting")
                try:
                    self.transport.connect()
                    self.health.set_connection_status("connected")
                    self.backoff.record_success()
                except TransportError as e:
                    self.health.set_connection_status("fatal_auth_error")
                    self.health.record_failure()
                    logger.critical(f"Permanent TLS configuration/certificate error: {e}. Aborting retry loop.")
                    time.sleep(10.0)
                    continue
                except Exception as e:
                    self.health.set_connection_status("connection_failed")
                    self.health.record_failure()
                    delay = self.backoff.record_failure(e)
                    self.backoff.wait(delay)
                    continue

            # Lease batch from durable queue
            batch_id = str(uuid.uuid4())
            batch = self.queue.lease_batch(self.config.batch_size, batch_id)
            if not batch:
                continue

            # Transmit batch over mTLS and await receiver acknowledgement
            try:
                success, acked_ids, error_msg = self.transport.send_batch(batch_id, batch)

                if success:
                    # Retire acknowledged events permanently from disk
                    deleted = self.queue.acknowledge_batch(batch_id, acked_ids)
                    self.health.record_delivered(deleted)
                    self.backoff.record_success()
                    logger.debug(f"Batch {batch_id} delivered and acknowledged: {deleted} events.")
                else:
                    # Receiver returned NACK or error
                    logger.warning(f"Receiver NACK for batch {batch_id}: {error_msg}. Re-queueing.")
                    self.queue.requeue_batch(batch_id)
                    self.health.record_failure()
                    delay = self.backoff.record_failure(Exception(error_msg))
                    self.backoff.wait(delay)

            except Exception as e:
                # Network dropped, timeout, or framing corruption
                logger.warning(f"Transmission failure for batch {batch_id}: {e}. Re-queueing events.")
                self.queue.requeue_batch(batch_id)
                self.transport.close()
                self.health.set_connection_status("disconnected")
                self.health.record_failure()
                delay = self.backoff.record_failure(e)
                self.backoff.wait(delay)
