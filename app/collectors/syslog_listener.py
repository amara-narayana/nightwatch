"""
NIGHTWATCH — Real-Time UDP Syslog Listener (RFC 3164 / RFC 5424)
Listens on UDP port 1514 for live incoming syslog streams from network devices,
forwarders, and local services in real time.
"""

import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from app.core.config import get_settings
from app.models.event import NormalizedEvent
from app.parsers.syslog import SyslogParser
from app.storage.engine import get_storage_engine

logger = logging.getLogger("nightwatch.collector.syslog")


class SyslogListener:
    """Real-time UDP Syslog Server listening on port 1514."""

    def __init__(self, host: str = "0.0.0.0", port: int = 1514):
        self.host = host
        self.port = port
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.parser = SyslogParser()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self.total_received = 0

    def start(self) -> None:
        """Starts real-time UDP Syslog listener thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._listen_loop,
            name="NightwatchSyslogListener",
            daemon=True
        )
        self._thread.start()
        logger.info(f"NIGHTWATCH Real-Time Syslog Listener active on UDP {self.host}:{self.port}")

    def stop(self) -> None:
        """Stops UDP listener socket and thread."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("NIGHTWATCH Syslog Listener stopped.")

    def _listen_loop(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)
        except Exception as e:
            logger.error(f"Failed to bind Syslog UDP socket on {self.host}:{self.port}: {e}")
            self._running = False
            return

        batch = []
        last_flush = time.time()

        while self._running:
            try:
                data, addr = self._sock.recvfrom(8192)
                raw_text = data.decode("utf-8", errors="replace").strip()
                if not raw_text:
                    continue

                client_ip = addr[0]
                ev = self.parser.parse(
                    raw_line=raw_text,
                    source=f"udp:{client_ip}:{addr[1]}",
                    default_host=client_ip
                )
                if ev:
                    ev.index_name = "main"
                    batch.append(ev)
                    self.total_received += 1

                # Flush batch every 20 events or 1.0 second
                now = time.time()
                if len(batch) >= 20 or (batch and now - last_flush >= 1.0):
                    self.storage.insert_events_batch(batch)
                    batch.clear()
                    last_flush = now

            except socket.timeout:
                # Flush pending batch on timeout
                if batch:
                    self.storage.insert_events_batch(batch)
                    batch.clear()
                    last_flush = time.time()
            except Exception as e:
                if self._running:
                    logger.debug(f"Syslog receive error: {e}")

        # Final flush on stop
        if batch:
            self.storage.insert_events_batch(batch)


_syslog_listener_instance: Optional[SyslogListener] = None


def get_syslog_listener() -> SyslogListener:
    global _syslog_listener_instance
    if _syslog_listener_instance is None:
        _syslog_listener_instance = SyslogListener()
    return _syslog_listener_instance
