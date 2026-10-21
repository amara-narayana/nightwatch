"""
NIGHTWATCH Forwarder Agent — Bounded Exponential Backoff with Jitter
Handles connection failures, network partitions, and receiver timeouts cleanly.
"""

import logging
import random
import time
from typing import Optional

logger = logging.getLogger("nightwatch.forwarder.retry")


class RetryBackoff:
    """
    Computes bounded exponential backoff with randomized jitter to prevent thundering herds.
    """

    def __init__(
        self,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        factor: float = 2.0,
        jitter_pct: float = 0.2
    ):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.factor = factor
        self.jitter_pct = jitter_pct

        self.consecutive_failures = 0
        self.last_failure_time: Optional[float] = None
        self.last_error_message: str = ""

    def record_success(self) -> None:
        """Resets backoff state after a successful connection/delivery."""
        if self.consecutive_failures > 0:
            logger.info(f"Transport recovered after {self.consecutive_failures} failures.")
        self.consecutive_failures = 0
        self.last_error_message = ""

    def record_failure(self, error: Exception) -> float:
        """
        Increments failure counter, records timestamp, and returns sleep seconds.
        """
        self.consecutive_failures += 1
        self.last_failure_time = time.time()
        self.last_error_message = str(error)

        # Base exponential delay
        base_delay = min(self.max_delay, self.initial_delay * (self.factor ** (self.consecutive_failures - 1)))

        # Jitter: +/- jitter_pct
        jitter = base_delay * self.jitter_pct * (2 * random.random() - 1)
        delay = max(self.initial_delay, base_delay + jitter)

        logger.warning(
            f"Transport failure #{self.consecutive_failures} ({type(error).__name__}: {error}). "
            f"Backing off for {delay:.2f}s."
        )
        return delay

    def wait(self, delay: float) -> None:
        """Sleeps for the computed delay."""
        time.sleep(delay)
