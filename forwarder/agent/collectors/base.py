"""
NIGHTWATCH Forwarder Agent — Base Collector Interface
"""

from abc import ABC, abstractmethod
from typing import List
from forwarder.agent.event_schema import ForwarderEvent


class BaseCollector(ABC):
    """Abstract base class for all endpoint log collectors."""

    @abstractmethod
    def collect(self) -> List[ForwarderEvent]:
        """
        Polls the log source for newly appended events.
        Returns a list of parsed ForwarderEvent instances.
        Does NOT commit checkpoints until caller confirms events are queued.
        """
        pass

    @abstractmethod
    def commit_checkpoint(self) -> None:
        """
        Persists collection checkpoint after caller has durably enqueued the events.
        """
        pass
