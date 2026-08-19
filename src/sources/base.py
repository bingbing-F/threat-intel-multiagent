"""Abstract base class for intelligence sources."""
from abc import ABC, abstractmethod
from typing import List

from src.models.source import RawContent


class BaseSource(ABC):
    """Base class for all OSINT sources."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def fetch(self) -> List[RawContent]:
        """Fetch raw content from this source."""
        raise NotImplementedError

    def is_enabled(self) -> bool:
        return self.enabled
