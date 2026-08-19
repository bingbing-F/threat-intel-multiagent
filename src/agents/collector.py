"""Perception Agent: collect raw intelligence from multiple sources."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.storage.db import Database
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CollectorAgent:
    """Agent responsible for collecting raw content from configured sources."""

    def __init__(self, sources: List[BaseSource], db: Database, max_workers: int = 5):
        self.sources = sources
        self.db = db
        self.max_workers = max_workers

    def collect(self, persist: bool = True) -> List[RawContent]:
        """Collect from all enabled sources concurrently."""
        enabled = [s for s in self.sources if s.is_enabled()]
        logger.info(f"Starting collection from {len(enabled)} sources")

        results: List[RawContent] = []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(enabled) or 1)) as executor:
            future_to_source = {executor.submit(s.fetch): s for s in enabled}
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    items = future.result()
                    logger.info(f"Source {source.name} returned {len(items)} items")
                    results.extend(items)
                except Exception as e:
                    logger.error(f"Source {source.name} failed: {e}")

        if persist:
            saved = 0
            duplicates = 0
            for item in results:
                if self.db.save_raw_content(item):
                    saved += 1
                else:
                    duplicates += 1
            logger.info(f"Persisted {saved} new raw items, skipped {duplicates} duplicates")

        return results
