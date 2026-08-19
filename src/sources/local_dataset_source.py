"""Local dataset source: reads curated seed/monitoring samples from disk.

Each JSON file under ``data/dark_dataset/`` is a synthetic threat-intelligence
sample (always tagged ``sample: true``) covering multiple domains and two
source tiers:

- ``dark``     -> emulated dark-web forum / market / channel source.
- ``clearnet`` -> public vendor blog / threat feed.

The source exists so the monitoring + dark-web capability works deterministically
and offline (no Tor, no SOCKS proxy, no .onion resolution) while the pipeline
(Collector -> Analyzer -> Validator -> Correlator -> Reporter) and the
cross-domain monitor stay fully real. It mirrors ``DemoSource`` in spirit but
carries a ``source_tier`` field for zone-level reporting.
"""
import hashlib
import json
from pathlib import Path
from typing import List

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DIR = PROJECT_ROOT / "data" / "dark_dataset"


def _stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LocalDatasetSource(BaseSource):
    """Serves seed monitoring samples from a local JSON directory."""

    def __init__(self, directory: str = None, name: str = "local_dataset", enabled: bool = True):
        super().__init__(name, enabled)
        self.directory = Path(directory) if directory else DEFAULT_DIR

    def fetch(self) -> List[RawContent]:
        results: List[RawContent] = []
        if not self.directory.exists():
            logger.warning(f"Local dataset directory not found: {self.directory}")
            return results
        for path in sorted(self.directory.glob("*.json")):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to read dataset sample {path}: {e}")
                continue
            content = entry.get("content", "").strip()
            if not content:
                continue
            metadata = {
                "tier": entry.get("tier", "clearnet"),
                "domain": entry.get("domain", "未分类"),
                "sample": True,
                "dataset_file": path.name,
            }
            if entry.get("keywords"):
                metadata["keywords"] = list(entry["keywords"])
            results.append(
                RawContent(
                    source_name=entry.get("source", f"{self.name}:{path.stem}"),
                    url=entry.get("url"),
                    title=entry.get("title"),
                    content=content,
                    content_hash=_stable_hash(content),
                    metadata=metadata,
                )
            )
        logger.info(f"LocalDatasetSource[{self.name}] loaded {len(results)} samples")
        return results