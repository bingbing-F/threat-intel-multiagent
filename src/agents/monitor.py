"""Monitoring Agent: cross-domain thematic monitoring over collected raw items.

The monitor is deliberately *generic*: instead of being hard-wired to a single
sector, it evaluates every raw item against a configurable set of *domains*
(卫星/航天, 勒索软件, APT, 供应链, IoT 僵尸网络, ...) and produces per-domain
``DomainMetric`` aggregates. It also tracks the *source tier* of every heat item
(dark vs. clearnet) so the dashboard can show dark-web contribution — without
the monitor yourself depending on Tor.
"""
from collections import defaultdict
from typing import Dict, List

from src.config_loader import get_settings
from src.models.metric import DomainMetric
from src.models.source import RawContent
from src.storage.db import Database
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DomainMonitorAgent:
    """Aggregates keyword-matching stats per configured domain."""

    def __init__(self, domains: Dict[str, List[str]] = None, db: Database = None):
        self.domains = domains
        self.db = db
        if self.domains is None:
            self.domains = self._load_domains_from_settings()

    @staticmethod
    def _load_domains_from_settings() -> Dict[str, List[str]]:
        settings = get_settings()
        domain_cfg = settings.get("monitor.domains", {})
        return {
            name: [k.lower() for k in (cfg.get("keywords", []) or [])]
            for name, cfg in domain_cfg.items()
            if isinstance(cfg, dict)
        }

    def scan(self, raw_items: List[RawContent]) -> List[DomainMetric]:
        """Scan raw items and return one metric per configured domain."""
        by_domain: Dict[str, List[RawContent]] = defaultdict(list)
        for item in raw_items:
            joined = ((item.title or "") + " " + item.content).lower()
            for domain, keywords in self.domains.items():
                if any(k in joined for k in keywords):
                    by_domain[domain].append(item)

        metrics: List[DomainMetric] = []
        for domain, items in sorted(by_domain.items()):
            sources = sorted({i.source_name for i in items})
            dark_sources = sum(1 for i in items if str(i.metadata.get("tier", "")).lower() == "dark")
            matched = sorted(
                {
                    k
                    for i in items
                    for k in self.domains[domain]
                    if k in ((i.title or "") + " " + i.content).lower()
                }
            )
            metrics.append(
                DomainMetric(
                    domain=domain,
                    matched_items=len(items),
                    total_sources=len(sources),
                    dark_sources=dark_sources,
                    matched_keywords=matched,
                    sample_summary="; ".join((i.title or i.content[:40]) for i in items[:3]),
                )
            )
            logger.info(
                f"Monitor domain={domain} matched={len(items)} "
                f"sources={len(sources)} dark={dark_sources}"
            )

        if by_domain:
            self._persist(metrics)
        logger.info(f"Monitoring scan complete: {len(metrics)} domains matched")
        return metrics

    def _persist(self, metrics: List[DomainMetric]) -> None:
        if self.db is None:
            return
        try:
            self.db.save_domain_metrics(metrics)
        except Exception as e:  # noqa: BLE001 - monitoring must never break the run
            logger.error(f"Failed to persist domain metrics: {e}")