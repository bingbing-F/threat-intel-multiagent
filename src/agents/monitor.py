"""监控代理：对采集到的原始条目进行跨域主题监测并统计域级指标。

该监控器设计为通用组件：它不会硬编码到单个领域，而是将每条原文
与配置的多个监控域（例如：卫星/航天、勒索软件、APT、供应链、IoT 等）
进行匹配，并产出每个域的 `DomainMetric` 汇总。它还会统计来源层级
（如 darknet vs clearnet），以便仪表盘展示暗网贡献度，而不要求监控器
自身直接依赖 Tor，实现更安全的度量采集。
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
    """按配置域聚合关键字匹配统计的监控 Agent。"""

    def __init__(self, domains: Dict[str, List[str]] = None, db: Database = None):
        self.domains = domains
        self.db = db
        if self.domains is None:
            self.domains = self._load_domains_from_settings()

    @staticmethod
    def _load_domains_from_settings() -> Dict[str, List[str]]:
        settings = get_settings()
        domain_cfg = settings.get("monitor.domains", {})
        # 将配置中的关键字标准化为小写以便匹配时忽略大小写
        return {
            name: [k.lower() for k in (cfg.get("keywords", []) or [])]
            for name, cfg in domain_cfg.items()
            if isinstance(cfg, dict)
        }

    def scan(self, raw_items: List[RawContent]) -> List[DomainMetric]:
        """扫描原始条目并返回每个配置域对应的 `DomainMetric` 列表。

        实现要点：将标题与正文合并为待匹配文本（小写），对每个域的关键字
        进行包含性匹配，收集匹配到的条目，计算来源数、暗网来源数、命中关键字
        列表和示例摘要。
        """
        by_domain: Dict[str, List[RawContent]] = defaultdict(list)
        for item in raw_items:
            joined = ((item.title or "") + " " + item.content).lower()
            for domain, keywords in self.domains.items():
                if any(k in joined for k in keywords):
                    by_domain[domain].append(item)

        metrics: List[DomainMetric] = []
        for domain, items in sorted(by_domain.items()):
            sources = sorted({i.source_name for i in items})
            # 将 metadata.tier 字段视作来源层级，暗网标记为 'dark'
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
            # 将监控指标写入数据库，失败时记录错误但不中断主流程
            self._persist(metrics)
        logger.info(f"Monitoring scan complete: {len(metrics)} domains matched")
        return metrics

    def _persist(self, metrics: List[DomainMetric]) -> None:
        if self.db is None:
            return
        try:
            self.db.save_domain_metrics(metrics)
        except Exception as e:  # noqa: BLE001 - 监控持久化失败不能中断主流程
            logger.error(f"Failed to persist domain metrics: {e}")