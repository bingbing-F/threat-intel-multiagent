"""关联代理：将独立采集到的情报条目聚合为跨来源事件。

单次 LLM 调用无法可靠执行跨来源关联，本代理通过标准化指标（如 IP、域名、CVE、哈希）
在不同来源之间建立联系，基于互证提升置信度，并构建事件的时间窗口。
"""
from collections import defaultdict
from typing import Dict, List

from src.models.event import ThreatEvent
from src.models.intelligence import ThreatIntelligence
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CorrelatorAgent:
    """将共享指标的情报条目分组为关联事件，并计算互证与置信度。"""

    def correlate(self, items: List[ThreatIntelligence]) -> List[ThreatEvent]:
        if not items:
            return []

        meta: Dict[str, ThreatIntelligence] = {item.id: item for item in items}

        # 构建指标索引：indicator(lowercase) -> set of intelligence ids
        index: Dict[str, set] = defaultdict(set)
        for item in items:
            for ioc in item.iocs:
                index[ioc.lower()].add(item.id)

        # 对共享至少一个指标的条目构建并查集（union-find）以检出连通分量（簇）
        parent = {item.id: item.id for item in items}

        def find(node: str) -> str:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        # 对每个指标，将索引到的所有条目合并到同一集合中
        for ids in index.values():
            ids_list = list(ids)
            for other in ids_list[1:]:
                union(ids_list[0], other)

        clusters: Dict[str, set] = defaultdict(set)
        for item_id in meta:
            clusters[find(item_id)].add(item_id)

        events: List[ThreatEvent] = []
        for cluster in clusters.values():
            if len(cluster) < 2:
                continue
            event_items = [meta[i] for i in cluster]

                # 互证要求至少来自两个不同来源
            distinct_sources = {item.source for item in event_items}
            corroborated = len(distinct_sources) >= 2

            # 出现在多条条目中的指标视为 "关键指标"
            # （匹配时使用小写归并，但展示时保留原始拼写）
            indicator_matches: Dict[str, list] = defaultdict(list)
            for item in event_items:
                for ioc in item.iocs:
                    indicator_matches[ioc.lower()].append(ioc)
            shared = sorted({
                orig
                for originals in indicator_matches.values()
                for orig in originals
                if len(originals) >= 2
            })
            key_indicators = shared or sorted(
                {ioc.lower() for item in event_items for ioc in item.iocs}
            )

            confidence = max(item.confidence for item in event_items)
            if corroborated:
                # 若被多源互证，给予少量置信度加成，且上限为 1.0
                confidence = min(1.0, confidence + 0.03)

            times = [item.created_at for item in event_items]
            event = ThreatEvent(
                title=(
                    f"跨源关联事件 · {event_items[0].threat_type} · "
                    f"指标: {', '.join(key_indicators[:3])}"
                ),
                key_indicators=key_indicators,
                intel_ids=sorted(cluster),
                sources=sorted(distinct_sources),
                source_count=len(distinct_sources),
                threat_types=sorted({item.threat_type for item in event_items}),
                confidence=round(confidence, 4),
                corroborated=corroborated,
                first_seen=min(times),
                last_seen=max(times),
            )
            events.append(event)
            logger.info(
                f"Correlated event {event.id[:8]}: {len(event.intel_ids)} items, "
                f"{event.source_count} sources, corroborated={corroborated}, "
                f"conf={event.confidence:.2f}"
            )
        return events