"""Correlation Agent: aggregate independently-collected items into events.

A single LLM call cannot correlate - this agent links intelligence items that
share normalized indicators (IP / domain / CVE / hash) across *different*
sources, boosts confidence through corroboration, and builds an event timeline.
"""
from collections import defaultdict
from typing import Dict, List

from src.models.event import ThreatEvent
from src.models.intelligence import ThreatIntelligence
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CorrelatorAgent:
    """Group intelligence items sharing indicators into corroborated events."""

    def correlate(self, items: List[ThreatIntelligence]) -> List[ThreatEvent]:
        if not items:
            return []

        meta: Dict[str, ThreatIntelligence] = {item.id: item for item in items}

        # indicator -> set of intelligence ids
        index: Dict[str, set] = defaultdict(set)
        for item in items:
            for ioc in item.iocs:
                index[ioc.lower()].add(item.id)

        # Build a union-find over items sharing at least one indicator.
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

            # corroboration requires at least two distinct sources
            distinct_sources = {item.source for item in event_items}
            corroborated = len(distinct_sources) >= 2

            # indicators that appear in more than one item are "key"
            # (group by lower-case for matching, keep original spelling for display)
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
                # corroboration reward, capped at 1.0
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