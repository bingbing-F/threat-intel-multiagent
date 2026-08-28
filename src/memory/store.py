"""记忆模块：为分析 Agent 提供跨运行的 IOC 记忆（短期 + 持久种子）。

设计目标：
- 让 AnalyzerAgent 不再只是「单次抽取」，而是具备「记忆」：能够识别某个 IOC 是否
  在历史事件中出现过（去重、 novelty 判断、跨源印证的前置信号）。
- 记忆来源 = 当前运行内累积的 IOC + 数据库里近期情报的 IOC（持久种子）。
- 完全本地、合规，不依赖任何外部检索服务。
"""
from typing import Iterable, Optional, Set

from src.storage.db import Database


class MemoryStore:
    """轻量级 IOC 记忆库，支持 recall（是否见过）与 remember（写入）。"""

    def __init__(self, db: Optional[Database] = None, max_items: int = 1000):
        self.seen: Set[str] = set()
        self.max_items = max_items
        if db is not None:
            # 用历史情报中的 IOC 作为「长期记忆」种子，使跨运行的去重/ novelty 判断成立。
            try:
                for ioc in db.recent_iocs(limit=max_items):
                    self.seen.add(ioc.lower())
            except Exception:
                # 记忆种子加载失败不应中断主流程，仅退化为空记忆。
                pass

    def recall(self, ioc: str) -> bool:
        """判断某个 IOC 是否曾在记忆中出现过。"""
        return ioc.lower() in self.seen

    def remember(self, iocs: Iterable[str]) -> None:
        """把一批 IOC 写入短期记忆（当前运行内累积）。"""
        for ioc in iocs:
            if ioc:
                self.seen.add(ioc.lower())
        # 简单封顶，避免无限增长。
        if len(self.seen) > self.max_items * 2:
            self.seen = set(list(self.seen)[-self.max_items:])

    def stats(self) -> dict:
        return {"known_iocs": len(self.seen)}
