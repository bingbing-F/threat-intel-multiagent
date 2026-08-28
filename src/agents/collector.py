"""感知代理：从多个来源收集原始情报内容，并支持并发采集与持久化去重。

此模块负责将配置的 `BaseSource` 列表并发拉取数据，合并结果并可选地
将原始内容保存到数据库。对外暴露的主要接口是 `collect()`，其返回
`RawContent` 列表。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.storage.db import Database
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CollectorAgent:
    """负责从配置来源并发采集原始内容并在需要时持久化到数据库的 Agent。

    参数说明：
    - `sources`: 已配置的来源实例列表，每个来源实现 `BaseSource` 接口。
    - `db`: 用于持久化原始内容与后续检索的数据库对象。
    - `max_workers`: 并发 worker 数量上限，控制对外部来源并发请求的并行度，
      避免同时打开过多网络连接导致资源耗尽或目标封禁。
    """

    def __init__(self, sources: List[BaseSource], db: Database, max_workers: int = 5):
        self.sources = sources
        self.db = db
        self.max_workers = max_workers

    def collect(self, persist: bool = True) -> List[RawContent]:
        """并发从所有启用的来源采集数据并返回原始内容列表。

        实现要点：
        - 通过 `is_enabled()` 过滤掉当前被禁用的来源。
        - 使用 `ThreadPoolExecutor` 并发调用每个来源的 `fetch()` 方法。
        - 捕获每个来源的异常，记录日志但不阻塞其它来源的执行。
        - 可选地将结果持久化到数据库，`save_raw_content` 返回 `True` 表示
          写入成功，返回 `False` 表示被判定为重复并被跳过。
        """
        # 筛选出当前处于启用状态的来源
        enabled = [s for s in self.sources if s.is_enabled()]
        logger.info(f"Starting collection from {len(enabled)} sources")

        results: List[RawContent] = []
        # 当没有启用来源时，len(enabled) 为 0，min(...) 需要传入至少 1
        # 避免 max_workers 为 0 导致 ThreadPoolExecutor 报错
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(enabled) or 1)) as executor:
            # future_to_source 保留 future -> source 的映射，便于定位出错来源
            future_to_source = {executor.submit(s.fetch): s for s in enabled}
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    items = future.result()
                    logger.info(f"Source {source.name} returned {len(items)} items")
                    results.extend(items)
                except Exception as e:
                    # 单个来源失败不应中断整个采集流程，记录后继续
                    logger.error(f"Source {source.name} failed: {e}")

        if persist:
            # 将采集到的原始内容持久化到数据库。
            # `save_raw_content` 负责判重（重复返回 False），并执行写入操作。
            saved = 0
            duplicates = 0
            for item in results:
                if self.db.save_raw_content(item):
                    saved += 1
                else:
                    duplicates += 1
            logger.info(f"Persisted {saved} new raw items, skipped {duplicates} duplicates")

        return results
