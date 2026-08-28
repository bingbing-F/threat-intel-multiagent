"""情报来源抽象基类。

定义了所有数据源（如爬虫、API 拉取、文件读取等）应遵循的接口契约：
必须实现 `fetch()` 方法返回 `RawContent` 列表，并支持通过 `is_enabled()`
控制是否启用该来源。
"""
from abc import ABC, abstractmethod
from typing import List

from src.models.source import RawContent


class BaseSource(ABC):
    """所有 OSINT/情报来源的基类。

    子类需实现 `fetch()` 执行实际的数据抓取逻辑，并返回 `RawContent` 列表。
    `enabled` 标志用于运行时开关来源，便于在配置或测试中临时关闭某些来源。
    """

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def fetch(self) -> List[RawContent]:
        """从该来源拉取原始内容并返回 `RawContent` 列表。

        注意：实现应尽量保证对外部错误的容错（例如网络失败），
        并将每条采集到的记录包装为 `RawContent` 实例。
        """
        raise NotImplementedError

    def is_enabled(self) -> bool:
        """返回来源是否处于启用状态（可被采集器过滤）。"""
        return self.enabled
