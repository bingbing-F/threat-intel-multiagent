"""通用 JSON API 来源的实现。"""
import hashlib
from typing import Any, Dict, List

import httpx

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)


class APISource(BaseSource):
    """从通用 JSON API 拉取数据并抽取文本字段的来源实现。

    说明：该实现尝试从响应中抽取若干文本字段（`text_fields`）与标题字段，
    将它们合并为一段待分析文本，并使用 SHA-256 哈希进行去重标识。
    对于 API 返回的不同结构，`_extract_items` 尝试常见的列表字段名以定位到条目集合。
    """

    def __init__(
        self,
        name: str,
        url: str,
        params: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        text_fields: List[str] = None,
        title_field: str = "",
        url_field: str = "",
        enabled: bool = True,
        timeout: int = 30,
    ):
        super().__init__(name, enabled)
        self.url = url
        self.params = params or {}
        self.headers = headers or {}
        self.text_fields = text_fields or ["description", "details", "summary"]
        self.title_field = title_field
        self.url_field = url_field
        self.timeout = timeout

    def fetch(self) -> List[RawContent]:
        results: List[RawContent] = []
        try:
            logger.info(f"Fetching API source: {self.name} ({self.url})")
            response = httpx.get(
                self.url, params=self.params, headers=self.headers, timeout=self.timeout, follow_redirects=True
            )
            response.raise_for_status()
            data = response.json()

            items = data if isinstance(data, list) else self._extract_items(data)
            for item in items[:20]:
                if not isinstance(item, dict):
                    continue
                title = self._get_value(item, self.title_field) or ""
                url = self._get_value(item, self.url_field) or ""
                text_parts = [title]
                for field in self.text_fields:
                    value = self._get_value(item, field)
                    if value:
                        text_parts.append(str(value))
                text = "\n\n".join(text_parts).strip()
                if not text:
                    continue
                content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
                results.append(
                    RawContent(
                        source_name=self.name,
                        url=url,
                        title=title,
                        content=text,
                        content_hash=content_hash,
                        metadata={"api_name": self.name},
                    )
                )
            logger.info(f"Fetched {len(results)} items from {self.name}")
        except Exception as e:
            logger.error(f"Failed to fetch API source {self.name}: {e}")
        return results

    def _extract_items(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """尝试从常见的响应字段中定位条目列表（例如 `items`、`data` 等）。"""
        for key in ["vulnerabilities", "items", "data", "results", "advisories", "cves"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]

    def _get_value(self, item: Dict[str, Any], field: str) -> Any:
        if not field:
            return None
        keys = field.split(".")
        value = item
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
