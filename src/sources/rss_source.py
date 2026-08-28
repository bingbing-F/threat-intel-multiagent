"""RSS/Atom 订阅源实现，使用标准库的 XML 解析。"""
import hashlib
from typing import List
from xml.etree import ElementTree as ET

import httpx

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)


def _strip_html_tags(text: str) -> str:
    """移除简单的 HTML 标签，返回纯文本片段。

    此函数用于将 RSS/Atom 条目中的 HTML 内容简化为可索引的纯文本。
    """
    result = []
    in_tag = False
    for ch in text:
        if ch == "<":
            in_tag = True
        elif ch == ">":
            in_tag = False
        elif not in_tag:
            result.append(ch)
    return "".join(result)


class RSSSource(BaseSource):
    """从 RSS 或 Atom 订阅源拉取文章并构造成 `RawContent` 列表。"""

    def __init__(self, name: str, url: str, enabled: bool = True, timeout: int = 30):
        super().__init__(name, enabled)
        self.url = url
        self.timeout = timeout

    def fetch(self) -> List[RawContent]:
        results: List[RawContent] = []
        try:
            logger.info(f"Fetching RSS source: {self.name} ({self.url})")
            response = httpx.get(self.url, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
            root = ET.fromstring(response.content)

            # 判别 RSS 与 Atom：RSS 在根下通常包含 <channel> 节点，Atom 则使用命名空间和 <entry>
            channel = root.find("channel")
            if channel is not None:
                items = channel.findall("item")
                feed_title_elem = channel.find("title")
            else:
                # Atom feed
                ns = {"atom": "http://www.w3.org/2005/Atom"}
                items = root.findall("atom:entry", ns) or root.findall("entry")
                feed_title_elem = root.find("atom:title", ns) or root.find("title")

            feed_title = feed_title_elem.text if feed_title_elem is not None else ""

            for item in items[:20]:
                title = self._get_text(item, "title")
                link = self._get_text(item, "link") or self._get_attr(item, "link", "href")
                description = self._get_text(item, "description") or self._get_text(item, "summary") or ""
                content = self._get_text(item, "content:encoded") or self._get_text(item, "content") or ""

                text = f"{title}\n\n{_strip_html_tags(content or description)}".strip()
                if not text:
                    continue
                content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
                results.append(
                    RawContent(
                        source_name=self.name,
                        url=link,
                        title=title,
                        content=text,
                        content_hash=content_hash,
                        metadata={"feed_title": feed_title},
                    )
                )
            logger.info(f"Fetched {len(results)} items from {self.name}")
        except Exception as e:
            logger.error(f"Failed to fetch RSS source {self.name}: {e}")
        return results

    def _get_text(self, item: ET.Element, tag: str) -> str:
        """从元素中读取子标签的文本并去除首尾空白（若不存在返回空串）。"""
        elem = item.find(tag)
        if elem is not None and elem.text:
            return elem.text.strip()
        return ""

    def _get_attr(self, item: ET.Element, tag: str, attr: str) -> str:
        """读取子元素的属性值（如 Atom 的 link/@href），不存在则返回空串。"""
        elem = item.find(tag)
        if elem is not None:
            return elem.get(attr, "")
        return ""
