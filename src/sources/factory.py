"""从配置构建情报来源的工厂函数。"""
from typing import List

from src.config_loader import get_settings
from src.sources.api_source import APISource
from src.sources.base import BaseSource
from src.sources.dark_web_source import DarkWebSource
from src.sources.local_dataset_source import LocalDatasetSource
from src.sources.rss_source import RSSSource
from src.utils.logger import get_logger

logger = get_logger(__name__)


def build_sources() -> List[BaseSource]:
    """根据配置动态构造并返回启用的 `BaseSource` 实例列表。

    支持的来源类型示例：`rss`、`api`、本地数据集以及（可选的）暗网来源。
    工厂函数会过滤掉未启用的配置项，并对 API 参数进行简单清洗以避免
    传递空值。
    """
    settings = get_settings()
    source_configs = settings.get("sources", [])
    sources: List[BaseSource] = []

    for cfg in source_configs:
        if not cfg.get("enabled", True):
            continue
        source_type = cfg.get("type", "").lower()
        name = cfg["name"]
        url = cfg["url"]

        if source_type == "rss":
            sources.append(RSSSource(name=name, url=url, enabled=True))
        elif source_type == "api":
            params = cfg.get("params", {})
            # 清理空值参数以避免传给上游 API 无意义的空字段
            params = {k: v for k, v in params.items() if v not in (None, "")}
            text_fields = cfg.get("text_fields", ["description", "details", "summary", "title"])
            title_field = cfg.get("title_field", "")
            url_field = cfg.get("url_field", "")
            sources.append(
                APISource(
                    name=name,
                    url=url,
                    params=params,
                    text_fields=text_fields,
                    title_field=title_field,
                    url_field=url_field,
                    enabled=True,
                )
            )

    # 本地种子数据集：在离线或演示场景中用于确保跨域的确定性监控，
    # 行为与 DemoSource 类似但会携带来源层级标签。
    if settings.get("sources.dataset_enabled", True):
        sources.append(LocalDatasetSource())

    # 暗网来源：默认处于禁用状态，只有在配置显式开启时才注入（遵循合规要求）
    dw = settings.get("darkweb", {})
    if settings.get("darkweb.enabled", False):
        proxy = dw.get("proxy", {})
        sources.append(
            DarkWebSource(
                name="darkweb",
                enabled=True,
                whitelist=dw.get("whitelist", []),
                keywords=dw.get("keywords", []),
                proxy_host=proxy.get("host", ""),
                proxy_port=str(proxy.get("port", "") or ""),
                proxy_type=proxy.get("type", "socks5h"),
                max_capture_chars=dw.get("max_capture_chars", 2000),
                max_items=dw.get("max_items", 20),
                timeout=dw.get("timeout", 15),
            )
        )
        logger.warning("DarkWebSource is ENABLED via settings (explicit operator opt-in).")

    return sources
