"""Factory for building sources from configuration."""
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
    """Build all enabled sources from settings."""
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
            # Remove empty values to avoid sending them
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

    # Local seed dataset: enables deterministic offline monitoring across
    # multiple domains (mirrors DemoSource but carries a source-tier label).
    if settings.get("sources.dataset_enabled", True):
        sources.append(LocalDatasetSource())

    # Dark web source: compliance-scoped and disabled by default.
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
