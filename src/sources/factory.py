"""Factory for building sources from configuration."""
from typing import List

from src.config_loader import get_settings
from src.sources.api_source import APISource
from src.sources.base import BaseSource
from src.sources.rss_source import RSSSource


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

    return sources
