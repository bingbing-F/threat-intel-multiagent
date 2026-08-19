"""Dark-web intelligence source (compliance-scoped).

This source models access to *whitelisted* dark-web boards used purely for
threat-intelligence monitoring. It is bounded by hard safety constraints
aimed at legality, attribution and analyst safety:

- ``enabled: false`` by default: it never runs unless explicitly enabled.
- A fixed ``whitelist`` of known URLs (``.onion``, ``.i2p``) from settings;
  the source performs NO crawling/discovery, only fetches those URLs.
- All traffic goes through an explicit SOCKS5/SOCKS5h proxy from settings;
  requests fail closed if the proxy is missing (never a direct connection).
- ``keywords`` filter: an item is kept only if the body matches at least one
  of the configured monitoring keywords (uppercase/lowercase normalized).
- Result pages are truncated (``max_capture_chars``) to keep only the body
  excerpt needed for analysis; raw content is never archived beyond the
  pipeline's normal hashed storage.
- Full ``logger`` coverage on every enabled/disabled/proxy/filter decision so
  the authorization + filtering decision is always auditable.

The fetch path itself is exercised by ``tests/test_dark_web_source.py`` with a
mock transport; it never resolves a real .onion address.
"""
import hashlib
import re
from typing import Dict, List

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Notices/captchas/etc. that mean 'nothing meaningful to analyze'.
_NOISE_FRAGMENTS = ("cloudflare", "enable javascript", "captcha", "access denied")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def _first_text_block(soup_like: str) -> str:
    """Crude text extraction: join visible words, collapse whitespace."""
    return re.sub(r"\s+", " ", _strip_html(soup_like)).strip()


class DarkWebSource(BaseSource):
    """Fetches whitelisted dark-web pages through an explicit SOCKS proxy.

    The class is transport-agnostic: if ``requests`` + ``pysocks`` are
    available it uses ``requests.get(..., proxies={"https": proxy_url})``;
    a *mock transport* (or a raw socket client) can be injected in tests.
    """

    def __init__(
        self,
        name: str = "darkweb",
        enabled: bool = False,
        whitelist: List[str] = None,
        keywords: List[str] = None,
        proxy_host: str = "",
        proxy_port: str = "",
        proxy_type: str = "socks5h",
        max_capture_chars: int = 2000,
        max_items: int = 20,
        timeout: int = 15,
        transport=None,
    ):
        super().__init__(name, enabled)
        self.whitelist = whitelist or []
        self.keywords = [k.lower() for k in (keywords or [])]
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.max_capture_chars = max_capture_chars
        self.max_items = max_items
        self.timeout = timeout
        # Injectable transport for tests (defaults to requests+httpx-free path).
        self._transport = transport

    # ------------------------------------------------------------------ #
    # Class/instance-level helpers
    # ------------------------------------------------------------------ #
    def _proxy_url(self) -> str:
        return f"{self.proxy_type}://{self.proxy_host}:{self.proxy_port}"

    def _build_proxies(self) -> Dict[str, str]:
        prox = self._proxy_url()
        return {"http": prox, "https": prox}

    def _matches_keywords(self, text: str) -> bool:
        lower = text.lower()
        return any(k in lower for k in self.keywords)

    def _is_noise(self, text: str) -> bool:
        lower = text.lower()
        return any(frag in lower for frag in _NOISE_FRAGMENTS)

    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #
    def _request(self, url: str) -> str:
        """Fetch a page body. Uses the injected mock transport when present."""
        if self._transport is not None:
            return self._transport(url)
        import requests  # vendored lazily: needed only for real dark-web use

        resp = requests.get(
            url,
            proxies=self._build_proxies(),
            timeout=self.timeout,
            headers={"User-Agent": "threat-intel-monitor/2.1 (monitoring)"},
        )
        resp.raise_for_status()
        return resp.text

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #
    def fetch(self) -> List[RawContent]:
        if not self.is_enabled():
            logger.info(f"DarkWebSource[{self.name}] disabled; skipping (enabled={self.enabled})")
            return []
        if not self.whitelist:
            logger.warning(f"DarkWebSource[{self.name}] enabled but whitelist is empty; refusing to fetch")
            return []
        if not (self.proxy_host and self.proxy_port):
            logger.warning(
                f"DarkWebSource[{self.name}] enabled but SOCKS proxy not configured; "
                f"refusing to fetch (fail-closed, no direct connection)"
            )
            return []

        results: List[RawContent] = []
        pages_fetched = 0
        failed = 0
        for url in self.whitelist:
            if len(results) >= self.max_items:
                break
            try:
                logger.info(f"DarkWebSource[{self.name}] fetching whitelisted URL: {url}")
                body = self._request(url)
                pages_fetched += 1
            except Exception as e:
                failed += 1
                logger.error(f"DarkWebSource[{self.name}] fetch failed for {url}: {e}")
                continue

            text = _first_text_block(body)
            if not text or self._is_noise(text):
                logger.info(f"DarkWebSource[{self.name}] page {url} has no analyzable content")
                continue
            if self.keywords and not self._matches_keywords(text):
                logger.info(f"DarkWebSource[{self.name}] page {url} filtered: no monitoring keyword matched")
                continue

            excerpt = text[: self.max_capture_chars]
            title = excerpt.split(" ")  # rough title: first 8 words
            title_text = " ".join(title[:8])
            results.append(
                RawContent(
                    source_name=self.name,
                    url=url,
                    title=title_text,
                    content=excerpt,
                    content_hash=_sha256(excerpt),
                    metadata={
                        "tier": "dark",
                        "whitelisted": True,
                        "proxy": self._proxy_url(),
                        "sample": False,
                    },
                )
            )
            logger.info(
                f"DarkWebSource[{self.name}] captured {url} -> "
                f"{len(excerpt)} chars (matched monitoring keyword)"
            )

        logger.info(
            f"DarkWebSource[{self.name}] finished: {len(results)} items "
            f"(fetched {pages_fetched} pages, {failed} failed)"
        )
        return results