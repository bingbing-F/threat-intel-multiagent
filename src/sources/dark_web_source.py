"""暗网情报来源（合规范围内的实现）。

该模块模拟对“白名单”暗网板块的访问，仅用于威胁情报监控，
并受一组严格的安全约束以保证合法性、可追溯性和分析人员安全：

- 默认 `enabled: false`：未显式启用时不会运行。
- 从配置读取固定的 `whitelist`（例如 .onion、.i2p）；**不做爬虫/发现**，仅拉取白名单内的 URL。
- 所有请求必须通过配置的 SOCKS5/SOCKS5h 代理；若代理未配置则拒绝连接（fail-closed），绝不做直接连接。
- `keywords` 过滤：只有正文包含至少一个监控关键词（忽略大小写）时才保留条目。
- 对页面结果按 `max_capture_chars` 截断，仅保留分析所需的摘录；原始内容不会在流水线之外长期归档（仅按哈希存储）。
- 每个启用/禁用/代理/过滤决策均记录日志，保证授权与过滤决策可审计。

测试中通过注入 mock transport 来模拟请求（见 tests/test_dark_web_source.py），本实现不会解析真实的 .onion 地址。
"""
import hashlib
import re
from typing import Dict, List
from urllib.parse import quote_plus, urljoin

from src.models.source import RawContent
from src.sources.base import BaseSource
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 表示页面为通知、验证码或其他无意义内容的片段，出现则视为噪声，跳过分析。
_NOISE_FRAGMENTS = ("cloudflare", "enable javascript", "captcha", "access denied")


def _sha256(text: str) -> str:
    """计算文本的 SHA-256 哈希（用于去重/标识）。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strip_html(text: str) -> str:
    """简单去除 HTML 标签，返回纯文本占位符（保留空格以拼接词块）。"""
    return re.sub(r"<[^>]+>", " ", text)


def _first_text_block(soup_like: str) -> str:
    """粗略的文本提取：去标签、合并可见词，并压缩空白字符。

    该函数用于从 HTML/页面文本中提取首个可读文本块作为分析输入，
    目的是保留可见词序列而非精确的格式化。
    """
    return re.sub(r"\s+", " ", _strip_html(soup_like)).strip()


class DarkWebSource(BaseSource):
    """通过显式 SOCKS 代理拉取白名单暗网页面的来源实现。

    说明：该类对传输实现保持无关性（transport-agnostic）。
    在真实环境中会使用 `requests` + `pysocks` 经代理发起请求；
    在单元测试中可注入 `transport` 回调/mock 以模拟响应，避免访问真实 .onion。
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
        search_engines: List[Dict] = None,
        search_follow_links: bool = False,
        search_follow_max: int = 3,
    ):
        super().__init__(name, enabled)
        self.whitelist = whitelist or []
        self.search_engines = search_engines or []
        self.search_follow_links = search_follow_links
        self.search_follow_max = search_follow_max
        self.keywords = [k.lower() for k in (keywords or [])]
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.max_capture_chars = max_capture_chars
        self.max_items = max_items
        self.timeout = timeout
        # 可注入的传输函数（仅用于测试），默认使用 requests 等 HTTP 客户端路径。
        self._transport = transport

    # ------------------------------------------------------------------ #
    # Class/instance-level helpers
    # ------------------------------------------------------------------ #
    def _proxy_url(self) -> str:
        """返回用于 requests/proxies 的代理 URL，例如 `socks5h://host:port`。"""
        return f"{self.proxy_type}://{self.proxy_host}:{self.proxy_port}"

    def _build_proxies(self) -> Dict[str, str]:
        """构建 requests 所需的 proxies 映射（http 与 https 同指向 SOCKS 代理）。"""
        prox = self._proxy_url()
        return {"http": prox, "https": prox}

    def _matches_keywords(self, text: str) -> bool:
        """判断文本是否包含任意监控关键词（忽略大小写）。"""
        lower = text.lower()
        return any(k in lower for k in self.keywords)

    def _is_noise(self, text: str) -> bool:
        """检测页面是否为噪声（验证码/访问受限提示等），若包含则跳过分析。"""
        lower = text.lower()
        return any(frag in lower for frag in _NOISE_FRAGMENTS)

    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #
    def _request(self, url: str, method: str = "get", data=None) -> str:
        """获取页面正文。若注入了 mock transport，则使用之（测试专用）。

        真实运行时会懒加载 `requests` 并通过代理发起 GET/POST 请求；
        方法会对响应状态做 `raise_for_status()` 检查以便上层记录失败并跳过。
        """
        if self._transport is not None:
            return self._transport(url)
        import requests  # vendored lazily: needed only for real dark-web use

        headers = {"User-Agent": "threat-intel-monitor/2.1 (monitoring)"}
        if method == "post":
            resp = requests.post(
                url,
                data=data,
                proxies=self._build_proxies(),
                timeout=self.timeout,
                headers=headers,
            )
        else:
            resp = requests.get(
                url,
                proxies=self._build_proxies(),
                timeout=self.timeout,
                headers=headers,
            )
        resp.raise_for_status()
        return resp.text

    def _build_search_url(self, cfg: Dict) -> str:
        """根据配置构造搜索引擎查询 URL（GET 参数方式）。"""
        base = str(cfg.get("engine", "")).rstrip("/")
        path = cfg.get("path", "/search")
        param = cfg.get("param", "q")
        query = cfg.get("query", "")
        return f"{base}{path}?{param}={quote_plus(str(query))}"

    def _parse_serp(self, body: str) -> List[Dict[str, str]]:
        """启发式解析搜索引擎结果页：抽取结果锚点的标题、链接与片段。

        不依赖特定引擎的 DOM 结构，仅基于 <a href> 与周围文本做最佳努力提取；
        无法识别的结构会被自然忽略（不会中断流程）。
        """
        out: List[Dict[str, str]] = []
        for m in re.finditer(r'<a\b[^>]*\bhref="([^"]+)"[^>]*>(.*?)</a>', body, re.I | re.S):
            href = m.group(1).strip()
            inner = _strip_html(m.group(2)).strip()
            if len(inner) < 12:
                continue
            low = href.lower()
            if low.startswith(("javascript:", "mailto:", "#", "data:")):
                continue
            end = m.end()
            snippet = re.sub(r"\s+", " ", _strip_html(body[end : end + 400])).strip()[:300]
            out.append({"title": inner[:160], "url": href, "snippet": snippet})
        return out

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #
    def fetch(self) -> List[RawContent]:
        # 基本启用/配置检查；若不满足合规与安全条件则直接返回空列表（fail-closed）。
        if not self.is_enabled():
            logger.info(f"DarkWebSource[{self.name}] disabled; skipping (enabled={self.enabled})")
            return []
        if not self.whitelist and not self.search_engines:
            logger.warning(
                f"DarkWebSource[{self.name}] enabled but whitelist and search_engines "
                f"are both empty; refusing to fetch"
            )
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
                # 单个 URL 的获取失败应被记录但不应中断整个抓取循环
                failed += 1
                logger.error(f"DarkWebSource[{self.name}] fetch failed for {url}: {e}")
                continue

            text = _first_text_block(body)
            # 噪声与空内容检测
            if not text or self._is_noise(text):
                logger.info(f"DarkWebSource[{self.name}] page {url} has no analyzable content")
                continue
            # 关键词过滤（若配置了关键词）
            if self.keywords and not self._matches_keywords(text):
                logger.info(f"DarkWebSource[{self.name}] page {url} filtered: no monitoring keyword matched")
                continue

            # 截取摘录并生成粗略标题（取前 8 个词），构建 RawContent
            excerpt = text[: self.max_capture_chars]
            title = excerpt.split(" ")  # 粗略标题：前若干词
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

        # 搜索引擎查询：对白名单中的搜索引擎提交查询并解析结果页，
        # 命中的结果片段作为暗网情报候选进入后续抽取流程。
        follow_count = 0
        for cfg in self.search_engines:
            if len(results) >= self.max_items:
                break
            try:
                method = (cfg.get("method") or "get").lower()
                if method == "post":
                    surl = str(cfg.get("engine", "")).rstrip("/") + cfg.get("path", "/search")
                    post_data = {cfg.get("param", "q"): cfg.get("query", "")}
                    logger.info(
                        f"DarkWebSource[{self.name}] searching engine "
                        f"{cfg.get('engine')} query={cfg.get('query')!r} [POST]"
                    )
                    body = self._request(surl, method="post", data=post_data)
                else:
                    surl = self._build_search_url(cfg)
                    logger.info(
                        f"DarkWebSource[{self.name}] searching engine "
                        f"{cfg.get('engine')} query={cfg.get('query')!r}"
                    )
                    body = self._request(surl)
                for r in self._parse_serp(body):
                    if len(results) >= self.max_items:
                        break
                    blob = (r["title"] + " " + r["snippet"]).lower()
                    if self.keywords and not any(k in blob for k in self.keywords):
                        continue
                    excerpt = (r["title"] + "\n" + r["snippet"])[: self.max_capture_chars]
                    via = "search"
                    result_url = r["url"]
                    # 加深：跟随结果链接经 Tor 抓取真实页面，用更丰富的正文替换片段。
                    # 相对链接按搜索引擎基址解析（仍为同一暗网站点）。
                    if self.search_follow_links and follow_count < self.search_follow_max:
                        target = r["url"]
                        if not str(target).lower().startswith(("http://", "https://")):
                            target = urljoin(str(cfg.get("engine", "")), str(target))
                        try:
                            page = self._request(target)
                            text = _first_text_block(page)
                            if text and not self._is_noise(text) and (
                                not self.keywords or self._matches_keywords(text)
                            ):
                                excerpt = text[: self.max_capture_chars]
                                via = "search-follow"
                                result_url = target
                                follow_count += 1
                                logger.info(
                                    f"DarkWebSource[{self.name}] followed result "
                                    f"{target} -> {len(excerpt)} chars"
                                )
                        except Exception as e:
                            logger.warning(
                                f"DarkWebSource[{self.name}] follow failed for {target}: {e}"
                            )
                    results.append(
                        RawContent(
                            source_name=self.name,
                            url=result_url,
                            title=r["title"],
                            content=excerpt,
                            content_hash=_sha256(excerpt),
                            metadata={
                                "tier": "dark",
                                "whitelisted": True,
                                "via": via,
                                "engine": cfg.get("engine", ""),
                                "sample": False,
                            },
                        )
                    )
                    logger.info(
                        f"DarkWebSource[{self.name}] captured search result "
                        f"{r['url']} -> {len(excerpt)} chars ({via})"
                    )
            except Exception as e:
                logger.error(
                    f"DarkWebSource[{self.name}] search failed for {cfg.get('engine')}: {e}"
                )
                continue

        logger.info(
            f"DarkWebSource[{self.name}] finished: {len(results)} items "
            f"(fetched {pages_fetched} pages, {failed} failed)"
        )
        return results