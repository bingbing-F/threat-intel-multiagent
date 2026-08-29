"""Tests for the compliance-scoped dark-web source."""
from src.sources.dark_web_source import DarkWebSource


def test_disabled_by_default_returns_empty():
    source = DarkWebSource(name="darkweb", enabled=False, whitelist=["http://x.onion/"])
    assert source.fetch() == []


def test_enabled_without_proxy_fails_closed():
    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=["http://x.onion/"],
        keywords=["勒索"],
        proxy_host="",
        proxy_port="",
    )
    assert source.fetch() == []


def test_enabled_with_empty_whitelist_refuses():
    source = DarkWebSource(
        name="darkweb", enabled=True, whitelist=[], proxy_host="127.0.0.1", proxy_port="9050"
    )
    assert source.fetch() == []


def _mock_transport(page_text: str):
    def _fetch(url: str) -> str:
        return page_text

    return _fetch


def test_fetches_matching_page_via_injected_transport():
    imports_html = " ".join(
        [
            "<html><body><h1>target</h1><p>",
            "某团伙出售地面站凭据，回连 203.0.113.19，涉及勒索赎金。",
            "</p></body></html>",
        ]
    )
    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=["http://forum-alpha-sample.onion/threads/4827"],
        keywords=["凭据", "勒索"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        max_capture_chars=2000,
        transport=_mock_transport(imports_html),
    )
    items = source.fetch()
    assert len(items) == 1
    assert items[0].url == "http://forum-alpha-sample.onion/threads/4827"
    assert items[0].metadata["tier"] == "dark"
    assert items[0].metadata["whitelisted"] is True
    assert "凭据" in items[0].content


def test_filters_page_with_no_matching_keyword():
    page = "<html><body><p>无关的普通内容，不含监测关键词。</p></body></html>"
    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=["http://y.onion/page"],
        keywords=["勒索", "凭据"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        transport=_mock_transport(page),
    )
    assert source.fetch() == []


def test_skips_noise_pages():
    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=["http://z.onion/"],
        keywords=["勒索"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        transport=_mock_transport("<html><p>Enable JavaScript and retry</p></html>"),
    )
    assert source.fetch() == []


def test_transport_failure_logged_and_skipped(caplog):
    def _boom(url: str):
        raise RuntimeError("connection refused (mock)")

    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=["http://a.onion/", "http://b.onion/"],
        keywords=["勒索"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        transport=_boom,
    )
    items = source.fetch()
    assert items == []
    assert any("fetch failed" in r.message for r in caplog.records)


def test_search_engine_parses_results():
    serp = """
    <html><body>
      <a href="http://leakforum.onion/t/9">1.2M leaked credentials from database breach</a>
      <p>Full dump includes emails and hashes for sale.</p>
      <a href="javascript:void(0)">ignore</a>
    </body></html>
    """
    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=[],
        keywords=["leak", "breach", "credential"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        search_engines=[
            {"engine": "http://metager.onion", "path": "/meta.ger3", "param": "eingabe", "query": "leaked credentials"}
        ],
        transport=_mock_transport(serp),
    )
    items = source.fetch()
    assert len(items) == 1
    assert items[0].metadata["via"] == "search"
    assert items[0].metadata["engine"] == "http://metager.onion"
    assert items[0].url == "http://leakforum.onion/t/9"
    assert "leak" in items[0].content.lower()


def test_search_engine_follows_links_when_enabled():
    serp = '<html><body><a href="http://leakforum.onion/t/9">leaked credentials database breach</a><p>short snippet</p></body></html>'
    rich = (
        "<html><body><h1>1.2M leaked credentials</h1>"
        "<p>Emails, password hashes and internal VPN accounts of a telecom leaked for sale. C2: 203.0.113.19</p>"
        "</body></html>"
    )

    def _transport(url: str) -> str:
        return rich if "leakforum.onion" in url else serp

    source = DarkWebSource(
        name="darkweb",
        enabled=True,
        whitelist=[],
        keywords=["leak", "breach", "credential"],
        proxy_host="127.0.0.1",
        proxy_port="9050",
        search_follow_links=True,
        search_follow_max=3,
        search_engines=[
            {"engine": "http://metager.onion", "path": "/meta.ger3", "param": "eingabe", "query": "leaked credentials"}
        ],
        transport=_transport,
    )
    items = source.fetch()
    assert len(items) == 1
    assert items[0].metadata["via"] == "search-follow"
    assert "203.0.113.19" in items[0].content  # richer followed page used, not just snippet
