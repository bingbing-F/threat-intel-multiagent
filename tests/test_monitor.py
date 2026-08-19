"""Tests for the multi-domain monitoring agent + metric persistence."""
import sqlite3

from src.agents.monitor import DomainMonitorAgent
from src.models.metric import DomainMetric
from src.models.source import RawContent
from src.storage.db import Database

DOMAINS = {
    "ransomware": ["勒索", "赎金"],
    "satellite": ["卫星", "地面站"],
    "iot": ["botnet"],
}


def _raw(source_name, content, tier="clearnet"):
    return RawContent(
        source_name=source_name,
        content=content,
        content_hash=source_name + content,
        metadata={"tier": tier},
    )


def test_scan_groups_items_by_domain_keywords():
    items = [
        _raw("clearnet:vendor-a", "勒索团伙公布受害者名单，涉及赎金", tier="clearnet"),
        _raw("dark:forum", "某市场出售地面站凭据，卫星数据", tier="dark"),
        _raw("dark:market", "真正的botnet 列表转售", tier="dark"),  # noqa: E501
        _raw("clearnet:blog", "普通科普内容，无关"),
    ]
    monitor = DomainMonitorAgent(domains=DOMAINS)
    metrics = monitor.scan(items)

    by_name = {m.domain: m for m in metrics}
    assert set(by_name) == {"ransomware", "satellite", "iot"}
    assert by_name["ransomware"].matched_items == 1
    assert by_name["satellite"].matched_items == 1
    assert by_name["iot"].matched_items == 1
    assert by_name["satellite"].total_sources == 1
    assert by_name["satellite"].dark_sources == 1
    assert by_name["ransomware"].total_sources == 1
    assert by_name["ransomware"].dark_sources == 0


def test_scan_persists_metrics(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    items = [
        _raw("clearnet:feed", "勒索软件事件通报"),
        _raw("dark:market", "地面站凭据出售", tier="dark"),
    ]
    monitor = DomainMonitorAgent(domains=DOMAINS, db=db)
    monitor.scan(items)

    rows = db.latest_domain_metrics()
    assert len(rows) == 2
    domains = {r.domain for r in rows}
    assert domains == {"ransomware", "satellite"}
    for row in rows:
        assert row.matched_items == 1


def test_latest_domain_metrics_dedupes_per_domain(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    monitor = DomainMonitorAgent(domains=DOMAINS, db=db)
    monitor.scan([_raw("a", "勒索事件第二波"), _raw("b", "地面站")])
    monitor.scan([_raw("c", "勒索事件第三波（最新）")])

    rows = db.latest_domain_metrics(limit_per_domain=1)
    by_domain = {r.domain: r for r in rows}
    # Only the latest ransomware row is kept (matched_items == 1).
    assert by_domain["ransomware"].matched_items == 1
    assert by_domain["satellite"].matched_items == 1
    assert db.list_domain_metrics() is not None

    # Sanity: no orphan metric rows / table is readable via sqlite3.
    conn = sqlite3.connect(tmp_path / "test.db")
    count = conn.execute("SELECT COUNT(*) FROM domain_metrics").fetchone()[0]
    conn.close()
    assert count == 3


def test_empty_domains_yields_no_metrics(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'x.db'}")
    db.create_tables()
    monitor = DomainMonitorAgent(domains={}, db=db)
    assert monitor.scan([_raw("a", "勒索")]) == []


def test_domain_metric_model_schema():
    m = DomainMetric(
        domain="satellite",
        matched_items=2,
        total_sources=2,
        dark_sources=1,
        matched_keywords=["卫星", "地面站"],
        sample_summary="样本",
    )
    assert m.id
    assert m.domain == "satellite"
    assert m.matched_items == 2