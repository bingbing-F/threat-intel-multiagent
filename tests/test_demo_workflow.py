"""Tests for the zero-cost demo end-to-end pipeline."""
from src.graph.workflow import ThreatIntelWorkflow
from src.llm.demo_client import DemoLLM
from src.llm.parser import StructuredParser
from src.models.intelligence import ExtractedIntelligence
from src.sources.demo_source import DemoSource
from src.storage.db import Database


def test_demo_source_fetch():
    source = DemoSource()
    items = source.fetch()
    assert items
    hashes = [i.content_hash for i in items]
    assert len(set(hashes)) == len(hashes)


def test_demo_llm_returns_parseable_json():
    prompt = "原文：\n某商业卫星通信链路访问权限被出售 IP 198.51.100.32"
    out = DemoLLM().invoke(prompt)
    parsed = StructuredParser.parse(out, ExtractedIntelligence)
    assert parsed.threat_type
    assert "198.51.100.32" in parsed.iocs


def test_demo_workflow_end_to_end(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'demo.db'}"
    db = Database(db_url)
    db.create_tables()

    workflow = ThreatIntelWorkflow(db=db, demo=True)
    result = workflow.run(send_alerts=False, generate_report=True)

    assert result.raw_count > 0
    assert result.analyzed_count > 0
    assert result.valid_count + result.invalid_count == result.analyzed_count
    assert result.valid_items
    # Analyzer persists before validation; validator re-saves the same row.
    assert db.count_intelligence() == result.analyzed_count
    assert db.count_raw_contents() == result.raw_count
    # Adversarial review runs and finds at least the crafted edge-case sample.
    assert result.reviews_persisted == result.analyzed_count
    assert result.review_flagged >= 1
    assert db.count_reviews() == result.analyzed_count
    # Cross-source correlation finds the corroborated CVE event.
    assert result.event_count >= 1
    assert result.corroborated_events >= 1
    assert db.count_events() == result.event_count

    report = workflow.reporter.generate_daily_report(result.valid_items)
    assert "威胁情报日报" in report