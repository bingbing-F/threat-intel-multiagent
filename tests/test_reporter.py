"""Tests for the reporting agent."""
from src.agents.reporter import ReporterAgent
from src.models.intelligence import ThreatIntelligence


def test_reporter_generates_markdown():
    agent = ReporterAgent()
    items = [
        ThreatIntelligence(
            title="Test Alert",
            threat_type="数据泄露",
            iocs=["192.0.2.1"],
            confidence=0.95,
            source="test",
            raw_text="raw",
            summary="Test summary",
            is_valid=True,
        )
    ]
    report = agent.generate_daily_report(items)
    assert "威胁情报日报" in report
    assert "Test Alert" in report
    assert "192.0.2.1" in report
