"""Tests for the analysis agent."""
from src.agents.analyzer import AnalyzerAgent
from src.evaluation.prompt_registry import PromptRegistry
from src.models.source import RawContent
from src.storage.db import Database


def test_analyzer_extracts_structured_intelligence(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    class MockLLM:
        def invoke(self, prompt):
            return """{
                "title": "Test CVE",
                "threat_type": "漏洞利用",
                "iocs": ["192.0.2.1"],
                "involved_assets": ["卫星系统"],
                "confidence": 0.92,
                "summary": "测试摘要"
            }"""

    registry = PromptRegistry()
    agent = AnalyzerAgent(llm_client=MockLLM(), prompt_registry=registry, db=db)
    raw = RawContent(source_name="test", content="A satellite system has CVE-2024-1234 and IP 192.0.2.1", content_hash="h1")
    intel = agent.analyze(raw)

    assert intel is not None
    assert intel.title == "Test CVE"
    assert intel.source == "test"
    assert "192.0.2.1" in intel.iocs
