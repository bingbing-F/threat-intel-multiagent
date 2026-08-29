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


def test_analyzer_retries_on_malformed_json(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    class RetryMockLLM:
        def __init__(self):
            self.calls = 0

        def invoke(self, prompt):
            self.calls += 1
            if self.calls == 1:
                # 第一次返回散文 + 非法 JSON（触发解析失败重试）
                return "IOC 未发现，仅记录历史暗网市场名称。未返回结构化 JSON。\n\n```json\n{ this is not valid"
            return """{
                "title": "Retry OK",
                "threat_type": "数据泄露",
                "iocs": ["198.51.100.7"],
                "involved_assets": [],
                "confidence": 0.8,
                "summary": "retry success"
            }"""

    llm = RetryMockLLM()
    agent = AnalyzerAgent(llm_client=llm, prompt_registry=PromptRegistry(), db=db)
    raw = RawContent(source_name="test", content="leaked credentials database", content_hash="h2")
    intel = agent.analyze(raw)

    assert intel is not None
    assert intel.title == "Retry OK"
    assert "198.51.100.7" in intel.iocs
    assert llm.calls == 2  # 首次失败 -> 严格约束重试一次


def test_analyzer_returns_none_when_retry_also_fails(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    class AlwaysBadLLM:
        def __init__(self):
            self.calls = 0

        def invoke(self, prompt):
            self.calls += 1
            return "no json at all, just prose"

    llm = AlwaysBadLLM()
    agent = AnalyzerAgent(llm_client=llm, prompt_registry=PromptRegistry(), db=db)
    raw = RawContent(source_name="test", content="leaked credentials", content_hash="h3")
    intel = agent.analyze(raw)

    assert intel is None
    assert llm.calls == 2  # 解析失败重试一次后仍失败

