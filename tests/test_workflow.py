"""Tests for the workflow orchestrator."""
from src.agents.analyzer import AnalyzerAgent
from src.agents.collector import CollectorAgent
from src.agents.reporter import ReporterAgent
from src.agents.validator import ValidatorAgent
from src.evaluation.prompt_registry import PromptRegistry
from src.graph.workflow import ThreatIntelWorkflow
from src.models.source import RawContent
from src.sources.base import BaseSource
from src.storage.db import Database


class MockSource(BaseSource):
    def __init__(self, items):
        super().__init__("mock", enabled=True)
        self.items = items

    def fetch(self):
        return self.items


class MockLLM:
    def invoke(self, prompt):
        return """{
            "title": "Satellite data leak",
            "threat_type": "数据泄露",
            "iocs": ["192.0.2.1"],
            "involved_assets": ["卫星系统"],
            "confidence": 0.95,
            "summary": "Test summary"
        }"""


def test_workflow_end_to_end(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    raw_items = [
        RawContent(source_name="mock", content="A satellite data leak with IP 192.0.2.1", content_hash="h1")
    ]
    source = MockSource(raw_items)
    collector = CollectorAgent(sources=[source], db=db)

    registry = PromptRegistry()
    analyzer = AnalyzerAgent(llm_client=MockLLM(), prompt_registry=registry, db=db)
    validator = ValidatorAgent(confidence_threshold=0.9, min_ioc_count=1, required_keywords=[], db=db)
    reporter = ReporterAgent(db=db)

    workflow = ThreatIntelWorkflow(
        db=db,
        collector=collector,
        analyzer=analyzer,
        validator=validator,
        reporter=reporter,
    )
    result = workflow.run(send_alerts=False, generate_report=True)

    assert result.raw_count == 1
    assert result.analyzed_count == 1
    assert result.valid_count == 1
    assert result.invalid_count == 0
