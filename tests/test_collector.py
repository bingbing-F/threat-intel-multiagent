"""Tests for the perception/collector agent."""
from unittest.mock import MagicMock

from src.agents.collector import CollectorAgent
from src.models.source import RawContent
from src.sources.base import BaseSource
from src.storage.db import Database


class MockSource(BaseSource):
    def __init__(self, name: str, items):
        super().__init__(name, enabled=True)
        self.items = items

    def fetch(self):
        return self.items


def test_collector_persists_new_items(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    items = [
        RawContent(source_name="mock", content="test 1", content_hash="a"),
        RawContent(source_name="mock", content="test 2", content_hash="b"),
    ]
    source = MockSource("mock", items)
    agent = CollectorAgent(sources=[source], db=db)
    result = agent.collect(persist=True)

    assert len(result) == 2
    assert db.count_raw_contents() == 2


def test_collector_skips_duplicates(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()

    items = [
        RawContent(source_name="mock", content="test 1", content_hash="same"),
        RawContent(source_name="mock", content="test 2", content_hash="same"),
    ]
    source = MockSource("mock", items)
    agent = CollectorAgent(sources=[source], db=db)
    result = agent.collect(persist=True)

    assert len(result) == 2
    assert db.count_raw_contents() == 1
