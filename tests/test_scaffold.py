"""Sanity tests for the project scaffold."""
from src.config_loader import get_settings
from src.models.intelligence import ThreatIntelligence
from src.models.source import RawContent
from src.storage.db import Database, init_db


def test_settings_load():
    settings = get_settings()
    assert settings.get("app.name")
    assert settings.get("llm.provider") == "openai"


def test_models():
    raw = RawContent(source_name="test", content="hello", content_hash="abc123")
    assert raw.source_name == "test"
    intel = ThreatIntelligence(
        title="Test",
        threat_type="漏洞利用",
        confidence=0.92,
        source="test",
        raw_text="raw",
    )
    assert intel.is_valid is False
    assert intel.confidence == 0.92


def test_database(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    db = Database(db_url)
    db.create_tables()
    raw = RawContent(source_name="test", content="hello", content_hash="abc123")
    assert db.save_raw_content(raw) is True
    assert db.save_raw_content(raw) is False  # duplicate
