"""Tests for the local dataset source (seed monitoring samples)."""
from src.models.source import RawContent
from src.sources.local_dataset_source import LocalDatasetSource

EXPECTED_SAMPLES = 9


def test_loads_default_dataset_with_tiers():
    source = LocalDatasetSource()
    items = source.fetch()
    assert len(items) == EXPECTED_SAMPLES


def test_items_are_typed_raw_content_with_metadata():
    source = LocalDatasetSource()
    for item in source.fetch():
        assert isinstance(item, RawContent)
        assert item.metadata.get("tier") in ("dark", "clearnet")
        assert item.metadata.get("sample") is True
        assert item.content_hash


def test_has_both_dark_and_clearnet_samples():
    source = LocalDatasetSource()
    tiers = {i.metadata.get("tier") for i in source.fetch()}
    assert tiers == {"dark", "clearnet"}


def test_missing_directory_returns_empty(tmp_path):
    source = LocalDatasetSource(directory=str(tmp_path / "nope"))
    assert source.fetch() == []