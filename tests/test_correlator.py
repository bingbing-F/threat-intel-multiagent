"""Tests for the cross-source correlation agent."""
from src.agents.correlator import CorrelatorAgent
from src.models.intelligence import ThreatIntelligence


def make_item(source, iocs, threat_type="漏洞利用", confidence=0.9, title="t"):
    return ThreatIntelligence(
        title=title, threat_type=threat_type, iocs=iocs,
        involved_assets=[], satellite_model="", confidence=confidence,
        summary="", source=source, raw_text="x",
    )


def test_correlates_shared_indicator_across_sources():
    items = [
        make_item("vendorA", ["CVE-2025-6601", "192.0.2.99"]),
        make_item("vendorB", ["192.0.2.99", "CVE-2025-6601"]),
    ]
    events = CorrelatorAgent().correlate(items)
    assert len(events) == 1
    event = events[0]
    assert event.corroborated
    assert event.source_count == 2
    assert "CVE-2025-6601" in event.key_indicators
    assert event.confidence > max(i.confidence for i in items)


def test_no_event_without_shared_indicators():
    items = [
        make_item("vendorA", ["198.51.100.1"]),
        make_item("vendorB", ["198.51.100.2"]),
    ]
    assert CorrelatorAgent().correlate(items) == []


def test_same_source_not_corroborated():
    # Two items sharing an IoC but from the SAME source still group into an
    # event, but must not be flagged as corroborated (no independent evidence).
    items = [
        make_item("vendorA", ["CVE-2025-6601"]),
        make_item("vendorA", ["CVE-2025-6601", "192.0.2.99"]),
    ]
    events = CorrelatorAgent().correlate(items)
    assert len(events) == 1
    assert events[0].corroborated is False