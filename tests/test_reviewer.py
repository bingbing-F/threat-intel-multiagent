"""Tests for the adversarial review collaboration loop."""
from src.agents.reviewer import CoordinatorAgent, ReviewerAgent
from src.models.intelligence import ThreatIntelligence


def make_intel(**overrides):
    base = dict(
        title="测试情报",
        threat_type="数据泄露",
        iocs=["192.0.2.10", "mal.example.com"],
        involved_assets=["遥感卫星"],
        satellite_model="",
        confidence=0.95,
        summary="测试",
        source="test",
        raw_text="某地面站数据泄露，IP 192.0.2.10，域名 mal.example.com",
    )
    base.update(overrides)
    return ThreatIntelligence(**base)


def test_reviewer_approves_clean_extraction():
    intel = make_intel()
    verdict = ReviewerAgent().review(intel, intel.raw_text)
    assert verdict.approved
    assert verdict.issues == []


def test_reviewer_flags_irrelevant_high_confidence():
    # IoC present but classified irrelevant with high confidence.
    intel = make_intel(threat_type="其他", confidence=0.92)
    verdict = ReviewerAgent().review(intel, intel.raw_text)
    codes = verdict.issue_codes
    assert "TYPE_IRRELEVANT_WITH_IOC" in codes
    assert "HIGH_CONF_IRRELEVANT" in codes


def test_coordinator_calibrates_irrelevant_confidence():
    intel = make_intel(threat_type="其他", confidence=0.92)
    coordinator = CoordinatorAgent()
    revised = coordinator.collaborate(intel, intel.raw_text)
    # Fix applied: confidence calibrated, item no longer implied valid.
    assert revised.confidence == 0.35
    assert revised.review_fixes_applied >= 1
    # Type conflict is not auto-fixable -> remains flagged (goes to manual queue).
    assert revised.review_approved is False


def test_coordinator_removes_fabricated_iocs():
    intel = make_intel(iocs=["192.0.2.10", "mal.example.com", "9.9.9.9"])
    coordinator = CoordinatorAgent()
    revised = coordinator.collaborate(intel, intel.raw_text)
    assert "9.9.9.9" not in revised.iocs
    assert revised.review_fixes_applied >= 1


def test_coordinator_backfills_missing_iocs():
    raw = "某卫星任务控制系统遭入侵，关联 CVE-2025-1111 与 IP 192.0.2.77"
    intel = make_intel(iocs=[], raw_text=raw)
    coordinator = CoordinatorAgent()
    revised = coordinator.collaborate(intel, raw)
    assert "CVE-2025-1111" in revised.iocs
    assert "192.0.2.77" in revised.iocs
    assert revised.review_fixes_applied >= 1