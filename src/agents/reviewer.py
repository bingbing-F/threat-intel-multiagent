"""Adversarial collaboration: reviewer agent critiques, coordinator fixes.

This is the core "multi-agent" collaboration loop: after the analyzer produces a
candidate, an independent reviewer (rule-based deterministic checks, plus an
optional real-LLM semantic pass) criticizes it. The coordinator then applies the
fixable feedback and the item is re-reviewed, so we can measure controversy rate
and fix rate - a direct, demoable proxy for a test engineer auditing an AI.
"""
import json
from typing import List, Optional

from src.models.intelligence import ThreatIntelligence
from src.models.review import ReviewIssue, ReviewVerdict
from src.utils.ioc_extractor import IOCExtractor
from src.utils.logger import get_logger

logger = get_logger(__name__)

REVIEW_SYSTEM = (
    "你是一名独立的威胁情报质量评审员。请对分析Agent的提取结果进行批判性检阅，"
    "检查是否存在误报、类型冲突、编造的IoC或置信度失真。"
)

REVIEW_USER_TEMPLATE = """原文：
{raw_text}

分析Agent提取结果（JSON）：
{extraction}

请严格按以下JSON格式输出评审结论，不要输出其他内容：
{{"agree": true, "issues": ["..."]}}  // agree=true表示通过；issues列出发现的问题
"""


class ReviewerAgent:
    """Independent quality reviewer of analyzer outputs."""

    def __init__(self, llm_client=None):
        # Real mode: pass the analyzer's LLM client so a semantic critique runs.
        self.llm = llm_client if self._is_real_llm(llm_client) else None
        self.mode = "rule" if self.llm is None else "rule+llm"

    @staticmethod
    def _is_real_llm(client) -> bool:
        if client is None:
            return False
        # DemoLLM is deterministic and schema-specific; skip semantic pass.
        return "demo" not in type(client).__name__.lower()

    def review(self, intel: ThreatIntelligence, raw_text: str) -> ReviewVerdict:
        """Produce a review verdict for one extraction."""
        issues: List[ReviewIssue] = self._rule_checks(intel, raw_text)

        if self.llm is not None:
            llm_issues = self._llm_semantic_check(intel, raw_text)
            for code, message in llm_issues:
                issues.append(ReviewIssue(code=code, message=message, fixable=False))

        return ReviewVerdict(
            intelligence_id=intel.id,
            version=getattr(intel, "review_version", ""),
            reviewer_mode=self.mode,
            approved=not issues,
            issues=issues,
            rounds=1,
        )

    def _rule_checks(self, intel: ThreatIntelligence, raw_text: str) -> List[ReviewIssue]:
        issues: List[ReviewIssue] = []

        # Issue 1: classified as irrelevant but carries IOCs.
        if intel.threat_type == "其他" and intel.iocs:
            issues.append(
                ReviewIssue(
                    code="TYPE_IRRELEVANT_WITH_IOC",
                    message=f"威胁类型标记为「其他」，但提取到 {len(intel.iocs)} 个 IoC，存在类型冲突",
                    fixable=False,
                )
            )

        # Issue 2: irrelevant content confidence out of calibration.
        if intel.threat_type == "其他" and intel.confidence >= 0.5:
            issues.append(
                ReviewIssue(
                    code="HIGH_CONF_IRRELEVANT",
                    message=f"无关/低相关内容置信度偏高：{intel.confidence:.2f}（应低于 0.4）",
                    fixable=True,
                )
            )

        # Issue 3: a real threat event without any IoC.
        if intel.threat_type != "其他" and not intel.iocs:
            issues.append(
                ReviewIssue(
                    code="MISSING_IOC",
                    message="威胁事件未提取到任何 IoC",
                    fixable=True,
                )
            )

        # Issue 4: fabricated IOCs not present in the source text.
        fabricated = [i for i in intel.iocs if i not in raw_text]
        if fabricated:
            issues.append(
                ReviewIssue(
                    code="FABRICATED_IOC",
                    message=f"检测到 {len(fabricated)} 个原文中不存在的 IoC：{', '.join(fabricated[:3])}",
                    fixable=True,
                )
            )

        return issues

    def _llm_semantic_check(self, intel: ThreatIntelligence, raw_text: str) -> List[tuple]:
        try:
            from src.llm.parser import StructuredParser

            extraction = json.dumps(
                {
                    "title": intel.title,
                    "threat_type": intel.threat_type,
                    "iocs": intel.iocs,
                    "confidence": intel.confidence,
                    "summary": intel.summary,
                },
                ensure_ascii=False,
            )
            user = REVIEW_USER_TEMPLATE.format(raw_text=raw_text, extraction=extraction)
            content = self.llm.invoke(user, REVIEW_SYSTEM)
            data = StructuredParser.extract_json(content)
            if data.get("agree"):
                return []
            issues = data.get("issues", []) or ["LLM 语义复核未通过"]
            return [("LLM_SEMANTIC", str(issue)) for issue in issues[:5]]
        except Exception as e:  # noqa: BLE001 - review must never crash the loop
            logger.error(f"LLM semantic review failed: {e}")
            return []


class CoordinatorAgent:
    """Applies reviewer feedback, revises the extraction, and re-runs review."""

    def __init__(self, reviewer: Optional[ReviewerAgent] = None):
        self.reviewer = reviewer or ReviewerAgent()

    def fix(self, intel: ThreatIntelligence, verdict: ReviewVerdict,
            raw_text: str) -> ThreatIntelligence:
        """Apply fixable review feedback to a copy of the extraction."""
        revised = intel.model_copy(deep=True)
        fixes = 0
        for issue in verdict.issues:
            if issue.code == "MISSING_IOC":
                added = sorted(set(IOCExtractor.extract(raw_text)) - set(revised.iocs))
                if added:
                    revised.iocs = sorted(set(revised.iocs + added))
                    fixes += 1
            elif issue.code == "FABRICATED_IOC":
                before = len(revised.iocs)
                revised.iocs = [i for i in revised.iocs if i in raw_text]
                if len(revised.iocs) != before:
                    fixes += 1
            elif issue.code == "HIGH_CONF_IRRELEVANT":
                revised.confidence = 0.35
                revised.is_valid = False
                fixes += 1
        revised.review_fixes_applied = fixes
        return revised

    def collaborate(self, intel: ThreatIntelligence, raw_text: str,
                    max_rounds: int = 1, version: str = "") -> ThreatIntelligence:
        """Run review -> fix -> re-review; attach review metadata to the item.

        Returns the (possibly revised) item with ``review_*`` attributes the
        workflow can surface and persist.
        """
        verdict = self.reviewer.review(intel, raw_text)
        history = [verdict]
        confidence_before = intel.confidence

        if not verdict.approved:
            revised = self.fix(intel, verdict, raw_text)
            second = self.reviewer.review(revised, raw_text)
            second.rounds = 2
            history.append(second)
            # Prefer the revised version; re-review result decides final quality.
            intel = revised
            verdict = second

        intel.review_approved = verdict.approved
        intel.review_issues = [i.message for i in verdict.issues]
        intel.review_issue_codes = [i.code for i in verdict.issues]
        intel.review_rounds = len(history)
        intel.review_version = version or intel.review_version
        intel.review_mode = verdict.reviewer_mode
        intel.confidence_delta = round(intel.confidence - confidence_before, 4)
        intel.review_history = [
            {
                "approved": v.approved,
                "rounds": v.rounds,
                "issues": [i.code for i in v.issues],
            }
            for v in history
        ]
        return intel