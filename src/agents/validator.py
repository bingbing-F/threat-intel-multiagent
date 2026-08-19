"""Validation Agent: multi-dimensional assertion on extracted intelligence."""
from typing import List, Optional

from src.config_loader import get_settings
from src.models.intelligence import ThreatIntelligence, ValidationResult
from src.storage.db import Database
from src.utils.ioc_extractor import IOCExtractor
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidatorAgent:
    """Agent that validates extracted intelligence using rules and semantic checks."""

    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        min_ioc_count: Optional[int] = None,
        required_keywords: Optional[List[str]] = None,
        db: Optional[Database] = None,
    ):
        settings = get_settings()
        self.confidence_threshold = confidence_threshold if confidence_threshold is not None else float(
            settings.get("validation.confidence_threshold", 0.9)
        )
        self.min_ioc_count = min_ioc_count if min_ioc_count is not None else int(
            settings.get("validation.min_ioc_count", 1)
        )
        self.required_keywords = required_keywords if required_keywords is not None else list(
            settings.get("validation.required_keywords", [])
        )
        self.db = db

    def validate(self, intel: ThreatIntelligence, persist: bool = True) -> ThreatIntelligence:
        """Validate a single intelligence item and update its status."""
        result = self._validate(intel)
        intel.is_valid = result.is_valid
        intel.validation_reason = result.reason
        intel.confidence = result.confidence

        if persist and self.db:
            self.db.save_intelligence(intel)
        return intel

    def validate_batch(self, items: List[ThreatIntelligence], persist: bool = True) -> List[ThreatIntelligence]:
        """Validate a batch of intelligence items."""
        return [self.validate(item, persist=persist) for item in items]

    def _validate(self, intel: ThreatIntelligence) -> ValidationResult:
        matched_rules: List[str] = []

        # Rule 1: Confidence threshold
        if intel.confidence < self.confidence_threshold:
            return ValidationResult(
                is_valid=False,
                confidence=intel.confidence,
                reason=(
                    f"Confidence {intel.confidence:.2f} below threshold "
                    f"{self.confidence_threshold:.2f}"
                ),
                matched_rules=[],
            )
        matched_rules.append("confidence_threshold")

        # Rule 2: Minimum IOC count
        valid_iocs = IOCExtractor.filter_valid(intel.iocs)
        if len(valid_iocs) < self.min_ioc_count:
            return ValidationResult(
                is_valid=False,
                confidence=intel.confidence,
                reason=f"Too few valid IOCs ({len(valid_iocs)} < {self.min_ioc_count})",
                matched_rules=["confidence_threshold"],
            )
        matched_rules.append("min_ioc_count")

        # Rule 3: Keyword matching
        text = f"{intel.title} {intel.summary} {intel.raw_text}".lower()
        matched_keywords = [kw for kw in self.required_keywords if kw.lower() in text]
        if self.required_keywords and not matched_keywords:
            return ValidationResult(
                is_valid=False,
                confidence=intel.confidence,
                reason="No required keywords matched",
                matched_rules=matched_rules,
            )
        if matched_keywords:
            matched_rules.append("keyword_match")

        # Rule 4: Threat type must be from allowed set (semantic sanity)
        allowed_types = {
            "数据泄露", "漏洞利用", "漏洞", "恶意软件", "APT攻击", "拒绝服务",
            "供应链攻击", "钓鱼攻击", "内部威胁", "其他",
        }
        if intel.threat_type not in allowed_types:
            return ValidationResult(
                is_valid=False,
                confidence=intel.confidence,
                reason=f"Unknown threat type: {intel.threat_type}",
                matched_rules=matched_rules,
            )
        matched_rules.append("threat_type_valid")

        # All rules passed
        final_confidence = min(1.0, intel.confidence + 0.02 * len(matched_rules))
        return ValidationResult(
            is_valid=True,
            confidence=final_confidence,
            reason=f"Passed all validation rules: {', '.join(matched_rules)}",
            matched_rules=matched_rules,
        )
