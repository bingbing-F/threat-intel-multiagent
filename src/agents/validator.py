"""校验代理：对抽取出的情报进行多维度断言与语义检查。

该模块将一系列规则作为验证链路，对 `ThreatIntelligence` 对象进行
置信度、IOC 数量、关键字匹配及类型语义的校验，并返回 `ValidationResult`。
"""
from typing import List, Optional

from src.config_loader import get_settings
from src.models.intelligence import ThreatIntelligence, ValidationResult
from src.storage.db import Database
from src.utils.ioc_extractor import IOCExtractor
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidatorAgent:
    """使用规则与简单语义检查对抽取情报有效性进行判定的 Agent。

    主要规则（可通过配置覆盖）：
    1) 置信度阈值（confidence_threshold）
    2) 最小有效 IOC 数量（min_ioc_count）
    3) 必要关键词匹配（required_keywords）
    4) 威胁类型需在允许集合内（threat_type 语义校验）

    参数:
    - `confidence_threshold`: 最低置信度（缺省从配置读取）。
    - `min_ioc_count`: 至少需要的有效 IOC 个数（缺省从配置读取）。
    - `required_keywords`: 必须出现的关键字列表（缺省从配置读取）。
    - `db`: 可选的数据库实例，用于在校验后持久化情报状态。
    """

    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        min_ioc_count: Optional[int] = None,
        required_keywords: Optional[List[str]] = None,
        db: Optional[Database] = None,
    ):
        settings = get_settings()
        # 优先使用构造参数，其次从配置中读取默认值
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
        """对单条情报执行校验并更新其状态字段。

        返回更新后的 `ThreatIntelligence`（含 `is_valid`、`validation_reason`、`confidence` 字段）。
        若 `persist` 且提供了 `db`，则会将更新后的情报写回数据库。
        """
        result = self._validate(intel)
        intel.is_valid = result.is_valid
        intel.validation_reason = result.reason
        intel.confidence = result.confidence

        if persist and self.db:
            self.db.save_intelligence(intel)
        return intel

    def validate_batch(self, items: List[ThreatIntelligence], persist: bool = True) -> List[ThreatIntelligence]:
        """对一批情报执行校验并返回更新后的列表（顺序不变）。"""
        return [self.validate(item, persist=persist) for item in items]

    def _validate(self, intel: ThreatIntelligence) -> ValidationResult:
        """内部校验实现：按规则逐条判断，首次失败即返回失败结果，最后汇总通过结果。"""
        matched_rules: List[str] = []

        # 规则 1：置信度门槛
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

        # 规则 2：最小有效 IOC 个数
        valid_iocs = IOCExtractor.filter_valid(intel.iocs)
        if len(valid_iocs) < self.min_ioc_count:
            return ValidationResult(
                is_valid=False,
                confidence=intel.confidence,
                reason=f"Too few valid IOCs ({len(valid_iocs)} < {self.min_ioc_count})",
                matched_rules=["confidence_threshold"],
            )
        matched_rules.append("min_ioc_count")

        # 规则 3：关键字匹配（用于主题/语义过滤）
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

        # 规则 4：威胁类型需在允许集合内（语义合理性校验）
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

        # 所有规则通过：对置信度进行少量奖励以反映规则通过带来的置信度提升
        final_confidence = min(1.0, intel.confidence + 0.02 * len(matched_rules))
        return ValidationResult(
            is_valid=True,
            confidence=final_confidence,
            reason=f"Passed all validation rules: {', '.join(matched_rules)}",
            matched_rules=matched_rules,
        )
