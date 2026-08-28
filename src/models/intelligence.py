"""结构化威胁情报的数据模型。

包含由 LLM 或规则抽取出的字段（`ExtractedIntelligence`），以及运行时
元数据（`ThreatIntelligence`）和校验结果结构（`ValidationResult`）。
这些模型作为系统内各 Agent 之间传递的标准数据契约。
"""
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ExtractedIntelligence(BaseModel):
    """由 LLM 从原文中提取出的结构化字段。

    字段包括标题、威胁类型、IoC 列表、涉及资产、卫星/机型信息、置信度与摘要。
    """

    title: str = Field(..., min_length=1, max_length=200)
    threat_type: str = Field(..., min_length=1, max_length=50)
    iocs: List[str] = Field(default_factory=list)
    involved_assets: List[str] = Field(default_factory=list)
    satellite_model: Optional[str] = Field(default="", max_length=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(default="", max_length=500)

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        # 将置信度统一四位小数以便后续比较与展示一致
        return round(v, 4)


class ThreatIntelligence(ExtractedIntelligence):
    """带运行时元数据的结构化威胁情报对象。

    在 `ExtractedIntelligence` 的基础上增加了标识、来源信息、原文、
    时间戳、验证与对抗式评审元数据，便于在工作流各阶段记录与追溯。
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = Field(default="", min_length=0)
    raw_text: str = Field(default="", min_length=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_valid: bool = Field(default=False)
    validation_reason: str = Field(default="")
    source_url: Optional[str] = None

    # 对抗式审查相关元数据（由审查协作环路填写）
    review_approved: Optional[bool] = None
    review_issues: List[str] = Field(default_factory=list)
    review_issue_codes: List[str] = Field(default_factory=list)
    review_rounds: int = Field(default=0, ge=0)
    review_version: str = Field(default="")
    review_mode: str = Field(default="")
    confidence_delta: float = Field(default=0.0)
    review_fixes_applied: int = Field(default=0, ge=0)
    review_history: List[dict] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ValidationResult(BaseModel):
    """校验器返回的结果结构，包含是否通过、调整后置信度、原因与匹配规则。"""

    is_valid: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    matched_rules: List[str] = Field(default_factory=list)
