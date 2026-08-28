"""与跨来源关联威胁事件相关的数据模型。"""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class ThreatEvent(BaseModel):
    """表示一个通过共享指标在多个来源中得到相互印证的威胁事件。

    该模型用于在 Correlator 中将来自不同情报条目的指示器聚类为单个事件，
    并记录相关源、置信度与时间窗口等元数据，便于后续告警与报告。
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(..., min_length=1)
    # 关键指标（如 IP、域名、哈希）用于聚类和显示
    key_indicators: List[str] = Field(default_factory=list)
    # 组成此事件的情报条目 id 列表
    intel_ids: List[str] = Field(default_factory=list)
    # 涉及的来源名称列表
    sources: List[str] = Field(default_factory=list)
    source_count: int = Field(default=0, ge=0)
    threat_types: List[str] = Field(default_factory=list)
    # 置信度（0.0 - 1.0），可由 Correlator/Reviewer 合成或累积计算
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    corroborated: bool = Field(default=False)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)