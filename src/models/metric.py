
"""跨域监控指标的数据模型。"""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class DomainMetric(BaseModel):
    """单次运行中按域名聚合的监控指标。

    用于汇总每个域在一次扫描/监控运行中的匹配情况、来源数量、样本摘要等，
    便于上报与趋势分析。
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    domain: str = Field(..., min_length=1)
    run_at: datetime = Field(default_factory=datetime.utcnow)
    matched_items: int = Field(default=0, ge=0)
    total_sources: int = Field(default=0, ge=0)
    dark_sources: int = Field(default=0, ge=0)
    matched_keywords: List[str] = Field(default_factory=list)
    sample_summary: str = Field(default="")


class MonitorRun(BaseModel):
    """一次跨所有域名的监控扫描摘要。

    包含扫描时间、扫描到的条目数、涉及域列表以及每域的 `DomainMetric`。
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    run_at: datetime = Field(default_factory=datetime.utcnow)
    scanned_items: int = Field(default=0, ge=0)
    domains: List[str] = Field(default_factory=list)
    metrics: List[DomainMetric] = Field(default_factory=list)