"""用于提示（prompt）A/B 评估的数据模型。"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class PromptVersion(BaseModel):
    """登记的提示模板版本信息。

    `version` 使用诸如 `v1.0` 的版本串以便在评估中区分不同提示变体。
    """

    version: str = Field(..., pattern=r"^v\d+\.\d+$")
    name: str
    description: str
    file_path: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EvaluationMetrics(BaseModel):
    """单个提示版本在基准测试上的评价指标。"""

    accuracy: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1: float = Field(..., ge=0.0, le=1.0)
    avg_confidence: float = Field(..., ge=0.0, le=1.0)
    samples_count: int = Field(..., ge=0)


class EvaluationResult(BaseModel):
    """一次 A/B 评估运行的结果汇总。"""

    id: str = Field(default_factory=lambda: str(uuid4()))
    run_at: datetime = Field(default_factory=datetime.utcnow)
    benchmark_path: str
    results: Dict[str, EvaluationMetrics] = Field(default_factory=dict)
    winner: Optional[str] = None
    notes: str = ""
