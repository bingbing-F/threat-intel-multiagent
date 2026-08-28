"""对抗式审查协作环（Reviewer/Coordinator）使用的数据模型。"""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class ReviewIssue(BaseModel):
    """由审查者对分析结果提出的单个问题（Issue）。"""

    code: str
    message: str
    # 表示该问题是否可自动修复（Coordinator 可应用修复并重审）
    fixable: bool = Field(default=False)


class ReviewVerdict(BaseModel):
    """审查者对一次抽取/分析结果的判定信息。

    包含审查模式（规则/LLM/混合）、是否通过、发现的问题、审查轮次与置信度变化。
    """

    intelligence_id: str
    version: str = ""
    reviewer_mode: str = Field(default="rule", description="rule | llm | rule+llm")
    approved: bool
    issues: List[ReviewIssue] = Field(default_factory=list)
    rounds: int = Field(default=1, ge=1)
    confidence_delta: float = Field(default=0.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def issue_codes(self) -> List[str]:
        return [issue.code for issue in self.issues]


class ReviewRecord(BaseModel):
    """用于持久化的审查记录（便于指标统计与历史回溯）。"""

    id: str = Field(default_factory=lambda: str(uuid4()))
    intelligence_id: str
    version: str = ""
    reviewer_mode: str = "rule"
    approved: bool
    issue_codes: List[str] = Field(default_factory=list)
    rounds: int = Field(default=1)
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)