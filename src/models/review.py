"""Data models for the adversarial review collaboration loop."""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class ReviewIssue(BaseModel):
    """A single issue raised by the reviewer against an analysis result."""

    code: str
    message: str
    fixable: bool = Field(default=False)


class ReviewVerdict(BaseModel):
    """Verdict of the reviewer agent on one extraction result."""

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
    """A persisted review record used for metrics and history."""

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