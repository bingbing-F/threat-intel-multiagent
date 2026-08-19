"""Data models for structured threat intelligence."""
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ExtractedIntelligence(BaseModel):
    """Fields extracted from raw text by the LLM."""

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
        return round(v, 4)


class ThreatIntelligence(ExtractedIntelligence):
    """A structured threat intelligence item with runtime metadata."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = Field(default="", min_length=0)
    raw_text: str = Field(default="", min_length=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_valid: bool = Field(default=False)
    validation_reason: str = Field(default="")

    # Adversarial review metadata (filled by the collaboration loop).
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
    """Result of validation agent."""

    is_valid: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    matched_rules: List[str] = Field(default_factory=list)
