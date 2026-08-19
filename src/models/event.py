"""Data models for cross-source correlated threat events."""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class ThreatEvent(BaseModel):
    """A threat event corroborated across multiple sources by shared indicators."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(..., min_length=1)
    key_indicators: List[str] = Field(default_factory=list)
    intel_ids: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    source_count: int = Field(default=0, ge=0)
    threat_types: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    corroborated: bool = Field(default=False)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)