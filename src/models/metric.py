"""Data models for cross-domain monitoring metrics."""
from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, Field


class DomainMetric(BaseModel):
    """Aggregated per-domain monitoring metrics for one run."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    domain: str = Field(..., min_length=1)
    run_at: datetime = Field(default_factory=datetime.utcnow)
    matched_items: int = Field(default=0, ge=0)
    total_sources: int = Field(default=0, ge=0)
    dark_sources: int = Field(default=0, ge=0)
    matched_keywords: List[str] = Field(default_factory=list)
    sample_summary: str = Field(default="")


class MonitorRun(BaseModel):
    """Summary of a single monitoring sweep across all domains."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    run_at: datetime = Field(default_factory=datetime.utcnow)
    scanned_items: int = Field(default=0, ge=0)
    domains: List[str] = Field(default_factory=list)
    metrics: List[DomainMetric] = Field(default_factory=list)