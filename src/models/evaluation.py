"""Data models for prompt A/B evaluation."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class PromptVersion(BaseModel):
    """A registered prompt version."""

    version: str = Field(..., pattern=r"^v\d+\.\d+$")
    name: str
    description: str
    file_path: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EvaluationMetrics(BaseModel):
    """Metrics for a single prompt version on a benchmark."""

    accuracy: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1: float = Field(..., ge=0.0, le=1.0)
    avg_confidence: float = Field(..., ge=0.0, le=1.0)
    samples_count: int = Field(..., ge=0)


class EvaluationResult(BaseModel):
    """Result of an A/B evaluation run."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    run_at: datetime = Field(default_factory=datetime.utcnow)
    benchmark_path: str
    results: Dict[str, EvaluationMetrics] = Field(default_factory=dict)
    winner: Optional[str] = None
    notes: str = ""
