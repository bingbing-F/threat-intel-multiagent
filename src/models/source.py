"""Data models for raw collected content."""
from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class RawContent(BaseModel):
    """A piece of raw content collected from a source."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_name: str
    url: Optional[str] = None
    title: Optional[str] = None
    content: str
    content_hash: str
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict = Field(default_factory=dict)

    class Config:
        from_attributes = True
