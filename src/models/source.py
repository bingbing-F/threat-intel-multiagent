"""原始采集内容的数据模型。

该模块定义了存储从各类来源采集到的原始条目的 Pydantic 模型 `RawContent`，
用于统一传递采集到的文本、元数据与时间戳，便于在采集、分析与持久化
之间建立一致的数据契约。
"""
from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class RawContent(BaseModel):
    """表示一条来自数据源的原始内容记录。

    字段说明：
    - `id`: 唯一标识符，默认使用 UUID4 生成。
    - `source_name`: 来源名称（例如：darkweb_1、twitter、rss_feed 等）。
    - `url`: 原始来源地址（若有）。
    - `title`: 可选标题（如页面标题或帖子标题）。
    - `content`: 原始文本内容（正文）。
    - `content_hash`: 用于去重的内容哈希值。
    - `collected_at`: 采集时间（UTC）。
    - `metadata`: 可扩展的元数据字典，用于记录来源层级、抓取上下文等额外信息。
    """

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
